//! Linux sandbox backend using Landlock + seccomp.
//!
//! - Landlock: kernel-enforced filesystem access control (since 5.13)
//! - seccomp-BPF: syscall filtering for network isolation
//! - PR_SET_NO_NEW_PRIVS: prevent privilege escalation via setuid

use std::collections::BTreeMap;
use std::path::Path;

use crate::policy::sandbox_types::{
    Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy, SystemCap,
};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use tracing::{Level, instrument};

use super::{SandboxError, SupportLevel, do_exec};

/// Apply sandbox policy and exec the command.
#[instrument(level = Level::TRACE, skip(policy))]
pub fn exec_sandboxed(
    policy: &SandboxPolicy,
    cwd: &Path,
    command: &[String],
) -> Result<std::convert::Infallible, SandboxError> {
    let cwd_str = cwd.to_string_lossy();

    // 1. Set NO_NEW_PRIVS (must come before seccomp and landlock)
    set_no_new_privs()?;

    // 2. Install seccomp network filter based on network policy.
    //
    // `localhost_serve` unblocks the server-side syscalls. Restricting the
    // listener to loopback is advisory on Linux (seccomp cannot dereference
    // the sockaddr), matching how the outbound side is already handled.
    let localhost_serve = policy.system.contains(SystemCap::LOCALHOST_SERVE);
    match &policy.network {
        NetworkPolicy::Deny => {
            install_seccomp_network_filter(localhost_serve)?;
        }
        NetworkPolicy::Localhost => {
            // Localhost-only: seccomp cannot filter connect() by destination
            // address, so this is advisory. Block bind/listen/accept to prevent
            // server-side operations.
            install_seccomp_advisory_network_filter(localhost_serve)?;
        }
        NetworkPolicy::LocalhostPorts(_) => {
            // Port-level filtering is not enforceable via seccomp (can't inspect
            // connect() sockaddr). Same advisory behavior as Localhost — including
            // for serving, so the declared port list does not constrain bind().
            install_seccomp_advisory_network_filter(localhost_serve)?;
        }
        NetworkPolicy::AllowDomains(_) => {
            // On Linux, seccomp cannot filter connect() by destination address
            // (the address arg is a pointer seccomp can't dereference). We allow
            // outbound connections and rely on the HTTP proxy for domain filtering.
            // This is advisory: programs that bypass HTTP_PROXY can reach any host.
            install_seccomp_advisory_network_filter(localhost_serve)?;
        }
        NetworkPolicy::Allow => {
            // No filter needed
        }
    }

    // 3. Apply Landlock filesystem rules
    install_landlock_rules(policy, &cwd_str)?;

    // 4. Exec the command
    do_exec(command)
}

/// Check if the current kernel supports sandboxing.
#[instrument(level = Level::TRACE)]
pub fn check_support() -> SupportLevel {
    // Try to detect Landlock ABI support
    let abi_result = std::panic::catch_unwind(|| {
        // landlock crate will check kernel support internally
        Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(ABI::V5))
    });

    match abi_result {
        Ok(Ok(_)) => SupportLevel::Full,
        Ok(Err(_)) => SupportLevel::Partial {
            missing: vec!["Landlock may not be fully supported on this kernel".into()],
        },
        Err(_) => SupportLevel::Unsupported {
            reason: "Landlock not available on this kernel".into(),
        },
    }
}

/// Prevent privilege escalation via setuid/setgid binaries.
#[instrument(level = Level::TRACE)]
fn set_no_new_privs() -> Result<(), SandboxError> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(SandboxError::Apply(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Map Cap flags to Landlock AccessFs bitflags.
#[instrument(level = Level::TRACE)]
fn cap_to_access_fs(caps: Cap) -> landlock::BitFlags<AccessFs> {
    let mut access = landlock::BitFlags::<AccessFs>::empty();

    if caps.contains(Cap::READ) {
        access |= AccessFs::ReadFile | AccessFs::ReadDir;
    }
    if caps.contains(Cap::WRITE) {
        access |= AccessFs::WriteFile | AccessFs::Truncate | AccessFs::Refer;
    }
    if caps.contains(Cap::CREATE) {
        access |= AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::MakeSym
            | AccessFs::MakeFifo
            | AccessFs::MakeSock;
    }
    if caps.contains(Cap::DELETE) {
        access |= AccessFs::RemoveFile | AccessFs::RemoveDir;
    }
    if caps.contains(Cap::EXECUTE) {
        access |= AccessFs::Execute;
    }

    access
}

/// Collect the effective Landlock rules from the sandbox policy.
///
/// Strategy: since Landlock is additive (you grant access to paths, default is
/// deny-all for the handled access types), we need to:
/// 1. Determine which access types we want to restrict (handle)
/// 2. For each rule path, compute effective caps and add Landlock rules
#[instrument(level = Level::TRACE, skip(policy))]
fn install_landlock_rules(policy: &SandboxPolicy, cwd: &str) -> Result<(), SandboxError> {
    let abi = ABI::V5;
    let all_access = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all_access)
        .map_err(|e| SandboxError::Apply(format!("landlock handle_access: {}", e)))?
        .create()
        .map_err(|e| SandboxError::Apply(format!("landlock create: {}", e)))?;

    // Always allow read+execute on the root filesystem (for system binaries, libs, etc.)
    // unless the policy explicitly denies reads somewhere
    let default_access = cap_to_access_fs(policy.default);
    if !default_access.is_empty() {
        ruleset = add_path_rule(ruleset, "/", default_access)?;
    }

    // Always allow write to /dev/null
    ruleset = add_path_rule(
        ruleset,
        "/dev/null",
        AccessFs::WriteFile | AccessFs::Truncate | AccessFs::ReadFile,
    )?;

    // Apply each rule
    for rule in &policy.rules {
        if rule.path_match == PathMatch::Regex {
            // Landlock can't enforce regex path rules — skip silently.
            // Regex rules are enforced on macOS via Seatbelt SBPL.
            continue;
        }
        if rule.effect == RuleEffect::Allow {
            let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
            let access = cap_to_access_fs(rule.caps);
            // Merge with default access for this path
            let total_access = access | default_access;
            if !total_access.is_empty() {
                ruleset = add_path_rule(ruleset, &resolved, total_access)?;
            }
        }
        // Deny rules are handled by NOT granting those caps — Landlock is
        // default-deny for handled access types, so we only grant what's allowed.
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Apply(format!("landlock restrict_self: {}", e)))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Apply(
            "landlock: ruleset not enforced (kernel may not support Landlock)".into(),
        ));
    }

    Ok(())
}

/// Add a path-based rule to the Landlock ruleset.
/// Silently ignores paths that don't exist (the sandbox shouldn't fail because
/// an optional path like $TMPDIR doesn't exist).
#[instrument(level = Level::TRACE)]
fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    match PathFd::new(path) {
        Ok(fd) => ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| SandboxError::Apply(format!("landlock add_rule for '{}': {}", path, e))),
        Err(_) => {
            // Path doesn't exist — skip silently
            Ok(ruleset)
        }
    }
}

/// Install a seccomp-BPF filter to block network syscalls.
///
/// Blocks socket creation for non-AF_UNIX domains, and blocks most
/// network-related syscalls outright. AF_UNIX is preserved for IPC
/// (tools like cargo use socketpair internally).
///
/// When `localhost_serve` is set, the server-side syscalls are permitted and
/// AF_INET/AF_INET6 sockets may be created, while `connect` and the datagram
/// send paths stay blocked — the process can accept connections but still
/// cannot reach out. seccomp cannot dereference the `sockaddr` argument, so
/// the *loopback* half of the restriction is advisory on Linux: a process
/// granted `localhost_serve` can bind `0.0.0.0` too. This matches the existing
/// advisory treatment of `Localhost`/`LocalhostPorts`.
#[instrument(level = Level::TRACE)]
fn install_seccomp_network_filter(localhost_serve: bool) -> Result<(), SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    let deny_syscalls = deny_filter_syscalls(localhost_serve);

    for &syscall in &deny_syscalls {
        rules.insert(syscall, vec![]);
    }

    // For socket() and socketpair(): deny domains the sandbox has no use for.
    // AF_UNIX is always permitted for IPC; the IP families are added only when
    // the sandbox may serve. Conditions within a rule are ANDed, so this denies
    // only when the domain matches none of the permitted families.
    let mut domain_conditions = vec![domain_is_not(libc::AF_UNIX)?];
    if localhost_serve {
        domain_conditions.push(domain_is_not(libc::AF_INET)?);
        domain_conditions.push(domain_is_not(libc::AF_INET6)?);
    }
    let domain_rule = SeccompRule::new(domain_conditions)
        .map_err(|e| SandboxError::Apply(format!("seccomp rule: {}", e)))?;

    rules.insert(libc::SYS_socket, vec![domain_rule.clone()]);
    rules.insert(libc::SYS_socketpair, vec![domain_rule]);

    let arch = seccomp_arch()?;
    apply_seccomp_filter(rules, arch)
}

/// Syscalls the `Deny` network filter blocks, given the serve capability.
///
/// Split out from filter installation so the policy decision is unit-testable
/// without applying a real seccomp filter to the test process.
fn deny_filter_syscalls(localhost_serve: bool) -> Vec<i64> {
    // Blocked whether or not the sandbox may serve: the paths that reach *out*.
    let mut syscalls = vec![
        libc::SYS_connect,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_sendto,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        // Also block ptrace for security
        libc::SYS_ptrace,
    ];

    // Server-side syscalls, plus the socket introspection a listener needs.
    if !localhost_serve {
        syscalls.extend_from_slice(&[
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_getsockname,
            libc::SYS_getsockopt,
            libc::SYS_setsockopt,
        ]);
    }

    syscalls
}

/// Syscalls the advisory (`Localhost`/`LocalhostPorts`/`AllowDomains`) filter
/// blocks, given the serve capability.
fn advisory_filter_syscalls(localhost_serve: bool) -> Vec<i64> {
    let mut syscalls = vec![libc::SYS_ptrace];
    if !localhost_serve {
        // Block server-side operations
        syscalls.extend_from_slice(&[
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_bind,
            libc::SYS_listen,
        ]);
    }
    syscalls
}

/// Build a "socket domain is not `family`" seccomp condition on argument 0.
fn domain_is_not(family: libc::c_int) -> Result<SeccompCondition, SandboxError> {
    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, family as u64)
        .map_err(|e| SandboxError::Apply(format!("seccomp condition: {}", e)))
}

/// Install a permissive seccomp filter for `AllowDomains` on Linux.
///
/// Allows socket creation for AF_INET/AF_INET6 (needed for proxy connection)
/// and outbound connections, but blocks bind/listen/accept to prevent the
/// sandboxed process from running a server. Domain filtering is handled by
/// the HTTP proxy, not seccomp.
///
/// When `localhost_serve` is set, the server-side syscalls are permitted.
/// seccomp cannot inspect the bind address, so — as with the outbound
/// destination — restricting the listener to loopback is advisory on Linux.
#[instrument(level = Level::TRACE)]
fn install_seccomp_advisory_network_filter(localhost_serve: bool) -> Result<(), SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    let deny_syscalls = advisory_filter_syscalls(localhost_serve);

    for &syscall in &deny_syscalls {
        rules.insert(syscall, vec![]);
    }

    let arch = seccomp_arch()?;
    apply_seccomp_filter(rules, arch)
}

/// Detect the target architecture for seccomp.
fn seccomp_arch() -> Result<TargetArch, SandboxError> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else {
        Err(SandboxError::Apply(
            "seccomp: unsupported architecture".into(),
        ))
    }
}

/// Build and apply a seccomp-BPF filter from the given rules.
fn apply_seccomp_filter(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    arch: TargetArch,
) -> Result<(), SandboxError> {
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,    // default: allow all syscalls
        SeccompAction::Errno(1), // EPERM for filtered syscalls
        arch,
    )
    .map_err(|e| SandboxError::Apply(format!("seccomp filter: {}", e)))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| SandboxError::Apply(format!("seccomp compile: {}", e)))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| SandboxError::Apply(format!("seccomp apply: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_SIDE: [i64; 4] = [
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_listen,
    ];

    #[test]
    fn deny_filter_without_serve_blocks_server_syscalls() {
        let blocked = deny_filter_syscalls(false);
        for sc in SERVER_SIDE {
            assert!(blocked.contains(&sc), "syscall {sc} should be blocked");
        }
        // The pre-existing blocklist must be preserved exactly, so sandboxes
        // that do not opt in see no change in behaviour.
        for sc in [
            libc::SYS_getsockname,
            libc::SYS_getsockopt,
            libc::SYS_setsockopt,
        ] {
            assert!(blocked.contains(&sc), "syscall {sc} should be blocked");
        }
    }

    #[test]
    fn deny_filter_with_serve_unblocks_server_syscalls_but_not_outbound() {
        let blocked = deny_filter_syscalls(true);
        for sc in SERVER_SIDE {
            assert!(
                !blocked.contains(&sc),
                "localhost_serve must unblock syscall {sc}"
            );
        }
        // Serving must not become a way to reach out.
        for sc in [
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_sendmmsg,
            libc::SYS_ptrace,
        ] {
            assert!(
                blocked.contains(&sc),
                "syscall {sc} must stay blocked even when serving"
            );
        }
    }

    #[test]
    fn advisory_filter_serve_toggles_only_server_syscalls() {
        let without = advisory_filter_syscalls(false);
        let with = advisory_filter_syscalls(true);

        for sc in SERVER_SIDE {
            assert!(without.contains(&sc));
            assert!(!with.contains(&sc));
        }
        // ptrace is blocked regardless — it is not a network concern.
        assert!(without.contains(&libc::SYS_ptrace));
        assert!(with.contains(&libc::SYS_ptrace));
    }

    #[test]
    fn serve_capability_never_unblocks_ptrace() {
        // Guards against a future refactor folding ptrace into the toggled set.
        assert!(deny_filter_syscalls(true).contains(&libc::SYS_ptrace));
        assert!(advisory_filter_syscalls(true).contains(&libc::SYS_ptrace));
    }
}
