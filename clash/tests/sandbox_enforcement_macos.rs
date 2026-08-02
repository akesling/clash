//! Behavioral sandbox enforcement tests (macOS).
//!
//! These drive the real kernel via `sandbox-exec` rather than asserting on the
//! text of the generated profile. Profile-text assertions cannot catch the
//! failure mode that matters: a rule that is present but does not take effect
//! (Seatbelt rule precedence is undocumented, and the network section relies on
//! specific allows preceding a blanket `(deny network*)`).
#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};

use clash::policy::sandbox_types::{Cap, NetworkPolicy, SandboxPolicy, SystemCap};
use clash::sandbox::macos::compile_to_sbpl;

fn policy(network: NetworkPolicy, system: SystemCap) -> SandboxPolicy {
    SandboxPolicy {
        default: Cap::READ | Cap::EXECUTE,
        rules: vec![],
        network,
        system,
        doc: None,
    }
}

/// Run `script` under the compiled profile and return combined output.
fn run_under_sandbox(policy: &SandboxPolicy, script: &str) -> String {
    let profile = compile_to_sbpl(policy, "/tmp");
    let out = Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .output()
        .expect("sandbox-exec should be available on macOS");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Can the sandbox bind a listener on `port`?
///
/// Uses listener liveness rather than a connect probe: connecting is itself an
/// *outbound* operation that a restrictive network policy blocks independently,
/// which would mask the bind result.
fn can_bind(policy: &SandboxPolicy, port: u16) -> bool {
    let script = format!(
        "nc -l 127.0.0.1 {port} 2>/dev/null & p=$!; /bin/sleep 1; \
         if kill -0 $p 2>/dev/null; then echo LISTENING; else echo DENIED; fi; \
         kill $p 2>/dev/null"
    );
    run_under_sandbox(policy, &script).contains("LISTENING")
}

#[test]
fn localhost_serve_is_required_to_bind() {
    assert!(
        !can_bind(&policy(NetworkPolicy::Localhost, SystemCap::empty()), 46101),
        "binding must be denied without the localhost_serve capability"
    );
    assert!(
        can_bind(
            &policy(NetworkPolicy::Localhost, SystemCap::LOCALHOST_SERVE),
            46102
        ),
        "localhost_serve must actually permit binding, not just appear in the profile"
    );
}

#[test]
fn localhost_serve_survives_the_blanket_network_deny() {
    // net=deny still emits `(deny network*)`; the serve allows must win.
    assert!(
        can_bind(
            &policy(NetworkPolicy::Deny, SystemCap::LOCALHOST_SERVE),
            46103
        ),
        "serve allows must take precedence over the trailing (deny network*)"
    );
}

#[test]
fn localhost_serve_is_confined_to_declared_ports() {
    let p = policy(
        NetworkPolicy::LocalhostPorts(vec![46201]),
        SystemCap::LOCALHOST_SERVE,
    );
    assert!(can_bind(&p, 46201), "declared port should be bindable");
    assert!(
        !can_bind(&p, 46202),
        "a port outside the declared list must not be bindable"
    );
}

#[test]
fn signal_is_scoped_to_the_same_sandbox_instance() {
    // A process must not be able to signal one outside its own sandbox, even
    // when that process runs under an identical profile.
    let p = policy(NetworkPolicy::Deny, SystemCap::empty());

    let mut victim = Command::new("/bin/sleep")
        .arg("30")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn victim");
    let victim_pid = victim.id();

    let out = run_under_sandbox(&p, &format!("/bin/kill -TERM {victim_pid} 2>&1; echo done"));
    let still_alive = matches!(victim.try_wait(), Ok(None));
    let _ = victim.kill();
    let _ = victim.wait();

    assert!(
        still_alive,
        "sandboxed process must not signal outside its sandbox (output: {out})"
    );
}

#[test]
fn signal_within_the_same_sandbox_instance_is_permitted() {
    // The converse of the isolation test: a process must be able to manage its
    // own children, which is what the preamble's signal rule exists for.
    let p = policy(NetworkPolicy::Deny, SystemCap::empty());
    let out = run_under_sandbox(
        &p,
        "/bin/sleep 5 & p=$!; if kill -TERM $p 2>/dev/null; then echo KILLED; else echo BLOCKED; fi",
    );
    assert!(
        out.contains("KILLED"),
        "a sandbox must be able to signal its own children (output: {out})"
    );
}

#[test]
fn power_capability_is_scoped_to_the_power_user_client() {
    // The narrow scoping is the whole security argument for `power`; assert the
    // profile never widens to a blanket iokit-open.
    let profile = compile_to_sbpl(&policy(NetworkPolicy::Deny, SystemCap::POWER), "/tmp");
    assert!(
        profile.contains("(allow iokit-open (iokit-user-client-class \"RootDomainUserClient\"))")
    );
    assert!(!profile.contains("(allow iokit-open)"));
    assert!(!profile.contains("(allow iokit*)"));
}
