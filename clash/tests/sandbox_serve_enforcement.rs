//! Cross-platform behavioral coverage for the `localhost_serve` capability.
//!
//! These drive the real `clash` binary end to end — inline sandbox JSON through
//! the policy types into whichever kernel backend the platform uses — rather
//! than asserting on a generated profile or a syscall list. That is the only
//! way to catch a rule that is present but does not take effect.
//!
//! macOS (Seatbelt) and Linux (seccomp) enforce different amounts of this
//! capability, and the assertions below encode that difference deliberately:
//! seccomp cannot dereference the `sockaddr` argument, so on Linux the
//! loopback-only and port-list halves are advisory. If that ever changes, these
//! tests should be tightened, not deleted.

use std::process::{Command, Stdio};

const CLASH: &str = env!("CARGO_BIN_EXE_clash");

/// Run a shell snippet under an inline sandbox definition, returning output.
fn run_sandboxed(sandbox_json: &str, script: &str) -> String {
    let out = Command::new(CLASH)
        .args(["sandbox", "exec", "--sandbox", sandbox_json, "--"])
        .args(["/bin/sh", "-c", script])
        .env_remove("CLASH_DISABLE")
        .stdin(Stdio::null())
        .output()
        .expect("clash binary should run");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Whether the sandbox can hold a listening socket on `port`.
///
/// Deliberately avoids a connect probe: connecting is an *outbound* operation
/// that a restrictive network policy blocks on its own, which would mask the
/// bind result and make a broken capability look correctly denied.
fn can_bind(sandbox_json: &str, port: u16) -> bool {
    let script = format!(
        "nc -l 127.0.0.1 {port} 2>/dev/null & p=$!; sleep 1; \
         if kill -0 $p 2>/dev/null; then echo LISTENING; else echo DENIED; fi; \
         kill $p 2>/dev/null"
    );
    run_sandboxed(sandbox_json, &script).contains("LISTENING")
}

fn sandbox(network: &str, system: &str) -> String {
    format!(
        r#"{{"default":["read","execute"],"network":{network},"system":{system}}}"#,
        network = network,
        system = system
    )
}

#[test]
fn binding_requires_the_localhost_serve_capability() {
    assert!(
        !can_bind(&sandbox(r#""localhost""#, "[]"), 47101),
        "a sandbox without localhost_serve must not be able to listen"
    );
    assert!(
        can_bind(&sandbox(r#""localhost""#, r#"["localhost_serve"]"#), 47102),
        "localhost_serve must actually permit listening"
    );
}

#[test]
fn serving_survives_a_deny_all_network_policy() {
    // The capability is orthogonal to the outbound policy: `deny` still emits a
    // blanket network deny, and the serve grant has to win against it.
    assert!(
        !can_bind(&sandbox(r#""deny""#, "[]"), 47103),
        "net=deny without the capability must not listen"
    );
    assert!(
        can_bind(&sandbox(r#""deny""#, r#"["localhost_serve"]"#), 47104),
        "net=deny with the capability must still be able to listen"
    );
}

#[test]
fn serving_never_implies_outbound_access() {
    // The security property that makes `deny + serve` acceptable: a sandbox may
    // accept connections without gaining the ability to reach out.
    let out = run_sandboxed(
        &sandbox(r#""deny""#, r#"["localhost_serve"]"#),
        "curl -sS --max-time 5 -o /dev/null -w 'code:%{http_code}' https://example.com 2>&1 | tail -1",
    );
    assert!(
        out.contains("code:000")
            || out.to_lowercase().contains("could not resolve")
            || out.to_lowercase().contains("failed")
            || out.to_lowercase().contains("not permitted"),
        "outbound must stay blocked when only serving is granted, got: {out}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn declared_ports_confine_serving_on_macos() {
    // Seatbelt can filter the bind address and port, so the port list in the
    // network policy must constrain inbound exactly as it does outbound.
    let json = sandbox(r#"{"localhost":[47201]}"#, r#"["localhost_serve"]"#);
    assert!(can_bind(&json, 47201), "declared port must be bindable");
    assert!(
        !can_bind(&json, 47202),
        "a port outside the declared list must not be bindable"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn declared_ports_are_advisory_on_linux() {
    // seccomp cannot inspect the sockaddr, so the port list cannot constrain
    // bind(). This asserts the documented (weaker) behaviour so that the
    // platform gap stays visible instead of being silently assumed away.
    let json = sandbox(r#"{"localhost":[47201]}"#, r#"["localhost_serve"]"#);
    assert!(can_bind(&json, 47201), "declared port must be bindable");
    assert!(
        can_bind(&json, 47202),
        "documented Linux limitation: the port list does not constrain bind(); \
         if this now fails, seccomp gained the ability to filter and the docs \
         plus the macOS-only port test should be updated"
    );
}
