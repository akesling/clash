//! Capability-based env injection for hook handlers.
//!
//! The three production hook entry points need to be unit-testable without
//! reaching into the real `$HOME`, real filesystem, or real sandbox probe.
//! Each env-dependent capability is expressed as a small trait. Production
//! wires the real functions via [`Env::prod`]; tests construct an [`Env`]
//! from stub or in-memory implementations.

#![allow(clippy::disallowed_methods)] // adapter module: the only place that may call the wrapped functions

/// Read/write user-, project-, and session-level policy state.
pub trait PolicyStore {}

/// Per-session bookkeeping: audit init, active-session marker, trace init,
/// incremental stats/trace updates, and pending-ask recording.
pub trait SessionRecorder {}

/// Probe the host for sandbox support.
pub trait SandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel;
}

/// Bundle of env capabilities passed through hook handlers.
///
/// Construct via [`Env::prod`] in production and via `Env { ... }` with
/// fake/stub impls in tests.
pub struct Env<'a> {
    pub policy: &'a dyn PolicyStore,
    pub session: &'a dyn SessionRecorder,
    pub sandbox: &'a dyn SandboxProbe,
}

/// Production [`PolicyStore`]. Zero-sized; lives as a `static`.
pub struct DefaultPolicyStore;
impl PolicyStore for DefaultPolicyStore {}

/// Production [`SessionRecorder`]. Zero-sized; lives as a `static`.
pub struct DefaultSessionRecorder;
impl SessionRecorder for DefaultSessionRecorder {}

/// Production [`SandboxProbe`]. Zero-sized; lives as a `static`.
pub struct DefaultSandboxProbe;
impl SandboxProbe for DefaultSandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel {
        crate::sandbox::check_support()
    }
}

pub static DEFAULT_POLICY_STORE: DefaultPolicyStore = DefaultPolicyStore;
pub static DEFAULT_SESSION_RECORDER: DefaultSessionRecorder = DefaultSessionRecorder;
pub static DEFAULT_SANDBOX_PROBE: DefaultSandboxProbe = DefaultSandboxProbe;

impl Env<'static> {
    /// Build the production [`Env`] — wires every capability to the real
    /// filesystem/policy/sandbox subsystems.
    pub fn prod() -> Self {
        Env {
            policy: &DEFAULT_POLICY_STORE,
            session: &DEFAULT_SESSION_RECORDER,
            sandbox: &DEFAULT_SANDBOX_PROBE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_prod_constructs() {
        let _env = Env::prod();
    }

    #[test]
    fn default_sandbox_probe_matches_check_support() {
        let direct = crate::sandbox::check_support();
        let via_env = DEFAULT_SANDBOX_PROBE.check_support();
        let same_variant = matches!(
            (&direct, &via_env),
            (
                crate::sandbox::SupportLevel::Full,
                crate::sandbox::SupportLevel::Full
            ) | (
                crate::sandbox::SupportLevel::Partial { .. },
                crate::sandbox::SupportLevel::Partial { .. }
            ) | (
                crate::sandbox::SupportLevel::Unsupported { .. },
                crate::sandbox::SupportLevel::Unsupported { .. }
            )
        );
        assert!(same_variant, "trait delegate diverged from direct call");
    }
}
