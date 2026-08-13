//! Sandbox capability types for kernel-enforced process restrictions.
//!
//! These types define a platform-agnostic sandbox policy that compiles to
//! Landlock+seccomp on Linux or Seatbelt SBPL on macOS.

use std::path::Path;

use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// High-level filesystem capabilities.
    ///
    /// Each platform backend maps these to its own enforcement primitives:
    /// - Linux: Landlock `AccessFs` bitflags
    /// - macOS: Seatbelt SBPL operations
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Cap: u8 {
        /// Read files and list directories.
        const READ    = 0b0000_0001;
        /// Write/modify existing files (includes truncate).
        const WRITE   = 0b0000_0010;
        /// Create new files, directories, symlinks, etc.
        const CREATE  = 0b0000_0100;
        /// Delete (unlink) files or remove directories.
        const DELETE  = 0b0000_1000;
        /// Execute files as programs.
        const EXECUTE = 0b0001_0000;
    }
}

impl Cap {
    /// Return capabilities as a list of name strings.
    pub fn to_list(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.contains(Cap::READ) {
            names.push("read");
        }
        if self.contains(Cap::WRITE) {
            names.push("write");
        }
        if self.contains(Cap::CREATE) {
            names.push("create");
        }
        if self.contains(Cap::DELETE) {
            names.push("delete");
        }
        if self.contains(Cap::EXECUTE) {
            names.push("execute");
        }
        names
    }

    /// Parse a single capability name.
    pub fn parse_single(s: &str) -> Result<Cap, String> {
        match s {
            "read" => Ok(Cap::READ),
            "write" => Ok(Cap::WRITE),
            "create" => Ok(Cap::CREATE),
            "delete" => Ok(Cap::DELETE),
            "execute" => Ok(Cap::EXECUTE),
            "full" | "all" => Ok(Cap::all()),
            other => Err(format!("unknown capability: '{}'", other)),
        }
    }

    /// Format capabilities as a human-readable string like "read + write".
    pub fn display(&self) -> String {
        let mut parts = Vec::new();
        if self.contains(Cap::READ) {
            parts.push("read");
        }
        if self.contains(Cap::WRITE) {
            parts.push("write");
        }
        if self.contains(Cap::CREATE) {
            parts.push("create");
        }
        if self.contains(Cap::DELETE) {
            parts.push("delete");
        }
        if self.contains(Cap::EXECUTE) {
            parts.push("execute");
        }
        parts.join(" + ")
    }

    /// Compact `ls -l`-style capability string: `rwcdx`.
    ///
    /// Each position is the capability letter when set, or `-` when absent:
    /// `r`ead `w`rite `c`reate `d`elete e`x`ecute.
    ///
    /// Examples: `rwcdx` (all), `rw---` (read+write), `r---x` (read+exec).
    pub fn short(&self) -> String {
        let mut s = String::with_capacity(5);
        s.push(if self.contains(Cap::READ) { 'r' } else { '-' });
        s.push(if self.contains(Cap::WRITE) { 'w' } else { '-' });
        s.push(if self.contains(Cap::CREATE) { 'c' } else { '-' });
        s.push(if self.contains(Cap::DELETE) { 'd' } else { '-' });
        s.push(if self.contains(Cap::EXECUTE) {
            'x'
        } else {
            '-'
        });
        s
    }
}

impl Serialize for Cap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let names = self.to_list();
        let mut seq = serializer.serialize_seq(Some(names.len()))?;
        for name in &names {
            seq.serialize_element(name)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Cap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct CapVisitor;

        impl<'de> de::Visitor<'de> for CapVisitor {
            type Value = Cap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#"a list of capabilities like ["read", "write"]"#)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Cap, A::Error> {
                let mut caps = Cap::empty();
                while let Some(name) = seq.next_element::<String>()? {
                    caps |= Cap::parse_single(&name).map_err(de::Error::custom)?;
                }
                if caps.is_empty() {
                    return Err(de::Error::custom("capability list must not be empty"));
                }
                Ok(caps)
            }
        }

        deserializer.deserialize_any(CapVisitor)
    }
}

bitflags::bitflags! {
    /// Opt-in system capabilities beyond filesystem and network access.
    ///
    /// These grant narrow kernel services that some workloads require but
    /// that default-deny sandboxes block. Each is enforced where the
    /// platform supports it (macOS Seatbelt) and is a no-op elsewhere
    /// (Linux Landlock/seccomp does not restrict these services).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SystemCap: u8 {
        /// Receive power-management notifications (system sleep/wake).
        /// Required by JVM-based tools: Bazel's server registers via
        /// `IORegisterForSystemPower()` at startup and aborts if the call
        /// fails. On macOS this compiles to an `iokit-open` allowance
        /// scoped to the power-management user client only.
        const POWER = 0b0000_0001;
        /// Bind and accept connections on loopback (localhost) ports.
        /// Required by tools with a client/server split over localhost
        /// (Bazel's gRPC server, dev servers under test). Outbound
        /// loopback access is governed by the network policy; this only
        /// adds serving.
        const LOCALHOST_SERVE = 0b0000_0010;
    }
}

impl SystemCap {
    /// Return capabilities as a list of name strings.
    pub fn to_list(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.contains(SystemCap::POWER) {
            names.push("power");
        }
        if self.contains(SystemCap::LOCALHOST_SERVE) {
            names.push("localhost_serve");
        }
        names
    }

    /// Parse a single system capability name.
    pub fn parse_single(s: &str) -> Result<SystemCap, String> {
        match s {
            "power" => Ok(SystemCap::POWER),
            "localhost_serve" => Ok(SystemCap::LOCALHOST_SERVE),
            other => Err(format!(
                "unknown system capability: '{}' (expected \"power\" or \"localhost_serve\")",
                other
            )),
        }
    }

    /// Format capabilities as a human-readable string like "power + localhost_serve".
    pub fn display(&self) -> String {
        self.to_list().join(" + ")
    }
}

impl Serialize for SystemCap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let names = self.to_list();
        let mut seq = serializer.serialize_seq(Some(names.len()))?;
        for name in &names {
            seq.serialize_element(name)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SystemCap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct SystemCapVisitor;

        impl<'de> de::Visitor<'de> for SystemCapVisitor {
            type Value = SystemCap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#"a list of system capabilities like ["power"]"#)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<SystemCap, A::Error> {
                let mut caps = SystemCap::empty();
                while let Some(name) = seq.next_element::<String>()? {
                    caps |= SystemCap::parse_single(&name).map_err(de::Error::custom)?;
                }
                Ok(caps)
            }
        }

        deserializer.deserialize_any(SystemCapVisitor)
    }
}

/// Whether a sandboxed process starts from the parent environment or an empty
/// one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvDefault {
    /// Inherit the parent environment, then apply edits. The default, so
    /// adding an `env` block never silently strips something.
    #[default]
    Inherit,
    /// Start from an empty environment; only explicitly inherited or assigned
    /// names are present. Fails closed: a credential nobody thought to name is
    /// absent rather than passed through.
    Clean,
}

impl EnvDefault {
    fn is_inherit(&self) -> bool {
        matches!(self, EnvDefault::Inherit)
    }
}

/// Environment manipulation applied to a sandboxed process.
///
/// The operations are not equally strong, and it matters which one a policy
/// leans on:
///
/// - `default: Clean` plus `inherit` is confinement, and it fails closed —
///   anything not named is absent.
/// - `remove` is confinement, but it fails *open*: it only withholds names
///   somebody thought to list. Prefer `Clean` when the goal is keeping
///   credentials away from a process.
/// - `set` is configuration, not enforcement. It shapes how a cooperating
///   program behaves and constrains nothing.
///
/// Removal is applied after assignment, so a name in both is withheld.
///
/// Assigned values may reference the *parent's* environment with `$NAME` or
/// `${NAME}`, so a sandbox can relocate tool state without hard-coding a path:
/// `"CARGO_HOME": "$HOME/.sandboxed/cargo"`. `$PWD`, `$HOME` and `$TMPDIR`
/// work because they are ordinary environment variables — there is no separate
/// placeholder vocabulary. An undefined name expands to empty, matching how
/// clash resolves `$VAR` elsewhere. Write `$$` for a literal `$`. Under
/// `Clean`, expansion still reads the parent environment, before it is
/// discarded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvPolicy {
    /// Whether to start from the parent environment or an empty one.
    #[serde(default, skip_serializing_if = "EnvDefault::is_inherit")]
    pub default: EnvDefault,

    /// Names passed through from the parent. Only meaningful under `Clean`;
    /// under `Inherit` everything is already passed through.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub inherit: std::collections::BTreeSet<String>,

    /// Variables to define for the sandboxed process.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub set: std::collections::BTreeMap<String, String>,

    /// Variables to withhold from the sandboxed process.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub remove: std::collections::BTreeSet<String>,
}

impl EnvPolicy {
    /// Whether this policy would change anything.
    pub fn is_empty(&self) -> bool {
        self.default.is_inherit()
            && self.inherit.is_empty()
            && self.set.is_empty()
            && self.remove.is_empty()
    }

    /// Whether the parent environment is discarded before edits are applied.
    pub fn is_clean(&self) -> bool {
        matches!(self.default, EnvDefault::Clean)
    }

    /// The variables a `Clean` policy carries over, read from `parent`.
    ///
    /// Names absent from the parent are skipped rather than defined empty, so
    /// a pass-through never invents a value.
    fn inherited_from<'a>(
        &'a self,
        parent: &'a std::collections::HashMap<String, String>,
    ) -> impl Iterator<Item = (&'a String, &'a String)> + 'a {
        self.inherit
            .iter()
            .filter_map(move |name| parent.get_key_value(name))
    }

    /// Expand `$NAME` / `${NAME}` against `parent`; `$$` is a literal `$`.
    ///
    /// An undefined name expands to empty, consistent with how `$VAR` resolves
    /// elsewhere in clash.
    pub fn expand(raw: &str, parent: &std::collections::HashMap<String, String>) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '$' {
                out.push(c);
                continue;
            }
            match chars.peek() {
                Some('$') => {
                    chars.next();
                    out.push('$');
                }
                Some('{') => {
                    chars.next();
                    let mut name = String::new();
                    let mut closed = false;
                    for c in chars.by_ref() {
                        if c == '}' {
                            closed = true;
                            break;
                        }
                        name.push(c);
                    }
                    if closed {
                        out.push_str(parent.get(&name).map(String::as_str).unwrap_or(""));
                    } else {
                        // Unterminated: emit verbatim rather than silently
                        // swallowing the rest of the value.
                        out.push_str("${");
                        out.push_str(&name);
                    }
                }
                Some(c0) if c0.is_ascii_alphabetic() || *c0 == '_' => {
                    let mut name = String::new();
                    while let Some(c) = chars.peek() {
                        if c.is_ascii_alphanumeric() || *c == '_' {
                            name.push(*c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    out.push_str(parent.get(&name).map(String::as_str).unwrap_or(""));
                }
                // A `$` not starting a name is literal.
                _ => out.push('$'),
            }
        }
        out
    }

    /// Apply to a `Command` the caller is about to spawn.
    pub fn apply_to_command(&self, cmd: &mut std::process::Command) {
        let parent: std::collections::HashMap<String, String> = std::env::vars().collect();
        if self.is_clean() {
            cmd.env_clear();
            for (name, value) in self.inherited_from(&parent) {
                cmd.env(name, value);
            }
        }
        for (key, value) in &self.set {
            cmd.env(key, Self::expand(value, &parent));
        }
        for key in &self.remove {
            cmd.env_remove(key);
        }
    }

    /// Render as `/usr/bin/env` arguments, for callers that hand the command
    /// to something else to spawn and so cannot set env directly.
    ///
    /// Empty when nothing would change, so callers can skip interposing `env`.
    ///
    /// Under `Clean` the pass-through values have to be materialised here, so
    /// they land in argv alongside assignments — see the policy guide's note
    /// about `ps` visibility. Pass through configuration, not secrets.
    pub fn to_env_args(&self) -> Vec<String> {
        if self.is_empty() {
            return Vec::new();
        }
        let parent: std::collections::HashMap<String, String> = std::env::vars().collect();
        let mut args = vec!["/usr/bin/env".to_string()];
        if self.is_clean() {
            args.push("-i".to_string());
            for (name, value) in self.inherited_from(&parent) {
                if !self.remove.contains(name) && !self.set.contains_key(name) {
                    args.push(format!("{name}={value}"));
                }
            }
        } else {
            for key in &self.remove {
                args.push("-u".to_string());
                args.push(key.clone());
            }
        }
        for (key, value) in &self.set {
            // `remove` wins, so skip a name that is also being withheld.
            if self.remove.contains(key) {
                continue;
            }
            args.push(format!("{key}={}", Self::expand(value, &parent)));
        }
        args
    }
}

/// A sandbox policy is a list of capability rules applied to paths,
/// plus a network policy. Platform backends compile this to their
/// native enforcement (Landlock+seccomp, Seatbelt SBPL, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Default capabilities for paths not matched by any rule.
    /// Typical default: `read + execute` (can read and run, but not modify).
    pub default: Cap,

    /// List of rules. Deny rules take precedence over allow rules
    /// (matching the existing clash policy precedence model).
    #[serde(default)]
    pub rules: Vec<SandboxRule>,

    /// Network access policy.
    #[serde(default)]
    pub network: NetworkPolicy,

    /// Opt-in system capabilities (power notifications, loopback serving).
    #[serde(
        default = "SystemCap::empty",
        skip_serializing_if = "SystemCap::is_empty"
    )]
    pub system: SystemCap,

    /// Environment manipulation applied to the sandboxed process.
    #[serde(default, skip_serializing_if = "EnvPolicy::is_empty")]
    pub env: EnvPolicy,

    /// Optional docstring describing this sandbox's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// A single sandbox rule granting or revoking capabilities on a path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRule {
    /// Whether this rule grants or revokes capabilities.
    pub effect: RuleEffect,

    /// The capabilities this rule applies to.
    pub caps: Cap,

    /// The path or pattern this rule applies to. Supports `$PWD`, `$HOME`, `$TMPDIR`.
    pub path: String,

    /// How the path is matched against the filesystem.
    #[serde(default)]
    pub path_match: PathMatch,

    /// When true, also grant this rule's access to the git worktree's
    /// shared directories (`.git/worktrees/<name>` and the main `.git/`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub follow_worktrees: bool,

    /// Optional docstring describing this rule's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// How a sandbox rule's path is matched against the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PathMatch {
    /// Match this path and all descendants (recursive).
    Subpath,
    /// Match exactly this path (non-recursive).
    #[default]
    Literal,
    /// Match direct children of this path (one level deep).
    #[serde(rename = "child_of")]
    ChildOf,
    /// Match paths against a regex pattern.
    /// Supported on macOS (Seatbelt SBPL). Skipped on Linux (Landlock).
    Regex,
}

/// Whether a rule grants or revokes capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleEffect {
    Allow,
    Deny,
}

/// Network access policy for sandboxed processes.
///
/// Five modes:
/// - `Deny`: block all network at kernel level
/// - `Allow`: unrestricted network access
/// - `Localhost`: allow connections only to localhost (127.0.0.1/::1),
///   enforced at kernel level without a proxy.
/// - `LocalhostPorts`: allow localhost connections only on specific TCP ports,
///   enforced at kernel level on macOS, advisory on Linux.
/// - `AllowDomains`: domain-specific filtering via local HTTP proxy.
///   The sandbox restricts connections to localhost only; a proxy enforces
///   the domain allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// No network access. Unix domain sockets still allowed where possible.
    #[default]
    Deny,
    /// Unrestricted network access.
    Allow,
    /// Allow only localhost connections (127.0.0.1/::1). Enforced at kernel
    /// level on macOS (Seatbelt) and advisory on Linux (seccomp cannot filter
    /// connect by destination). No proxy is needed.
    Localhost,
    /// Allow only localhost connections on specific ports. Enforced at kernel
    /// level on macOS (Seatbelt restricts to specific TCP ports) and advisory
    /// on Linux (same as Localhost — seccomp cannot filter by port).
    LocalhostPorts(Vec<u16>),
    /// Allow network access only to specific domains via HTTP proxy.
    /// Domains support exact match and subdomain match (e.g., "github.com"
    /// also matches "api.github.com").
    AllowDomains(Vec<String>),
}

impl Serialize for NetworkPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            NetworkPolicy::Deny => serializer.serialize_str("deny"),
            NetworkPolicy::Allow => serializer.serialize_str("allow"),
            NetworkPolicy::Localhost => serializer.serialize_str("localhost"),
            NetworkPolicy::LocalhostPorts(ports) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("localhost", ports)?;
                map.end()
            }
            NetworkPolicy::AllowDomains(domains) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("allow_domains", domains)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for NetworkPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct NetworkPolicyVisitor;

        impl<'de> de::Visitor<'de> for NetworkPolicyVisitor {
            type Value = NetworkPolicy;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    r#""deny", "allow", "localhost", {"localhost": [ports]}, or {"allow_domains": [...]}"#,
                )
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<NetworkPolicy, E> {
                match value {
                    "deny" => Ok(NetworkPolicy::Deny),
                    "allow" => Ok(NetworkPolicy::Allow),
                    "localhost" => Ok(NetworkPolicy::Localhost),
                    other => Err(de::Error::unknown_variant(
                        other,
                        &["deny", "allow", "localhost"],
                    )),
                }
            }

            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<NetworkPolicy, A::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected allow_domains or localhost key"))?;
                match key.as_str() {
                    "allow_domains" => {
                        let domains: Vec<String> = map.next_value()?;
                        Ok(NetworkPolicy::AllowDomains(domains))
                    }
                    "localhost" => {
                        let ports: Vec<u16> = map.next_value()?;
                        if ports.is_empty() {
                            Ok(NetworkPolicy::Localhost)
                        } else {
                            Ok(NetworkPolicy::LocalhostPorts(ports))
                        }
                    }
                    _ => Err(de::Error::unknown_field(
                        &key,
                        &["allow_domains", "localhost"],
                    )),
                }
            }
        }

        deserializer.deserialize_any(NetworkPolicyVisitor)
    }
}

/// Resolve symlinks in a path without resolving firmlinks.
///
/// Walks each component of the path and resolves actual symlinks via
/// `std::fs::read_link`. Unlike `std::fs::canonicalize`, this does NOT
/// resolve macOS firmlinks (e.g. `/Users` → `/System/Volumes/Data/Users`)
/// which are transparent to Seatbelt and would produce paths that never
/// match.
///
/// Falls back to the original path if resolution fails (e.g. path does
/// not exist on the current system).
pub fn resolve_symlinks(path: &str) -> String {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::{Component, Path, PathBuf};

    let path = Path::new(path);
    if !path.is_absolute() {
        return path.to_string_lossy().into_owned();
    }

    // Collect path components into a work queue so that symlink targets
    // can be spliced in for further resolution.
    let mut pending: VecDeque<OsString> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_owned()),
            _ => None,
        })
        .collect();

    let mut resolved = PathBuf::from("/");
    let mut symlink_depth: usize = 0;
    const MAX_SYMLINK_DEPTH: usize = 40;

    while let Some(component) = pending.pop_front() {
        resolved.push(&component);

        if let Ok(target) = std::fs::read_link(&resolved) {
            symlink_depth += 1;
            if symlink_depth > MAX_SYMLINK_DEPTH {
                return path.to_string_lossy().into_owned();
            }

            // Splice the target's components into the front of the queue
            // so they get resolved on subsequent iterations.
            if target.is_absolute() {
                resolved = PathBuf::from("/");
            } else {
                resolved.pop();
            }

            let target_components: Vec<OsString> = target
                .components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_owned()),
                    _ => None,
                })
                .collect();

            for (i, tc) in target_components.into_iter().enumerate() {
                pending.insert(i, tc);
            }
        }
    }

    resolved.to_string_lossy().into_owned()
}

impl SandboxPolicy {
    /// Resolve a path, expanding environment variables ($PWD, $HOME, $TMPDIR).
    ///
    /// This is a convenience wrapper around [`super::path::PathResolver`].
    /// The `cwd` parameter is used for `$PWD`; `$HOME` and `$TMPDIR` are
    /// read from the current process environment.
    pub fn resolve_path(path: &str, cwd: &str) -> String {
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        super::path::PathResolver::new(cwd, home, tmpdir).resolve_env_vars(path)
    }

    /// Expand rules that have `follow_worktrees` set by detecting if `cwd` is
    /// inside a git worktree and adding rules for the worktree's git directories.
    ///
    /// In a worktree, git data lives outside the working directory (in the main
    /// repo's `.git/`), so sandboxed processes need access to those paths for
    /// git operations to work.
    pub fn expand_worktree_rules(&self, cwd: &Path) -> SandboxPolicy {
        let has_worktree_rules = self.rules.iter().any(|r| r.follow_worktrees);
        if !has_worktree_rules {
            return self.clone();
        }

        let wt_paths = worktree_sandbox_paths(cwd);
        if wt_paths.is_empty() {
            return self.clone();
        }

        let mut expanded = self.rules.clone();
        for rule in &self.rules {
            if !rule.follow_worktrees {
                continue;
            }
            for path in &wt_paths {
                expanded.push(SandboxRule {
                    effect: rule.effect,
                    caps: rule.caps,
                    path: path.clone(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                });
            }
        }

        SandboxPolicy {
            rules: expanded,
            ..self.clone()
        }
    }

    /// Compute the effective capabilities for a given path by evaluating all rules.
    ///
    /// Uses depth-sorted last-match-wins precedence, matching macOS Seatbelt
    /// (SBPL) evaluation semantics: rules are sorted by path depth ascending
    /// (broadest first), with deny-before-allow at the same depth. Each rule
    /// overrides previous decisions for the capabilities it covers, so deeper
    /// (more specific) rules take precedence over shallower ones, and at the
    /// same depth an allow wins over a deny.
    pub fn effective_caps(&self, path: &str, cwd: &str) -> Cap {
        struct MatchedRule {
            effect: RuleEffect,
            caps: Cap,
            depth: usize,
        }

        let mut matched: Vec<MatchedRule> = Vec::new();

        // Canonicalize the query path so that /var/foo and /private/var/foo
        // are treated identically when matching against rules.
        let canonical_path = resolve_symlinks(path);

        for rule in &self.rules {
            let rule_path = Self::resolve_path(&rule.path, cwd);
            let canonical_rule = resolve_symlinks(&rule_path);
            let matches = match rule.path_match {
                PathMatch::Subpath => {
                    canonical_path.starts_with(&canonical_rule) || canonical_path == canonical_rule
                }
                PathMatch::Literal => canonical_path == canonical_rule,
                PathMatch::ChildOf => canonical_path
                    .strip_prefix(&format!("{canonical_rule}/"))
                    .is_some_and(|rest| !rest.contains('/')),
                PathMatch::Regex => regex::Regex::new(&rule_path)
                    .map(|re| re.is_match(path))
                    .unwrap_or(false),
            };

            if matches {
                matched.push(MatchedRule {
                    effect: rule.effect,
                    caps: rule.caps,
                    depth: std::path::Path::new(&rule_path).components().count(),
                });
            }
        }

        // Sort by path depth ascending so broadest rules are applied first.
        // Within the same depth, deny before allow so that allow wins via
        // last-match-wins — matching SBPL evaluation order.
        matched.sort_by(|a, b| {
            a.depth.cmp(&b.depth).then_with(|| {
                let effect_ord = |e: &RuleEffect| match e {
                    RuleEffect::Deny => 0,
                    RuleEffect::Allow => 1,
                };
                effect_ord(&a.effect).cmp(&effect_ord(&b.effect))
            })
        });

        let mut result = self.default;
        for rule in &matched {
            match rule.effect {
                RuleEffect::Allow => result |= rule.caps,
                RuleEffect::Deny => result &= !rule.caps,
            }
        }

        result
    }

    /// Explain why a path lacks the required capabilities.
    ///
    /// Returns the most specific deny rule that covers the required caps,
    /// formatted like `"deny rwcdx in /Users (subpath)"`.
    /// Returns `None` if the path has the required capabilities.
    pub fn explain_denial(&self, path: &str, cwd: &str, required: Cap) -> Option<String> {
        let effective = self.effective_caps(path, cwd);
        if effective.contains(required) {
            return None;
        }

        // Find the deepest (most specific) deny rule that matches this path
        // and covers at least one of the required capabilities.
        let mut best: Option<(&SandboxRule, String)> = None;
        let mut best_depth: usize = 0;

        // Canonicalize query path for consistent matching across symlink forms.
        let canonical_path = resolve_symlinks(path);

        for rule in &self.rules {
            if rule.effect != RuleEffect::Deny {
                continue;
            }
            // Does this deny cover any of the required caps?
            if (rule.caps & required).is_empty() {
                continue;
            }
            let rule_path = Self::resolve_path(&rule.path, cwd);
            let canonical_rule = resolve_symlinks(&rule_path);
            let matches = match rule.path_match {
                PathMatch::Subpath => {
                    canonical_path.starts_with(&canonical_rule) || canonical_path == canonical_rule
                }
                PathMatch::Literal => canonical_path == canonical_rule,
                PathMatch::ChildOf => canonical_path
                    .strip_prefix(&format!("{canonical_rule}/"))
                    .is_some_and(|rest| !rest.contains('/')),
                PathMatch::Regex => regex::Regex::new(&rule_path)
                    .map(|re| re.is_match(path))
                    .unwrap_or(false),
            };
            if matches {
                let depth = std::path::Path::new(&rule_path).components().count();
                if best.is_none() || depth >= best_depth {
                    best_depth = depth;
                    best = Some((rule, rule_path));
                }
            }
        }

        if let Some((rule, resolved_path)) = best {
            let match_type = match rule.path_match {
                PathMatch::Subpath => "subpath",
                PathMatch::Literal => "literal",
                PathMatch::ChildOf => "child_of",
                PathMatch::Regex => "regex",
            };
            Some(format!(
                "deny {} in {} ({})",
                rule.caps.short(),
                resolved_path,
                match_type,
            ))
        } else {
            Some("no allow rule grants access to this path".to_string())
        }
    }
}

/// What the model should do when a sandbox violation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    /// Stop and suggest a policy fix. Don't retry.
    #[default]
    Stop,
    /// Try an alternative approach. If no workaround is possible, suggest the policy fix.
    Workaround,
    /// Let the model assess context to decide between stop and workaround.
    Smart,
}

impl ViolationAction {
    pub fn is_default(&self) -> bool {
        matches!(self, ViolationAction::Stop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_short() {
        assert_eq!(Cap::READ.short(), "r----");
        assert_eq!((Cap::READ | Cap::WRITE).short(), "rw---");
        assert_eq!((Cap::READ | Cap::EXECUTE).short(), "r---x");
        assert_eq!(Cap::all().short(), "rwcdx");
        assert_eq!(Cap::empty().short(), "-----");
    }

    #[test]
    fn test_cap_display() {
        assert_eq!(Cap::READ.display(), "read");
        assert_eq!((Cap::READ | Cap::WRITE).display(), "read + write");
        assert_eq!(
            Cap::all().display(),
            "read + write + create + delete + execute"
        );
    }

    #[test]
    fn test_cap_serde_roundtrip() {
        let caps = Cap::READ | Cap::WRITE | Cap::CREATE;
        let json = serde_json::to_string(&caps).unwrap();
        assert_eq!(json, r#"["read","write","create"]"#);
        let deserialized: Cap = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, caps);
    }

    #[test]
    fn test_cap_deserialize_string_rejected() {
        // Legacy string format is no longer accepted
        let result: Result<Cap, _> = serde_json::from_str(r#""read + write""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_effective_caps() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE,
                    path: "/project".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE | Cap::DELETE | Cap::CREATE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };

        // Default path: read + execute
        let caps = policy.effective_caps("/etc/passwd", "/project");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);

        // Project dir: read + write + create + delete + execute (default + allow)
        let caps = policy.effective_caps("/project/src/main.rs", "/project");
        assert_eq!(
            caps,
            Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE | Cap::EXECUTE
        );

        // .git dir: deny overrides allow, so only read + execute remain
        let caps = policy.effective_caps("/project/.git/config", "/project");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn test_network_policy_localhost_serde() {
        let json = serde_json::to_string(&NetworkPolicy::Localhost).unwrap();
        assert_eq!(json, r#""localhost""#);
        let deserialized: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, NetworkPolicy::Localhost);
    }

    #[test]
    fn test_network_policy_localhost_ports_serde() {
        let policy = NetworkPolicy::LocalhostPorts(vec![8080, 3000]);
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, r#"{"localhost":[8080,3000]}"#);
        let deserialized: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized,
            NetworkPolicy::LocalhostPorts(vec![8080, 3000])
        );
    }

    #[test]
    fn test_network_policy_localhost_ports_empty_is_localhost() {
        // Empty ports list deserializes to plain Localhost
        let json = r#"{"localhost":[]}"#;
        let deserialized: NetworkPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(deserialized, NetworkPolicy::Localhost);
    }

    #[test]
    fn test_sandbox_policy_serde() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE,
                path: "$PWD".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.default, policy.default);
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.network, NetworkPolicy::Deny);
    }

    fn parent_env(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn expand_substitutes_from_the_parent() {
        let p = parent_env(&[("HOME", "/home/alice"), ("X", "1")]);
        assert_eq!(EnvPolicy::expand("$HOME/.cargo", &p), "/home/alice/.cargo");
        assert_eq!(EnvPolicy::expand("${HOME}x", &p), "/home/alicex");
        assert_eq!(EnvPolicy::expand("a${X}b$X", &p), "a1b1");
    }

    #[test]
    fn expand_undefined_name_is_empty() {
        // Matches how `$VAR` resolves elsewhere in clash.
        let p = parent_env(&[]);
        assert_eq!(EnvPolicy::expand("/pre/$NOPE/post", &p), "/pre//post");
    }

    #[test]
    fn expand_escapes_and_literals() {
        let p = parent_env(&[("X", "1")]);
        assert_eq!(EnvPolicy::expand("$$X", &p), "$X");
        assert_eq!(EnvPolicy::expand("cost: 5$", &p), "cost: 5$");
        assert_eq!(EnvPolicy::expand("$ X", &p), "$ X");
        // Unterminated braces are emitted verbatim, not swallowed.
        assert_eq!(EnvPolicy::expand("${UNCLOSED", &p), "${UNCLOSED");
    }

    #[test]
    fn clean_mode_emits_env_dash_i_and_only_named_passthrough() {
        let mut env = EnvPolicy {
            default: EnvDefault::Clean,
            ..Default::default()
        };
        env.inherit.insert("PATH".into());
        env.set.insert("MARK".into(), "1".into());
        let args = env.to_env_args();
        assert_eq!(args[0], "/usr/bin/env");
        assert_eq!(args[1], "-i");
        assert!(args.contains(&"MARK=1".to_string()));
        // PATH is materialised from the real parent env, so just check shape.
        assert!(args.iter().any(|a| a.starts_with("PATH=")));
        // Nothing else leaks in.
        assert!(!args.iter().any(|a| a.starts_with("HOME=")));
    }

    #[test]
    fn clean_mode_is_not_empty_even_with_no_edits() {
        let env = EnvPolicy {
            default: EnvDefault::Clean,
            ..Default::default()
        };
        assert!(!env.is_empty(), "a clean environment is itself a change");
        assert_eq!(env.to_env_args(), vec!["/usr/bin/env", "-i"]);
    }

    #[test]
    fn env_policy_empty_by_default_and_omitted() {
        let json = r#"{"default":["read"],"rules":[],"network":"deny"}"#;
        let p: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert!(p.env.is_empty());
        assert!(!serde_json::to_string(&p).unwrap().contains("env"));
    }

    #[test]
    fn env_policy_roundtrips() {
        let json = r#"{"default":["read"],"rules":[],"network":"deny",
                       "env":{"set":{"CARGO_HOME":"/tmp/ch"},"remove":["AWS_SECRET_ACCESS_KEY"]}}"#;
        let p: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(p.env.set.get("CARGO_HOME").unwrap(), "/tmp/ch");
        assert!(p.env.remove.contains("AWS_SECRET_ACCESS_KEY"));
        let out = serde_json::to_string(&p).unwrap();
        assert!(out.contains("CARGO_HOME"));
        assert!(out.contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn env_args_are_empty_when_nothing_changes() {
        assert!(EnvPolicy::default().to_env_args().is_empty());
    }

    #[test]
    fn env_args_unset_then_assign() {
        let mut env = EnvPolicy::default();
        env.set.insert("A".into(), "1".into());
        env.remove.insert("B".into());
        let args = env.to_env_args();
        assert_eq!(args[0], "/usr/bin/env");
        assert!(args.contains(&"-u".to_string()));
        assert!(args.contains(&"B".to_string()));
        assert!(args.contains(&"A=1".to_string()));
    }

    #[test]
    fn removal_wins_over_assignment_for_the_same_name() {
        // Documented precedence: a name in both is withheld, and must not be
        // re-introduced by the assignment half of the same policy.
        let mut env = EnvPolicy::default();
        env.set.insert("TOKEN".into(), "secret".into());
        env.remove.insert("TOKEN".into());
        let args = env.to_env_args();
        assert!(
            !args.iter().any(|a| a.starts_with("TOKEN=")),
            "removed name must not be assigned: {args:?}"
        );
        assert!(args.contains(&"TOKEN".to_string()));
    }

    #[test]
    fn test_system_cap_serde_roundtrip() {
        let caps = SystemCap::POWER | SystemCap::LOCALHOST_SERVE;
        let json = serde_json::to_string(&caps).unwrap();
        assert_eq!(json, r#"["power","localhost_serve"]"#);
        let deserialized: SystemCap = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, caps);
    }

    #[test]
    fn test_system_cap_unknown_name_rejected() {
        let result: Result<SystemCap, _> = serde_json::from_str(r#"["iokit"]"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_system_cap_rejects_bare_string() {
        // Must be a list; a bare string is a policy authoring mistake and
        // should fail loudly rather than silently granting nothing.
        let result: Result<SystemCap, _> = serde_json::from_str(r#""power""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_system_cap_duplicates_collapse() {
        let caps: SystemCap = serde_json::from_str(r#"["power","power"]"#).unwrap();
        assert_eq!(caps, SystemCap::POWER);
    }

    #[test]
    fn test_system_cap_empty_list_is_empty() {
        let caps: SystemCap = serde_json::from_str("[]").unwrap();
        assert!(caps.is_empty());
    }

    #[test]
    fn test_sandbox_policy_rejects_unknown_system_cap() {
        // A typo must fail policy load rather than being dropped: silently
        // ignoring it would leave the workload broken with no explanation.
        let json = r#"{"default":["read"],"rules":[],"network":"deny","system":["powr"]}"#;
        let result: Result<SandboxPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unknown system capability"), "got: {msg}");
    }

    #[test]
    fn test_sandbox_policy_system_defaults_empty_and_omitted() {
        // Policies without a "system" field deserialize to empty caps.
        let json = r#"{"default":["read"],"rules":[],"network":"deny"}"#;
        let policy: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert!(policy.system.is_empty());

        // Empty caps are omitted on serialization (wire compat).
        let out = serde_json::to_string(&policy).unwrap();
        assert!(!out.contains("system"));
    }

    #[test]
    fn test_sandbox_policy_system_roundtrip() {
        let json = r#"{"default":["read"],"rules":[],"network":"localhost","system":["power"]}"#;
        let policy: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.system, SystemCap::POWER);
        let out = serde_json::to_string(&policy).unwrap();
        assert!(out.contains(r#""system":["power"]"#));
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy::resolve_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_path_pwd_replacement() {
        let result = SandboxPolicy::resolve_path("$PWD/src", "/my/project");
        assert_eq!(result, "/my/project/src");
    }

    #[test]
    fn resolve_path_home_replacement() {
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let result = SandboxPolicy::resolve_path("$HOME/.config", "/ignored");
        assert_eq!(result, format!("{}/.config", home));
    }

    #[test]
    fn resolve_path_tmpdir_replacement() {
        // SAFETY: test-only, single-threaded access
        let saved = std::env::var("TMPDIR").ok();
        unsafe { std::env::set_var("TMPDIR", "/custom/tmp") };
        let result = SandboxPolicy::resolve_path("$TMPDIR/scratch", "/ignored");
        assert_eq!(result, "/custom/tmp/scratch");
        match saved {
            Some(v) => unsafe { std::env::set_var("TMPDIR", v) },
            None => unsafe { std::env::remove_var("TMPDIR") },
        }
    }

    #[test]
    fn resolve_path_tmpdir_fallback() {
        let saved = std::env::var("TMPDIR").ok();
        unsafe { std::env::remove_var("TMPDIR") };
        let result = SandboxPolicy::resolve_path("$TMPDIR/scratch", "/ignored");
        assert_eq!(result, "/tmp/scratch");
        match saved {
            Some(v) => unsafe { std::env::set_var("TMPDIR", v) },
            None => unsafe { std::env::remove_var("TMPDIR") },
        }
    }

    #[test]
    fn resolve_path_multiple_vars() {
        unsafe { std::env::set_var("TMPDIR", "/var/tmp") };
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let result = SandboxPolicy::resolve_path("$PWD:$HOME:$TMPDIR", "/work");
        assert_eq!(result, format!("/work:{}:/var/tmp", home));
        unsafe { std::env::remove_var("TMPDIR") };
    }

    #[test]
    fn resolve_path_no_variables() {
        let result = SandboxPolicy::resolve_path("/usr/local/bin", "/ignored");
        assert_eq!(result, "/usr/local/bin");
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy::effective_caps tests
    // -----------------------------------------------------------------------

    #[test]
    fn effective_caps_regex_path_match() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: r"/project/.*\.rs$".into(),
                path_match: PathMatch::Regex,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        let caps = policy.effective_caps("/project/src/main.rs", "/project");
        assert_eq!(caps, Cap::READ | Cap::WRITE);

        // Non-rs file should not match the regex rule
        let caps = policy.effective_caps("/project/src/main.py", "/project");
        assert_eq!(caps, Cap::READ);
    }

    #[test]
    fn effective_caps_literal_path_match() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/etc/hosts".into(),
                path_match: PathMatch::Literal,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // Exact match
        let caps = policy.effective_caps("/etc/hosts", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::WRITE);

        // Child path should NOT match literal
        let caps = policy.effective_caps("/etc/hosts/foo", "/ignored");
        assert_eq!(caps, Cap::READ);
    }

    #[test]
    fn effective_caps_allow_wins_at_same_depth() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::WRITE | Cap::CREATE,
                    path: "/data".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE,
                    path: "/data".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // At same depth, allow wins (last-match-wins, matching SBPL semantics)
        let caps = policy.effective_caps("/data/file.txt", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::WRITE | Cap::CREATE);
    }

    #[test]
    fn effective_caps_multiple_overlapping_rules() {
        let policy = SandboxPolicy {
            default: Cap::empty() | Cap::READ,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::all(),
                    path: "/project".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::DELETE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE | Cap::CREATE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // In /project but outside .git: full caps
        let caps = policy.effective_caps("/project/src/lib.rs", "/project");
        assert_eq!(caps, Cap::all());

        // In .git: all minus delete, write, create
        let caps = policy.effective_caps("/project/.git/HEAD", "/project");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn effective_caps_default_when_no_rules_match() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/specific/path".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // Path that matches no rules gets default
        let caps = policy.effective_caps("/unrelated/path", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn effective_caps_deeper_allow_overrides_shallower_deny() {
        // Mirrors the real "cwd" sandbox: broad deny on /Users, specific allow on $PWD
        let policy = SandboxPolicy {
            default: Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE | Cap::CREATE,
                    path: "/Users/eliot/code/project".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ,
                    path: "/Users/eliot".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ,
                    path: "/".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE | Cap::EXECUTE,
                    path: "/Users".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };

        // Inside $PWD: the deeper allow overrides the shallower deny on /Users
        let caps = policy.effective_caps("/Users/eliot/code/project/src/main.rs", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::WRITE | Cap::CREATE);

        // Inside $HOME but outside $PWD: read from $HOME allow overrides /Users deny
        let caps = policy.effective_caps("/Users/eliot/.config/foo", "/ignored");
        assert_eq!(caps, Cap::READ);

        // Outside /Users entirely: default + broad allow on /
        let caps = policy.effective_caps("/etc/passwd", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy::expand_worktree_rules tests
    // -----------------------------------------------------------------------

    #[test]
    fn expand_worktree_no_worktree_rules_unchanged() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "$PWD".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // No follow_worktrees rules → policy unchanged regardless of cwd
        let expanded = policy.expand_worktree_rules(Path::new("/any/path"));
        assert_eq!(expanded.rules.len(), 1);
    }

    #[test]
    fn expand_worktree_not_in_worktree_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("normal-repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "$PWD".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: true,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // Normal repo (not a worktree) → no expansion
        let expanded = policy.expand_worktree_rules(&repo);
        assert_eq!(expanded.rules.len(), 1);
    }

    #[test]
    fn expand_worktree_adds_git_dir_rules() {
        let tmp = tempfile::tempdir().unwrap();

        // Set up a fake worktree structure
        let main_repo = tmp.path().join("main-repo");
        let git_dir = main_repo.join(".git");
        let wt_git = git_dir.join("worktrees").join("feature");
        std::fs::create_dir_all(&wt_git).unwrap();
        std::fs::write(wt_git.join("commondir"), "../..").unwrap();
        std::fs::write(wt_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();

        let worktree = tmp.path().join("feature-worktree");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}", wt_git.display()),
        )
        .unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE,
                    path: "$PWD".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: true,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::DELETE,
                    path: "/etc".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };

        let expanded = policy.expand_worktree_rules(&worktree);

        // Original 2 rules + 2 new rules (git_dir + common_dir) for the
        // follow_worktrees rule
        assert_eq!(expanded.rules.len(), 4);

        // New rules should be subpath allows with the same caps
        let new_rules: Vec<_> = expanded.rules[2..].to_vec();
        for rule in &new_rules {
            assert_eq!(rule.effect, RuleEffect::Allow);
            assert_eq!(rule.caps, Cap::READ | Cap::WRITE);
            assert_eq!(rule.path_match, PathMatch::Subpath);
            assert!(!rule.follow_worktrees);
        }

        // The non-follow_worktrees rule should NOT generate extra rules
        assert_eq!(expanded.rules[1].path, "/etc");
    }

    #[test]
    fn expand_worktree_follow_worktrees_not_serialized_when_false() {
        let rule = SandboxRule {
            effect: RuleEffect::Allow,
            caps: Cap::READ,
            path: "$PWD".into(),
            path_match: PathMatch::Subpath,
            follow_worktrees: false,
            doc: None,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(!json.contains("follow_worktrees"));
    }

    #[test]
    fn expand_worktree_follow_worktrees_serialized_when_true() {
        let rule = SandboxRule {
            effect: RuleEffect::Allow,
            caps: Cap::READ,
            path: "$PWD".into(),
            path_match: PathMatch::Subpath,
            follow_worktrees: true,
            doc: None,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"follow_worktrees\":true"));
    }

    // -----------------------------------------------------------------------
    // resolve_symlinks tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_symlinks_unrelated_path_unchanged() {
        assert_eq!(resolve_symlinks("/usr/local/bin"), "/usr/local/bin");
    }

    #[test]
    fn resolve_symlinks_follows_real_symlink() {
        // Use /tmp explicitly to avoid interference from tests that mutate $TMPDIR.
        let tmp = tempfile::tempdir_in("/tmp").unwrap();
        let target = tmp.path().join("target_dir");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = resolve_symlinks(&format!("{}/child", link.display()));
        // The expected path must also be resolved since the tempdir itself
        // may live under a symlink (e.g. /var/folders on macOS).
        let expected = format!("{}/child", resolve_symlinks(&target.to_string_lossy()));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_symlinks_nonexistent_path_returned_as_is() {
        let result = resolve_symlinks("/nonexistent/made/up/path");
        assert_eq!(result, "/nonexistent/made/up/path");
    }

    // macOS-specific: /var, /tmp, /etc are symlinks to /private/*
    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_var() {
        assert_eq!(
            resolve_symlinks("/var/folders/xx"),
            "/private/var/folders/xx"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_tmp() {
        assert_eq!(resolve_symlinks("/tmp/build"), "/private/tmp/build");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_etc() {
        assert_eq!(resolve_symlinks("/etc/hosts"), "/private/etc/hosts");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_exact() {
        assert_eq!(resolve_symlinks("/var"), "/private/var");
        assert_eq!(resolve_symlinks("/tmp"), "/private/tmp");
        assert_eq!(resolve_symlinks("/etc"), "/private/etc");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_already_private() {
        assert_eq!(
            resolve_symlinks("/private/var/folders"),
            "/private/var/folders"
        );
    }

    // -----------------------------------------------------------------------
    // symlink duality in effective_caps / explain_denial
    // -----------------------------------------------------------------------

    #[test]
    fn effective_caps_symlink_rule_matches_resolved_query() {
        // Create a symlink so resolve_symlinks can resolve both forms
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: link.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // Query via the resolved (real) path should match the symlink rule
        let query = format!("{}/file.txt", real_dir.display());
        let caps = policy.effective_caps(&query, "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on symlink path should match query via resolved path"
        );
    }

    #[test]
    fn effective_caps_resolved_rule_matches_symlink_query() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: real_dir.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        // Query via the symlink should match the real-path rule
        let query = format!("{}/file.txt", link.display());
        let caps = policy.effective_caps(&query, "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on real path should match query via symlink"
        );
    }

    #[test]
    fn effective_caps_symlink_deny() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ | Cap::WRITE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Deny,
                caps: Cap::WRITE,
                path: link.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        let query = format!("{}/file.txt", real_dir.display());
        let caps = policy.effective_caps(&query, "/ignored");
        assert!(
            !caps.contains(Cap::WRITE),
            "deny on symlink should apply to resolved path"
        );
    }

    #[test]
    fn explain_denial_across_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Deny,
                caps: Cap::READ,
                path: link.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        let query = format!("{}/secret", real_dir.display());
        let explanation = policy.explain_denial(&query, "/ignored", Cap::READ);
        assert!(
            explanation.is_some(),
            "deny on symlink should explain denial for resolved path"
        );
    }

    // macOS-specific: test with /var → /private/var system symlinks
    #[cfg(target_os = "macos")]
    #[test]
    fn effective_caps_macos_var_symlink_duality() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/var/folders".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        let caps = policy.effective_caps("/private/var/folders/xx/data", "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on /var/folders should match query for /private/var/folders/xx/data"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn effective_caps_macos_private_rule_matches_symlink_query() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/private/tmp".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            system: SystemCap::empty(),
            env: Default::default(),
            doc: None,
        };
        let caps = policy.effective_caps("/tmp/scratch", "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on /private/tmp should match query for /tmp/scratch"
        );
    }
}

#[cfg(test)]
mod violation_action_tests {
    use super::*;

    #[test]
    fn test_violation_action_default_is_stop() {
        let action: ViolationAction = Default::default();
        assert!(matches!(action, ViolationAction::Stop));
    }

    #[test]
    fn test_violation_action_deserialize_stop() {
        let action: ViolationAction = serde_json::from_str("\"stop\"").unwrap();
        assert!(matches!(action, ViolationAction::Stop));
    }

    #[test]
    fn test_violation_action_deserialize_workaround() {
        let action: ViolationAction = serde_json::from_str("\"workaround\"").unwrap();
        assert!(matches!(action, ViolationAction::Workaround));
    }

    #[test]
    fn test_violation_action_deserialize_smart() {
        let action: ViolationAction = serde_json::from_str("\"smart\"").unwrap();
        assert!(matches!(action, ViolationAction::Smart));
    }

    #[test]
    fn test_violation_action_serialize_roundtrip() {
        for action in [
            ViolationAction::Stop,
            ViolationAction::Workaround,
            ViolationAction::Smart,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let back: ViolationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }
}

// ---------------------------------------------------------------------------
// Git worktree detection — inlined from clash::git to avoid a circular dep.
// Must stay in sync with clash/src/git.rs.
// ---------------------------------------------------------------------------

/// Return the git directories that need sandbox access for a worktree.
///
/// Returns an empty vec if `cwd` is not in a git worktree. Paths are
/// canonicalized when possible (needed for macOS Seatbelt).
fn worktree_sandbox_paths(cwd: &Path) -> Vec<String> {
    let info = match detect_worktree(cwd) {
        Some(info) => info,
        None => return Vec::new(),
    };

    let canonicalize = |p: &std::path::Path| -> String {
        std::fs::canonicalize(p)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
    };

    let mut paths = vec![canonicalize(&info.git_dir), canonicalize(&info.common_dir)];
    paths.dedup();
    paths
}

struct WorktreeInfo {
    git_dir: std::path::PathBuf,
    common_dir: std::path::PathBuf,
}

fn detect_worktree(cwd: &Path) -> Option<WorktreeInfo> {
    match try_detect_worktree(cwd) {
        Ok(info) => info,
        Err(e) => {
            tracing::debug!(
                "git worktree detection failed for {}: {:#}",
                cwd.display(),
                e
            );
            None
        }
    }
}

fn try_detect_worktree(cwd: &Path) -> anyhow::Result<Option<WorktreeInfo>> {
    let dot_git = find_dot_git(cwd)?;
    if dot_git.is_dir() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&dot_git)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", dot_git.display()))?;
    let git_dir = parse_gitdir_pointer(&content)
        .map_err(|e| anyhow::anyhow!("parsing gitdir in {}: {e}", dot_git.display()))?;
    let base = dot_git
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent", dot_git.display()))?;
    let git_dir = normalize_git_path(&base.join(&git_dir));
    let common_dir = resolve_common_dir(&git_dir)?;
    Ok(Some(WorktreeInfo {
        git_dir,
        common_dir,
    }))
}

fn find_dot_git(start: &Path) -> anyhow::Result<std::path::PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join(".git");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !current.pop() {
            anyhow::bail!("no .git found above {}", start.display());
        }
    }
}

fn parse_gitdir_pointer(content: &str) -> anyhow::Result<std::path::PathBuf> {
    let line = content
        .lines()
        .find(|l| l.starts_with("gitdir:"))
        .ok_or_else(|| anyhow::anyhow!("no 'gitdir:' line found"))?;
    let path_str = line.strip_prefix("gitdir:").unwrap().trim();
    if path_str.is_empty() {
        anyhow::bail!("empty gitdir path");
    }
    Ok(std::path::PathBuf::from(path_str))
}

fn resolve_common_dir(git_dir: &Path) -> anyhow::Result<std::path::PathBuf> {
    let commondir_file = git_dir.join("commondir");
    let content = std::fs::read_to_string(&commondir_file)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", commondir_file.display()))?;
    let relative = content.trim();
    if relative.is_empty() {
        anyhow::bail!("empty commondir in {}", commondir_file.display());
    }
    Ok(normalize_git_path(&git_dir.join(relative)))
}

fn normalize_git_path(path: &Path) -> std::path::PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}
