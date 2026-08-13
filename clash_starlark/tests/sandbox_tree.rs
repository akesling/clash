use clash_starlark::eval_policy_source_for_test;

#[test]
fn sandbox_tree_fs_and_net_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
sandbox("rust-dev", {
    default(): deny(),
    path("$PWD"): allow("rwc"),
    glob("/tmp/**"): allow("rwc"),
    domain("crates.io"): allow(),
    localhost(): allow(),
})
"#,
    )
    .unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    let sb = sandboxes
        .get("rust-dev")
        .expect("sandbox registered under name");

    // default: deny → default caps = ["execute"]
    assert_eq!(sb["default"], serde_json::json!(["execute"]));

    let rules = sb["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|r| r["path"] == "$PWD" && r["effect"] == "allow" && r["path_match"] == "literal"),
        "expected $PWD literal allow rule, got: {rules:#?}"
    );
    assert!(
        rules
            .iter()
            .any(|r| r["path"] == "/tmp" && r["effect"] == "allow" && r["path_match"] == "subpath"),
        "expected /tmp subpath allow rule (from /tmp/** glob), got: {rules:#?}"
    );

    // Network: domain + localhost present → represented somehow.
    let net = &sb["network"];
    let net_str = serde_json::to_string(net).unwrap();
    assert!(
        net_str.contains("crates.io"),
        "expected crates.io in network, got: {net_str}"
    );

    // No system= given → field omitted from the wire format.
    assert!(sb.get("system").is_none());
}

#[test]
fn sandbox_tree_system_caps_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
sandbox("bazel-box", {
    default(): deny(),
    path("$PWD"): allow("rwc"),
    localhost(): allow(),
}, system=["power", "localhost_serve"])
"#,
    )
    .unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    let sb = sandboxes.get("bazel-box").expect("sandbox registered");
    assert_eq!(
        sb["system"],
        serde_json::json!(["power", "localhost_serve"])
    );
}

#[test]
fn sandbox_legacy_system_caps_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
bazel_box = sandbox(
    name = "bazel-legacy",
    default = ask(),
    fs = {"$PWD": allow("rwc")},
    net = allow(),
    system = ["power"],
)
policy("p", {tool("Bash"): allow(sandbox = bazel_box)})
"#,
    )
    .unwrap();
    // Legacy sandboxes are collected via their allow(sandbox=...) reference
    // during policy registration; check the assembled document.
    let doc = ctx.assemble_document().unwrap();
    let sb = &doc["sandboxes"]["bazel-legacy"];
    assert_eq!(sb["system"], serde_json::json!(["power"]));
}

#[test]
fn sandbox_merge_unions_system_caps() {
    // `.update()` must carry system caps across, and must not duplicate a cap
    // present on both sides — a duplicated entry would still parse, but the
    // wire format should stay canonical.
    let ctx = eval_policy_source_for_test(
        r#"
power_box = sandbox(
    name = "merged",
    default = ask(),
    fs = {"$PWD": allow("r")},
    system = ["power"],
)
serve_box = sandbox(
    name = "serve",
    default = ask(),
    fs = {"$PWD": allow("r")},
    system = ["localhost_serve", "power"],
)
policy("p", {tool("Bash"): allow(sandbox = power_box.update(serve_box))})
"#,
    )
    .unwrap();
    let doc = ctx.assemble_document().unwrap();
    let system = doc["sandboxes"]["merged"]["system"].as_array().unwrap();
    let names: Vec<&str> = system.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"power"), "got {names:?}");
    assert!(names.contains(&"localhost_serve"), "got {names:?}");
    assert_eq!(names.len(), 2, "caps must be de-duplicated, got {names:?}");
}

#[test]
fn sandbox_merge_keeps_caps_when_other_side_has_none() {
    let ctx = eval_policy_source_for_test(
        r#"
with_caps = sandbox(name = "keep", default = ask(), fs = {"$PWD": allow("r")}, system = ["power"])
plain = sandbox(name = "plain", default = ask(), fs = {"$PWD": allow("r")})
policy("p", {tool("Bash"): allow(sandbox = with_caps.update(plain))})
"#,
    )
    .unwrap();
    let doc = ctx.assemble_document().unwrap();
    assert_eq!(
        doc["sandboxes"]["keep"]["system"],
        serde_json::json!(["power"]),
        "merging with a capability-less sandbox must not drop caps"
    );
}

#[test]
fn sandbox_empty_system_list_is_omitted() {
    let ctx =
        eval_policy_source_for_test(r#"sandbox("empty", {default(): deny()}, system=[])"#).unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    assert!(sandboxes.get("empty").unwrap().get("system").is_none());
}

#[test]
fn sandbox_system_rejects_non_list_and_non_string() {
    for (src, want) in [
        (
            r#"sandbox("bad", {default(): deny()}, system="power")"#,
            "must be a list",
        ),
        (
            r#"sandbox("bad", {default(): deny()}, system=[42])"#,
            "must be strings",
        ),
    ] {
        let err = eval_policy_source_for_test(src).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(want), "expected {want:?} in error, got: {msg}");
    }
}

#[test]
fn sandbox_unknown_system_cap_fails() {
    let err = eval_policy_source_for_test(
        r#"
sandbox("bad", {default(): deny()}, system=["iokit"])
"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unknown system capability"),
        "expected validation error, got: {msg}"
    );
}

#[test]
fn sandbox_tree_env_controls_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
sandbox("boxed", {
    default(): deny(),
    path("$PWD"): allow("rwc"),
}, env = {"FOO": "bar", "SECRET": deny()})
"#,
    )
    .unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    let sb = sandboxes.get("boxed").expect("registered");
    assert_eq!(sb["env"]["set"]["FOO"], "bar", "got {:?}", sb["env"]);
    assert_eq!(sb["env"]["remove"], serde_json::json!(["SECRET"]));
}

#[test]
fn sandbox_legacy_env_controls_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
boxed = sandbox(
    name = "legacy-env",
    default = ask(),
    fs = {"$PWD": allow("rwc")},
    env = {"FOO": "bar", "SECRET": deny()},
)
policy("p", {tool("Bash"): allow(sandbox = boxed)})
"#,
    )
    .unwrap();
    let doc = ctx.assemble_document().unwrap();
    let sb = &doc["sandboxes"]["legacy-env"];
    assert_eq!(sb["env"]["set"]["FOO"], "bar", "got {:?}", sb["env"]);
    assert_eq!(sb["env"]["remove"], serde_json::json!(["SECRET"]));
}

#[test]
fn sandbox_env_clean_mode_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
sandbox("clean", {
    default(): deny(),
    path("$PWD"): allow("rwc"),
}, env = {
    default(): deny(),
    "PATH": allow(),
    "CARGO_HOME": "$HOME/.sbx/cargo",
})
"#,
    )
    .unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    let sb = sandboxes.get("clean").expect("registered");
    assert_eq!(sb["env"]["default"], "clean");
    assert_eq!(sb["env"]["inherit"], serde_json::json!(["PATH"]));
    assert_eq!(sb["env"]["set"]["CARGO_HOME"], "$HOME/.sbx/cargo");
}

#[test]
fn sandbox_env_inherit_is_the_default_and_omitted() {
    let ctx =
        eval_policy_source_for_test(r#"sandbox("d", {default(): deny()}, env = {"X": deny()})"#)
            .unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    let sb = sandboxes.get("d").expect("registered");
    assert!(sb["env"].get("default").is_none(), "inherit is the default");
    assert_eq!(sb["env"]["remove"], serde_json::json!(["X"]));
}

#[test]
fn sandbox_env_passthrough_without_clean_is_rejected() {
    // allow() only means something once the environment is cleared; silently
    // ignoring it would make a policy look like it did something it did not.
    let err = eval_policy_source_for_test(
        r#"sandbox("d", {default(): deny()}, env = {"PATH": allow()})"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("default(): deny()"), "got: {msg}");
}
