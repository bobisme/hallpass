//! `diff --containment` gives one overall verdict that covers the whole pass.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/required-counters.toml");
const AT: &str = "2026-11-20T10:00:00Z";

fn write(dir: &Path, file: &str, body: &str) {
    let path = dir.join(file);
    fs::write(&path, body).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

/// Run `diff --containment` on BASE and a revision; return exit code, JSON and text.
fn run(revision: &str) -> (i32, Value, String) {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old", BASE);
    write(tmp.path(), "new", revision);
    let go = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        cmd.args(["diff", "old", "new", "--containment", "--at", AT])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env("XDG_STATE_HOME", tmp.path().join("state"))
            .output()
            .expect("run")
    };
    let j = go(true);
    let t = go(false);
    assert_eq!(j.status.code(), t.status.code());
    (
        j.status.code().expect("code"),
        serde_json::from_slice(&j.stdout).expect("json"),
        String::from_utf8(t.stdout).expect("utf8"),
    )
}

fn widened(revision: &str, field: &str) {
    let (code, json, text) = run(revision);
    assert_eq!(code, 2, "{text}");
    assert_eq!(json["result"], "widened");
    let c = &json["containment"];
    assert_eq!(c["result"], "widened");
    assert_eq!(c["endpoint_result"], "contained");
    let fields: Vec<_> = c["loosenings"]
        .as_array()
        .expect("list")
        .iter()
        .map(|l| l["field"].as_str().expect("field"))
        .collect();
    assert_eq!(fields, [field]);
    assert!(text.contains(&format!("Loosened: {field}:")), "{text}");
    assert!(text.contains("Overall verdict: widened."), "{text}");
}

#[test]
fn a_later_end_of_window_is_widened() {
    widened(
        &BASE.replace("2026-11-20T17:00:00Z", "2026-12-20T17:00:00Z"),
        "approval.valid_until",
    );
}

#[test]
fn an_earlier_start_of_window_is_widened() {
    widened(
        &BASE.replace("2026-11-20T08:00:00Z", "2026-11-19T08:00:00Z"),
        "approval.valid_from",
    );
}

#[test]
fn a_higher_ceiling_is_widened() {
    widened(
        &BASE.replace("requests = 5", "requests = 5000"),
        "ceilings.requests",
    );
}

#[test]
fn a_removed_ceiling_narrows() {
    // A counter without a ceiling cannot be spent, so removing one narrows.
    // A required counter must keep its ceiling, so remove an optional one.
    let old = format!("{BASE}\nextra = 9\n");
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old", &old);
    write(tmp.path(), "new", BASE);
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["--json", "diff", "old", "new", "--containment", "--at", AT])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("XDG_STATE_HOME", tmp.path().join("state"))
        .output()
        .expect("run");
    let json: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json["result"], "contained", "{json}");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn a_new_optional_ceiling_is_widened() {
    // A counter that had no ceiling could not be spent; now it can.
    widened(&format!("{BASE}\nextra = 9\n"), "ceilings.extra");
}

#[test]
fn a_dropped_required_counter_is_widened() {
    widened(
        &BASE.replace("[\"requests\", \"bytes\"]", "[\"requests\"]"),
        "required_counters_v1",
    );
}

#[test]
fn a_dropped_require_target_is_widened() {
    let old = BASE.replace("format = 1\n", "format = 1\nrequire_target_v1 = true\n");
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old", &old);
    write(tmp.path(), "new", BASE);
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["--json", "diff", "old", "new", "--containment", "--at", AT])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("XDG_STATE_HOME", tmp.path().join("state"))
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let json: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json["result"], "widened");
    assert_eq!(
        json["containment"]["loosenings"][0]["field"],
        "require_target_v1"
    );
}

#[test]
fn an_un_revoke_is_widened() {
    // A revoked pass has no open window, so the endpoint proof is inconclusive;
    // the known loosening still gives the definite verdict.
    let old = BASE.replace(
        "revoked = false",
        "revoked = true\nrevoked_reason = \"stood down\"",
    );
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old", &old);
    write(tmp.path(), "new", BASE);
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["--json", "diff", "old", "new", "--containment", "--at", AT])
        .current_dir(tmp.path())
        .env("HOME", tmp.path())
        .env("XDG_STATE_HOME", tmp.path().join("state"))
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let json: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json["result"], "widened");
    assert_eq!(json["containment"]["endpoint_result"], "inconclusive");
}

#[test]
fn the_lead_repro_is_not_contained() {
    let (code, json, _) = run(&BASE
        .replace("2026-11-20T17:00:00Z", "2026-12-20T17:00:00Z")
        .replace("requests = 5", "requests = 500000"));
    assert_eq!(code, 2);
    assert_eq!(json["result"], "widened");
    assert_eq!(
        json["containment"]["loosenings"]
            .as_array()
            .expect("list")
            .len(),
        2
    );
}

#[test]
fn a_narrowing_revision_is_contained_and_exits_zero() {
    let (code, json, text) = run(&BASE
        .replace("2026-11-20T17:00:00Z", "2026-11-20T12:00:00Z")
        .replace("requests = 5", "requests = 3")
        .replace("bytes = 100", "bytes = 60")
        .replace(
            "[\"requests\", \"bytes\"]",
            "[\"requests\", \"bytes\", \"extra\"]",
        )
        .replace("[ceilings]", "[ceilings]\nextra = 9"));
    assert_eq!(code, 0, "{text}");
    assert_eq!(json["result"], "contained");
    assert_eq!(json["containment"]["endpoint_result"], "contained");
    assert_eq!(json["containment"]["loosenings"], serde_json::json!([]));
    assert!(text.contains("Overall verdict: contained."), "{text}");
}

#[test]
fn an_endpoint_expansion_stays_expanded() {
    let (code, json, _) = run(&BASE.replace("192.0.2.10", "192.0.2.11"));
    assert_eq!(code, 2);
    assert_eq!(json["result"], "expanded");
    assert_eq!(json["containment"]["endpoint_result"], "expanded");
}
