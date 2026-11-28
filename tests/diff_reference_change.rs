//! A changed `approval.reference` cites a different written approval, so
//! `diff` marks it for review and `diff --containment` calls it widened.
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

fn run(dir: &Path, json: bool, extra: &[&str]) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
    if json {
        cmd.arg("--json");
    }
    let out = cmd
        .args(["diff", "old", "new"])
        .args(extra)
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("utf8"),
    )
}

fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old", BASE);
    write(
        tmp.path(),
        "new",
        &BASE.replace("Documentation fixture", "A phone call"),
    );
    tmp
}

#[test]
fn diff_marks_a_changed_reference_for_review() {
    let tmp = setup();
    let (_, text) = run(tmp.path(), false, &[]);
    let line = text
        .lines()
        .find(|l| l.contains("approval.reference"))
        .expect("line");
    assert!(line.ends_with("[review required]"), "{text}");
    let (_, json) = run(tmp.path(), true, &[]);
    let v: Value = serde_json::from_str(&json).expect("json");
    assert_eq!(v["review_required"], true, "{json}");
    let change = v["changes"]
        .as_array()
        .expect("list")
        .iter()
        .find(|c| c["field"] == "approval.reference")
        .expect("change");
    assert_eq!(change["review_required"], true);
}

#[test]
fn containment_calls_a_changed_reference_widened() {
    let tmp = setup();
    let args = ["--containment", "--at", AT];
    let (code, text) = run(tmp.path(), false, &args);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("Loosened: approval.reference:"), "{text}");
    assert!(text.contains("Overall verdict: widened."), "{text}");
    let (code, json) = run(tmp.path(), true, &args);
    assert_eq!(code, Some(2));
    let v: Value = serde_json::from_str(&json).expect("json");
    assert_eq!(v["result"], "widened");
    assert_eq!(v["containment"]["endpoint_result"], "contained");
    assert_eq!(
        v["containment"]["loosenings"][0]["field"],
        "approval.reference"
    );
}
