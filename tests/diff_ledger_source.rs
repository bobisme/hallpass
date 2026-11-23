//! `diff --budget-impact` reads the live ledger, and read-only commands never
//! advise `hallpass adopt`.
#![cfg(feature = "cli")]

use hallpass::{
    SpendRequest, StateDir, spend_in,
    time::{OffsetDateTime, format_description::well_known::Rfc3339},
};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/review-approval.toml");

fn write_pass(dir: &Path, file: &str, ceiling: u32) {
    let path = dir.join(file);
    fs::write(&path, format!("{BASE}\n[ceilings]\ncalls = {ceiling}\n")).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn run(dir: &Path, json: bool, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
    if json {
        cmd.arg("--json");
    }
    let out = cmd
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T10:00:00Z")
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run");
    let mut text = String::from_utf8(out.stdout).expect("utf8");
    text.push_str(&String::from_utf8(out.stderr).expect("utf8"));
    (out.status.code().expect("exit"), text)
}

fn spend(dir: &Path, file: &str) {
    let now = OffsetDateTime::parse("2026-11-20T10:00:00Z", &Rfc3339).expect("instant");
    let state = StateDir::new(dir.join("state/hallpass"));
    spend_in(&dir.join(file), &SpendRequest::new("calls", 4), now, &state).expect("spend");
}

fn impact(dir: &Path) -> (Value, String) {
    let (code, text) = run(dir, false, &["diff", "old", "new", "--budget-impact"]);
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("hallpass adopt"), "{text}");
    let (code, json) = run(dir, true, &["diff", "old", "new", "--budget-impact"]);
    assert_eq!(code, 0, "{json}");
    let value: Value = serde_json::from_str(&json).expect("json");
    (value["budget_impact"].clone(), text)
}

fn fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("dir");
    write_pass(tmp.path(), "old", 10);
    write_pass(tmp.path(), "new", 6);
    tmp
}

#[test]
fn only_new_ledger_present_is_used() {
    let tmp = fixture();
    spend(tmp.path(), "new");
    let (b, text) = impact(tmp.path());
    assert_eq!(b["ledger_source"], "new");
    assert!(b["ledger"].as_str().expect("path").ends_with("new.ledger"));
    assert_eq!(b["counters"][0]["spent"], 4, "{b}");
    assert_eq!(b["counters"][0]["proposed_remaining"], 2);
    assert!(
        text.contains("Ledger used:") && text.contains("beside NEW"),
        "{text}"
    );
}

#[test]
fn only_old_ledger_present_is_used() {
    let tmp = fixture();
    spend(tmp.path(), "old");
    let (b, text) = impact(tmp.path());
    assert_eq!(b["ledger_source"], "old");
    assert!(b["ledger"].as_str().expect("path").ends_with("old.ledger"));
    assert_eq!(b["counters"][0]["spent"], 4);
    assert!(text.contains("beside OLD"), "{text}");
}

#[test]
fn new_ledger_wins_when_both_exist() {
    let tmp = fixture();
    spend(tmp.path(), "old");
    fs::write(tmp.path().join("new.ledger"), "corrupt").expect("decoy");
    let (code, text) = run(tmp.path(), true, &["diff", "old", "new", "--budget-impact"]);
    assert_eq!(code, 1, "{text}");
    assert!(!text.contains("hallpass adopt"), "{text}");
}

#[test]
fn neither_ledger_present_projects_zero_spend() {
    let tmp = fixture();
    let (b, text) = impact(tmp.path());
    assert_eq!(b["ledger_source"], "none");
    assert!(b["tip"].is_null());
    assert!(text.contains("neither OLD nor NEW"), "{text}");
}

#[test]
fn lost_ledger_is_reported_without_adopt_advice_by_read_only_commands() {
    let tmp = fixture();
    let dir = tmp.path();
    spend(dir, "new");
    fs::remove_file(dir.join("new.ledger")).expect("lose");
    for args in [
        vec!["diff", "old", "new", "--budget-impact"],
        vec!["receipt", "new", "--caller-ref", "x"],
        vec!["checkpoint", "new"],
        vec!["reconcile", "new", "missing-manifest"],
        vec!["audit-receipts", "new", "."],
        vec!["audit-charges", "new", "."],
        vec!["compare-backups", "new", "old"],
        vec!["capacity", "new", "calls"],
        vec!["ledger", "new"],
        vec!["lint", "new"],
    ] {
        for json in [false, true] {
            let (_, text) = run(dir, json, &args);
            assert!(!text.contains("hallpass adopt"), "{args:?}: {text}");
        }
    }
    let (code, text) = run(dir, true, &["diff", "old", "new", "--budget-impact"]);
    assert_eq!(code, 1);
    assert!(text.contains("\"ledger-missing\""), "{text}");
    // Commands that write keep the recovery advice.
    let (_, text) = run(dir, false, &["spend", "new", "calls"]);
    assert!(text.contains("hallpass adopt"), "{text}");
}
