//! A held writer or ledger lock shows in `doctor` as `lock-held` without any
//! wait, and `diff --budget-impact` reads the live ledger the witness names
//! when neither file has one beside it (bn-22sm).
#![cfg(feature = "cli")]

use hallpass::{
    SpendRequest, StateDir, spend_in,
    time::{OffsetDateTime, format_description::well_known::Rfc3339},
};
use serde_json::Value;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/review-approval.toml");

fn write_pass(dir: &Path, file: &str, ceiling: u32) {
    let path = dir.join(file);
    fs::write(&path, format!("{BASE}\n[ceilings]\ncalls = {ceiling}\n")).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(10);
    File::options()
        .write(true)
        .open(&path)
        .expect("open")
        .set_modified(old)
        .expect("backdate");
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

/// A pass with one spend. The directory is private, as passes require.
fn spent() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("dir");
    write_pass(tmp.path(), "p.toml", 10);
    // Recorded under the test clock, as doctor then runs.
    let (code, text) = run(
        tmp.path(),
        false,
        &[
            "spend",
            "p.toml",
            "calls",
            "--to",
            "192.0.2.10:443/tcp",
            "--name",
            "app.example.com",
        ],
    );
    assert_eq!(code, 0, "{text}");
    tmp
}

fn doctor_json(dir: &Path) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["--json", "doctor", "p.toml"])
        .current_dir(dir)
        .env("HOME", dir)
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T10:00:00Z")
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run");
    let text = String::from_utf8(out.stdout).expect("utf8");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// The lock is held by this test process through its own descriptor, for as
/// long as the guard lives, so doctor meets it however loaded the machine is.
fn hold(path: &Path) -> File {
    let file = File::options().read(true).open(path).expect("open lock");
    file.lock().expect("hold");
    file
}

fn proc_locks_readable() -> bool {
    fs::read_to_string("/proc/locks").is_ok()
}

#[test]
fn held_writer_lock_is_reported_with_its_holder() {
    let tmp = spent();
    let lock = tmp.path().join("state/hallpass/review-example.lock");
    let guard = hold(&lock);
    let report = doctor_json(tmp.path());
    assert_eq!(report["result"], "needs-action", "{report}");
    let text = report.to_string();
    assert!(text.contains("review-example.lock"), "{text}");
    assert!(text.contains("hung"), "{text}");
    assert!(text.contains("fuser") || text.contains("ps -p"), "{text}");
    if proc_locks_readable() {
        assert!(
            text.contains(&format!("process {}", std::process::id())),
            "{text}"
        );
    }
    // The writer lock does not stop the read of the ledger.
    let (_, plain) = run(tmp.path(), false, &["doctor", "p.toml"]);
    assert!(plain.starts_with("NEEDS ACTION: lock-held"), "{plain}");
    drop(guard);
    assert_eq!(doctor_json(tmp.path())["result"], "healthy");
}

#[test]
fn held_ledger_lock_is_reported_without_waiting_for_it() {
    let tmp = spent();
    let _guard = hold(&tmp.path().join("p.toml.ledger"));
    let report = doctor_json(tmp.path());
    assert_eq!(report["result"], "needs-action", "{report}");
    let text = report.to_string();
    assert!(text.contains("p.toml.ledger"), "{text}");
    assert!(text.contains("did not read the ledger"), "{text}");
    let (_, plain) = run(tmp.path(), false, &["doctor", "p.toml"]);
    assert!(plain.starts_with("NEEDS ACTION: lock-held"), "{plain}");
}

#[test]
fn a_free_lock_stays_free_after_the_probe() {
    let tmp = spent();
    assert_eq!(doctor_json(tmp.path())["result"], "healthy");
    for path in [
        tmp.path().join("state/hallpass/review-example.lock"),
        tmp.path().join("p.toml.ledger"),
    ] {
        let file = File::open(&path).expect("open");
        file.try_lock().expect("doctor let go of the lock");
    }
}

#[test]
fn doctor_creates_no_lock_file() {
    let tmp = spent();
    let lock = tmp.path().join("state/hallpass/review-example.lock");
    fs::remove_file(&lock).expect("remove");
    let _ = doctor_json(tmp.path());
    assert!(!lock.exists(), "doctor made a lock file");
}

/// A live pass with a spend, and archived OLD and proposed NEW copies of the
/// same id in another directory with no ledger beside them.
fn live_and_archived() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("dir");
    fs::create_dir(tmp.path().join("live")).expect("live");
    fs::set_permissions(tmp.path().join("live"), fs::Permissions::from_mode(0o700)).expect("mode");
    write_pass(&tmp.path().join("live"), "p.toml", 10);
    spend(tmp.path(), "live/p.toml");
    write_pass(tmp.path(), "old.toml", 10);
    write_pass(tmp.path(), "new.toml", 6);
    tmp
}

#[test]
fn archived_old_uses_the_live_ledger_named_by_the_witness() {
    let tmp = live_and_archived();
    let args = ["diff", "old.toml", "new.toml", "--budget-impact"];
    let (code, text) = run(tmp.path(), false, &args);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("(the live ledger, named by the witness)") && text.contains("Ledger used:"),
        "{text}"
    );
    assert!(!text.contains("hallpass adopt"), "{text}");
    let (code, json) = run(tmp.path(), true, &args);
    assert_eq!(code, 0, "{json}");
    let value: Value = serde_json::from_str(&json).expect("json");
    let b = &value["budget_impact"];
    assert_eq!(b["ledger_source"], "live", "{b}");
    assert!(
        b["ledger"]
            .as_str()
            .expect("path")
            .ends_with("live/p.toml.ledger")
    );
    assert_eq!(b["counters"][0]["spent"], 4, "{b}");
    assert_eq!(b["counters"][0]["proposed_remaining"], 2, "{b}");
    // Nothing was written beside the archived copies.
    assert!(!tmp.path().join("old.toml.ledger").exists());
    assert!(!tmp.path().join("new.toml.ledger").exists());
}

#[test]
fn live_ledger_without_a_live_pass_says_to_give_the_live_pass_as_old() {
    let tmp = live_and_archived();
    fs::remove_file(tmp.path().join("live/p.toml")).expect("remove live pass");
    let (code, text) = run(
        tmp.path(),
        false,
        &["diff", "old.toml", "new.toml", "--budget-impact"],
    );
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("give the live pass file as OLD"), "{text}");
    assert!(!text.contains("hallpass adopt"), "{text}");
    assert!(!text.contains("to recover"), "{text}");
}
