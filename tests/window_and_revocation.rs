//! Containment of a revocation (bn-1ab) and warnings about an implausible
//! approval window (bn-1cz).
#![cfg(feature = "cli")]
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

const BASE: &str = include_str!("../docs/review-approval.toml");
const AT: &str = "2026-11-20T09:00:00Z";
const CLOCK: &str = "2026-11-20T09:00:00Z";

fn write_pass(dir: &Path, file: &str, pass: &str) {
    let path = dir.join(file);
    fs::write(&path, pass).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    // Date the file back so the reader does not wait for it to settle.
    let earlier = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|f| f.set_modified(earlier))
        .expect("date back");
}

fn run(dir: &Path, format: &str, clock: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["--format", format])
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", clock)
        .output()
        .expect("run hallpass")
}

fn json(dir: &Path, clock: &str, exit: i32, args: &[&str]) -> Value {
    let out = run(dir, "json", clock, args);
    assert_eq!(
        out.status.code(),
        Some(exit),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).expect("one JSON document")
}

fn contain(dir: &Path, old: &str, new: &str, exit: i32) -> Value {
    write_pass(dir, "old.toml", old);
    write_pass(dir, "new.toml", new);
    json(
        dir,
        CLOCK,
        exit,
        &["diff", "old.toml", "new.toml", "--containment", "--at", AT],
    )
}

fn revoked(text: &str) -> String {
    text.replace("revoked = false", "revoked = true")
}

#[test]
fn a_pure_revocation_is_contained() {
    let dir = tempfile::tempdir().expect("dir");
    let r = contain(dir.path(), BASE, &revoked(BASE), 0);
    assert_eq!(r["result"], "contained");
    assert_eq!(r["containment"]["endpoint_result"], "contained");
    assert_eq!(r["containment"]["reason"], "new-admits-nothing");
    assert_eq!(
        r["containment"]["loosenings"]
            .as_array()
            .expect("list")
            .len(),
        0
    );
}

#[test]
fn a_window_moved_to_be_closed_at_the_instant_is_contained() {
    let dir = tempfile::tempdir().expect("dir");
    // NEW ends before the instant: closed there, and only narrower. NEW still
    // admits requests earlier, so the rules are compared.
    let new = BASE.replace(
        "valid_until = 2026-11-20T17:00:00Z",
        "valid_until = 2026-11-20T08:30:00Z",
    );
    let r = contain(dir.path(), BASE, &new, 0);
    assert_eq!(r["result"], "contained");
    assert_eq!(r["containment"]["reason"], "rules-and-ipv4-edges-covered");
}

#[test]
fn a_revocation_with_a_raised_ceiling_is_widened() {
    let dir = tempfile::tempdir().expect("dir");
    let old = format!("{BASE}\n[ceilings]\nscans = 5\n");
    let new = revoked(&format!("{BASE}\n[ceilings]\nscans = 50\n"));
    let r = contain(dir.path(), &old, &new, 2);
    assert_eq!(r["result"], "widened");
    assert_eq!(r["containment"]["endpoint_result"], "contained");
    assert_eq!(r["containment"]["loosenings"][0]["field"], "ceilings.scans");
}

#[test]
fn old_closed_and_new_open_is_widened_by_the_un_revoke() {
    let dir = tempfile::tempdir().expect("dir");
    let r = contain(dir.path(), &revoked(BASE), BASE, 2);
    // The un-revoke is a loosening, so the overall verdict is widened. The
    // revocation is judged as its own term: the rules are the same, so the
    // endpoint proof is contained. Either way a gate exits 2.
    assert_eq!(r["result"], "widened");
    assert_eq!(
        r["containment"]["loosenings"][0]["field"],
        "approval.revoked"
    );
    assert_eq!(r["containment"]["endpoint_result"], "contained");
    assert_eq!(r["containment"]["reason"], "rules-and-ipv4-edges-covered");
}

#[test]
fn a_different_pass_id_is_still_inconclusive_for_a_revoked_new() {
    let dir = tempfile::tempdir().expect("dir");
    let r = contain(
        dir.path(),
        BASE,
        &revoked(&BASE.replace("review-example", "other")),
        2,
    );
    assert_eq!(r["containment"]["reason"], "different-pass-id");
}

fn codes(v: &Value) -> Vec<String> {
    v["window_warnings"]
        .as_array()
        .expect("window_warnings")
        .iter()
        .map(|w| w["code"].as_str().expect("code").to_owned())
        .collect()
}

fn long(text: &str) -> String {
    text.replace(
        "valid_until = 2026-11-20T17:00:00Z",
        "valid_until = 2062-11-30T17:00:00Z",
    )
}

/// Every command, at its own exit code for a window that is open at `clock`.
const COMMANDS: [(&str, &str); 3] = [("check", "check"), ("status", "status"), ("lint", "lint")];

#[test]
fn a_normal_window_has_no_warning() {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "p.toml", BASE);
    for (name, _) in COMMANDS {
        let v = json(dir.path(), CLOCK, 0, &[name, "p.toml"]);
        assert_eq!(codes(&v), Vec::<String>::new(), "{name}");
        assert!(
            v["warnings"]
                .as_array()
                .expect("w")
                .iter()
                .all(|w| !w.as_str().expect("s").contains("window")),
            "{name}"
        );
        let out = run(dir.path(), "text", CLOCK, &[name, "p.toml"]);
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("approval window"),
            "{name}"
        );
    }
}

#[test]
fn a_long_window_warns_in_json_and_text_without_changing_the_exit_code() {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "p.toml", &long(BASE));
    for (name, _) in COMMANDS {
        let v = json(dir.path(), CLOCK, 0, &[name, "p.toml"]);
        assert_eq!(codes(&v), ["window-too-long"], "{name}");
        let message = v["warnings"]
            .as_array()
            .expect("w")
            .iter()
            .find_map(|w| w.as_str().filter(|s| s.contains("approval window")))
            .expect("message");
        assert!(message.contains("13159 days long"), "{message}");
        let out = run(dir.path(), "text", CLOCK, &[name, "p.toml"]);
        assert_eq!(out.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("warning: the approval window is 13159 days long"),
            "{name}"
        );
    }
}

#[test]
fn ninety_days_is_the_longest_window_without_a_warning() {
    let dir = tempfile::tempdir().expect("dir");
    // 2026-11-20T08:00Z plus 90 days is 2027-02-18T08:00Z.
    let edge = BASE.replace(
        "valid_until = 2026-11-20T17:00:00Z",
        "valid_until = 2027-02-18T08:00:00Z",
    );
    write_pass(dir.path(), "p.toml", &edge);
    assert_eq!(
        codes(&json(dir.path(), CLOCK, 0, &["check", "p.toml"])),
        Vec::<String>::new()
    );
    let over = BASE.replace(
        "valid_until = 2026-11-20T17:00:00Z",
        "valid_until = 2027-02-18T08:00:01Z",
    );
    write_pass(dir.path(), "p.toml", &over);
    assert_eq!(
        codes(&json(dir.path(), CLOCK, 0, &["check", "p.toml"])),
        ["window-too-long"]
    );
}

#[test]
fn an_ended_window_warns_and_check_honours_the_test_clock() {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "p.toml", BASE);
    let later = "2026-11-21T00:00:00Z";
    let v = json(dir.path(), later, 0, &["check", "p.toml"]);
    assert_eq!(codes(&v), ["window-ended"]);
    assert_eq!(v["now"], later);
    assert_eq!(v["test_clock"], true);
    // status refuses an expired window as before; the warning is added.
    assert_eq!(
        codes(&json(dir.path(), later, 2, &["status", "p.toml"])),
        ["window-ended"]
    );
    assert_eq!(
        codes(&json(dir.path(), later, 0, &["lint", "p.toml"])),
        ["window-ended"]
    );
    let out = run(dir.path(), "text", later, &["check", "p.toml"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("warning: the approval window ended at 2026-11-20T17:00:00Z")
    );
    // A revoked pass is refused by name; no second warning.
    write_pass(dir.path(), "r.toml", &revoked(BASE));
    assert_eq!(
        codes(&json(dir.path(), later, 0, &["check", "r.toml"])),
        Vec::<String>::new()
    );
}

#[test]
fn a_window_that_starts_far_ahead_warns() {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "p.toml", BASE);
    let early = "2026-09-01T00:00:00Z";
    for (name, exit) in [("check", 0), ("status", 2), ("lint", 0)] {
        let v = json(dir.path(), early, exit, &[name, "p.toml"]);
        assert_eq!(codes(&v), ["window-starts-far-ahead"], "{name}");
        assert!(
            v["window_warnings"][0]["message"]
                .as_str()
                .expect("m")
                .contains("80 days after now")
        );
    }
    // Thirty days ahead is not far.
    let near = "2026-10-21T08:00:00Z";
    assert_eq!(
        codes(&json(dir.path(), near, 0, &["check", "p.toml"])),
        Vec::<String>::new()
    );
    let out = run(dir.path(), "text", early, &["check", "p.toml"]);
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("warning: the approval window opens at 2026-11-20T08:00:00Z")
    );
}

#[test]
fn diff_shows_the_window_warnings_for_new() {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "old.toml", BASE);
    write_pass(dir.path(), "new.toml", &long(BASE));
    let v = json(dir.path(), CLOCK, 0, &["diff", "old.toml", "new.toml"]);
    assert_eq!(v["new_window_warnings"][0]["code"], "window-too-long");
    assert!(
        v["warnings"][0]
            .as_str()
            .expect("w")
            .starts_with("NEW revision: the approval window is")
    );
    // Without --at the clock-dependent warnings are not judged.
    write_pass(
        dir.path(),
        "new.toml",
        &BASE.replace("2026-11-20", "2026-11-19"),
    );
    let none = json(dir.path(), CLOCK, 0, &["diff", "old.toml", "new.toml"]);
    assert_eq!(none["new_window_warnings"].as_array().expect("l").len(), 0);
    // With --at the ended window is judged at that instant.
    let at = json(
        dir.path(),
        CLOCK,
        0,
        &["diff", "old.toml", "new.toml", "--examples", "--at", AT],
    );
    assert_eq!(at["new_window_warnings"][0]["code"], "window-ended");
    let out = run(
        dir.path(),
        "text",
        CLOCK,
        &["diff", "old.toml", "new.toml", "--examples", "--at", AT],
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("warning: NEW revision: the approval window ended")
    );
}
