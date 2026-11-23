//! `ledger --tail` and `--since`: slice the output, still verify everything.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = r#"format = 1
id = "example-2026-11"
name = "Example"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = 5060

[ceilings]
calls = 20
requests = 500
"#;

struct Case {
    dir: tempfile::TempDir,
    file: PathBuf,
}

impl Case {
    /// Six spends: seq 1..=6, odd ones on calls, even ones on requests.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let file = dir.path().join("p.toml");
        fs::write(&file, PASS).expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");
        let case = Self { dir, file };
        for i in 1..=6 {
            let counter = if i % 2 == 1 { "calls" } else { "requests" };
            let (rc, out) = case.json(&["spend", s(&case.file), counter], true);
            assert_eq!(rc, 0, "{out}");
        }
        case
    }

    fn command(&self, clock: bool) -> Command {
        let home = self.dir.path().join("home");
        let mut c = Command::new(BIN);
        c.env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"));
        if clock {
            c.env("HALLPASS_UNSAFE_TEST_CLOCK", NOW);
        }
        c
    }

    fn json(&self, args: &[&str], clock: bool) -> (i32, Value) {
        let out = self
            .command(clock)
            .args(["--format", "json"])
            .args(args)
            .output()
            .expect("run");
        let stdout = String::from_utf8(out.stdout).expect("utf8");
        let v: Value = serde_json::from_str(stdout.trim()).expect("json");
        (out.status.code().expect("code"), v)
    }

    fn ledger(&self, extra: &[&str]) -> (i32, Value) {
        let mut args = vec!["ledger", s(&self.file)];
        args.extend_from_slice(extra);
        self.json(&args, false)
    }

    fn text(&self, extra: &[&str]) -> String {
        let out = self
            .command(false)
            .arg("ledger")
            .arg(&self.file)
            .args(extra)
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(0));
        String::from_utf8(out.stdout).expect("utf8")
    }
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8")
}

fn seqs(out: &Value) -> Vec<u64> {
    out["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["seq"].as_u64().expect("seq"))
        .collect()
}

#[test]
fn unsliced_has_null_shown() {
    let case = Case::new();
    let (rc, out) = case.ledger(&[]);
    assert_eq!(rc, 0);
    assert_eq!(out["shown"], Value::Null);
    assert_eq!(seqs(&out), [1, 2, 3, 4, 5, 6]);
    assert!(!case.text(&[]).contains("Showing"));
}

#[test]
fn tail_shows_last_entries_with_whole_totals() {
    let case = Case::new();
    let (rc, out) = case.ledger(&["--tail", "2"]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(seqs(&out), [5, 6]);
    assert_eq!(
        out["shown"],
        serde_json::json!({"from": 5, "to": 6, "of": 6})
    );
    let totals = out["totals"].as_array().expect("totals");
    assert_eq!(totals[0]["spent"], 3);
    assert_eq!(totals[1]["spent"], 3);
    let (_, out) = case.ledger(&["--tail", "100"]);
    assert_eq!(seqs(&out).len(), 6);
    assert_eq!(out["shown"]["from"], 1);
}

#[test]
fn since_shows_from_seq() {
    let case = Case::new();
    let (_, out) = case.ledger(&["--since", "4"]);
    assert_eq!(seqs(&out), [4, 5, 6]);
    assert_eq!(
        out["shown"],
        serde_json::json!({"from": 4, "to": 6, "of": 6})
    );
}

#[test]
fn both_flags_intersect() {
    let case = Case::new();
    let (_, out) = case.ledger(&["--since", "3", "--tail", "2"]);
    assert_eq!(seqs(&out), [5, 6]);
    let (_, out) = case.ledger(&["--since", "5", "--tail", "4"]);
    assert_eq!(seqs(&out), [5, 6]);
    assert_eq!(out["shown"]["of"], 6);
}

#[test]
fn tail_zero_shows_nothing_but_reports_totals() {
    let case = Case::new();
    let (rc, out) = case.ledger(&["--tail", "0"]);
    assert_eq!(rc, 0);
    assert_eq!(seqs(&out), Vec::<u64>::new());
    assert_eq!(
        out["shown"],
        serde_json::json!({"from": null, "to": null, "of": 6})
    );
    assert_eq!(out["verified"], true);
    assert_eq!(out["totals"][0]["spent"], 3);
    let text = case.text(&["--tail", "0"]);
    assert!(text.contains("Showing no entries of 6"), "{text}");
    assert!(text.contains("3 spent of 20"), "{text}");
}

#[test]
fn since_beyond_the_end_shows_nothing() {
    let case = Case::new();
    let (rc, out) = case.ledger(&["--since", "99"]);
    assert_eq!(rc, 0);
    assert_eq!(seqs(&out), Vec::<u64>::new());
    assert_eq!(out["shown"]["from"], Value::Null);
    assert_eq!(out["shown"]["of"], 6);
}

#[test]
fn counter_filter_applies_before_the_slice() {
    let case = Case::new();
    // calls are seq 1, 3, 5.
    let (_, out) = case.ledger(&["--counter", "calls", "--tail", "2"]);
    assert_eq!(seqs(&out), [3, 5]);
    let (_, out) = case.ledger(&["--counter", "calls", "--since", "2", "--tail", "1"]);
    assert_eq!(seqs(&out), [5]);
    assert_eq!(out["totals"].as_array().map(Vec::len), Some(1));
    assert_eq!(out["totals"][0]["spent"], 3);
}

#[test]
fn text_names_the_slice() {
    let case = Case::new();
    let text = case.text(&["--since", "2", "--tail", "3"]);
    assert!(
        text.contains("Showing entries 4 to 6 of 6 in the ledger (--since 2, --tail 3)"),
        "{text}"
    );
    assert!(!text.contains("\n      1  "), "{text}");
}

#[test]
fn tampered_earlier_line_still_fails() {
    let case = Case::new();
    let ledger = dir_ledger(&case);
    let text = fs::read_to_string(&ledger).expect("read");
    fs::write(&ledger, text.replacen("\"n\":1", "\"n\":2", 1)).expect("damage");
    for extra in [&["--tail", "1"][..], &["--since", "6"], &["--tail", "0"]] {
        let (rc, out) = case.ledger(extra);
        assert_eq!(rc, 1, "{out}");
        assert_eq!(out["error"]["code"], "ledger-corrupt");
    }
}

fn dir_ledger(case: &Case) -> PathBuf {
    case.dir.path().join("p.toml.ledger")
}
