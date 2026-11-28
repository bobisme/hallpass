//! CLI consistency: checkpoint witness relation, empty checkpoint, error
//! recording, `--at now`, init errors and receipt timestamps.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const CLOCK: &str = "2026-11-20T09:00:00Z";

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = dir.path().join("approval");
        let body = format!(
            "{}\n[ceilings]\ncalls = 10\n",
            include_str!("../docs/review-approval.toml")
        );
        fs::write(&pass, body).expect("pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        Self { dir, pass }
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn witness(&self) -> PathBuf {
        self.state().join("hallpass/review-example.witness")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(args)
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.state())
            .env("HALLPASS_UNSAFE_TEST_CLOCK", CLOCK)
            .output()
            .expect("run")
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        let value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().expect("code"), value)
    }

    fn spend(&self, caller_ref: &str) {
        let pass = self.pass.to_str().expect("utf8");
        let out = self.run(&["spend", pass, "calls", "--caller-ref", caller_ref]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn checkpoint(&self) -> (i32, Value) {
        self.json(&["checkpoint", self.pass.to_str().expect("utf8")])
    }
}

#[test]
fn matching_witness_gets_no_lag_warning_and_round_trips() {
    let f = Fixture::new();
    f.spend("a");
    let (code, v) = f.checkpoint();
    assert_eq!(code, 0);
    assert_eq!(v["local_corroboration"], true);
    assert_eq!(v["witness"]["relation"], "matches");
    assert_eq!(v["witness"]["witnessed_seq"], 1);
    assert_eq!(v["warnings"], serde_json::json!([]));
    let saved = f.dir.path().join("checkpoint.json");
    fs::write(&saved, v.to_string()).expect("save");
    let ledger = format!("{}.ledger", f.pass.display());
    let (code, verified) = f.json(&["verify-checkpoint", &ledger, saved.to_str().expect("utf8")]);
    assert_eq!(code, 0, "{verified}");
}

#[test]
fn lagging_witness_names_both_sequences() {
    let f = Fixture::new();
    f.spend("a");
    let old = fs::read(f.witness()).expect("witness");
    f.spend("b");
    fs::write(f.witness(), old).expect("rewind witness");
    let (code, v) = f.checkpoint();
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["local_corroboration"], true);
    assert_eq!(v["witness"]["relation"], "lags");
    assert_eq!(v["witness"]["witnessed_seq"], 1);
    assert_eq!(v["witness"]["exported_seq"], 2);
    let warning = v["warnings"][0].as_str().expect("warning");
    assert!(warning.contains("sequence 1") && warning.contains("sequence 2"));
}

#[test]
fn absent_witness_is_reported() {
    let f = Fixture::new();
    f.spend("a");
    fs::remove_file(f.witness()).expect("remove witness");
    fs::remove_file(f.witness().with_extension("recorded")).expect("and its copy");
    let (code, v) = f.checkpoint();
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["local_corroboration"], false);
    assert_eq!(v["witness"]["relation"], "absent");
    assert_eq!(v["warnings"][0], "There is no local witness corroboration.");
}

#[test]
fn contradictory_history_still_fails() {
    let f = Fixture::new();
    f.spend("a");
    f.spend("b");
    let ledger = format!("{}.ledger", f.pass.display());
    let text = fs::read_to_string(&ledger).expect("ledger");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.pop();
    fs::write(&ledger, format!("{}\n", lines.join("\n"))).expect("truncate");
    let (code, v) = f.checkpoint();
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["result"], "error");
}

#[test]
fn checkpoint_before_any_ledger_reports_nothing_recorded() {
    let f = Fixture::new();
    let (code, v) = f.checkpoint();
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["result"], "empty");
    assert!(v["checkpoint"].is_null());
    assert!(
        v["warnings"][0]
            .as_str()
            .expect("warning")
            .contains("Nothing has been recorded")
    );
    let text = f.run(&["checkpoint", f.pass.to_str().expect("utf8")]);
    assert!(
        text.stdout.is_empty(),
        "stdout must stay empty for redirects"
    );
    // Once something is recorded, the export works.
    f.spend("a");
    assert_eq!(f.checkpoint().0, 0);
}

#[test]
fn witnessed_spend_with_missing_ledger_is_still_an_error() {
    let f = Fixture::new();
    f.spend("a");
    fs::remove_file(format!("{}.ledger", f.pass.display())).expect("remove ledger");
    let (code, v) = f.checkpoint();
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["result"], "error");
}

#[test]
fn witness_unavailable_spend_says_not_recorded() {
    let f = Fixture::new();
    // A regular file where the state directory must be.
    fs::write(f.state(), b"x").expect("block state dir");
    let (code, v) = f.json(&["spend", f.pass.to_str().expect("utf8"), "calls"]);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["error"]["code"], "witness-unavailable");
    assert_eq!(v["error"]["recording"], "not-recorded");
}

#[test]
fn diff_at_now_says_it_is_not_accepted() {
    let f = Fixture::new();
    let pass = f.pass.to_str().expect("utf8");
    let (code, v) = f.json(&["diff", "--containment", "--at", "now", pass, pass]);
    assert_eq!(code, 1, "{v}");
    let message = v["error"]["message"].as_str().expect("message");
    assert!(message.contains("does not accept `now`"), "{message}");
    assert!(!message.contains("'year' component"), "{message}");
}

#[test]
fn init_error_does_not_claim_nothing_was_permitted() {
    let f = Fixture::new();
    let out = f.run(&["init", f.pass.to_str().expect("utf8")]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("never overwrites"), "{stderr}");
    assert!(!stderr.contains("Nothing was permitted"), "{stderr}");
    // A deciding command keeps the suffix.
    let out = f.run(&["spend", "/nonexistent/pass", "calls"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("Nothing was permitted."));
}

#[test]
fn receipt_text_uses_whole_second_timestamps() {
    let f = Fixture::new();
    f.spend("ref-1");
    let pass = f.pass.to_str().expect("utf8");
    let out = f.run(&["receipt", pass, "--caller-ref", "ref-1"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("2026-11-20T09:00:00Z"), "{text}");
    assert!(!text.contains("T09:00:00."), "{text}");
    // JSON keeps its original precision field untouched.
    let (_, v) = f.json(&["receipt", pass, "--caller-ref", "ref-1"]);
    assert!(v["matches"][0]["time"].is_string());
}
