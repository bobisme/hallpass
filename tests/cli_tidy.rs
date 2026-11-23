#![cfg(feature = "cli")]
//! Small CLI consistency tidy-ups: conflicting format flags, `--n` errors,
//! `error.recording`, text times, reconcile value types, capacity wording and
//! the `ledger` text details column.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
/// A clock with a fractional second, so a text time that is not rounded shows.
const NOW: &str = "2026-11-20T09:00:00.123456789Z";
const ENDPOINT: &str = "192.0.2.10:443/tcp@app.example.com";

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        Self { dir }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        path
    }
    fn pass(&self) -> PathBuf {
        self.file(
            "pass",
            &format!(
                "{}\n[ceilings]\nrequests=1000\nbytes=1000\n",
                include_str!("../docs/review-approval.toml")
            ),
        )
    }
    fn run(&self, args: &[&str]) -> Output {
        let home = self.path("home");
        Command::new(BIN)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .args(args)
            .output()
            .expect("run")
    }
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        let value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{e}: {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("code"), value)
    }
    fn text(&self, args: &[&str]) -> (i32, String) {
        let mut all = vec!["--format", "text"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        (
            out.status.code().expect("code"),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8")
}

fn debit(case: &Case, file: &str, reference: &str, note: Option<&str>) -> String {
    let mut args = vec![
        "spend",
        file,
        "--charge",
        "requests=1",
        "--charge",
        "bytes=4",
        "--to",
        ENDPOINT,
        "--record-target",
        "--caller-ref",
        reference,
    ];
    if let Some(note) = note {
        args.extend(["--note", note]);
    }
    let (code, v) = case.json(&args);
    assert_eq!(code, 0, "{v}");
    v["digest"].as_str().expect("digest").to_owned()
}

#[test]
fn conflicting_format_flags_are_a_usage_error_naming_both() {
    let case = Case::new();
    for args in [
        vec!["--format", "text", "--json", "version"],
        vec!["--json", "--format", "text", "version"],
        vec!["version", "--json", "--format=pretty"],
    ] {
        let out = case.run(&args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
        assert_eq!(v["error"]["code"], "usage", "{args:?}");
        assert_eq!(v["error"]["recording"], "not-recorded", "{args:?}");
        let message = v["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("--format") && message.contains("--json"),
            "{message}"
        );
        assert!(out.stderr.is_empty(), "{args:?}");
    }
    // The same format twice is not a conflict.
    for args in [
        vec!["--json", "--format", "json", "version"],
        vec!["--format=json", "--json", "version"],
        vec!["--json", "--json", "version"],
    ] {
        let out = case.run(&args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let v: Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(v["result"], "ok", "{args:?}");
    }
}

#[test]
fn a_negative_or_malformed_n_gets_a_clear_usage_error() {
    let case = Case::new();
    let p = case.pass();
    for bad in ["-5", "abc", "1.5"] {
        let (code, v) = case.json(&["spend", s(&p), "requests", "--n", bad]);
        assert_eq!(code, 1, "{bad}");
        assert_eq!(v["error"]["code"], "usage", "{bad}");
        let message = v["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("N must be a positive integer"),
            "{message}"
        );
        assert!(!message.contains("-- -5"), "{message}");
        assert_eq!(v["error"]["recording"], "not-recorded");
    }
    // `capacity` shares the argument.
    let (code, v) = case.json(&["capacity", s(&p), "requests", "--n", "-1"]);
    assert_eq!(code, 1, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .expect("message")
            .contains("N must be a positive integer")
    );
    let out = case.run(&["spend", s(&p), "requests", "--n", "-5"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("N must be a positive integer"), "{stderr}");
    assert!(!stderr.contains("use '-- -5'"), "{stderr}");
    assert!(!case.path("pass.ledger").exists());
}

#[test]
fn recording_is_not_recorded_wherever_nothing_can_have_been_recorded() {
    let case = Case::new();
    let p = case.pass();
    // A semantic usage error from a writer: zero is rejected before any write.
    let (code, v) = case.json(&["spend", s(&p), "requests", "--n", "0"]);
    assert_eq!((code, v["error"]["code"].as_str()), (1, Some("usage")));
    assert_eq!(v["error"]["recording"], "not-recorded", "{v}");
    // An `io` error from a read-only command.
    let missing = case.path("missing");
    for command in ["ledger", "check", "status"] {
        let (code, v) = case.json(&[command, s(&missing)]);
        assert_eq!(code, 1, "{command}: {v}");
        assert_eq!(v["error"]["code"], "io", "{command}");
        let expected = if command == "status" {
            Value::Null
        } else {
            json!("not-recorded")
        };
        assert_eq!(v["error"]["recording"], expected, "{command}: {v}");
    }
    // A writer's `io` error stays null: the failure may be before or after the write.
    let (_, v) = case.json(&["spend", s(&missing), "requests"]);
    assert_eq!(v["error"]["code"], "io");
    assert_eq!(v["error"]["recording"], Value::Null, "{v}");
}

#[test]
fn text_times_use_whole_seconds_in_every_command() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let archive = case.path("archive");
    fs::create_dir(&archive).expect("archive");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert_eq!(case.json(&["archive", file, s(&archive)]).0, 0);
    debit(&case, file, "ref-1", None);
    // JSON keeps the exact recorded time.
    let (_, receipt) = case.json(&["receipt", file, "--caller-ref", "ref-1"]);
    assert!(
        receipt["matches"][0]["time"]
            .as_str()
            .expect("time")
            .contains(".123456789"),
        "{receipt}"
    );
    let (_, audit) = case.json(&["audit-receipts", file, s(&archive)]);
    assert!(
        audit["corroborated"]["details"][0]["time"]
            .as_str()
            .is_some_and(|t| t.contains(".123456789")),
        "{audit}"
    );
    for command in [
        vec!["receipt", file, "--caller-ref", "ref-1"],
        vec!["audit-receipts", file, s(&archive)],
        vec!["ledger", file],
    ] {
        let (_, out) = case.text(&command);
        assert!(out.contains("2026-11-20T09:00:00Z"), "{command:?}: {out}");
        assert!(!out.contains(".123456789"), "{command:?}: {out}");
    }
}

#[test]
fn reconcile_differences_use_each_field_s_natural_json_type() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let digest = debit(&case, file, "r", None);
    let manifest = case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "review-example", "units": [{
            "caller_ref": "r",
            "digest": &digest,
            "charges": [{"counter": "bytes", "n": 5}, {"counter": "requests", "n": 1}],
            "targets": [
                {"target": "192.0.2.10:443/tcp", "name": "x.example.com"},
                {"target": "192.0.2.11:443/tcp", "name": "other.example.com"}
            ],
        }]})
        .to_string(),
    );
    let (code, v) = case.json(&["reconcile", file, s(&manifest)]);
    assert_eq!(code, 2, "{v}");
    let diffs = v["rows"][0]["differences"].as_array().expect("differences");
    let find = |field: &str| diffs.iter().find(|d| d["field"] == field).expect(field);
    assert_eq!(find("charge.bytes")["expected"], json!(5));
    assert_eq!(find("charge.bytes")["recorded"], json!(4));
    assert_eq!(find("targets.count")["expected"], json!(2));
    assert_eq!(find("targets.count")["recorded"], json!(1));
    // Text fields stay strings.
    assert_eq!(find("name[1]")["expected"], json!("x.example.com"));
    assert_eq!(find("name[1]")["recorded"], json!("app.example.com"));
}

#[test]
fn a_refused_capacity_does_not_claim_to_have_recorded_nothing() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let (code, v) = case.json(&["capacity", file, "nonesuch"]);
    assert_eq!(code, 2, "{v}");
    let message = v["refusal"]["message"].as_str().expect("message");
    assert!(!message.contains("Nothing was recorded"), "{message}");
    assert!(message.contains("nonesuch"), "{message}");
    let (_, text) = case.text(&["capacity", file, "nonesuch"]);
    assert!(text.starts_with("REFUSED: "), "{text}");
    assert!(!text.contains("Nothing was recorded"), "{text}");
    // `spend` still says it, because it can record.
    let (code, v) = case.json(&["spend", file, "nonesuch"]);
    assert_eq!(code, 2, "{v}");
    assert!(
        v["refusal"]["message"]
            .as_str()
            .expect("message")
            .ends_with("Nothing was recorded")
    );
}

#[test]
fn ledger_text_labels_receipt_and_note_details() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    debit(&case, file, "ref-1", Some("a note"));
    let (code, _) = case.json(&["spend", file, "requests", "--note", "plain note"]);
    assert_eq!(code, 0);
    let (_, out) = case.text(&["ledger", file]);
    let header = out.lines().find(|l| l.contains("digest")).expect("header");
    assert!(header.trim_end().ends_with("details"), "{header}");
    let debit_line = out.lines().find(|l| l.contains("DEBIT")).expect("debit");
    let receipt = debit_line.find("receipt: ref \"ref-1\"").expect(debit_line);
    let note = debit_line.find("note: a note").expect(debit_line);
    assert!(receipt < note, "{debit_line}");
    assert!(debit_line.ends_with("note: a note"), "{debit_line}");
    let plain = out
        .lines()
        .find(|l| l.contains("plain note"))
        .expect("plain");
    assert!(plain.ends_with("note: plain note"), "{plain}");
}
