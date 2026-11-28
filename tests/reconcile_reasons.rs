//! Reconcile rows that are `incomplete` say why: the manifest lists targets
//! and the debit recorded none. The reason shows in JSON and in text.
//! Helpers are copied from `tests/evidence_text.rs` on purpose.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const ENDPOINT: &str = "192.0.2.10:443/tcp@app.example.com";

thread_local! {
    static HOME: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        fs::create_dir(&home).expect("home");
        HOME.with(|h| *h.borrow_mut() = Some(home));
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
    /// The approval, with its modified time backdated past the read settle.
    fn pass(&self) -> PathBuf {
        let text = format!(
            "{}\n[ceilings]\nrequests=1000\nbytes=1000\n",
            include_str!("../docs/review-approval.toml")
        );
        let path = self.file("pass", &text);
        let past = SystemTime::now() - Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&path)
            .expect("open")
            .set_modified(past)
            .expect("backdate");
        path
    }
}

fn run(args: &[&str], format: Option<&str>) -> (i32, String) {
    let home = HOME.with(|h| h.borrow().clone()).expect("case");
    let mut command = Command::new(BIN);
    command
        .env_remove("FORMAT")
        .env_remove("HALLPASS_FORMAT")
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW);
    if let Some(format) = format {
        command.args(["--format", format]);
    }
    let out = command.args(args).output().expect("run");
    (
        out.status.code().expect("code"),
        String::from_utf8(out.stdout).expect("utf8"),
    )
}

fn json(args: &[&str]) -> (i32, Value) {
    let (code, out) = run(args, Some("json"));
    (code, serde_json::from_str(out.trim()).expect("json"))
}

fn text(args: &[&str]) -> (i32, String) {
    run(args, None)
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8")
}

/// Spend one debit. `record` adds `--record-target`; the target is always passed.
fn spend(file: &str, reference: &str, record: bool) -> String {
    let mut args = vec![
        "spend",
        file,
        "--charge",
        "requests=1",
        "--charge",
        "bytes=4",
        "--to",
        ENDPOINT,
        "--caller-ref",
        reference,
    ];
    if record {
        args.push("--record-target");
    }
    let (code, out) = run(&args, Some("json"));
    let v: Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(code, 0, "{v}");
    v["digest"].as_str().expect("digest").to_owned()
}

/// A manifest with one unit per `(caller_ref, with_targets)` pair.
fn manifest(case: &Case, digest: &str, units: &[(&str, bool)]) -> PathBuf {
    let units: Vec<Value> = units
        .iter()
        .map(|(reference, with_targets)| {
            let mut unit = json!({
                "caller_ref": reference,
                "digest": digest,
                "charges": [{"counter": "bytes", "n": 4}, {"counter": "requests", "n": 1}],
            });
            if *with_targets {
                unit["targets"] =
                    json!([{"target": "192.0.2.10:443/tcp", "name": "app.example.com"}]);
            }
            unit
        })
        .collect();
    case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "review-example", "units": units}).to_string(),
    )
}

fn row<'a>(v: &'a Value, reference: &str) -> &'a Value {
    v["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|r| r["caller_ref"] == reference)
        .expect(reference)
}

#[test]
fn an_incomplete_row_gives_targets_unrecorded_in_json() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let digest = spend(file, "r", false);
    let path = manifest(&case, &digest, &[("r", true)]);
    let (code, v) = json(&["reconcile", file, s(&path)]);
    assert_eq!(code, 2, "{v}");
    let r = row(&v, "r");
    assert_eq!(r["result"], "incomplete", "{v}");
    assert_eq!(r["reason"], "targets-unrecorded", "{v}");
    assert_eq!(r["differences"], json!([]), "{v}");
    assert_eq!(v["result"], "discrepancy");
}

#[test]
fn an_incomplete_row_says_targets_unrecorded_in_text() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let digest = spend(file, "r", false);
    let path = manifest(&case, &digest, &[("r", true)]);
    let (code, out) = text(&["reconcile", file, s(&path)]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("incomplete"), "{out}");
    assert!(out.contains("reason targets-unrecorded:"), "{out}");
    assert!(out.contains("without --record-target"), "{out}");
}

#[test]
fn only_incomplete_rows_carry_a_reason() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let unrecorded = spend(file, "unrecorded", false);
    let recorded = spend(file, "recorded", true);
    let plain = spend(file, "plain", false);
    assert_eq!(unrecorded, recorded);
    assert_eq!(unrecorded, plain);
    let path = manifest(
        &case,
        &unrecorded,
        &[
            ("unrecorded", true),
            ("recorded", true),
            ("plain", false),
            ("absent", true),
        ],
    );
    let (_, v) = json(&["reconcile", file, s(&path)]);
    assert_eq!(row(&v, "unrecorded")["reason"], "targets-unrecorded");
    assert_eq!(row(&v, "unrecorded")["result"], "incomplete");
    assert!(row(&v, "recorded")["reason"].is_null(), "{v}");
    assert!(row(&v, "plain")["reason"].is_null(), "{v}");
    assert!(row(&v, "absent")["reason"].is_null(), "{v}");
    assert_eq!(row(&v, "absent")["result"], "absent");
}

#[test]
fn a_recorded_match_has_no_reason() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let digest = spend(file, "r", true);
    let path = manifest(&case, &digest, &[("r", true)]);
    let (code, v) = json(&["reconcile", file, s(&path)]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(row(&v, "r")["result"], "match");
    assert!(row(&v, "r")["reason"].is_null(), "{v}");
}

#[test]
fn a_unit_without_targets_is_not_incomplete() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let digest = spend(file, "r", false);
    let path = manifest(&case, &digest, &[("r", false)]);
    let (code, v) = json(&["reconcile", file, s(&path)]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(row(&v, "r")["result"], "match");
    assert!(row(&v, "r")["reason"].is_null(), "{v}");
}

#[test]
fn an_incomplete_candidate_that_is_repeated_stays_ambiguous_without_a_reason() {
    let case = Case::new();
    let p = case.pass();
    let file = s(&p);
    let digest = spend(file, "r", false);
    spend(file, "r", false);
    let path = manifest(&case, &digest, &[("r", true)]);
    let (_, v) = json(&["reconcile", file, s(&path)]);
    assert_eq!(row(&v, "r")["result"], "ambiguous", "{v}");
    assert!(row(&v, "r")["reason"].is_null(), "{v}");
}
