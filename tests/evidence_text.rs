//! Readable text for the advanced evidence commands, and reconcile differences.
//! Helpers are copied from `tests/cli.rs` on purpose.

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const ENDPOINT: &str = "192.0.2.10:443/tcp@app.example.com";

type Edit = Box<dyn Fn(&mut Value)>;

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
    fn witness(&self) -> PathBuf {
        self.path("home/state/hallpass/review-example.witness")
    }
}

fn approval() -> String {
    format!(
        "{}\n[ceilings]\nrequests=1000\nbytes=1000\n",
        include_str!("../docs/review-approval.toml")
    )
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
    let (code, out) = run(args, None);
    assert!(!out.contains("{\""), "raw JSON in text: {out}");
    (code, out)
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8")
}

fn debit(file: &str, reference: &str) -> Value {
    let (code, v) = json(&[
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
    ]);
    assert_eq!(code, 0, "{v}");
    v
}

fn manifest_with(case: &Case, digest: &str, edit: impl Fn(&mut Value)) -> PathBuf {
    let mut unit = json!({
        "caller_ref": "r",
        "digest": digest,
        "charges": [{"counter": "bytes", "n": 4}, {"counter": "requests", "n": 1}],
        "targets": [{"target": "192.0.2.10:443/tcp", "name": "app.example.com"}],
    });
    edit(&mut unit);
    case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "review-example", "units": [unit]}).to_string(),
    )
}

#[test]
fn reconcile_names_exactly_the_field_that_differs() {
    let case = Case::new();
    let p = case.file("pass", &approval());
    let file = s(&p);
    let digest = debit(file, "r")["digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    let other_digest = format!("{}0", &digest[..digest.len() - 1]);
    assert_ne!(other_digest, digest);

    let matching = manifest_with(&case, &digest, |_| {});
    let (code, v) = json(&["reconcile", file, s(&matching)]);
    assert_eq!((code, v["rows"][0]["differences"].clone()), (0, json!([])));

    let cases: Vec<(&str, &str, Edit, Value, Value)> = vec![
        (
            "digest",
            "digest",
            Box::new(move |u| u["digest"] = json!(other_digest)),
            json!(other_digest_value(&digest)),
            json!(digest.clone()),
        ),
        (
            "charge amount",
            "charge.bytes",
            Box::new(|u| u["charges"][0]["n"] = json!(5)),
            json!(5),
            json!(4),
        ),
        (
            "extra charge",
            "charge.extra",
            Box::new(|u| {
                u["charges"]
                    .as_array_mut()
                    .expect("a")
                    .push(json!({"counter": "extra", "n": 2}));
            }),
            json!(2),
            Value::Null,
        ),
        (
            "target",
            "target[1]",
            Box::new(|u| u["targets"][0]["target"] = json!("192.0.2.10:444/tcp")),
            json!("192.0.2.10:444/tcp"),
            json!("192.0.2.10:443/tcp"),
        ),
        (
            "name",
            "name[1]",
            Box::new(|u| u["targets"][0]["name"] = json!("other.example.com")),
            json!("other.example.com"),
            json!("app.example.com"),
        ),
    ];
    for (label, field, edit, expected, recorded) in cases {
        let path = manifest_with(&case, &digest, edit);
        let (code, v) = json(&["reconcile", file, s(&path)]);
        assert_eq!(code, 2, "{label}: {v}");
        let row = &v["rows"][0];
        assert_eq!(row["result"], "mismatch", "{label}");
        let diffs = row["differences"].as_array().expect("differences");
        assert_eq!(diffs.len(), 1, "{label}: {diffs:?}");
        assert_eq!(diffs[0]["field"], field, "{label}");
        assert_eq!(diffs[0]["sequence"], 1, "{label}");
        assert_eq!(diffs[0]["expected"], expected, "{label}");
        assert_eq!(diffs[0]["recorded"], recorded, "{label}");
        let (_, out) = text(&["reconcile", file, s(&path)]);
        assert_eq!(out.matches("differs").count(), 1, "{label}: {out}");
        assert!(
            out.contains(&format!("sequence 1: {field} differs")),
            "{label}: {out}"
        );
    }
}

fn other_digest_value(digest: &str) -> String {
    format!("{}0", &digest[..digest.len() - 1])
}

#[test]
fn reconcile_with_several_candidates_says_which_candidate_differs() {
    let case = Case::new();
    let p = case.file("pass", &approval());
    let file = s(&p);
    let digest = debit(file, "r")["digest"]
        .as_str()
        .expect("digest")
        .to_owned();
    debit(file, "r");
    let path = manifest_with(&case, &digest, |u| u["charges"][0]["n"] = json!(9));
    let (_, v) = json(&["reconcile", file, s(&path)]);
    let row = &v["rows"][0];
    assert_eq!(row["result"], "ambiguous");
    let diffs = row["differences"].as_array().expect("differences");
    assert_eq!(diffs.len(), 2);
    assert_eq!(diffs[0]["sequence"], 1);
    assert_eq!(diffs[1]["sequence"], 2);
    let (_, out) = text(&["reconcile", file, s(&path)]);
    assert!(out.contains("2 candidates"), "{out}");
    assert!(
        out.contains("sequence 2: charge.bytes differs: expected 9, recorded 4"),
        "{out}"
    );
}

#[test]
fn other_advanced_commands_print_readable_text() {
    let case = Case::new();
    let archive = case.path("archive");
    fs::create_dir(&archive).expect("archive");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("chmod");
    let p = case.file("pass", &approval());
    let file = s(&p);
    let (code, archived) = json(&["archive", file, s(&archive)]);
    assert_eq!(code, 0);
    // As `verify-approval --archive` records it; the audits do not verify it again.
    hallpass::archive_verified_signature(
        &archive,
        archived["digest"]
            .as_str()
            .and_then(|d| d.parse().ok())
            .expect("digest"),
        b"signature",
        "owner@example.org",
        hallpass::Digest::of(b"trusted signers"),
    )
    .expect("signature record");
    debit(file, "anchor");
    let anchor_witness = fs::read(case.witness()).expect("witness");
    debit(file, "tip");
    let ledger = hallpass::ledger_path(&p);
    let extension = case.file("extension", &fs::read_to_string(&ledger).expect("ledger"));

    let (_, out) = text(&["ledger", file]);
    assert!(out.contains("DEBIT"), "{out}");
    assert!(out.contains("ref \"tip\""), "{out}");
    assert!(out.contains("label \"web\""), "{out}");

    let (code, out) = text(&["audit-receipts", file, s(&archive)]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("#1 target 1"), "{out}");
    assert!(out.contains("recorded label web confirmed"), "{out}");

    let (code, out) = text(&["audit-charges", file, s(&archive)]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Mismatches 0"), "{out}");
    assert!(out.contains("Gaps none"), "{out}");

    fs::write(case.witness(), &anchor_witness).expect("captured witness");
    fs::remove_file(&ledger).expect("lost");
    let (code, out) = text(&["compare-backups", file, "--ancestry", s(&extension)]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Captured witness: sequence 1 hash "), "{out}");
    assert!(out.contains("extended"), "{out}");
    assert!(out.contains("No tip group is a prefix of another"), "{out}");
    assert!(out.contains("prefixes of the witness"), "{out}");
    assert!(out.contains("Maximal groups"), "{out}");
    let (_, out) = text(&["compare-backups", file, s(&extension)]);
    assert!(!out.contains("Ancestry"), "{out}");
}
