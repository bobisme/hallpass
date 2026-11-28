#![cfg(feature = "cli")]
//! The reference caller always passes `--require-new-ref`, so after an
//! adoption that may have lost lines it can spend again only once the
//! references are reconciled. Its `reconcile-references` builds the list
//! from its journals and records it; then it sends new units, and `handoff`
//! explains the units whose debits were lost.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = include_str!("../docs/review-approval.toml");
const TO: &str = "192.0.2.10:443/tcp@app.example.com";

struct Shift {
    root: tempfile::TempDir,
}

impl Shift {
    fn new() -> Self {
        let shift = Self {
            root: tempfile::tempdir().expect("directory"),
        };
        for dir in ["archive", "home"] {
            fs::create_dir(shift.path(dir)).expect("directory");
            fs::set_permissions(shift.path(dir), fs::Permissions::from_mode(0o700))
                .expect("private directory");
        }
        fs::write(shift.pass(), format!("{PASS}\n[ceilings]\ncalls = 100\n")).expect("pass");
        fs::set_permissions(shift.pass(), fs::Permissions::from_mode(0o600)).expect("private");
        shift
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn pass(&self) -> PathBuf {
        self.path("engagement.pass.toml")
    }

    fn pass_arg(&self) -> String {
        self.pass().display().to_string()
    }

    fn bin_path() -> std::ffi::OsString {
        let bin = Path::new(env!("CARGO_BIN_EXE_hallpass"));
        let mut paths = vec![bin.parent().expect("binary directory").to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        std::env::join_paths(paths).expect("PATH")
    }

    /// Run the reference caller; returns its exit status and standard output.
    fn caller(&self, args: &[&str]) -> (Option<i32>, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let out = Command::new("python3")
            .arg("-I")
            .arg("-B")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(&script)
            .args(args)
            .current_dir(self.root.path())
            .env("PATH", Self::bin_path())
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("TMPDIR", self.path("home"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env_remove("REFERENCE_CALLER_INTERRUPT")
            .output()
            .expect("run the reference caller");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        eprintln!("{args:?}\n{stdout}{}", String::from_utf8_lossy(&out.stderr));
        (out.status.code(), stdout)
    }

    fn unit(&self, journal: &str, reference: &str) -> (Option<i32>, String) {
        let pass = self.pass_arg();
        self.caller(&[
            "run",
            journal,
            &pass,
            reference,
            "--rehearsal",
            "--to",
            TO,
            "--charge",
            "calls=1",
        ])
    }

    fn hallpass(&self, args: &[&str]) -> (Option<i32>, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(["--format", "json"])
            .args(args)
            .current_dir(self.root.path())
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("hallpass");
        (
            out.status.code(),
            serde_json::from_slice(&out.stdout).expect("JSON"),
        )
    }

    fn sent(&self) -> Vec<String> {
        fs::read_to_string(self.path("outbox.jsonl"))
            .expect("outbox")
            .lines()
            .map(|line| {
                let unit: Value = serde_json::from_str(line).expect("JSON line");
                unit["ref"].as_str().expect("ref").to_owned()
            })
            .collect()
    }

    fn journal(&self, name: &str) -> Vec<Value> {
        fs::read_to_string(self.path(name))
            .expect("journal")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON line"))
            .collect()
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_reference_caller_reconciles_its_journals_and_sends_again() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    for journal in ["a.jsonl", "b.jsonl"] {
        assert_eq!(shift.caller(&["pin", journal, &pass, "archive"]).0, Some(0));
    }
    assert_eq!(shift.unit("a.jsonl", "a-1").0, Some(0));
    assert_eq!(shift.unit("b.jsonl", "b-1").0, Some(0));
    assert_eq!(shift.unit("a.jsonl", "a-2").0, Some(0));

    // The ledger is lost, and the loss is adopted.
    fs::rename(
        hallpass::ledger_path(&shift.pass()),
        shift.path("lost.ledger"),
    )
    .expect("lose the ledger");
    let (code, adopted) = shift.hallpass(&["adopt", &pass, "--reason", "ledger lost"]);
    assert_eq!(code, Some(0), "{adopted}");
    assert_eq!(adopted["carried"], json!({"calls": 3}));

    // Every guarded unit is refused until the references are reconciled,
    // and nothing is sent.
    let (code, stdout) = shift.unit("a.jsonl", "a-3");
    assert_eq!(code, Some(2));
    assert!(
        stdout.contains("a-3: refused reference-inconclusive, nothing sent"),
        "{stdout}"
    );
    let (code, stdout) = shift.caller(&["handoff", "a.jsonl", &pass]);
    assert_eq!(code, Some(2), "{stdout}");
    assert!(
        stdout.contains("may be in the lines the adoption at seq 1 lost"),
        "{stdout}"
    );

    // Both journals in one reconciliation: the guard resumes only once the
    // line is recorded, so a reference from a journal left out would be
    // accepted as new.
    let (code, stdout) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--also",
        "b.jsonl",
        "--reason",
        "every reference in the journals of workers a and b",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        stdout.contains("reconciled 4 references for the adoption at seq 1: ledger seq 2"),
        "{stdout}"
    );
    let (_, ledger) = shift.hallpass(&["ledger", &pass]);
    assert!(ledger["unreconciled_adoption"].is_null(), "{ledger}");
    assert_eq!(
        ledger["reference_reconciliations"][0]["references"],
        json!(["a-1", "a-2", "a-3", "b-1"])
    );
    assert_eq!(
        ledger["reference_reconciliations"][0]["reason"],
        "every reference in the journals of workers a and b"
    );
    let record = shift.journal("a.jsonl").pop().expect("a record");
    assert_eq!(record["event"], "reconcile-references", "{record}");
    assert_eq!(record["adoption"], 1);
    assert_eq!(record["seq"], 2);
    assert_eq!(record["references"], 4);

    // A new unit is sent; a reconciled reference is a duplicate.
    let (code, stdout) = shift.unit("a.jsonl", "a-4");
    assert_eq!(code, Some(0), "{stdout}");
    assert_eq!(shift.sent(), ["a-1", "b-1", "a-2", "a-4"]);
    let (code, refused) = shift.hallpass(&[
        "spend",
        &pass,
        "calls",
        "--to",
        TO,
        "--caller-ref",
        "b-1",
        "--require-new-ref",
    ]);
    assert_eq!(code, Some(2), "{refused}");
    assert_eq!(refused["refusal"]["code"], "duplicate-reference");
    assert_eq!(refused["reference_evidence"]["reconciled_at"], json!([2]));

    // handoff explains the units whose debits were lost.
    let (code, stdout) = shift.caller(&["handoff", "a.jsonl", &pass]);
    assert_eq!(code, Some(0), "{stdout}");
    for row in [
        "a-1  sent",
        "a-2  sent",
        "a-3  refused reference-inconclusive",
    ] {
        let line = stdout
            .lines()
            .find(|line| line.starts_with(row))
            .unwrap_or_else(|| panic!("{row}: {stdout}"));
        assert!(line.contains("reconciled seq 2"), "{line}");
        assert!(line.contains("ok: "), "{line}");
    }
    assert!(stdout.contains("Nothing needs attention."), "{stdout}");
    assert_eq!(ledger["reference_reconciliations"][0]["time"], NOW);

    // With nothing left to reconcile, it records nothing.
    let before = fs::read(hallpass::ledger_path(&shift.pass())).expect("ledger");
    let (code, stdout) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--reason",
        "again",
    ]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("nothing to do"), "{stdout}");
    assert_eq!(
        fs::read(hallpass::ledger_path(&shift.pass())).expect("ledger"),
        before
    );
}
