#![cfg(feature = "cli")]
//! The reference caller's `reconcile-references` splits a list above hallpass's
//! limit into parts, and refuses to record when the journals show fewer debits
//! than the adoption carried. The minimal caller names the unset clock variable.

use std::{
    fs,
    io::Write,
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

    fn caller(&self, args: &[&str]) -> (Option<i32>, String, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let bin = Path::new(env!("CARGO_BIN_EXE_hallpass"));
        let mut paths = vec![bin.parent().expect("binary directory").to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let out = Command::new("python3")
            .arg("-I")
            .arg("-B")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(&script)
            .args(args)
            .current_dir(self.root.path())
            .env("PATH", std::env::join_paths(paths).expect("PATH"))
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("TMPDIR", self.path("home"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_FORMAT")
            .env_remove("REFERENCE_CALLER_INTERRUPT")
            .output()
            .expect("run the reference caller");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        eprintln!("{args:?}\n{stdout}{stderr}");
        (out.status.code(), stdout, stderr)
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

    /// Pin journal `a.jsonl`, spend `a-1` (and `b-1` in `b.jsonl`), lose the
    /// ledger and adopt it.
    fn lossy_adoption(&self, with_b: bool) {
        let pass = self.pass_arg();
        let mut units = vec![("a.jsonl", "a-1")];
        if with_b {
            units.push(("b.jsonl", "b-1"));
        }
        for (journal, reference) in units {
            assert_eq!(self.caller(&["pin", journal, &pass, "archive"]).0, Some(0));
            let (code, _, _) = self.caller(&[
                "run",
                journal,
                &pass,
                reference,
                "--rehearsal",
                "--to",
                TO,
                "--charge",
                "calls=1",
            ]);
            assert_eq!(code, Some(0));
        }
        fs::rename(
            hallpass::ledger_path(&self.pass()),
            self.path("lost.ledger"),
        )
        .expect("lose the ledger");
        let (_, preview) = self.hallpass(&["adopt", &pass, "--preview"]);
        let token = preview["token"].as_str().expect("token").to_owned();
        let (code, adopted) =
            self.hallpass(&["adopt", &pass, "--reason", "ledger lost", "--token", &token]);
        assert_eq!(code, Some(0), "{adopted}");
    }
}

#[test]
fn a_missing_journal_is_named_and_nothing_is_recorded_without_the_flag() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    shift.lossy_adoption(true);
    let before = fs::read(hallpass::ledger_path(&shift.pass())).expect("ledger");

    let (code, stdout, stderr) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--reason",
        "journal a only",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(stderr.contains("short by calls 1"), "{stderr}");
    assert!(stderr.contains("--also"), "{stderr}");
    assert!(stderr.contains("nothing was recorded"), "{stderr}");
    assert_eq!(
        fs::read(hallpass::ledger_path(&shift.pass())).expect("ledger"),
        before
    );

    let (code, stdout, stderr) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--reason",
        "journal a only, b is gone",
        "--accept-shortfall",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stderr.contains("short by calls 1"), "{stderr}");
    assert!(stdout.contains("reconciled 1 references"), "{stdout}");

    // With every journal named there is no warning (a fresh run).
    let other = Shift::new();
    let pass = other.pass_arg();
    other.lossy_adoption(true);
    let (code, stdout, stderr) = other.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--also",
        "b.jsonl",
        "--reason",
        "a and b",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(!stderr.contains("short by"), "{stderr}");
}

#[test]
fn a_list_above_the_limit_is_recorded_in_parts_in_order() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    shift.lossy_adoption(false);
    let mut journal = fs::OpenOptions::new()
        .append(true)
        .open(shift.path("a.jsonl"))
        .expect("journal");
    for number in 1..=10_001 {
        let record =
            json!({"ref": format!("u-{number}"), "event": "intent", "pass_id": "review-example"});
        writeln!(journal, "{record}").expect("write");
    }
    drop(journal);
    let (code, stdout, stderr) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--reason",
        "every reference in the journal",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(stdout.contains("part 1 of 2: 10000 references"), "{stdout}");
    assert!(stdout.contains("part 2 of 2: 2 references"), "{stdout}");
    assert!(stdout.contains("reconciled 10002 references"), "{stdout}");
    let (_, ledger) = shift.hallpass(&["ledger", &pass]);
    let parts = ledger["reference_reconciliations"]
        .as_array()
        .expect("list");
    assert_eq!(parts.len(), 2, "{ledger}");
    assert_eq!(
        parts[0]["references"].as_array().expect("refs").len(),
        10_000
    );
    assert_eq!(parts[0]["references"][0], "a-1");
    assert_eq!(parts[1]["references"], json!(["u-10000", "u-10001"]));
    assert!(ledger["unreconciled_adoption"].is_null());
}

#[test]
fn hallpass_says_how_to_split_a_long_list() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    shift.lossy_adoption(false);
    let (_, ledger) = shift.hallpass(&["ledger", &pass]);
    let refs: Vec<String> = (1..=10_001).map(|n| format!("u-{n}")).collect();
    let list = json!({"version": 1, "pass_id": ledger["pass_id"], "references": refs});
    fs::write(shift.path("all.json"), list.to_string()).expect("list");
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["reconcile-references", &pass, "--adoption", "1"])
        .args(["--references", "all.json", "--reason", "all"])
        .current_dir(shift.root.path())
        .env("XDG_STATE_HOME", shift.path("home/state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .output()
        .expect("hallpass");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Split it into parts of at most 10000"),
        "{stderr}"
    );
    assert!(stderr.contains("before any spend"), "{stderr}");
}

#[test]
fn the_minimal_caller_names_the_unset_clock_variable() {
    let dir = tempfile::tempdir().expect("directory");
    let home = dir.path().join("home");
    fs::create_dir(&home).expect("home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("private");
    fs::write(
        dir.path().join("p.toml"),
        PASS.replace("2026-11-20T08:00:00Z", "2026-01-01T00:00:00Z")
            .replace("2026-11-20T17:00:00Z", "2099-01-01T00:00:00Z")
            + "\n[ceilings]\ncalls = 5\n",
    )
    .expect("pass");
    fs::set_permissions(dir.path().join("p.toml"), fs::Permissions::from_mode(0o600))
        .expect("private");
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/minimal-caller/minimal_caller.py");
    let bin = Path::new(env!("CARGO_BIN_EXE_hallpass"));
    let mut paths = vec![bin.parent().expect("binary directory").to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let out = Command::new("python3")
        .arg("-I")
        .arg("-B")
        .arg(script)
        .args(["--rehearsal", "p.toml", TO, "u1", "calls"])
        .current_dir(dir.path())
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
        .env_remove("HALLPASS_FORMAT")
        .env_remove("HALLPASS_REVIEWED_DIGEST")
        .output()
        .expect("run the minimal caller");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("set HALLPASS_UNSAFE_TEST_CLOCK in the environment"),
        "{stderr}"
    );
}
