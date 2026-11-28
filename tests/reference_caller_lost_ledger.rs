#![cfg(feature = "cli")]
//! The reference caller after a lossy adoption, and with one reference run
//! at the same time by several processes.
//!
//! - `handoff` must not say "not debited" while an adoption waits for a
//!   reference reconciliation: the unit may be in the lines it lost.
//! - `reconcile-references` counts a unit with an unknown outcome as possibly
//!   debited, so an ordinary crash does not need `--accept-shortfall`.
//! - Check-and-append of the intent is atomic, so one reference gets one
//!   intent record; `handoff` flags repeated intents and uses the debiting one.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde_json::Value;

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

    fn command(&self, args: &[&str], interrupt: Option<&str>) -> Command {
        let bin = Path::new(env!("CARGO_BIN_EXE_hallpass"));
        let mut paths = vec![bin.parent().expect("binary directory").to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let mut command = Command::new("python3");
        command
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
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env_remove("REFERENCE_CALLER_INTERRUPT");
        if let Some(point) = interrupt {
            command.env("REFERENCE_CALLER_INTERRUPT", point);
        }
        command
    }

    /// Run the reference caller; returns its exit status and standard output.
    fn caller(&self, args: &[&str]) -> (Option<i32>, String) {
        let out = self.command(args, None).output().expect("run the caller");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        eprintln!("{args:?}\n{stdout}{}", String::from_utf8_lossy(&out.stderr));
        (out.status.code(), stdout)
    }

    fn unit_args<'a>(journal: &'a str, pass: &'a str, reference: &'a str) -> Vec<&'a str> {
        vec![
            "run",
            journal,
            pass,
            reference,
            "--rehearsal",
            "--to",
            TO,
            "--charge",
            "calls=1",
        ]
    }

    fn unit(&self, journal: &str, reference: &str) -> (Option<i32>, String) {
        let pass = self.pass_arg();
        self.caller(&Self::unit_args(journal, &pass, reference))
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

    fn lose_and_adopt(&self) {
        fs::rename(
            hallpass::ledger_path(&self.pass()),
            self.path("lost.ledger"),
        )
        .expect("lose the ledger");
        let (code, adopted) =
            self.hallpass(&["adopt", &self.pass_arg(), "--reason", "ledger lost"]);
        assert_eq!(code, Some(0), "{adopted}");
    }
}

fn row<'a>(stdout: &'a str, reference: &str) -> &'a str {
    stdout
        .lines()
        .find(|line| line.starts_with(reference))
        .unwrap_or_else(|| panic!("{reference}: {stdout}"))
}

#[test]
fn handoff_and_the_shortfall_check_after_a_crash_and_a_lost_ledger() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    for journal in ["a.jsonl", "b.jsonl"] {
        assert_eq!(shift.caller(&["pin", journal, &pass, "archive"]).0, Some(0));
    }
    assert_eq!(shift.unit("a.jsonl", "a-1").0, Some(0));
    assert_eq!(shift.unit("b.jsonl", "b-1").0, Some(0));
    // a-2 crashes after its spend: debited, but the journal has only the intent.
    let crashed = shift
        .command(
            &Shift::unit_args("a.jsonl", &pass, "a-2"),
            Some("after-spend"),
        )
        .output()
        .expect("crashing run");
    assert_eq!(crashed.status.code(), Some(3));
    shift.lose_and_adopt();

    // Before the reconciliation, handoff must not say "not debited".
    let (code, stdout) = shift.caller(&["handoff", "a.jsonl", &pass]);
    assert_eq!(code, Some(2), "{stdout}");
    let line = row(&stdout, "a-2");
    assert!(!line.contains("not debited"), "{line}");
    assert!(
        line.contains("may be in the lines the adoption at seq 1 lost")
            && line.contains("caller.py reconcile-references"),
        "{line}"
    );
    assert!(
        stdout.contains("Pending: the adoption at seq 1 may have lost ledger lines"),
        "{stdout}"
    );

    // The journal of b is missing: a real shortfall (1 of 3 units unaccounted for).
    let (code, stdout) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--reason",
        "journal a only",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(1), "{stdout}");
    assert!(
        stdout.contains("1 units with unknown outcome counted as possibly debited"),
        "{stdout}"
    );
    let (_, ledger) = shift.hallpass(&["ledger", &pass]);
    assert!(!ledger["unreconciled_adoption"].is_null(), "{ledger}");

    // With both journals the unknown unit is counted: no --accept-shortfall.
    let (code, stdout) = shift.caller(&[
        "reconcile-references",
        "a.jsonl",
        &pass,
        "--also",
        "b.jsonl",
        "--reason",
        "journals a and b",
        "--rehearsal",
    ]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        stdout.contains("1 units with unknown outcome counted as possibly debited"),
        "{stdout}"
    );
    let (code, stdout) = shift.caller(&["handoff", "a.jsonl", &pass]);
    assert_eq!(code, Some(2), "{stdout}");
    let line = row(&stdout, "a-2");
    assert!(
        line.contains("maybe debited in lines an adoption lost"),
        "{line}"
    );
    assert!(!stdout.contains("Pending:"), "{stdout}");
}

#[test]
fn concurrent_runs_of_one_reference_write_one_intent_and_send_once() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    assert_eq!(
        shift.caller(&["pin", "j.jsonl", &pass, "archive"]).0,
        Some(0)
    );
    #[allow(clippy::needless_collect)] // all eight must start before any is waited for
    let children: Vec<_> = (0..8)
        .map(|_| {
            shift
                .command(&Shift::unit_args("j.jsonl", &pass, "same-1"), None)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn")
        })
        .collect();
    let codes: Vec<_> = children
        .into_iter()
        .map(|mut child| child.wait().expect("wait").code())
        .collect();
    assert_eq!(
        codes.iter().filter(|c| **c == Some(0)).count(),
        1,
        "{codes:?}"
    );

    let journal = fs::read_to_string(shift.path("j.jsonl")).expect("journal");
    let events: Vec<Value> = journal
        .lines()
        .map(|l| serde_json::from_str(l).expect("JSON line"))
        .filter(|r: &Value| r["ref"] == "same-1")
        .collect();
    let intents = events.iter().filter(|r| r["event"] == "intent").count();
    assert_eq!(intents, 1, "{events:?}");
    assert_eq!(events.iter().filter(|r| r["event"] == "spend").count(), 1);
    let outbox = fs::read_to_string(shift.path("outbox.jsonl")).expect("outbox");
    assert_eq!(outbox.lines().count(), 1, "{outbox}");
    let (code, stdout) = shift.caller(&["handoff", "j.jsonl", &pass]);
    assert_eq!(code, Some(0), "{stdout}");
    assert!(
        row(&stdout, "same-1").contains("ok: debited and sent"),
        "{stdout}"
    );
}

#[test]
fn handoff_flags_repeated_intents_and_judges_by_the_debiting_record() {
    let shift = Shift::new();
    let pass = shift.pass_arg();
    assert_eq!(
        shift.caller(&["pin", "j.jsonl", &pass, "archive"]).0,
        Some(0)
    );
    assert_eq!(shift.unit("j.jsonl", "same-1").0, Some(0));
    // A journal from an older caller: a racing run wrote its intent and a refusal first.
    let journal = fs::read_to_string(shift.path("j.jsonl")).expect("journal");
    let lines: Vec<&str> = journal.lines().collect();
    let intent = lines
        .iter()
        .find(|l| l.contains("\"intent\""))
        .expect("intent");
    let refused = r#"{"at": "2026-11-20T09:00:00Z", "ref": "same-1", "event": "spend", "outcome": "refused", "code": "duplicate-reference"}"#;
    let mut rewritten = vec![lines[0], intent, refused];
    rewritten.extend(&lines[1..]);
    fs::write(shift.path("j.jsonl"), rewritten.join("\n") + "\n").expect("journal");

    let (code, stdout) = shift.caller(&["handoff", "j.jsonl", &pass]);
    assert_eq!(code, Some(2), "{stdout}");
    let line = row(&stdout, "same-1");
    assert!(
        line.contains("2 intent records for this reference"),
        "{line}"
    );
    assert!(line.contains("sent"), "{line}");
    assert!(!line.contains("refused duplicate-reference"), "{line}");
}
