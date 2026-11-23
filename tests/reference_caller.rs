#![cfg(feature = "cli")]
//! Drives the reference caller, `docs/reference-caller/caller.py`, against
//! the built binary: a completed unit, a refusal, a duplicate reference and
//! interruptions between the debit and a recorded completion. Each case
//! counts the callback's lines in the outbox and reads the caller's journal.
//!
//! The caller runs with `--rehearsal` at a pinned `HALLPASS_UNSAFE_TEST_CLOCK`
//! (debug builds, or `--features test-clock`) and a private `HOME` and
//! `XDG_STATE_HOME`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const WALKTHROUGH: &str = include_str!("../docs/WALKTHROUGH.md");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASSFILE: &str = "engagement.pass.toml";
const TO: &str = "192.0.2.10:443/tcp@app.example.org";
const PASS: &str = r#"format = 1
id = "web-2026-11"
name = "Web edge"
require_target_v1 = true
required_counters_v1 = ["requests", "bytes"]

[approval]
owner = "Pat Owner"
reference = "email of 2026-11-19"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[[destination]]
label = "web6"
address = "2001:db8::10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[ceilings]
requests = 5
bytes = 100
"#;

/// A private directory holding the pass, its archive, journals and outbox.
struct Shift {
    dir: tempfile::TempDir,
}

/// One run of the caller: its exit code (`None` if a signal ended it) and stdout.
struct Run {
    code: Option<i32>,
    stdout: String,
}

impl Shift {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for (path, mode) in [("home", 0o700), ("approval-archive", 0o700)] {
            fs::create_dir(root.join(path)).expect("directory");
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(mode)).expect("mode");
        }
        fs::write(root.join(PASSFILE), PASS).expect("pass");
        fs::set_permissions(root.join(PASSFILE), fs::Permissions::from_mode(0o600)).expect("mode");
        Self { dir }
    }

    fn caller(&self, args: &[&str], interrupt: Option<&str>) -> Run {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let bin_dir = Path::new(BIN).parent().expect("binary directory");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![bin_dir.to_path_buf()];
        paths.extend(std::env::split_paths(&path));
        let home = self.dir.path().join("home");
        let mut command = Command::new("python3");
        command
            .arg("-I")
            .arg(script)
            .args(args)
            .current_dir(self.dir.path())
            .env("PATH", std::env::join_paths(paths).expect("PATH"))
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("REFERENCE_CALLER_INTERRUPT");
        if let Some(point) = interrupt {
            command.env("REFERENCE_CALLER_INTERRUPT", point);
        }
        let output = command.output().expect("run the reference caller");
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        eprintln!(
            "{args:?}\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Run {
            code: output.status.code(),
            stdout,
        }
    }

    fn pin(&self, journal: &str) {
        let run = self.caller(&["pin", journal, PASSFILE, "approval-archive"], None);
        assert_eq!(run.code, Some(0));
        assert!(run.stdout.starts_with("pinned web-2026-11 sha256:"));
    }

    /// One unit of one request and `bytes` bytes, journaled in `journal`.
    fn unit(&self, journal: &str, reference: &str, bytes: u32, interrupt: Option<&str>) -> Run {
        let bytes = format!("bytes={bytes}");
        let args = [
            "run",
            journal,
            PASSFILE,
            reference,
            "--rehearsal",
            "--to",
            TO,
            "--charge",
            "requests=1",
            "--charge",
            &bytes,
        ];
        self.caller(&args, interrupt)
    }

    fn handoff(&self, journal: &str) -> Run {
        self.caller(&["handoff", journal, PASSFILE], None)
    }

    fn lines(&self, name: &str) -> Vec<Value> {
        fs::read_to_string(self.dir.path().join(name))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
            .collect()
    }

    /// How often the callback ran: one outbox line per call.
    fn sent(&self) -> Vec<String> {
        self.lines("outbox.jsonl")
            .iter()
            .map(|line| line["ref"].as_str().expect("ref").to_owned())
            .collect()
    }

    /// The journal's events for one reference, with the spend outcome.
    fn events(&self, journal: &str, reference: &str) -> Vec<String> {
        self.lines(journal)
            .iter()
            .filter(|record| record["ref"] == reference)
            .map(|record| {
                let event = record["event"].as_str().expect("event");
                record["outcome"]
                    .as_str()
                    .map_or_else(|| event.to_owned(), |outcome| format!("{event} {outcome}"))
            })
            .collect()
    }

    fn record(&self, journal: &str, reference: &str, event: &str) -> Value {
        self.lines(journal)
            .into_iter()
            .find(|record| record["ref"] == reference && record["event"] == event)
            .unwrap_or_else(|| panic!("no {event} record for {reference}"))
    }

    /// The ledger's debits as (sequence, caller reference).
    fn debits(&self) -> Vec<(u64, String)> {
        let home = self.dir.path().join("home");
        let output = Command::new(BIN)
            .args(["--format", "json", "ledger", PASSFILE])
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("ledger");
        let ledger: Value = serde_json::from_slice(&output.stdout).expect("ledger JSON");
        assert_eq!(ledger["verified"], true, "{ledger}");
        ledger["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| {
                let reference = entry["receipt"]["caller_ref"].as_str().unwrap_or_default();
                (entry["seq"].as_u64().expect("seq"), reference.to_owned())
            })
            .collect()
    }
}

/// The handoff line for `reference`.
fn line<'a>(handoff: &'a Run, reference: &str) -> &'a str {
    handoff
        .stdout
        .lines()
        .find(|line| line.starts_with(&format!("{reference} ")))
        .unwrap_or_else(|| panic!("no handoff line for {reference}: {}", handoff.stdout))
}

#[test]
fn a_unit_is_sent_only_after_a_verified_debit() {
    let shift = Shift::new();
    shift.pin("shift.jsonl");
    let run = shift.unit("shift.jsonl", "unit-1", 24, None);
    assert_eq!(run.code, Some(0));
    assert_eq!(
        run.stdout,
        "unit-1: debit seq 1 verified, unit sent, completion recorded\n"
    );
    assert_eq!(shift.sent(), ["unit-1"]);
    assert_eq!(
        shift.events("shift.jsonl", "unit-1"),
        ["intent", "spend debited", "callback-start", "callback-done"]
    );
    let pin = shift.lines("shift.jsonl")[0].clone();
    let intent = shift.record("shift.jsonl", "unit-1", "intent");
    assert_eq!(intent["digest"], pin["digest"]);
    assert_eq!(
        intent["targets"],
        json!([{"target": "192.0.2.10:443/tcp", "name": "app.example.org"}])
    );
    assert_eq!(
        intent["charges"],
        json!([{"counter": "requests", "n": 1}, {"counter": "bytes", "n": 24}])
    );
    assert_eq!(shift.record("shift.jsonl", "unit-1", "spend")["seq"], 1);
    assert_eq!(shift.debits(), [(1, "unit-1".to_owned())]);

    let handoff = shift.handoff("shift.jsonl");
    assert_eq!(handoff.code, Some(0));
    assert!(line(&handoff, "unit-1").ends_with("sent  debit seq 1  ok: debited and sent"));
    assert!(
        handoff
            .stdout
            .contains("Spent: bytes 24 of 100, requests 1 of 5.")
    );
    assert!(handoff.stdout.ends_with("Nothing needs attention.\n"));
}

#[test]
fn a_target_is_canonicalized_by_hallpass_before_anything_is_journaled() {
    let shift = Shift::new();
    shift.pin("shift.jsonl");
    let run = shift.caller(
        &[
            "run",
            "shift.jsonl",
            PASSFILE,
            "unit-1",
            "--rehearsal",
            "--to",
            "[2001:DB8:0:0:0:0:0:10]:443/tcp@APP.Example.ORG.",
            "--charge",
            "requests=1",
            "--charge",
            "bytes=24",
        ],
        None,
    );
    assert_eq!(run.code, Some(0));
    assert_eq!(
        run.stdout,
        "unit-1: debit seq 1 verified, unit sent, completion recorded\n"
    );
    assert_eq!(shift.sent(), ["unit-1"]);
    let canonical = json!([{"target": "[2001:db8::10]:443/tcp", "name": "app.example.org"}]);
    assert_eq!(
        shift.record("shift.jsonl", "unit-1", "intent")["targets"],
        canonical
    );
    assert_eq!(shift.lines("outbox.jsonl")[0]["targets"], canonical);
    assert_eq!(shift.debits(), [(1, "unit-1".to_owned())]);
    let handoff = shift.handoff("shift.jsonl");
    assert_eq!(handoff.code, Some(0));
    assert!(line(&handoff, "unit-1").ends_with("sent  debit seq 1  ok: debited and sent"));
    assert!(handoff.stdout.ends_with("Nothing needs attention.\n"));
}

#[test]
fn input_hallpass_would_not_take_is_stopped_before_an_intent_exists() {
    let shift = Shift::new();
    shift.pin("shift.jsonl");
    let run = shift.caller(
        &[
            "run",
            "shift.jsonl",
            PASSFILE,
            "unit-1",
            "--rehearsal",
            "--to",
            "[2001:db8::10]:443/tcp@a b",
            "--charge",
            "requests=1",
            "--charge",
            "bytes=24",
        ],
        None,
    );
    assert_eq!(run.code, Some(1));
    assert_eq!(shift.events("shift.jsonl", "unit-1"), Vec::<String>::new());
    assert_eq!(shift.sent(), Vec::<String>::new());
    assert_eq!(shift.debits(), []);
}

#[test]
fn a_refused_unit_sends_nothing() {
    let shift = Shift::new();
    shift.pin("shift.jsonl");
    let run = shift.unit("shift.jsonl", "too-large", 101, None);
    assert_eq!(run.code, Some(2));
    assert_eq!(
        run.stdout,
        "too-large: refused ceiling-reached, nothing sent\n"
    );
    assert_eq!(
        shift.events("shift.jsonl", "too-large"),
        ["intent", "spend refused"]
    );
    assert_eq!(
        shift.record("shift.jsonl", "too-large", "spend")["code"],
        "ceiling-reached"
    );

    // Without --rehearsal the caller removes the pinned clock, as a live
    // caller must, so the real clock finds the 2026-11-20 window closed.
    let live = shift.caller(
        &[
            "run",
            "shift.jsonl",
            PASSFILE,
            "live",
            "--to",
            TO,
            "--charge",
            "requests=1",
            "--charge",
            "bytes=1",
        ],
        None,
    );
    assert_eq!(live.code, Some(2));
    assert_eq!(
        shift.record("shift.jsonl", "live", "spend")["code"],
        "expired"
    );
    assert_eq!(shift.sent(), Vec::<String>::new());
    assert_eq!(shift.debits(), Vec::new());

    let handoff = shift.handoff("shift.jsonl");
    assert_eq!(handoff.code, Some(0));
    assert!(line(&handoff, "too-large").contains("refused ceiling-reached  no debit"));
    assert!(line(&handoff, "live").ends_with("ok: refused, nothing debited or sent"));
}

#[test]
fn a_duplicate_reference_is_refused_and_sends_nothing() {
    let shift = Shift::new();
    shift.pin("a.jsonl");
    assert_eq!(shift.unit("a.jsonl", "batch-42", 24, None).code, Some(0));

    // The same journal never submits a reference twice.
    let journal = fs::read(shift.dir.path().join("a.jsonl")).expect("journal");
    assert_eq!(shift.unit("a.jsonl", "batch-42", 24, None).code, Some(1));
    assert_eq!(
        fs::read(shift.dir.path().join("a.jsonl")).expect("journal"),
        journal
    );

    // A second worker with its own journal is stopped by the ledger.
    shift.pin("b.jsonl");
    let run = shift.unit("b.jsonl", "batch-42", 24, None);
    assert_eq!(run.code, Some(2));
    assert_eq!(
        run.stdout,
        "batch-42: refused duplicate-reference, nothing sent\n"
    );
    assert_eq!(
        shift.events("b.jsonl", "batch-42"),
        ["intent", "spend refused"]
    );
    assert_eq!(shift.sent(), ["batch-42"]);
    assert_eq!(shift.debits(), [(1, "batch-42".to_owned())]);

    assert_eq!(shift.handoff("a.jsonl").code, Some(0));
    let handoff = shift.handoff("b.jsonl");
    assert_eq!(handoff.code, Some(2));
    assert!(
        line(&handoff, "batch-42").ends_with(
            "debit seq 1  ATTENTION: another run debited this reference; find its record"
        )
    );
}

#[test]
fn an_interrupted_unit_is_reconciled_by_reference_and_never_repeated() {
    let shift = Shift::new();
    shift.pin("shift.jsonl");
    // The caller dies with the spend reply unread: only the intent is journaled.
    let lost = shift.unit("shift.jsonl", "lost-reply", 24, Some("after-spend"));
    assert_eq!(lost.code, Some(3));
    assert_eq!(shift.events("shift.jsonl", "lost-reply"), ["intent"]);
    // The caller dies after the callback, before recording its completion.
    let ran = shift.unit("shift.jsonl", "no-completion", 24, Some("after-callback"));
    assert_eq!(ran.code, Some(3));
    assert_eq!(
        shift.events("shift.jsonl", "no-completion"),
        ["intent", "spend debited", "callback-start"]
    );
    assert_eq!(shift.sent(), ["no-completion"]);
    assert_eq!(
        shift.debits(),
        [
            (1, "lost-reply".to_owned()),
            (2, "no-completion".to_owned())
        ]
    );

    // A crash can also cut the journal's last line short.
    let mut journal = fs::read(shift.dir.path().join("shift.jsonl")).expect("journal");
    journal.extend_from_slice(br#"{"ref": "no-completion", "event": "callb"#);
    fs::write(shift.dir.path().join("shift.jsonl"), journal).expect("torn journal");

    for _ in 0..2 {
        let handoff = shift.handoff("shift.jsonl");
        assert_eq!(handoff.code, Some(2));
        assert!(line(&handoff, "lost-reply").ends_with(
            "unknown      debit seq 1  ATTENTION: debited, never sent; the debit stands"
        ));
        assert!(line(&handoff, "no-completion").ends_with(
            "unconfirmed  debit seq 2  ATTENTION: completion not recorded; check the target, do not repeat"
        ));
        assert!(handoff.stdout.ends_with("2 need attention.\n"));
    }
    for reference in ["lost-reply", "no-completion"] {
        assert_eq!(shift.unit("shift.jsonl", reference, 24, None).code, Some(1));
    }
    assert_eq!(shift.sent(), ["no-completion"]);
    assert_eq!(shift.debits().len(), 2);

    // A debit made outside the caller has no execution evidence in the journal.
    let home = shift.dir.path().join("home");
    let by_hand = Command::new(BIN)
        .args(["--format", "json", "spend", "--charge", "requests=1"])
        .args(["--charge", "bytes=1", "--to", TO, "--caller-ref", "by-hand"])
        .args(["--", PASSFILE])
        .current_dir(shift.dir.path())
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .output()
        .expect("spend by hand");
    assert_eq!(by_hand.status.code(), Some(0));
    let handoff = shift.handoff("shift.jsonl");
    assert!(line(&handoff, "by-hand").ends_with(
        "no record    debit seq 3  ATTENTION: no journal record; find the run record of this debit"
    ));
    assert!(handoff.stdout.ends_with("3 need attention.\n"));

    // docs/WALKTHROUGH.md shows exactly these lines.
    let shown = WALKTHROUGH
        .split("### Missing execution evidence")
        .nth(1)
        .and_then(|section| section.split("```text\n").nth(1))
        .and_then(|block| block.split("```").next())
        .expect("the walkthrough's missing-evidence block");
    let printed: Vec<&str> = handoff.stdout.lines().collect();
    assert_eq!(shown.lines().count(), 3);
    for line in shown.lines() {
        assert!(printed.contains(&line), "{line:?} not in {printed:#?}");
    }
}
