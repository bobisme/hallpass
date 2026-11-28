//! Doctor, compare-backups and the spend error name the same last resort,
//! the one that loses least (bn-aao7).
//!
//! - A changed ledger verifies as a chain (an older backup put back, with
//!   no newer copy): adopt it in place, which keeps its entries as
//!   receipts.
//! - A damaged ledger does not: move it aside with `mv -n`, then adopt the
//!   pass as ledger-missing; its receipts are not in the new chain.
//! - A rehearsal ledger is moved aside with `mv -n`, and its test-clock
//!   times are not compared with the real clock.
//!
//! Each case follows the named argv arrays mechanically to `healthy`, as
//! `tests/doctor_loop_ends.rs` does, and then checks which receipts the
//! ledger kept.

#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

use hallpass::time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const TO: &str = "192.0.2.10:443/tcp";
const ID: &str = "least-loss";
/// The caller references of the run record: one per spend.
const REFS: [&str; 5] = ["u1", "u2", "u3", "u4", "u5"];

fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("whole second")
        .format(&Rfc3339)
        .expect("RFC 3339")
}

/// A pass open from an hour ago until two days from now, so that both the
/// real clock and a rehearsal clock an hour ahead are inside it.
fn pass_text() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        r#"format = 1
id = "{ID}"
name = "Least-loss fixture"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-27"
operator = "Sam Tester"
valid_from = {}
valid_until = {}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
requests = 10
"#,
        stamp(now - Duration::hours(1)),
        stamp(now + Duration::days(2)),
    )
}

struct Case {
    dir: tempfile::TempDir,
    /// The test clock every command runs under, if any.
    clock: Option<String>,
}

impl Case {
    /// `p.toml` with no ledger yet.
    fn new(clock: Option<String>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let case = Self { dir, clock };
        let pass = case.path("p.toml");
        fs::write(&pass, pass_text()).expect("write pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::File::options()
            .write(true)
            .open(&pass)
            .expect("open")
            .set_modified(SystemTime::now() - std::time::Duration::from_secs(3600))
            .expect("backdate");
        case
    }

    /// `p.toml` after five spends, one per reference in [`REFS`], with a
    /// copy of the ledger taken after the first two (`old.ledger`).
    fn with_backup() -> Self {
        let case = Self::new(None);
        for (i, reference) in REFS.iter().enumerate() {
            if i == 2 {
                fs::copy(case.ledger(), case.path("old.ledger")).expect("backup");
            }
            case.spend(reference);
        }
        case
    }

    fn spend(&self, reference: &str) {
        let (rc, out) = self.json(&[
            "spend",
            "p.toml",
            "requests",
            "--to",
            TO,
            "--caller-ref",
            reference,
        ]);
        assert_eq!(rc, 0, "{out}");
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn ledger(&self) -> PathBuf {
        self.path("p.toml.ledger")
    }

    fn command(&self, program: &str, args: &[String]) -> Command {
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("HALLPASS_FORMAT")
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("state"));
        if let Some(clock) = &self.clock {
            command.env("HALLPASS_UNSAFE_TEST_CLOCK", clock);
        }
        command
    }

    /// Run hallpass with `--format json`: the exit code and the reply.
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--format".to_owned(), "json".to_owned()];
        all.extend(args.iter().map(|a| (*a).to_owned()));
        let out = self.command(BIN, &all).output().expect("run hallpass");
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    /// The caller references of the receipts in the ledger beside the pass.
    fn receipts(&self) -> Vec<String> {
        let (rc, ledger) = self.json(&["ledger", "p.toml"]);
        assert_eq!(rc, 0, "{ledger}");
        ledger["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .filter_map(|e| e["receipt"]["caller_ref"].as_str().map(str::to_owned))
            .collect()
    }

    fn spent(&self) -> Value {
        let (_, status) = self.json(&["status", "p.toml"]);
        status["counters"][0]["spent"].clone()
    }
}

fn words(value: &Value) -> Vec<String> {
    value.as_array().map_or_else(Vec::new, |a| {
        a.iter()
            .map(|w| w.as_str().expect("word").to_owned())
            .collect()
    })
}

/// Whether doctor's reply has a finding with this code.
fn finds(reply: &Value, code: &str) -> bool {
    reply["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|f| f["code"] == code)
}

/// The `last-resort` advice of a reply, if any.
fn last_resort(reply: &Value) -> Option<&Value> {
    reply["advice"]
        .as_array()?
        .iter()
        .find(|a| a["type"] == "last-resort")
}

/// Run one argv that doctor (or the command doctor named) gave, as a
/// caller would: it supplies only a reason, the token a preview prints, and
/// the references of its run record.
fn run(case: &Case, argv: &[String], log: &mut Vec<String>) {
    log.push(argv.join(" "));
    let strs: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    if argv[0] != "hallpass" {
        let status = case
            .command(&argv[0], &argv[1..])
            .status()
            .expect("run command");
        assert!(status.success(), "{argv:?} failed; steps: {log:#?}");
        return;
    }
    if strs.first() == Some(&"reconcile-references") {
        let list = serde_json::json!({"version": 1, "pass_id": ID, "references": REFS});
        fs::write(case.path("REFERENCES.json"), list.to_string()).expect("references");
        let mut call = strs.clone();
        let reason = call.iter().position(|a| *a == "--reason").expect("reason") + 1;
        call[reason] = "every reference of the run record";
        let (rc, out) = case.json(&call);
        assert_eq!(rc, 0, "{out}; steps: {log:#?}");
        return;
    }
    if let Some(at) = strs.iter().position(|w| *w == "--preview") {
        let (rc, preview) = case.json(&strs);
        assert_eq!(rc, 0, "{preview}; steps: {log:#?}");
        let token = preview["token"].as_str().expect("token").to_owned();
        let mut apply = strs.clone();
        apply.remove(at);
        apply.extend(["--token", &token, "--reason", "no backup copy exists"]);
        let (rc, out) = case.json(&apply);
        assert_eq!(rc, 0, "{out}; steps: {log:#?}");
        return;
    }
    let (_, reply) = case.json(&strs);
    if let Some(advice) = last_resort(&reply) {
        run(case, &words(&advice["argv"]), log);
    }
}

/// Follow doctor to `healthy`, and return the steps.
fn follow(case: &Case) -> Vec<String> {
    let mut log = Vec::new();
    for _ in 0..8 {
        let (rc, reply) = case.json(&["doctor", "p.toml"]);
        if reply["result"] == "healthy" {
            assert_eq!(rc, 0, "{reply}");
            return log;
        }
        let next = words(&reply["next"]);
        assert!(!next.is_empty(), "no command: {reply}; steps: {log:#?}");
        run(case, &next, &mut log);
    }
    panic!("doctor never reports healthy; steps: {log:#?}");
}

/// An older backup put back, with no newer copy: the spend error, doctor
/// and compare-backups all name the adoption in place, which keeps the two
/// receipts the copy holds and carries the other three spends.
#[test]
fn an_older_backup_put_back_is_adopted_in_place_and_keeps_its_receipts() {
    let case = Case::with_backup();
    fs::copy(case.path("old.ledger"), case.ledger()).expect("restore older copy");

    let (rc, spend) = case.json(&["spend", "p.toml", "requests", "--to", TO]);
    assert_eq!(rc, 1, "{spend}");
    let message = spend["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("`hallpass adopt p.toml --preview`"),
        "{message}"
    );
    assert!(
        message.contains("The adoption keeps the verified entries of this ledger as receipts."),
        "{message}"
    );
    assert!(!message.contains("mv "), "{message}");

    let (_, doctor) = case.json(&["doctor", "p.toml"]);
    assert_eq!(doctor["problem"], "ledger-changed", "{doctor}");
    assert_eq!(
        words(&doctor["next"]),
        ["hallpass", "compare-backups", "p.toml", "p.toml.ledger"]
    );
    let step = doctor["next_step"].as_str().expect("step");
    assert!(step.contains("`hallpass adopt p.toml --preview`"), "{step}");
    assert!(
        step.contains("The adoption keeps the 2 verified entries of this ledger as receipts."),
        "{step}"
    );
    assert!(!step.contains("mv "), "{step}");

    let (_, compared) = case.json(&["compare-backups", "p.toml", "p.toml.ledger"]);
    let advice = last_resort(&compared).expect("last-resort advice");
    assert_eq!(
        words(&advice["argv"]),
        ["hallpass", "adopt", "p.toml", "--preview"]
    );
    let text = advice["message"].as_str().expect("message");
    assert!(text.contains("keeps the 2 verified entries"), "{text}");

    let steps = follow(&case);
    assert_eq!(
        steps[..2],
        [
            "hallpass compare-backups p.toml p.toml.ledger",
            "hallpass adopt p.toml --preview",
        ],
        "{steps:#?}"
    );
    assert_eq!(
        case.receipts(),
        ["u1", "u2"],
        "the copy's receipts are kept"
    );
    assert_eq!(case.spent(), 5, "the count is never lowered");
    assert!(!case.path("p.toml.ledger.damaged").exists());
}

/// A damaged ledger does not verify, so the last resort moves it aside
/// with `mv -n` and starts a new ledger: none of its receipts are in the
/// new chain, and the moved file is kept.
#[test]
fn a_damaged_ledger_is_moved_aside_with_no_clobber_and_its_receipts_leave_the_chain() {
    let case = Case::with_backup();
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    fs::write(case.ledger(), text.replacen("\"n\":1", "\"n\":0", 1)).expect("damage");

    let (_, doctor) = case.json(&["doctor", "p.toml"]);
    assert_eq!(doctor["problem"], "ledger-corrupt", "{doctor}");
    let step = doctor["next_step"].as_str().expect("step");
    assert!(
        step.contains("`mv -n p.toml.ledger p.toml.ledger.damaged`"),
        "{step}"
    );
    assert!(
        step.contains("The receipts in the moved ledger are not in the new chain."),
        "{step}"
    );
    let (_, compared) = case.json(&["compare-backups", "p.toml", "p.toml.ledger"]);
    let advice = last_resort(&compared).expect("last-resort advice");
    assert_eq!(
        words(&advice["argv"]),
        ["mv", "-n", "p.toml.ledger", "p.toml.ledger.damaged"]
    );

    let steps = follow(&case);
    assert_eq!(
        steps[..3],
        [
            "hallpass compare-backups p.toml p.toml.ledger",
            "mv -n p.toml.ledger p.toml.ledger.damaged",
            "hallpass adopt p.toml --preview",
        ],
        "{steps:#?}"
    );
    assert!(case.receipts().is_empty(), "a new chain holds no receipts");
    assert_eq!(case.spent(), 5, "the count is never lowered");
    assert_eq!(
        fs::read_to_string(case.path("p.toml.ledger.damaged")).expect("kept"),
        text.replacen("\"n\":1", "\"n\":0", 1)
    );
}

/// A changed ledger with the ledger the witness last saw still intact
/// elsewhere: neither doctor nor compare-backups names an adoption.
#[test]
fn a_changed_ledger_with_another_ledger_in_sight_names_no_adoption() {
    let case = Case::with_backup();
    fs::create_dir(case.path("d")).expect("d");
    fs::copy(case.ledger(), case.path("d/p.toml.ledger")).expect("copy ledger");
    fs::copy(case.path("p.toml"), case.path("d/p.toml")).expect("copy pass");
    let (rc, out) = case.json(&["spend", "d/p.toml", "requests", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    fs::copy(case.path("old.ledger"), case.ledger()).expect("restore older copy");

    let (_, doctor) = case.json(&["doctor", "p.toml"]);
    let step = doctor["next_step"].as_str().unwrap_or_default();
    assert!(!step.contains("hallpass adopt"), "{doctor}");
    assert!(
        !words(&doctor["next"]).contains(&"adopt".to_owned()),
        "{doctor}"
    );
    let (_, compared) = case.json(&["compare-backups", "p.toml", "p.toml.ledger"]);
    assert!(last_resort(&compared).is_none(), "{compared}");
}

/// The rehearsal ledger is moved aside with `mv -n`, so the move never
/// overwrites a file at that name (an earlier rehearsal, the proof
/// `--drop-rehearsal` needs); and the rehearsal's test-clock times, an hour ahead,
/// are not reported as a real clock behind the ledger.
#[test]
fn a_rehearsal_ledger_moves_aside_without_overwriting_and_no_clock_warning() {
    let ahead = stamp(OffsetDateTime::now_utc() + Duration::hours(1));
    let rehearsal = Case::new(Some(ahead));
    rehearsal.spend("r1");
    let case = Case {
        dir: rehearsal.dir,
        clock: None,
    };

    let (rc, doctor) = case.json(&["doctor", "p.toml"]);
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "ledger-clock-mix", "{doctor}");
    assert_eq!(
        words(&doctor["next"]),
        ["mv", "-n", "p.toml.ledger", "p.toml.ledger.rehearsal"]
    );
    assert!(!finds(&doctor, "clock-behind-ledger"), "{doctor}");

    let steps = follow(&case);
    assert_eq!(
        steps,
        [
            "mv -n p.toml.ledger p.toml.ledger.rehearsal",
            "hallpass adopt p.toml --preview --drop-rehearsal p.toml.ledger.rehearsal",
        ],
        "{steps:#?}"
    );
    assert!(
        case.receipts().is_empty(),
        "the live ledger carries nothing"
    );
    assert_eq!(case.spent(), 0);
    assert!(case.path("p.toml.ledger.rehearsal").is_file(), "proof kept");
}

/// The warning still holds for the clock a rehearsal runs on: a test clock
/// set behind the rehearsal's own lines is reported.
#[test]
fn a_rehearsal_clock_behind_its_own_lines_is_still_reported() {
    let now = OffsetDateTime::now_utc();
    let rehearsal = Case::new(Some(stamp(now + Duration::hours(1))));
    rehearsal.spend("r1");
    let case = Case {
        dir: rehearsal.dir,
        clock: Some(stamp(now + Duration::minutes(10))),
    };
    let (_, doctor) = case.json(&["doctor", "p.toml"]);
    assert!(finds(&doctor, "clock-behind-ledger"), "{doctor}");
}
