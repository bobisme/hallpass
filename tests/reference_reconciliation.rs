#![cfg(feature = "cli")]
//! The reference reconciliation (bn-11i): after an adoption that may have
//! lost lines, the operator records which caller references may be in them,
//! and guarded spends (`--require-new-ref`) resume. A listed reference is
//! refused as a duplicate, any other is checked against the ledger, and a
//! later adoption that may lose lines makes references inconclusive again
//! until it is reconciled too. The new line shows in every reader, and a
//! hallpass from before it fails closed on it.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output},
};

use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = include_str!("../docs/review-approval.toml");
const SPEC: &str = include_str!("../docs/spec.md");
const TO: &str = "192.0.2.10:443/tcp@app.example.com";

/// A pass with its ledger in a temporary directory and its own state
/// directory.
struct Engagement {
    dir: tempfile::TempDir,
}

impl Engagement {
    fn new() -> Self {
        let e = Self {
            dir: tempfile::tempdir().expect("directory"),
        };
        fs::write(e.pass(), format!("{PASS}\n[ceilings]\ncalls = 100\n")).expect("pass");
        fs::set_permissions(e.pass(), fs::Permissions::from_mode(0o600)).expect("private pass");
        e
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn pass(&self) -> PathBuf {
        self.path("engagement.pass.toml")
    }

    fn ledger(&self) -> PathBuf {
        hallpass::ledger_path(&self.pass())
    }

    fn witness(&self) -> PathBuf {
        hallpass::StateDir::new(self.path("state").join("hallpass"))
            .witness_path("review-example")
            .expect("witness path")
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.ledger()).expect("ledger")
    }

    /// `hallpass --format json COMMAND PASS ARGS...`.
    fn command(&self, name: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.args(["--format", "json", name])
            .arg(self.pass())
            .args(args)
            .current_dir(self.dir.path())
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.path("state"))
            .env_remove("HALLPASS_FORMAT");
        cmd
    }

    fn json(&self, name: &str, args: &[&str], code: i32) -> Value {
        reply(&self.command(name, args).output().expect("hallpass"), code)
    }

    fn text(&self, name: &str, args: &[&str]) -> String {
        let out = self
            .command(name, args)
            .args(["--format", "text"])
            .output()
            .expect("hallpass");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn guarded(&self, reference: &str, flags: &[&str]) -> Command {
        let mut args = vec![
            "calls",
            "--to",
            TO,
            "--caller-ref",
            reference,
            "--require-new-ref",
        ];
        args.extend(flags);
        self.command("spend", &args)
    }

    fn recorded(&self, reference: &str, seq: u64) {
        let value = reply(&self.guarded(reference, &[]).output().expect("spend"), 0);
        assert_eq!(value["result"], "allowed", "{value}");
        assert_eq!(value["seq"], seq, "{value}");
    }

    fn adopt(&self) -> Value {
        self.json("adopt", &["--reason", "ledger lost"], 0)
    }

    /// Write the reference list `name` for this pass.
    fn list(&self, name: &str, references: &[&str]) -> String {
        let text = json!({"version": 1, "pass_id": "review-example", "references": references});
        fs::write(self.path(name), text.to_string()).expect("list");
        name.to_owned()
    }

    fn reconcile(&self, adoption: u64, references: &[&str]) -> Value {
        let list = self.list("list.json", references);
        self.json(
            "reconcile-references",
            &[
                "--adoption",
                &adoption.to_string(),
                "--references",
                &list,
                "--reason",
                "every reference in the run journals",
            ],
            0,
        )
    }

    /// Lose the ledger and adopt the loss: a new ledger whose first line is
    /// an adoption that carries the witnessed totals.
    fn lose_and_adopt(&self) {
        fs::rename(self.ledger(), self.path("lost.ledger")).expect("lose the ledger");
        let adopted = self.adopt();
        assert_eq!(adopted["case"], "ledger-missing", "{adopted}");
        assert_eq!(adopted["seq"], 1, "{adopted}");
    }
}

fn reply(out: &Output, code: i32) -> Value {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("JSON")
}

/// Refused as a duplicate; returns the refusal message.
fn duplicate(e: &Engagement, reference: &str, sequences: &[u64], reconciled: &[u64]) -> String {
    let value = reply(&e.guarded(reference, &[]).output().expect("spend"), 2);
    assert_eq!(value["refusal"]["code"], "duplicate-reference", "{value}");
    assert!(value["seq"].is_null());
    let mut evidence = json!({
        "caller_ref": reference,
        "match_count": sequences.len(),
        "sequences": sequences,
        "truncated": false,
    });
    if !reconciled.is_empty() {
        evidence["reconciled_at"] = json!(reconciled);
    }
    assert_eq!(value["reference_evidence"], evidence, "{value}");
    value["refusal"]["message"]
        .as_str()
        .expect("message")
        .to_owned()
}

/// Refused as inconclusive, for a spend and for its dry run, recording
/// nothing; returns the refusal message.
fn inconclusive(e: &Engagement, reference: &str) -> String {
    let before = e.bytes();
    let mut message = String::new();
    for flags in [&["--dry-run"][..], &[]] {
        let value = reply(&e.guarded(reference, flags).output().expect("spend"), 2);
        assert_eq!(
            value["refusal"]["code"], "reference-inconclusive",
            "{value}"
        );
        assert_eq!(
            value["reference_evidence"],
            json!({"caller_ref": reference, "match_count": 0, "sequences": [], "truncated": false})
        );
        message = value["refusal"]["message"]
            .as_str()
            .expect("message")
            .to_owned();
    }
    assert_eq!(e.bytes(), before, "a refusal records nothing");
    message
}

fn last_line(e: &Engagement) -> String {
    let text = String::from_utf8(e.bytes()).expect("UTF-8");
    text.lines().last().expect("a line").to_owned()
}

#[test]
fn guarded_spends_resume_after_the_lost_references_are_reconciled() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.recorded("unit-2", 2);
    e.lose_and_adopt();

    // Before the reconciliation every guarded spend is inconclusive, and the
    // message names the step that ends it.
    for reference in ["unit-1", "unit-3"] {
        let message = inconclusive(&e, reference);
        for part in [
            "the adoption at ledger sequence 1",
            "no reference reconciliation follows that adoption",
            "run record",
            &format!(
                "`hallpass reconcile-references {} --adoption 1 --references LIST --reason",
                e.pass().display()
            ),
            "without --require-new-ref",
        ] {
            assert!(message.contains(part), "{part}: {message}");
        }
    }
    let ledger = e.json("ledger", &[], 0);
    assert_eq!(ledger["unreconciled_adoption"], 1, "{ledger}");
    assert_eq!(ledger["adoptions"][0]["may_have_lost_references"], true);
    assert_eq!(ledger["reference_reconciliations"], json!([]));

    let reconciled = e.reconcile(1, &["unit-1", "unit-2"]);
    assert_eq!(reconciled["command"], "reconcile-references");
    assert_eq!(reconciled["result"], "ok");
    assert_eq!(reconciled["seq"], 2);
    assert_eq!(reconciled["adoption"], 1);
    assert_eq!(reconciled["references"], json!(["unit-1", "unit-2"]));
    assert_eq!(reconciled["reason"], "every reference in the run journals");
    assert_eq!(reconciled["test_clock"], true);
    assert_eq!(reconciled["warnings"], json!([]));
    assert_eq!(
        last_line(&e),
        format!(
            r#"{{"seq":2,"time":"{NOW}","event":"reconcile-references","adoption":1,"reason":"every reference in the run journals","digest":"{}","references":["unit-1","unit-2"],"prev":"{}"}}"#,
            hallpass::load(&e.pass()).expect("pass").digest,
            hallpass::Digest::of(
                String::from_utf8(e.bytes())
                    .expect("UTF-8")
                    .lines()
                    .nth(1)
                    .expect("adoption")
                    .as_bytes()
            )
        )
    );

    // A new reference is accepted; a reconciled one is a duplicate, and the
    // message says where it is listed.
    let preview = reply(
        &e.guarded("unit-3", &["--dry-run"])
            .output()
            .expect("preview"),
        0,
    );
    assert_eq!(preview["result"], "would-allow");
    e.recorded("unit-3", 3);
    for reference in ["unit-1", "unit-2"] {
        let message = duplicate(&e, reference, &[], &[2]);
        assert!(
            message.contains("listed in the reference reconciliation at ledger sequence 2"),
            "{message}"
        );
        assert!(
            message.contains("lost before the adoption at ledger sequence 1"),
            "{message}"
        );
    }
    duplicate(&e, "unit-3", &[3], &[]);

    let ledger = e.json("ledger", &[], 0);
    assert!(ledger["unreconciled_adoption"].is_null(), "{ledger}");
    assert_eq!(
        ledger["reference_reconciliations"],
        json!([{
            "seq": 2,
            "time": NOW,
            "adoption": 1,
            "reason": "every reference in the run journals",
            "digest": reconciled["digest"],
            "references": ["unit-1", "unit-2"],
        }])
    );
}

/// A later adoption that may lose lines makes new references inconclusive
/// again until it is reconciled too. A reconciliation made for one adoption
/// cannot be recorded against a later one.
#[test]
fn a_later_lossy_adoption_needs_its_own_reconciliation() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.lose_and_adopt();
    e.reconcile(1, &["unit-1"]);
    let backup = e.path("backup.ledger");
    fs::copy(e.ledger(), &backup).expect("back up");
    e.recorded("unit-2", 3);

    // The backup is put back: the witnessed line with unit-2 is gone.
    fs::copy(&backup, e.ledger()).expect("restore the backup");
    let adopted = e.adopt();
    assert_eq!(adopted["case"], "ledger-changed", "{adopted}");
    assert_eq!(adopted["seq"], 3);
    let warning = adopted["warnings"][0].as_str().expect("warning");
    assert!(
        warning.contains("hallpass reconcile-references"),
        "{warning}"
    );

    // The earlier reconciliation still lists unit-1. Everything else is
    // inconclusive again, unit-2 included, whose debit was lost.
    duplicate(&e, "unit-1", &[], &[2]);
    for reference in ["unit-2", "unit-4"] {
        let message = inconclusive(&e, reference);
        assert!(
            message.contains("the adoption at ledger sequence 3"),
            "{message}"
        );
        assert!(message.contains("--adoption 3"), "{message}");
    }
    assert_eq!(e.json("ledger", &[], 0)["unreconciled_adoption"], 3);

    // A list made for the first adoption is not recorded for the second.
    let before = e.bytes();
    let list = e.list("old.json", &["unit-1"]);
    let refused = e.json(
        "reconcile-references",
        &["--adoption", "1", "--references", &list, "--reason", "x"],
        1,
    );
    assert_eq!(refused["error"]["code"], "usage", "{refused}");
    assert_eq!(refused["error"]["recording"], "not-recorded");
    let message = refused["error"]["message"].as_str().expect("message");
    assert!(
        message.contains(
            "the latest adoption that may have lost lines is at ledger sequence 3, not 1"
        ),
        "{message}"
    );
    assert!(message.contains("--adoption 3"), "{message}");
    assert_eq!(e.bytes(), before);

    assert_eq!(e.reconcile(3, &["unit-2"])["seq"], 4);
    e.recorded("unit-4", 5);
    duplicate(&e, "unit-1", &[], &[2]);
    duplicate(&e, "unit-2", &[], &[4]);
    duplicate(&e, "unit-4", &[5], &[]);
    let ledger = e.json("ledger", &[], 0);
    assert!(ledger["unreconciled_adoption"].is_null(), "{ledger}");
    let seqs: Vec<&Value> = ledger["reference_reconciliations"]
        .as_array()
        .expect("reconciliations")
        .iter()
        .map(|r| &r["adoption"])
        .collect();
    assert_eq!(seqs, [&json!(1), &json!(3)]);

    // A second reconciliation of the same adoption adds its references.
    assert_eq!(e.reconcile(3, &["unit-9"])["seq"], 6);
    duplicate(&e, "unit-9", &[], &[6]);
    duplicate(&e, "unit-2", &[], &[4]);
}

#[test]
fn an_empty_list_states_that_no_reference_was_lost() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.lose_and_adopt();
    let reconciled = e.reconcile(1, &[]);
    assert_eq!(reconciled["references"], json!([]));
    e.recorded("unit-2", 3);
    // unit-1 was lost and not listed: the operator said no reference was.
    e.recorded("unit-1", 4);
    let text = e.text("ledger", &[]);
    assert!(
        text.contains("REFERENCES RECONCILED for the adoption at 1: 0 reference(s)  reason: every reference in the run journals"),
        "{text}"
    );
}

/// Each refusal records nothing and leaves the ledger as it was.
#[test]
#[allow(clippy::too_many_lines)]
fn a_reconciliation_that_cannot_be_recorded_records_nothing() {
    let e = Engagement::new();
    let list = e.list("list.json", &["unit-1"]);
    let attempt = |e: &Engagement, adoption: &str, list: &str, reason: &str| {
        e.json(
            "reconcile-references",
            &[
                "--adoption",
                adoption,
                "--references",
                list,
                "--reason",
                reason,
            ],
            1,
        )
    };
    let usage = |reply: &Value, part: &str| {
        assert_eq!(reply["error"]["code"], "usage", "{reply}");
        assert_eq!(reply["error"]["recording"], "not-recorded", "{reply}");
        let message = reply["error"]["message"].as_str().expect("message");
        assert!(message.contains(part), "{part}: {message}");
        assert!(message.contains("othing was recorded"), "{message}");
    };

    // No ledger yet: nothing to reconcile, and no ledger is created.
    usage(&attempt(&e, "1", &list, "x"), "there is no ledger");
    assert!(!e.ledger().exists());

    // A ledger whose adoption kept every line.
    e.recorded("unit-1", 1);
    fs::remove_file(e.witness()).expect("a new state directory");
    let kept = e.adopt();
    assert_eq!(kept["case"], "no-witness");
    let before = e.bytes();
    usage(
        &attempt(&e, "2", &list, "x"),
        "no adoption in this ledger may have lost lines",
    );
    assert_eq!(e.bytes(), before);

    // A lost ledger is adopted first.
    fs::rename(e.ledger(), e.path("lost.ledger")).expect("lose the ledger");
    let missing = attempt(&e, "1", &list, "x");
    assert_eq!(missing["error"]["code"], "ledger-missing", "{missing}");
    assert!(!e.ledger().exists());
    e.adopt();
    let before = e.bytes();

    for (name, text, part) in [
        (
            "other-pass.json",
            r#"{"version": 1, "pass_id": "other", "references": []}"#,
            "is for pass \"other\", but this pass is \"review-example\"",
        ),
        (
            "version.json",
            r#"{"version": 2, "pass_id": "review-example", "references": []}"#,
            "has version 2; it must be 1",
        ),
        (
            "twice.json",
            r#"{"version": 1, "pass_id": "review-example", "references": ["a", "b", "a"]}"#,
            "reference 3 (\"a\") is listed twice",
        ),
        (
            "blank.json",
            r#"{"version": 1, "pass_id": "review-example", "references": ["a", " "]}"#,
            "reference 2 (\" \") is not a caller reference",
        ),
        (
            "control.json",
            r#"{"version": 1, "pass_id": "review-example", "references": ["a\u0007"]}"#,
            "reference 1 (\"a\\u{0007}\") is not a caller reference",
        ),
        (
            "extra.json",
            r#"{"version": 1, "pass_id": "review-example", "references": [], "units": []}"#,
            "is not a list of the form",
        ),
        (
            "not-json.json",
            "unit-1\nunit-2\n",
            "is not a list of the form",
        ),
    ] {
        fs::write(e.path(name), text).expect("list");
        usage(&attempt(&e, "1", name, "x"), part);
        assert_eq!(e.bytes(), before, "{name}");
    }
    let long = "r".repeat(129);
    let list_long = e.list("long.json", &[&long]);
    usage(&attempt(&e, "1", &list_long, "x"), "at most 128 characters");
    usage(&attempt(&e, "1", &list, " "), "the reason is empty");
    usage(&attempt(&e, "1", &list, "a\nb"), "reason");
    usage(
        &attempt(&e, "7", &list, "x"),
        "is at ledger sequence 1, not 7",
    );
    let gone = attempt(&e, "1", "no-such-list.json", "x");
    assert_eq!(gone["error"]["code"], "io", "{gone}");
    assert_eq!(e.bytes(), before);

    // Without a witness hallpass cannot tell whether the ledger is
    // complete: adopt it as it stands first.
    fs::remove_file(e.witness()).expect("a new state directory");
    let message = attempt(&e, "1", &list, "x");
    usage(&message, "there is no witness for pass `review-example`");
    assert!(
        message["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("run `hallpass adopt")),
        "{message}"
    );
    assert_eq!(e.bytes(), before);
    assert!(!e.witness().exists());
    assert_eq!(e.adopt()["case"], "no-witness");
    assert_eq!(e.reconcile(1, &["unit-1"])["seq"], 3);
    duplicate(&e, "unit-1", &[], &[3]);
    e.recorded("unit-2", 4);
}

#[test]
fn the_reconciliation_shows_in_the_ledger_receipt_and_reconcile() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.lose_and_adopt();
    let mut references: Vec<String> = (1..=12).map(|n| format!("unit-{n}")).collect();
    references[11] = "quote\"d".to_owned();
    let listed: Vec<&str> = references.iter().map(String::as_str).collect();
    e.reconcile(1, &listed);
    e.recorded("unit-13", 3);

    let text = e.text("ledger", &[]);
    assert!(
        text.contains(
            "      2  2026-11-20T09:00:00Z  REFERENCES RECONCILED for the adoption at 1: 12 reference(s)  references: \"unit-1\", \"unit-2\", \"unit-3\", \"unit-4\", \"unit-5\", \"unit-6\", \"unit-7\", \"unit-8\", \"unit-9\", \"unit-10\", and 2 more (see --format json)  reason: every reference in the run journals\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("Ledger: 3 line(s) after the header, chain verified, the witness matches"),
        "{text}"
    );
    assert!(!text.contains("References:"), "{text}");

    // A slice counts the reconciliation as an entry; --counter keeps it.
    let sliced = e.json("ledger", &["--since", "2", "--tail", "1"], 0);
    assert_eq!(sliced["shown"], json!({"from": 3, "to": 3, "of": 3}));
    assert_eq!(sliced["reference_reconciliations"], json!([]));
    let sliced = e.json("ledger", &["--since", "2", "--tail", "2"], 0);
    assert_eq!(sliced["reference_reconciliations"][0]["seq"], 2);
    let counter = e.json("ledger", &["--counter", "calls"], 0);
    assert_eq!(counter["reference_reconciliations"][0]["seq"], 2);
    assert_eq!(
        counter["reference_reconciliations"][0]["references"][11],
        "quote\"d"
    );
    let status = e.text("status", &[]);
    assert!(status.contains("3 line(s) after the header"), "{status}");

    // receipt: a listed reference with no debit is absent, and says where
    // it is listed.
    let receipt = e.json("receipt", &["--caller-ref", "unit-1"], 2);
    assert_eq!(receipt["result"], "absent");
    assert_eq!(receipt["reconciled_at"], json!([2]));
    assert!(
        receipt["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w
                .contains("listed in the reference reconciliation at ledger sequence 2")
                && w.contains("adoption at sequence 1"))),
        "{receipt}"
    );
    let shown = e.text("receipt", &["--caller-ref", "unit-1"]);
    assert!(
        shown.contains("Listed in the reference reconciliation(s) at sequence 2."),
        "{shown}"
    );
    let found = e.json("receipt", &["--caller-ref", "unit-13"], 0);
    assert_eq!(found["reconciled_at"], json!([]));

    // reconcile: the row of a listed reference says where it is listed.
    let digest = hallpass::load(&e.pass()).expect("pass").digest.to_string();
    let manifest = json!({"version": 1, "pass_id": "review-example", "units": [
        {"caller_ref": "unit-1", "digest": digest, "charges": [{"counter": "calls", "n": 1}]},
        {"caller_ref": "unit-13", "digest": digest, "charges": [{"counter": "calls", "n": 1}]},
    ]});
    fs::write(e.path("manifest.json"), manifest.to_string()).expect("manifest");
    let reconciled = e.json("reconcile", &["manifest.json"], 2);
    assert_eq!(reconciled["rows"][0]["result"], "absent");
    assert_eq!(reconciled["rows"][0]["reconciled_at"], json!([2]));
    assert_eq!(reconciled["rows"][1]["result"], "match");
    assert_eq!(reconciled["rows"][1]["reconciled_at"], json!([]));
    assert!(
        reconciled["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w
                .starts_with("1 row(s) name a reference that a reference reconciliation lists"))),
        "{reconciled}"
    );
    let shown = e.text("reconcile", &["manifest.json"]);
    assert!(
        shown.contains("listed in the reference reconciliation(s) at sequence 2"),
        "{shown}"
    );
}

/// Every reader of the ledger accepts the line, and none counts it as a
/// spend.
#[test]
fn every_reader_reads_a_ledger_with_a_reconciliation() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.lose_and_adopt();
    e.reconcile(1, &["unit-1"]);
    let mut spend = e.command(
        "spend",
        &[
            "calls",
            "--to",
            TO,
            "--caller-ref",
            "unit-2",
            "--record-target",
        ],
    );
    assert_eq!(reply(&spend.output().expect("spend"), 0)["seq"], 3);
    let archive = e.path("archive");
    fs::create_dir(&archive).expect("archive");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
    let archive = archive.display().to_string();
    e.json("archive", &[&archive], 0);

    let status = e.json("status", &[], 0);
    assert_eq!(status["counters"][0]["spent"], 2, "{status}");
    let ledger = e.json("ledger", &[], 0);
    assert_eq!(ledger["totals"][0]["spent"], 2);
    let checkpoint = e.json("checkpoint", &[], 0);
    assert_eq!(checkpoint["checkpoint"]["seq"], 3);
    fs::write(
        e.path("checkpoint.json"),
        checkpoint["checkpoint"].to_string(),
    )
    .expect("checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(["--format", "json", "verify-checkpoint"])
        .arg(e.ledger())
        .arg(e.path("checkpoint.json"))
        .output()
        .expect("verify-checkpoint");
    assert_eq!(reply(&out, 0)["relation"], "exact");
    let backups = e.json("compare-backups", &[&e.ledger().display().to_string()], 0);
    assert_eq!(backups["candidates"][0]["tip"]["seq"], 3, "{backups}");
    let audit = e.json("audit-receipts", &[&archive], 2);
    assert_eq!(audit["result"], "incomplete", "{audit}");
    assert_eq!(audit["corroborated"]["count"], 1);
    assert_eq!(audit["gaps"]["adoption-carry"]["sequences"], json!([1]));
    let charges = e.json("audit-charges", &[&archive], 2);
    assert_eq!(charges["checked_debits"], 1, "{charges}");
    assert_eq!(charges["mismatches"]["count"], 0);
    let capacity = e.json("capacity", &["calls"], 0);
    assert_eq!(capacity["units"], 98, "{capacity}");
}

/// The hand-written lines a hallpass never writes are damage: the scan
/// fails closed at that line.
#[test]
fn a_reconciliation_line_hallpass_would_not_write_is_damage() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    let digest = hallpass::load(&e.pass()).expect("pass").digest;
    let good = e.bytes();
    let prev = hallpass::Digest::of(last_line(&e).as_bytes());
    let line = |body: &str| {
        format!(
            r#"{{"seq":2,"time":"{NOW}","event":"reconcile-references",{body},"digest":"{digest}","references":["unit-1"],"prev":"{prev}"}}"#
        )
    };
    for bad in [
        // No adoption before it may have lost lines.
        line(r#""adoption":1,"reason":"x""#),
        line(r#""adoption":0,"reason":"x""#),
    ] {
        fs::write(e.ledger(), &good).expect("reset");
        let mut ledger = fs::OpenOptions::new()
            .append(true)
            .open(e.ledger())
            .expect("ledger");
        writeln!(ledger, "{bad}").expect("append");
        let out = e.json("ledger", &[], 1);
        assert_eq!(out["error"]["code"], "ledger-corrupt", "{out}");
        assert_eq!(out["error"]["line"], 3, "{out}");
        assert!(
            out["error"]["message"].as_str().is_some_and(|m| m.contains(
                "the reference reconciliation does not name the latest adoption before it that may have lost lines"
            )),
            "{out}"
        );
    }

    // A complete line of an event this hallpass does not know: perhaps a
    // newer hallpass wrote it, and the message says so.
    fs::write(e.ledger(), &good).expect("reset");
    let mut ledger = fs::OpenOptions::new()
        .append(true)
        .open(e.ledger())
        .expect("ledger");
    writeln!(
        ledger,
        r#"{{"seq":2,"time":"{NOW}","event":"future-kind","digest":"{digest}","prev":"{prev}"}}"#
    )
    .expect("append");
    drop(ledger);
    let out = e.json("ledger", &[], 1);
    assert_eq!(out["error"]["code"], "ledger-corrupt", "{out}");
    assert!(
        out["error"]["message"].as_str().is_some_and(|m| m.contains(
            "the line is a complete record of an event this hallpass does not know (\"future-kind\"), perhaps written by a newer hallpass"
        )),
        "{out}"
    );

    // After a real lossy adoption and reconciliation, each variation of the
    // line is refused.
    fs::write(e.ledger(), &good).expect("reset");
    e.lose_and_adopt();
    e.reconcile(1, &["unit-1", "unit-2"]);
    let text = String::from_utf8(e.bytes()).expect("UTF-8");
    let written = text.lines().last().expect("line").to_owned();
    let head: String = text.lines().take(2).flat_map(|l| [l, "\n"]).collect();
    for (from, to) in [
        (r#""adoption":1"#, r#""adoption":2"#),
        (
            r#""references":["unit-1","unit-2"]"#,
            r#""references":["unit-1","unit-1"]"#,
        ),
        (
            r#""references":["unit-1","unit-2"]"#,
            r#""references":[""]"#,
        ),
        (
            r#""event":"reconcile-references""#,
            r#""event":"reconcile""#,
        ),
        (r#""reason":"every"#, r#""reason":"","x":"every"#),
        (r#""prev""#, r#""extra":true,"prev""#),
        (r#""reason":"every reference in the run journals","#, ""),
    ] {
        assert!(written.contains(from), "{from}");
        fs::write(
            e.ledger(),
            format!("{head}{}\n", written.replacen(from, to, 1)),
        )
        .expect("edit");
        let out = e.json("ledger", &[], 1);
        assert_eq!(out["error"]["code"], "ledger-corrupt", "{to}: {out}");
        assert_eq!(out["error"]["line"], 3, "{to}: {out}");
    }
}

// The line shapes of every hallpass before the reference reconciliation, as
// they were declared: each refuses unknown fields. `Line::decode` (and the
// untagged enum before it) tried only these.

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct OldSpend {
    seq: u64,
    time: String,
    counter: String,
    n: u64,
    digest: String,
    note: Option<String>,
    prev: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct OldDebit {
    seq: u64,
    time: String,
    event: String,
    version: u32,
    charges: Vec<serde_json::Map<String, Value>>,
    digest: String,
    note: Option<String>,
    receipt: Option<Value>,
    prev: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct OldAdopt {
    seq: u64,
    time: String,
    event: String,
    reason: String,
    digest: String,
    carried: std::collections::BTreeMap<String, u64>,
    witness: Option<Value>,
    prev: String,
}

/// A hallpass from before the reconciliation decodes none of its shapes
/// from the line, so it reports the ledger damaged at that line and spends
/// nothing more: it fails closed, never skipping or misreading the line.
#[test]
fn an_older_hallpass_decodes_no_shape_from_a_reconciliation_line() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.lose_and_adopt();
    for references in [&[][..], &["unit-1"]] {
        e.reconcile(1, references);
        let line = last_line(&e);
        assert!(serde_json::from_str::<OldSpend>(&line).is_err(), "{line}");
        assert!(serde_json::from_str::<OldDebit>(&line).is_err(), "{line}");
        assert!(serde_json::from_str::<OldAdopt>(&line).is_err(), "{line}");
    }
    // The old shapes still decode the lines around it, so the test would
    // notice a shape that no longer matches what hallpass writes.
    let text = String::from_utf8(e.bytes()).expect("UTF-8");
    let adoption = text.lines().nth(1).expect("adoption");
    assert!(
        serde_json::from_str::<OldAdopt>(adoption).is_ok(),
        "{adoption}"
    );
    e.recorded("unit-2", 4);
    let debit = last_line(&e);
    assert!(serde_json::from_str::<OldDebit>(&debit).is_ok(), "{debit}");
}

// The "JSON fields" section of docs/spec.md documents the new keys: the same
// rule as tests/doc_lists.rs, for the replies this change adds to.

/// The lines after the heading line `heading`, up to the next heading of
/// the same or a higher level.
fn section(heading: &str) -> String {
    let level = heading.chars().take_while(|c| *c == '#').count();
    let mut lines = SPEC.lines();
    assert!(lines.by_ref().any(|line| line == heading), "{heading}");
    let mut out = String::new();
    for line in lines {
        let depth = line.chars().take_while(|c| *c == '#').count();
        if depth > 0 && depth <= level && line[depth..].starts_with(' ') {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Every word inside the inline code spans of `text`.
fn code_words(text: &str) -> std::collections::BTreeSet<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .flat_map(|span| span.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')))
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The list item of "JSON fields" that names `command` in bold.
fn bullet(fields: &str, command: &str) -> String {
    let mark = format!("**{command}**");
    let mut items: Vec<String> = Vec::new();
    for line in fields.lines() {
        if line.starts_with("- ") {
            items.push(String::new());
        } else if line.is_empty() || !line.starts_with("  ") {
            items.push(String::new());
            continue;
        }
        if let Some(item) = items.last_mut() {
            item.push_str(line);
            item.push('\n');
        }
    }
    items
        .into_iter()
        .find(|item| item.contains(&mark))
        .unwrap_or_else(|| panic!("no JSON fields entry for {command}"))
}

/// Every key below the top level, except the counter names that key the
/// objects of amounts (`carried`, `totals`).
fn nested_keys(value: &Value, out: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                out.insert(key.clone());
                if key != "carried" && key != "totals" {
                    nested_keys(inner, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|v| nested_keys(v, out)),
        _ => {}
    }
}

fn assert_documented(command: &str, reply: &Value) {
    let fields = section("### JSON fields");
    let general = code_words(fields.split("\n- ").next().expect("paragraph"));
    let entry = code_words(&bullet(&fields, command));
    let anywhere = code_words(&fields);
    let object = reply.as_object().expect("object");
    for key in object.keys() {
        assert!(
            entry.contains(key) || general.contains(key),
            "{command}: `{key}` is not in its \"JSON fields\" entry of docs/spec.md"
        );
    }
    let mut deeper = std::collections::BTreeSet::new();
    for inner in object.values() {
        nested_keys(inner, &mut deeper);
    }
    for key in deeper {
        assert!(
            anywhere.contains(&key),
            "{command}: `{key}` is not in \"JSON fields\" of docs/spec.md"
        );
    }
}

#[test]
fn the_spec_documents_the_new_json_fields() {
    let e = Engagement::new();
    e.recorded("unit-1", 1);
    e.lose_and_adopt();
    let reconciled = e.reconcile(1, &["unit-1"]);
    assert_documented("reconcile-references", &reconciled);
    assert_documented("ledger", &e.json("ledger", &[], 0));
    let refused = reply(&e.guarded("unit-1", &[]).output().expect("spend"), 2);
    assert_eq!(refused["reference_evidence"]["reconciled_at"], json!([2]));
    assert_documented("spend", &refused);
    let digest = hallpass::load(&e.pass()).expect("pass").digest.to_string();
    let manifest = json!({"version": 1, "pass_id": "review-example", "units": [
        {"caller_ref": "unit-1", "digest": digest, "charges": [{"counter": "calls", "n": 1}]},
    ]});
    fs::write(e.path("manifest.json"), manifest.to_string()).expect("manifest");
    assert_documented("reconcile", &e.json("reconcile", &["manifest.json"], 2));
    let tests_clock = section("### Test clock");
    assert!(
        tests_clock.contains("`reconcile-references`"),
        "{tests_clock}"
    );
}
