//! Doctor's loop ends (bn-u4fy): "run the named command, then doctor
//! again, until healthy" reaches `healthy` from a changed or damaged ledger
//! with no backup, and a witness whose sequence alone was edited is blamed,
//! not the ledger.
//!
//! The follower here reads argv arrays only, never prose: doctor's `next`,
//! and, after a command it names, that command's `advice` entry of type
//! `last-resort`. It supplies only what a caller holds: a reason, the token
//! a preview prints, and, for the reconciliation, the caller references of
//! its own run record and the adoption sequence `hallpass ledger` gives.

#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const ID: &str = "loop-2026-11";
/// The caller references of the run record: one per spend.
const REFS: [&str; 3] = ["run-1", "run-2", "run-3"];

const PASS: &str = r#"format = 1
id = "loop-2026-11"
name = "Doctor loop fixture"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = 5060

[ceilings]
calls = 100
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    /// `c/p.toml` with one spend per reference in [`REFS`].
    fn spent() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        fs::create_dir(dir.path().join("c")).expect("c");
        let case = Self { dir };
        let pass = case.path("c/p.toml");
        fs::write(&pass, PASS).expect("write pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::File::options()
            .write(true)
            .open(&pass)
            .expect("open")
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .expect("backdate");
        for reference in REFS {
            let (rc, out) = case.json(&[
                "spend",
                "c/p.toml",
                "calls",
                "--to",
                TO,
                "--caller-ref",
                reference,
            ]);
            assert_eq!(rc, 0, "{out}");
        }
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn ledger(&self) -> PathBuf {
        self.path("c/p.toml.ledger")
    }

    fn witness(&self) -> PathBuf {
        self.path(&format!("home/state/hallpass/{ID}.witness"))
    }

    fn command(&self, program: &str, args: &[String]) -> Command {
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW);
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

    fn text(&self, args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let out = self.command(BIN, &args).output().expect("run hallpass");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
}

fn words(value: &Value) -> Vec<String> {
    value.as_array().map_or_else(Vec::new, |a| {
        a.iter()
            .map(|w| w.as_str().expect("word").to_owned())
            .collect()
    })
}

/// The argv of the reply's `last-resort` advice, if any.
fn last_resort(reply: &Value) -> Option<Vec<String>> {
    reply["advice"]
        .as_array()?
        .iter()
        .find(|a| a["type"] == "last-resort")
        .map(|a| words(&a["argv"]))
}

/// Run one argv that doctor (or the command doctor named) gave.
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
        // The caller's part: doctor names the command with the adoption
        // filled in; the caller writes REFERENCES.json from its run record
        // and gives the reason.
        let (_, ledger) = case.json(&["ledger", "c/p.toml"]);
        let adoption = ledger["unreconciled_adoption"].to_string();
        let at = |flag: &str| strs[strs.iter().position(|a| *a == flag).expect(flag) + 1];
        assert_eq!(at("--adoption"), adoption, "doctor names the adoption");
        assert_eq!(at("--references"), "REFERENCES.json");
        let list = serde_json::json!({"version": 1, "pass_id": ID, "references": REFS});
        fs::write(case.path("REFERENCES.json"), list.to_string()).expect("references");
        let mut call: Vec<&str> = strs.clone();
        let reason = call.iter().position(|a| *a == "--reason").expect("reason") + 1;
        call[reason] = "every reference of the run record";
        let (rc, out) = case.json(&call);
        assert_eq!(rc, 0, "{out}; steps: {log:#?}");
        log.push("reconcile-references (caller's list)".to_owned());
        return;
    }
    if let Some(at) = strs.iter().position(|w| *w == "--preview") {
        let (rc, preview) = case.json(&strs);
        assert_eq!(rc, 0, "{preview}; steps: {log:#?}");
        let token = preview["token"].as_str().expect("token").to_owned();
        let mut apply: Vec<&str> = strs.clone();
        apply.remove(at);
        apply.extend(["--token", &token]);
        if strs[0] == "adopt" {
            apply.extend(["--reason", "no backup copy exists"]);
        }
        let (rc, out) = case.json(&apply);
        assert_eq!(rc, 0, "{out}; steps: {log:#?}");
        return;
    }
    let (_, reply) = case.json(&strs);
    if let Some(argv) = last_resort(&reply) {
        run(case, &argv, log);
    }
}

/// Follow doctor from the case's state to `healthy`, and return the steps.
fn follow(case: &Case) -> Vec<String> {
    let mut log = Vec::new();
    for _ in 0..8 {
        let (rc, reply) = case.json(&["doctor", "c/p.toml"]);
        if reply["result"] == "healthy" {
            assert_eq!(rc, 0, "{reply}");
            return log;
        }
        let next = words(&reply["next"]);
        assert!(
            !next.is_empty(),
            "doctor names no command: {reply}; steps: {log:#?}"
        );
        run(case, &next, &mut log);
    }
    panic!("doctor never reports healthy; steps: {log:#?}");
}

/// What `healthy` must mean here: the count was never lowered, a reference
/// of the run record is still refused as a duplicate, and a new one goes
/// ahead under `--require-new-ref`.
fn assert_recovered(case: &Case) {
    let (_, status) = case.json(&["status", "c/p.toml"]);
    assert_eq!(status["counters"][0]["spent"], 3, "{status}");
    let guarded = |reference: &str| {
        case.json(&[
            "spend",
            "c/p.toml",
            "calls",
            "--to",
            TO,
            "--caller-ref",
            reference,
            "--require-new-ref",
        ])
    };
    let (rc, out) = guarded("run-2");
    assert_eq!(rc, 2, "{out}");
    assert_eq!(out["refusal"]["code"], "duplicate-reference", "{out}");
    let (rc, out) = guarded("run-4");
    assert_eq!((rc, &out["result"]), (0, &Value::from("allowed")), "{out}");
}

fn edit(path: &Path, from: &str, to: &str, nth_line: Option<usize>) {
    let text = fs::read_to_string(path).expect("read");
    let edited: String = nth_line.map_or_else(
        || text.replacen(from, to, 1),
        |n| {
            text.split_inclusive('\n')
                .enumerate()
                .map(|(i, line)| {
                    if i + 1 == n {
                        line.replacen(from, to, 1)
                    } else {
                        line.to_owned()
                    }
                })
                .collect()
        },
    );
    assert_ne!(edited, text, "nothing edited in {}", path.display());
    fs::write(path, edited).expect("write");
}

/// The step doctor names first, and that compare-backups ends the loop
/// with the last resort for the ledger beside the pass: the adoption in
/// place for a changed ledger, which verifies as a chain (bn-aao7), and the
/// move aside for a damaged one.
fn assert_loop_through_last_resort(case: &Case, problem: &str) {
    let (_, reply) = case.json(&["doctor", "c/p.toml"]);
    assert_eq!(reply["problem"], problem, "{reply}");
    assert_eq!(
        words(&reply["next"]),
        ["hallpass", "compare-backups", "c/p.toml", "c/p.toml.ledger"]
    );
    let steps = follow(case);
    if problem == "ledger-changed" {
        assert_eq!(
            steps[..2],
            [
                "hallpass compare-backups c/p.toml c/p.toml.ledger",
                "hallpass adopt c/p.toml --preview",
            ],
            "{steps:#?}"
        );
        assert!(!case.path("c/p.toml.ledger.damaged").exists(), "not moved");
    } else {
        assert_eq!(
            steps[..3],
            [
                "hallpass compare-backups c/p.toml c/p.toml.ledger",
                "mv -n c/p.toml.ledger c/p.toml.ledger.damaged",
                "hallpass adopt c/p.toml --preview",
            ],
            "{steps:#?}"
        );
        assert!(case.path("c/p.toml.ledger.damaged").is_file(), "kept aside");
    }
    assert_recovered(case);
}

/// Case A: the last line was deleted, and there is no backup.
#[test]
fn a_deleted_last_line_with_no_backup_reaches_healthy() {
    let case = Case::spent();
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    let kept: String = text.split_inclusive('\n').take(3).collect();
    fs::write(case.ledger(), kept).expect("truncate");
    assert_loop_through_last_resort(&case, "ledger-changed");
}

/// Case B: the ledger was cut back to its header, and there is no backup.
#[test]
fn a_ledger_cut_to_its_header_with_no_backup_reaches_healthy() {
    let case = Case::spent();
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    let header: String = text.split_inclusive('\n').take(1).collect();
    fs::write(case.ledger(), header).expect("truncate");
    assert_loop_through_last_resort(&case, "ledger-changed");
}

/// Case F: an entry's amount was edited, and there is no backup.
#[test]
fn an_edited_entry_with_no_backup_reaches_healthy() {
    let case = Case::spent();
    edit(&case.ledger(), "\"n\":1", "\"n\":0", Some(3));
    assert_loop_through_last_resort(&case, "ledger-corrupt");
}

/// The advice ends the loop only when no copy given holds the witnessed
/// line: with a backup that does, compare-backups gives no last resort.
#[test]
fn a_backup_that_holds_the_witnessed_line_gets_no_last_resort() {
    let case = Case::spent();
    fs::copy(case.ledger(), case.path("backup.ledger")).expect("backup");
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    let kept: String = text.split_inclusive('\n').take(3).collect();
    fs::write(case.ledger(), kept).expect("truncate");
    let (rc, reply) = case.json(&[
        "compare-backups",
        "c/p.toml",
        "c/p.toml.ledger",
        "backup.ledger",
    ]);
    assert_eq!((rc, &reply["result"]), (0, &Value::from("preserved")));
    assert_eq!(last_resort(&reply), None, "{reply}");
    // An unreadable candidate may be the good copy: no last resort either.
    let (_, reply) = case.json(&[
        "compare-backups",
        "c/p.toml",
        "c/p.toml.ledger",
        "missing.ledger",
    ]);
    assert_eq!(reply["assessment"], "no-match", "{reply}");
    assert_eq!(last_resort(&reply), None, "{reply}");
}

/// With another ledger for the pass id where the witness last saw it,
/// compare-backups never names the move that leads to an adoption.
#[test]
fn another_ledger_in_sight_gets_no_last_resort() {
    let case = Case::spent();
    fs::create_dir(case.path("d")).expect("d");
    fs::copy(case.ledger(), case.path("d/p.toml.ledger")).expect("copy ledger");
    fs::copy(case.path("c/p.toml"), case.path("d/p.toml")).expect("copy pass");
    let (rc, out) = case.json(&["spend", "d/p.toml", "calls", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    edit(&case.ledger(), "\"n\":1", "\"n\":0", Some(3));
    let (_, reply) = case.json(&["compare-backups", "c/p.toml", "c/p.toml.ledger"]);
    assert_eq!(last_resort(&reply), None, "{reply}");
}

/// Case H: only the witness's sequence was edited (3 to 2). The ledger
/// verifies and holds the line the witness names at sequence 3, so the
/// witness is damaged: spend and doctor say so, and the loop moves the
/// witness aside and adopts the intact ledger, which loses nothing.
#[test]
fn an_edited_witness_sequence_blames_the_witness() {
    let case = Case::spent();
    edit(&case.witness(), "\"seq\":3", "\"seq\":2", None);
    let (rc, out) = case.json(&["spend", "c/p.toml", "calls", "--to", TO]);
    assert_eq!(rc, 1, "{out}");
    assert_eq!(out["error"]["code"], "witness-unavailable", "{out}");
    let message = out["error"]["message"].as_str().expect("message");
    assert!(
        message.contains(
            "it records sequence 2, but the line it names is sequence 3 of the verified ledger, with spent: calls 3 there"
        ),
        "{message}"
    );
    assert!(!message.contains("was edited"), "{message}");
    let backups = case.text(&["compare-backups", "c/p.toml", "c/p.toml.ledger"]);
    assert!(
        backups.contains("holds the line it names at sequence 3"),
        "{backups}"
    );
    let (_, reply) = case.json(&["compare-backups", "c/p.toml", "c/p.toml.ledger"]);
    assert_eq!(last_resort(&reply), None, "{reply}");
    let steps = follow(&case);
    assert!(
        steps[0].starts_with("mv ") && steps[0].ends_with(".witness.damaged"),
        "{steps:#?}"
    );
    assert_eq!(steps[1], "hallpass adopt c/p.toml --preview", "{steps:#?}");
    assert_eq!(steps.len(), 2, "{steps:#?}");
    assert_recovered(&case);
}

/// Not a proof: the ledger lost its last line and the witness's sequence
/// was set to the new end. The line the witness names is in no ledger, so
/// the ledger may be the changed file, and it stays `ledger-changed`.
#[test]
fn a_witness_naming_no_line_of_the_ledger_is_not_blamed() {
    let case = Case::spent();
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    let kept: String = text.split_inclusive('\n').take(3).collect();
    fs::write(case.ledger(), kept).expect("truncate");
    edit(&case.witness(), "\"seq\":3", "\"seq\":2", None);
    let (_, out) = case.json(&["spend", "c/p.toml", "calls", "--to", TO]);
    assert_eq!(out["error"]["code"], "ledger-changed", "{out}");
}
