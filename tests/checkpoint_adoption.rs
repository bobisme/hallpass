//! A whole-machine restore, caught by a retained checkpoint and acted on
//! (bn-tia9): `doctor --checkpoint` blocks a ledger behind the checkpoint
//! and names `adopt --checkpoint --preview`; the adoption carries what the
//! checkpoint's totals record beyond the ledger, so counts only rise; it is
//! lossy, so guarded spends wait for `reconcile-references`; then doctor is
//! healthy. Every other relation `verify-checkpoint` reports is explained,
//! not merged.

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
const ID: &str = "restore-2026-11";
const PASS_FILE: &str = "c/p.toml";
const CHECKPOINT: &str = "offsite/checkpoint.json";

const PASS: &str = r#"format = 1
id = "restore-2026-11"
name = "Whole-machine restore fixture"

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
calls = 10
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for sub in ["home", "c", "offsite"] {
            fs::create_dir(dir.path().join(sub)).expect("dir");
        }
        let case = Self { dir };
        write_private(&case.path(PASS_FILE), PASS);
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("home/state/hallpass")
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(BIN)
            .args(["--format", "json"])
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass");
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    /// A spend of `n` calls with caller reference `reference`.
    fn spend(&self, reference: &str, n: u64) -> Value {
        let n = n.to_string();
        let (rc, out) = self.json(&[
            "spend",
            PASS_FILE,
            "calls",
            "--n",
            &n,
            "--to",
            TO,
            "--caller-ref",
            reference,
        ]);
        assert_eq!(rc, 0, "{out}");
        out
    }

    /// Copy the ledger and the state directory aside as `name`.
    fn snapshot(&self, name: &str) {
        let at = self.path(name);
        fs::create_dir(&at).expect("snapshot dir");
        fs::copy(self.path("c/p.toml.ledger"), at.join("ledger")).expect("copy ledger");
        copy_dir(&self.state(), &at.join("state"));
    }

    /// Put the ledger of snapshot `ledger` and the state directory of
    /// snapshot `state` back, as a restore does.
    fn restore(&self, ledger: &str, state: &str) {
        fs::copy(
            self.path(ledger).join("ledger"),
            self.path("c/p.toml.ledger"),
        )
        .expect("restore ledger");
        fs::remove_dir_all(self.state()).expect("drop state");
        copy_dir(&self.path(state).join("state"), &self.state());
    }

    /// Export a checkpoint to the offsite file, as the docs say.
    fn export(&self) -> Value {
        let (rc, out) = self.json(&["checkpoint", PASS_FILE]);
        assert_eq!(rc, 0, "{out}");
        write_private(&self.path(CHECKPOINT), &format!("{out}\n"));
        out
    }

    fn doctor(&self) -> (i32, Value) {
        self.json(&["doctor", PASS_FILE, "--checkpoint", CHECKPOINT])
    }

    fn spent(&self) -> u64 {
        let (rc, status) = self.json(&["status", PASS_FILE]);
        assert_eq!(rc, 0, "{status}");
        status["counters"]
            .as_array()
            .or_else(|| status["ceilings"].as_array())
            .and_then(|rows| rows.iter().find(|r| r["name"] == "calls"))
            .and_then(|r| r["spent"].as_u64())
            .unwrap_or_else(|| panic!("no spent count in {status}"))
    }

    /// Four spends, with a snapshot after the second, and a checkpoint at
    /// the fourth, then the snapshot put back whole.
    fn restored() -> Self {
        let case = Self::new();
        case.spend("run-1", 1);
        case.spend("run-2", 1);
        case.snapshot("snap");
        case.spend("run-3", 1);
        case.spend("run-4", 1);
        let out = case.export();
        assert_eq!(out["checkpoint"]["seq"], 4, "{out}");
        assert_eq!(out["checkpoint"]["totals"]["calls"], 4, "{out}");
        case.restore("snap", "snap");
        case
    }
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
    fs::File::options()
        .write(true)
        .open(path)
        .expect("open")
        .set_modified(SystemTime::now() - Duration::from_secs(3600))
        .expect("backdate");
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("dir");
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).expect("chmod");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        fs::copy(entry.path(), to.join(entry.file_name())).expect("copy");
    }
}

fn words(value: &Value) -> Vec<String> {
    value.as_array().map_or_else(Vec::new, |a| {
        a.iter()
            .map(|w| w.as_str().expect("word").to_owned())
            .collect()
    })
}

fn codes(reply: &Value) -> Vec<String> {
    reply["findings"].as_array().map_or_else(Vec::new, |rows| {
        rows.iter()
            .map(|f| f["code"].as_str().unwrap_or_default().to_owned())
            .collect()
    })
}

fn message(reply: &Value) -> String {
    reply["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
#[allow(clippy::too_many_lines)] // One flow, from the restore to healthy, read in order.
fn a_whole_machine_restore_goes_from_blocked_to_healthy_with_the_lost_spends_counted() {
    let case = Case::restored();

    // What the evaluation saw: everything agrees but the checkpoint.
    let (rc, verified) = case.json(&["verify-checkpoint", "c/p.toml.ledger", CHECKPOINT]);
    assert_eq!(
        (rc, &verified["result"], &verified["relation"]),
        (2, &Value::from("mismatch"), &Value::from("shorter")),
        "{verified}"
    );
    let (rc, plain) = case.json(&["doctor", PASS_FILE]);
    assert_eq!(
        (rc, &plain["result"]),
        (0, &Value::from("healthy")),
        "{plain}"
    );
    assert_eq!(case.spent(), 2);

    // Doctor with the checkpoint blocks and names the preview.
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["result"], "blocked", "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let next = words(&doctor["next"]);
    assert_eq!(
        next,
        [
            "hallpass",
            "adopt",
            PASS_FILE,
            "--checkpoint",
            CHECKPOINT,
            "--preview"
        ],
        "{doctor}"
    );
    let text = doctor["message"].as_str().expect("message");
    assert!(
        text.contains("entries 3 to 4") && text.contains("its hash does not cover its totals"),
        "{text}"
    );

    // The adoption without the checkpoint still has nothing to adopt, and
    // says where to look.
    let (rc, plain) = case.json(&["adopt", PASS_FILE, "--preview"]);
    assert_eq!(rc, 1, "{plain}");
    assert!(
        message(&plain).contains("--checkpoint CHECKPOINT"),
        "{plain}"
    );

    // The preview doctor named: what it carries, and what it relies on.
    let args: Vec<&str> = next.iter().skip(1).map(String::as_str).collect();
    let (rc, preview) = case.json(&args);
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["case"], "checkpoint-behind", "{preview}");
    assert_eq!(preview["present"]["calls"], 2, "{preview}");
    assert_eq!(preview["carried"]["calls"], 2, "{preview}");
    assert_eq!(preview["totals"]["calls"], 4, "{preview}");
    assert_eq!(preview["checkpoint"]["seq"], 4, "{preview}");
    let warnings = preview["warnings"].to_string();
    assert!(
        warnings.contains("only that this ledger once reached sequence 4")
            && warnings.contains("can only raise a count")
            && warnings.contains("reference-inconclusive"),
        "{warnings}"
    );
    // A preview writes nothing.
    assert_eq!(case.spent(), 2);

    let token = preview["token"].as_str().expect("token");
    let (rc, adopted) = case.json(&[
        "adopt",
        PASS_FILE,
        "--checkpoint",
        CHECKPOINT,
        "--reason",
        "whole-machine restore; checkpoint from the ticket",
        "--token",
        token,
    ]);
    assert_eq!(rc, 0, "{adopted}");
    assert_eq!(adopted["case"], "checkpoint-behind", "{adopted}");
    assert_eq!(adopted["carried"]["calls"], 2, "{adopted}");
    assert_eq!(adopted["totals"]["calls"], 4, "{adopted}");
    assert_eq!(adopted["checkpoint"]["seq"], 4, "{adopted}");
    let seq = adopted["seq"].as_u64().expect("seq");
    assert_eq!(seq, 3);
    // The lost spends count.
    assert_eq!(case.spent(), 4);

    // The ledger shows the adoption and the checkpoint it acted on.
    let (_, ledger) = case.json(&["ledger", PASS_FILE]);
    let adoption = &ledger["adoptions"][0];
    assert_eq!(adoption["checkpoint"]["seq"], 4, "{ledger}");
    assert_eq!(adoption["may_have_lost_references"], true, "{ledger}");
    assert_eq!(ledger["unreconciled_adoption"], seq, "{ledger}");

    // Lossy: a guarded spend waits for the references.
    let (rc, guarded) = case.json(&[
        "spend",
        PASS_FILE,
        "calls",
        "--to",
        TO,
        "--caller-ref",
        "run-5",
        "--require-new-ref",
    ]);
    assert_eq!(rc, 2, "{guarded}");
    assert_eq!(
        guarded["refusal"]["code"], "reference-inconclusive",
        "{guarded}"
    );

    // Doctor now names the reconciliation, and says the checkpoint was
    // acted on.
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["result"], "needs-action", "{doctor}");
    assert!(
        codes(&doctor).contains(&"checkpoint-adopted".to_owned()),
        "{doctor}"
    );
    let next = words(&doctor["next"]);
    assert_eq!(next[1], "reconcile-references", "{doctor}");

    // A second adoption from the same checkpoint is refused.
    let (rc, again) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 1, "{again}");
    assert!(
        message(&again).contains("already acted on this checkpoint"),
        "{again}"
    );

    // The caller reconciles the references of its run record.
    let list = serde_json::json!({"version": 1, "pass_id": ID, "references": ["run-3", "run-4"]});
    write_private(&case.path("refs.json"), &format!("{list}\n"));
    let seq_text = seq.to_string();
    let (rc, reconciled) = case.json(&[
        "reconcile-references",
        PASS_FILE,
        "--adoption",
        &seq_text,
        "--references",
        "refs.json",
        "--reason",
        "the run record of the lost spends",
    ]);
    assert_eq!(rc, 0, "{reconciled}");

    let (rc, doctor) = case.doctor();
    assert_eq!(
        (rc, &doctor["result"]),
        (0, &Value::from("healthy")),
        "{doctor}"
    );
    assert!(
        codes(&doctor).contains(&"checkpoint-adopted".to_owned()),
        "{doctor}"
    );

    // A lost reference is refused as used; a new one spends on top of the
    // lost spends.
    let (rc, duplicate) = case.json(&[
        "spend",
        PASS_FILE,
        "calls",
        "--to",
        TO,
        "--caller-ref",
        "run-3",
        "--require-new-ref",
    ]);
    assert_eq!(rc, 2, "{duplicate}");
    assert_eq!(
        duplicate["refusal"]["code"], "duplicate-reference",
        "{duplicate}"
    );
    let (rc, fresh) = case.json(&[
        "spend",
        PASS_FILE,
        "calls",
        "--to",
        TO,
        "--caller-ref",
        "run-5",
        "--require-new-ref",
    ]);
    assert_eq!(rc, 0, "{fresh}");
    assert_eq!(case.spent(), 5);

    // The ledger has grown past the checkpoint's sequence, so the line
    // there is the adoption's history, not the checkpoint's: still adopted.
    case.spend("run-6", 1);
    let (rc, doctor) = case.doctor();
    assert_eq!(
        (rc, &doctor["result"]),
        (0, &Value::from("healthy")),
        "{doctor}"
    );
    assert!(
        codes(&doctor).contains(&"checkpoint-adopted".to_owned()),
        "{doctor}"
    );
}

#[test]
fn a_ledger_that_holds_the_checkpointed_line_is_healthy_and_has_nothing_to_adopt() {
    let case = Case::new();
    case.spend("run-1", 1);
    case.export();
    let (rc, doctor) = case.doctor();
    assert_eq!(
        (rc, &doctor["result"]),
        (0, &Value::from("healthy")),
        "{doctor}"
    );
    assert!(
        codes(&doctor).contains(&"checkpoint-holds".to_owned()),
        "{doctor}"
    );

    case.spend("run-2", 1);
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 0, "{doctor}");
    let holds = doctor["findings"].to_string();
    assert!(holds.contains("followed by 1 later entries"), "{holds}");

    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 1, "{preview}");
    assert!(
        message(&preview).contains("holds the line the checkpoint commits to"),
        "{preview}"
    );
}

#[test]
fn another_history_at_the_checkpointed_sequence_is_explained_not_merged() {
    let case = Case::restored();
    // Spends after the restore carry the ledger past the checkpoint's
    // sequence with lines of its own.
    for reference in ["run-5", "run-6", "run-7"] {
        case.spend(reference, 1);
    }
    let (rc, verified) = case.json(&["verify-checkpoint", "c/p.toml.ledger", CHECKPOINT]);
    assert_eq!(
        (rc, &verified["relation"]),
        (2, &Value::from("mismatch")),
        "{verified}"
    );

    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-fork", "{doctor}");
    assert_eq!(doctor["next"], Value::Null, "{doctor}");
    assert!(
        doctor["next_step"]
            .as_str()
            .is_some_and(|s| s.contains("have the owner decide")),
        "{doctor}"
    );

    let before = fs::read(case.path("c/p.toml.ledger")).expect("ledger");
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 1, "{preview}");
    assert!(
        message(&preview).contains("different histories")
            && message(&preview).contains("does not merge"),
        "{preview}"
    );
    let (rc, adopt) = case.json(&[
        "adopt",
        PASS_FILE,
        "--checkpoint",
        CHECKPOINT,
        "--reason",
        "try anyway",
    ]);
    assert_eq!(rc, 1, "{adopt}");
    assert_eq!(
        fs::read(case.path("c/p.toml.ledger")).expect("ledger"),
        before
    );
}

#[test]
fn a_shorter_ledger_that_counts_more_than_the_checkpoint_has_new_spends_on_top() {
    let case = Case::restored();
    // One spend after the restore, larger than the lost two together. The
    // checkpoint's line hashes prove entries 1 and 2 its own and entry 3
    // not, so entry 3 counts on top of the checkpoint's totals.
    case.spend("run-5", 5);
    let (rc, verified) = case.json(&["verify-checkpoint", "c/p.toml.ledger", CHECKPOINT]);
    assert_eq!(
        (rc, &verified["relation"]),
        (2, &Value::from("shorter")),
        "{verified}"
    );
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["carried"]["calls"], 2, "{preview}");
    assert_eq!(preview["totals"]["calls"], 9, "{preview}");
}

#[test]
fn a_checkpoint_without_totals_shows_the_loss_but_carries_nothing() {
    let case = Case::restored();
    let mut exported: Value =
        serde_json::from_slice(&fs::read(case.path(CHECKPOINT)).expect("read")).expect("json");
    let inner = exported["checkpoint"].as_object_mut().expect("object");
    inner.remove("totals");
    // The bare object, as text mode prints it, is read the same way.
    let bare = exported["checkpoint"].to_string();
    write_private(&case.path(CHECKPOINT), &format!("{bare}\n"));

    let (rc, verified) = case.json(&["verify-checkpoint", "c/p.toml.ledger", CHECKPOINT]);
    assert_eq!(
        (rc, &verified["relation"]),
        (2, &Value::from("shorter")),
        "{verified}"
    );
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    assert_eq!(doctor["next"], Value::Null, "{doctor}");
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 1, "{preview}");
    assert!(message(&preview).contains("records no totals"), "{preview}");
}

#[test]
fn doctor_and_adopt_refuse_exactly_the_checkpoints_verify_checkpoint_refuses() {
    let case = Case::restored();
    let exported: Value =
        serde_json::from_slice(&fs::read(case.path(CHECKPOINT)).expect("read")).expect("json");
    let mut bad = exported["checkpoint"].clone();
    bad["totals"] = serde_json::json!({"calls": -1});
    let mut unknown = exported["checkpoint"].clone();
    unknown["note"] = Value::from("extra");
    let mut version = exported["checkpoint"].clone();
    version["version"] = Value::from(2);
    for (name, value) in [("bad", bad), ("unknown", unknown), ("version", version)] {
        let file = format!("offsite/{name}.json");
        write_private(&case.path(&file), &format!("{value}\n"));
        let (rc, verified) = case.json(&["verify-checkpoint", "c/p.toml.ledger", &file]);
        assert_eq!(rc, 1, "{verified}");
        let (rc, doctor) = case.json(&["doctor", PASS_FILE, "--checkpoint", &file]);
        assert_eq!(rc, 1, "{doctor}");
        assert_eq!(message(&doctor), message(&verified), "{name}");
        let (rc, adopt) = case.json(&["adopt", PASS_FILE, "--checkpoint", &file, "--preview"]);
        assert_eq!(rc, 1, "{adopt}");
        assert_eq!(message(&adopt), message(&verified), "{name}");
    }
    let names = serde_json::json!({"version": 1, "pass_id": ID, "seq": 4, "hash": exported["checkpoint"]["hash"], "totals": {"not a counter": 1}});
    write_private(&case.path("offsite/names.json"), &format!("{names}\n"));
    let (rc, verified) = case.json(&["verify-checkpoint", "c/p.toml.ledger", "offsite/names.json"]);
    assert_eq!(rc, 1, "{verified}");
    assert!(
        message(&verified).contains("invalid checkpoint totals"),
        "{verified}"
    );
}

#[test]
fn a_checkpoint_of_another_pass_blocks_as_foreign() {
    let case = Case::restored();
    let mut exported: Value =
        serde_json::from_slice(&fs::read(case.path(CHECKPOINT)).expect("read")).expect("json");
    exported["checkpoint"]["pass_id"] = Value::from("other-pass");
    write_private(&case.path(CHECKPOINT), &format!("{exported}\n"));
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-foreign", "{doctor}");
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 1, "{preview}");
    assert!(
        message(&preview).contains("is for pass `other-pass`"),
        "{preview}"
    );
}

#[test]
fn a_token_goes_stale_when_the_ledger_changes_after_the_preview() {
    let case = Case::restored();
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    let token = preview["token"].as_str().expect("token").to_owned();
    // One spend changes the ledger after the preview.
    case.spend("run-5", 1);
    let (rc, adopt) = case.json(&[
        "adopt",
        PASS_FILE,
        "--checkpoint",
        CHECKPOINT,
        "--reason",
        "restore",
        "--token",
        &token,
    ]);
    assert_eq!(rc, 1, "{adopt}");
    assert!(message(&adopt).contains("stale"), "{adopt}");
    assert_eq!(case.spent(), 3);
}

#[test]
fn with_a_witness_newer_than_the_ledger_the_higher_of_the_two_is_carried() {
    let case = Case::new();
    case.spend("run-1", 1);
    case.spend("run-2", 1);
    case.snapshot("ledger-at-2");
    case.spend("run-3", 1);
    case.snapshot("state-at-3");
    case.spend("run-4", 2);
    case.export();
    // The ledger from one copy, the state directory from a newer one.
    case.restore("ledger-at-2", "state-at-3");
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["case"], "ledger-changed", "{preview}");
    assert_eq!(preview["carried"]["calls"], 1, "{preview}");

    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["case"], "ledger-changed", "{preview}");
    assert_eq!(preview["carried"]["calls"], 3, "{preview}");
    assert_eq!(preview["totals"]["calls"], 5, "{preview}");
    let token = preview["token"].as_str().expect("token");
    let (rc, adopted) = case.json(&[
        "adopt",
        PASS_FILE,
        "--checkpoint",
        CHECKPOINT,
        "--reason",
        "partial restore",
        "--token",
        token,
    ]);
    assert_eq!(rc, 0, "{adopted}");
    assert_eq!(case.spent(), 5);
}

#[test]
fn a_restore_to_before_the_first_spend_is_caught_and_adopted() {
    let case = Case::new();
    case.spend("run-1", 2);
    case.export();
    // Nothing of the ledger or the state survives.
    fs::remove_file(case.path("c/p.toml.ledger")).expect("drop ledger");
    fs::remove_dir_all(case.state()).expect("drop state");
    let (rc, plain) = case.json(&["doctor", PASS_FILE]);
    assert_eq!(
        (rc, &plain["result"]),
        (0, &Value::from("healthy")),
        "{plain}"
    );
    let (rc, doctor) = case.doctor();
    assert_eq!(rc, 2, "{doctor}");
    assert_eq!(doctor["problem"], "checkpoint-behind", "{doctor}");
    let (rc, preview) = case.json(&["adopt", PASS_FILE, "--checkpoint", CHECKPOINT, "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["case"], "checkpoint-behind", "{preview}");
    assert_eq!(preview["carried"]["calls"], 2, "{preview}");
    assert!(
        !case.path("c/p.toml.ledger").exists(),
        "a preview creates nothing"
    );
    let token = preview["token"].as_str().expect("token");
    let (rc, adopted) = case.json(&[
        "adopt",
        PASS_FILE,
        "--checkpoint",
        CHECKPOINT,
        "--reason",
        "restored from a snapshot before the first spend",
        "--token",
        token,
    ]);
    assert_eq!(rc, 0, "{adopted}");
    assert_eq!(adopted["created"], true, "{adopted}");
    assert_eq!(case.spent(), 2);
}
