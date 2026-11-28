//! The witness against the verified ledger, and the notes beside it
//! (bn-2pm, bn-3at, bn-19x):
//!
//! - witness totals that differ from the verified ledger at the witnessed
//!   sequence make the witness damaged, as one that does not parse;
//! - a ledger from before an adoption is named as a different history from
//!   the adoption's sequence, not as an older copy;
//! - `compare-backups --ancestry` leads with its conclusion, and the adoption
//!   preview's warnings are whole sentences;
//! - a pass rewritten in place, not replaced by a rename, is warned about.

use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const IN_PLACE: &str = "was changed in place since hallpass last read it";

const PASS: &str = r#"format = 1
id = "acme-2026-11"
name = "Acme voice edge"

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

/// Set a file's modification time a minute back, so a read does not wait
/// for a save to settle.
fn backdate(path: &Path) {
    File::options()
        .write(true)
        .open(path)
        .expect("open")
        .set_modified(SystemTime::now() - Duration::from_secs(60))
        .expect("backdate");
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let case = Self { dir };
        let path = case.path("p.toml");
        fs::write(&path, PASS).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        backdate(&path);
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("home/state")
    }

    fn witness(&self) -> PathBuf {
        self.state().join("hallpass/acme-2026-11.witness")
    }

    fn ledger(&self) -> PathBuf {
        self.path("p.toml.ledger")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.state())
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass")
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    fn spend(&self) -> (i32, Value) {
        self.json(&["spend", "p.toml", "calls", "--to", TO])
    }

    fn spends(&self, n: usize) {
        for _ in 0..n {
            let (rc, out) = self.spend();
            assert_eq!(rc, 0, "{out}");
        }
    }

    /// Rewrite the witness's totals (a bit flip, a bad restore, a hand edit).
    fn edit_totals(&self, totals: &Value) {
        let mut w: Value = serde_json::from_slice(&fs::read(self.witness()).expect("witness"))
            .expect("witness JSON");
        w["totals"] = totals.clone();
        fs::write(self.witness(), format!("{w}\n")).expect("edit witness");
    }

    fn stderr(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.run(args).stderr).into_owned()
    }
}

fn error_code(reply: &Value) -> &str {
    reply["error"]["code"].as_str().unwrap_or("none")
}

fn all_text(reply: &Value) -> String {
    reply.to_string()
}

/// `status` answers with the witness not checked and says why; `spend`
/// refuses as for a damaged witness; nothing is recorded.
fn assert_damaged(case: &Case, recorded: &str, verified: &str) {
    let ledger = fs::read(case.ledger()).expect("ledger");
    let (rc, status) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 0, "{status}");
    assert_eq!(status["ledger"]["witness"], "not-checked", "{status}");
    let why = format!(
        "is damaged (it records spent: {recorded} at sequence 3, but the verified ledger has spent: {verified} there); move it aside and run `hallpass adopt` to record a new one"
    );
    assert!(all_text(&status).contains(&why), "{status}");
    let (rc, out) = case.spend();
    assert_eq!((rc, error_code(&out)), (1, "witness-unavailable"), "{out}");
    assert!(all_text(&out).contains(&why), "{out}");
    let (rc, out) = case.json(&["permits", "p.toml", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    assert!(all_text(&out).contains(&why), "{out}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), ledger);
}

#[test]
fn witness_totals_lower_than_the_ledger_are_damage() {
    let case = Case::new();
    case.spends(3);
    case.edit_totals(&serde_json::json!({"calls": 1}));
    assert_damaged(&case, "calls 1", "calls 3");
}

#[test]
fn witness_totals_higher_than_the_ledger_are_damage() {
    let case = Case::new();
    case.spends(3);
    case.edit_totals(&serde_json::json!({"calls": 4}));
    assert_damaged(&case, "calls 4", "calls 3");
}

#[test]
fn a_counter_removed_from_or_added_to_the_witness_is_damage() {
    let case = Case::new();
    case.spends(3);
    let good = fs::read(case.witness()).expect("witness");
    case.edit_totals(&serde_json::json!({}));
    assert_damaged(&case, "nothing", "calls 3");
    fs::write(case.witness(), &good).expect("restore");
    case.edit_totals(&serde_json::json!({"calls": 3, "minutes": 2}));
    assert_damaged(&case, "calls 3, minutes 2", "calls 3");
    // A counter recorded with 0 counts nothing: the witness still matches.
    fs::write(case.witness(), &good).expect("restore");
    case.edit_totals(&serde_json::json!({"calls": 3, "minutes": 0}));
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["ledger"]["witness"], "matches", "{status}");
}

#[test]
fn a_ledger_ahead_of_the_witness_is_checked_at_the_witnessed_sequence() {
    let case = Case::new();
    case.spends(3);
    let behind = fs::read(case.witness()).expect("witness");
    case.spends(2);
    // A crash between the ledger append and the witness update: the
    // witness is behind, and its totals are those at its own sequence.
    fs::write(case.witness(), &behind).expect("witness behind");
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["ledger"]["witness"], "extended", "{status}");
    let (rc, out) = case.spend();
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["spent"], 6, "{out}");
    // The same lag with totals that are not the ledger's at sequence 3.
    fs::write(case.witness(), &behind).expect("witness behind");
    case.edit_totals(&serde_json::json!({"calls": 6}));
    assert_damaged(&case, "calls 6", "calls 3");
}

#[test]
fn compare_backups_warns_of_a_witness_whose_totals_differ() {
    let case = Case::new();
    case.spends(3);
    fs::copy(case.ledger(), case.path("backup.ledger")).expect("backup");
    case.edit_totals(&serde_json::json!({"calls": 1}));
    let (_, out) = case.json(&["compare-backups", "p.toml", "backup.ledger"]);
    assert!(
        all_text(&out).contains("is damaged (it records spent: calls 1 at sequence 3"),
        "{out}"
    );
}

#[test]
fn an_adoption_preview_says_carried_totals_come_from_the_witness_alone() {
    let case = Case::new();
    case.spends(3);
    fs::rename(case.ledger(), case.path("lost.ledger")).expect("lose ledger");
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(rc, 0, "{out}");
    let warnings = out["warnings"].as_array().expect("warnings");
    assert!(
        warnings.iter().any(|w| w.as_str().is_some_and(|w| w.starts_with(
            "the carried totals (calls 3) come from the witness alone: the ledger is missing, so hallpass cannot check them."
        ))),
        "{out}"
    );
}

/// Spends 1-2, backup `at2`; spends 3-5, backup `at5`; `at2` restored and
/// adopted (the adoption is sequence 3); one more spend (sequence 4).
fn forked() -> Case {
    let case = Case::new();
    case.spends(2);
    fs::copy(case.ledger(), case.path("at2.ledger")).expect("at2");
    case.spends(3);
    fs::copy(case.ledger(), case.path("at5.ledger")).expect("at5");
    fs::copy(case.path("at2.ledger"), case.ledger()).expect("restore at2");
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(rc, 0, "{out}");
    // Every preview warning is a whole sentence.
    for w in out["warnings"].as_array().expect("warnings") {
        assert!(w.as_str().is_some_and(|w| w.ends_with('.')), "{w}");
    }
    let token = out["token"].as_str().expect("token").to_owned();
    let (rc, out) = case.json(&[
        "adopt",
        "p.toml",
        "--reason",
        "restored from backup at2",
        "--token",
        &token,
    ]);
    assert_eq!(rc, 0, "{out}");
    case.spends(1);
    case
}

#[test]
fn a_shorter_ledger_from_before_an_adoption_is_named_a_different_history() {
    let case = forked();
    case.spends(2);
    // The other backup goes back: shorter than the witness (6), and
    // different from sequence 3, where the adoption is.
    fs::copy(case.path("at5.ledger"), case.ledger()).expect("put back at5");
    let (rc, out) = case.json(&["status", "p.toml"]);
    assert_eq!((rc, error_code(&out)), (1, "ledger-changed"), "{out}");
    let message = out["error"]["message"].as_str().expect("message");
    assert!(
        message.contains(
            "but this ledger ends at sequence 5 and is a different history from sequence 3: hallpass adopted another copy of the ledger there on 2026-11-20T09:00:00Z"
        ),
        "{message}"
    );
    assert!(!message.contains("older copy"), "{message}");
    let (rc, out) = case.spend();
    assert_eq!((rc, error_code(&out)), (1, "ledger-changed"), "{out}");

    // Without the note, hallpass cannot tell, and says what it said before.
    fs::remove_file(case.state().join("hallpass/acme-2026-11.forks")).expect("note");
    let (_, out) = case.json(&["status", "p.toml"]);
    let message = out["error"]["message"].as_str().expect("message");
    assert!(message.contains("or this is an older copy"), "{message}");
}

#[test]
fn a_longer_ledger_from_before_an_adoption_is_named_a_different_history() {
    let case = forked();
    // The witness is at 4; the other backup has 5 lines, with a different
    // line at 4 because it leaves the current history at 3.
    fs::copy(case.path("at5.ledger"), case.ledger()).expect("put back at5");
    let (rc, out) = case.json(&["status", "p.toml"]);
    assert_eq!((rc, error_code(&out)), (1, "ledger-changed"), "{out}");
    let message = out["error"]["message"].as_str().expect("message");
    assert!(
        message.contains(
            "entry 4 is not the line hallpass wrote there on 2026-11-20T09:00:00Z: this ledger is a different history from sequence 3, where hallpass adopted another copy of the ledger on 2026-11-20T09:00:00Z"
        ),
        "{message}"
    );
}

#[test]
fn compare_backups_ancestry_leads_with_its_conclusion() {
    let case = Case::new();
    case.spends(2);
    fs::copy(case.ledger(), case.path("at2.ledger")).expect("at2");
    case.spends(3);
    fs::copy(case.ledger(), case.path("at5.ledger")).expect("at5");
    let out = case.run(&[
        "compare-backups",
        "p.toml",
        "at2.ledger",
        "at5.ledger",
        "--ancestry",
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(
            "Ancestry of the candidates at, ahead of or behind the witness (by tip group):\n  group 1 is a prefix of group 2"
        ),
        "{text}"
    );
    assert!(!text.contains("No tip group is a prefix"), "{text}");

    // Two extensions that split after the witness.
    let witness = fs::read(case.witness()).expect("witness");
    case.spends(1);
    fs::copy(case.ledger(), case.path("a.ledger")).expect("a");
    fs::copy(case.path("at5.ledger"), case.ledger()).expect("rewind");
    fs::write(case.witness(), &witness).expect("rewind witness");
    let (rc, out) = case.json(&["spend", "p.toml", "calls", "--to", TO, "--note", "other"]);
    assert_eq!(rc, 0, "{out}");
    fs::copy(case.ledger(), case.path("b.ledger")).expect("b");
    fs::write(case.witness(), &witness).expect("rewind witness");
    let out = case.run(&[
        "compare-backups",
        "p.toml",
        "a.ledger",
        "b.ledger",
        "--ancestry",
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("  The extended tip groups 1, 2 split after the witness: none is a\n  prefix of another, so at most one of them is the ledger hallpass wrote."),
        "{text}"
    );
}

fn inode(path: &Path) -> u64 {
    fs::metadata(path).expect("metadata").ino()
}

#[test]
fn a_pass_rewritten_in_place_is_warned_about_once() {
    let case = Case::new();
    let pass = case.path("p.toml");
    // The first spend makes the state directory and notes the file; a
    // read then finds the same file with the same contents.
    case.spends(1);
    assert!(!case.stderr(&["status", "p.toml"]).contains(IN_PLACE));
    let before = inode(&pass);
    fs::write(&pass, PASS.replace("calls = 10", "calls = 12")).expect("in place");
    backdate(&pass);
    assert_eq!(inode(&pass), before);
    let warned = case.stderr(&["permits", "p.toml", "--to", TO]);
    assert!(
        warned.contains("the pass file \"p.toml\" was changed in place since hallpass last read it: the same file was rewritten, not replaced."),
        "{warned}"
    );
    assert!(
        warned.contains("renaming it over the old one (`mv`)"),
        "{warned}"
    );
    assert!(warned.contains("(`--digest`)."), "{warned}");
    // Noted once: the next read of the same contents is quiet.
    assert!(!case.stderr(&["status", "p.toml"]).contains(IN_PLACE));

    // A spend sees it too, and is not refused for it.
    fs::write(&pass, PASS.replace("calls = 10", "calls = 14")).expect("in place");
    backdate(&pass);
    let (rc, out) = case.spend();
    assert_eq!(rc, 0, "{out}");
    assert!(all_text(&out).contains(IN_PLACE), "{out}");
    let (_, status) = case.json(&["status", "p.toml"]);
    assert!(!all_text(&status).contains(IN_PLACE), "{status}");
}

#[test]
fn a_pass_replaced_by_rename_or_only_touched_is_not_warned_about() {
    let case = Case::new();
    let pass = case.path("p.toml");
    case.spends(1);
    let before = inode(&pass);
    let next = case.path("p.toml.new");
    fs::write(&next, PASS.replace("calls = 10", "calls = 12")).expect("new version");
    fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).expect("chmod");
    backdate(&next);
    fs::rename(&next, &pass).expect("replace by rename");
    assert_ne!(inode(&pass), before);
    let (rc, out) = case.spend();
    assert_eq!(rc, 0, "{out}");
    assert!(!all_text(&out).contains(IN_PLACE), "{out}");
    assert!(
        !case
            .stderr(&["permits", "p.toml", "--to", TO])
            .contains(IN_PLACE)
    );

    // A new modification time with the same contents is not a change.
    File::options()
        .write(true)
        .open(&pass)
        .expect("open")
        .set_modified(SystemTime::now() - Duration::from_secs(30))
        .expect("touch");
    assert!(!case.stderr(&["status", "p.toml"]).contains(IN_PLACE));
}

/// Repro 21: the witness is edited, `status` notices, then the ledger is
/// lost. The adoption that would carry the edited totals is refused.
#[test]
fn damage_seen_before_the_ledger_is_lost_stops_the_adoption() {
    let case = Case::new();
    case.spends(3);
    case.edit_totals(&serde_json::json!({"calls": 1}));
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["ledger"]["witness"], "not-checked", "{status}");
    fs::rename(case.ledger(), case.path("lost.ledger")).expect("lose ledger");

    let refused = "is damaged: a command found that it records spent: calls 1 at sequence 3, while the verified ledger had spent: calls 3 there, and an adoption would carry those totals. Put the ledger back beside the pass, or a backup that holds sequence 3. If no copy is left, run `hallpass adopt p.toml --preview --carry-noted-totals`, review it, then `hallpass adopt p.toml --reason \"...\" --carry-noted-totals --token TOKEN`: it carries, per counter, the higher of the two totals.";
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!((rc, error_code(&out)), (1, "witness-unavailable"), "{out}");
    let message = out["error"]["message"].as_str().expect("message");
    assert!(message.contains(refused), "{message}");
    assert!(!message.contains("move it aside"), "{message}");
    let (rc, out) = case.json(&["adopt", "p.toml", "--reason", "ledger lost"]);
    assert_eq!((rc, error_code(&out)), (1, "witness-unavailable"), "{out}");
    assert!(
        !case.ledger().exists(),
        "a refused adoption starts no ledger"
    );
    let (rc, out) = case.spend();
    assert_eq!((rc, error_code(&out)), (1, "ledger-missing"), "{out}");

    // The owner accepts carrying the verified totals: never lower than
    // either record.
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview", "--carry-noted-totals"]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["carried"], serde_json::json!({"calls": 3}), "{out}");
    assert_eq!(out["from_note"], serde_json::json!({"calls": 3}), "{out}");
    let source = "the higher of the witness's total and the verified total noted when the witness was found damaged (from the note: calls 3)";
    assert!(
        out["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w.as_str().is_some_and(|w| w.starts_with(&format!(
                "the carried totals (calls 3) are, per counter, {source}: the ledger is missing"
            )))),
        "{out}"
    );
    assert!(!all_text(&out).contains("from the witness alone"), "{out}");
    let shown = case.run(&["adopt", "p.toml", "--preview", "--carry-noted-totals"]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains(
            "Carry: calls 3 (the higher of the witness's and the noted verified totals; from the note: calls 3). Projected: calls 3."
        ),
        "{}",
        String::from_utf8_lossy(&shown.stdout)
    );
    let token = out["token"].as_str().expect("token").to_owned();
    let (rc, out) = case.json(&[
        "adopt",
        "p.toml",
        "--reason",
        "ledger lost; owner accepts the noted totals",
        "--carry-noted-totals",
        "--token",
        &token,
    ]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["from_note"], serde_json::json!({"calls": 3}), "{out}");
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["counters"][0]["spent"], 3, "{status}");
    // The new witness is not the damaged one: no note applies any more.
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview", "--carry-noted-totals"]);
    assert_eq!(rc, 1, "{out}");
}

#[test]
fn noted_totals_never_lower_a_count() {
    let case = Case::new();
    case.spends(3);
    case.edit_totals(&serde_json::json!({"calls": 5}));
    let (rc, out) = case.spend();
    assert_eq!((rc, error_code(&out)), (1, "witness-unavailable"), "{out}");
    fs::rename(case.ledger(), case.path("lost.ledger")).expect("lose ledger");
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview", "--carry-noted-totals"]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["carried"], serde_json::json!({"calls": 5}), "{out}");
    // The witness's own total is the higher: nothing came from the note.
    assert_eq!(out["from_note"], serde_json::json!({}), "{out}");
    let token = out["token"].as_str().expect("token").to_owned();
    let shown = case.run(&[
        "adopt",
        "p.toml",
        "--reason",
        "lost",
        "--carry-noted-totals",
        "--token",
        &token,
    ]);
    let stdout = String::from_utf8_lossy(&shown.stdout);
    assert!(
        stdout.contains("Carried from the witness: calls 5."),
        "{stdout}"
    );
}

#[test]
fn without_a_damage_note_adoption_is_as_before() {
    let case = Case::new();
    case.spends(3);
    case.edit_totals(&serde_json::json!({"calls": 1}));
    // No command compared the witness with the ledger before it was lost.
    fs::rename(case.ledger(), case.path("lost.ledger")).expect("lose ledger");
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["carried"], serde_json::json!({"calls": 1}), "{out}");
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview", "--carry-noted-totals"]);
    assert_eq!((rc, error_code(&out)), (1, "usage"), "{out}");
    // A note for other witness bytes does not apply either.
    fs::rename(case.path("lost.ledger"), case.ledger()).expect("back");
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["ledger"]["witness"], "not-checked", "{status}");
    case.edit_totals(&serde_json::json!({"calls": 2}));
    fs::rename(case.ledger(), case.path("lost.ledger")).expect("lose ledger");
    let (rc, out) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(rc, 0, "{out}");
    assert_eq!(out["carried"], serde_json::json!({"calls": 2}), "{out}");
}

#[test]
fn the_adopted_line_names_the_counters_carried_from_the_note() {
    let case = Case::new();
    case.spends(3);
    case.edit_totals(&serde_json::json!({"calls": 1}));
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["ledger"]["witness"], "not-checked", "{status}");
    fs::rename(case.ledger(), case.path("lost.ledger")).expect("lose ledger");
    let (_, preview) = case.json(&["adopt", "p.toml", "--preview", "--carry-noted-totals"]);
    let token = preview["token"].as_str().expect("token").to_owned();
    let shown = case.run(&[
        "adopt",
        "p.toml",
        "--reason",
        "lost",
        "--carry-noted-totals",
        "--token",
        &token,
    ]);
    let stdout = String::from_utf8_lossy(&shown.stdout);
    assert!(
        stdout.contains(
            "Carried, per counter, the higher of the witness's total and the verified total noted when the witness was found damaged (from the note: calls 3): calls 3. Spent now: calls 3."
        ),
        "{stdout}"
    );
}
