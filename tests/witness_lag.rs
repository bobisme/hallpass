//! A witness that lags an intact ledger (bn-37e).
//!
//! The witness can trail the ledger: a spend killed between its ledger
//! append and its witness update, or a second state directory that spends on
//! the same pass file. The ledger where the witness last saw it still holds
//! the witnessed line, so it is intact and extends the witness. A copy of
//! the pass elsewhere is then `ledger-elsewhere`, with the live ledger's
//! current totals, and no adoption (whatever its reason) starts a second
//! count beside it.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const CEILING: u64 = 5;

const PASS: &str = r#"format = 1
id = "lag-2026-11"
name = "Lagging witness"

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
calls = 5
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
    /// `c/p.toml`, and the empty directory `d` for a copy.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for sub in ["home", "c", "d"] {
            fs::create_dir(dir.path().join(sub)).expect("mkdir");
        }
        let case = Self { dir };
        case.write_pass("c/p.toml");
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write_pass(&self, name: &str) {
        let path = self.path(name);
        fs::write(&path, PASS).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        backdate(&path);
    }

    fn state(&self, which: &str) -> PathBuf {
        self.path("home").join(which)
    }

    fn witness(&self) -> PathBuf {
        self.state("state").join("hallpass/lag-2026-11.witness")
    }

    fn run_in(&self, state: &str, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.state(state))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass")
    }

    fn json_in(&self, state: &str, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run_in(state, &all);
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        self.json_in("state", args)
    }

    fn spend_in(&self, state: &str, pass: &str) -> (i32, Value) {
        self.json_in(state, &["spend", pass, "calls", "--to", TO])
    }

    fn spend(&self, pass: &str) -> (i32, Value) {
        self.spend_in("state", pass)
    }

    /// A spend whose ledger line is written but whose witness update is
    /// not, as when it is killed between the two: the witness is put back
    /// as it was before the spend.
    fn spend_killed_before_witness(&self, pass: &str) {
        let before = fs::read(self.witness()).expect("read witness");
        let (rc, out) = self.spend(pass);
        assert_eq!(rc, 0, "{out}");
        fs::write(self.witness(), before).expect("rewind witness");
        let (_, status) = self.json(&["status", pass]);
        assert_eq!(status["ledger"]["witness"], "extended", "{status}");
    }

    /// Spend on `pass` until a spend is refused: how many were allowed.
    fn spend_until_refused(&self, state: &str, pass: &str) -> u64 {
        let mut n = 0;
        while self.spend_in(state, pass).0 == 0 {
            n += 1;
            assert!(n <= CEILING, "more spends allowed than the ceiling");
        }
        n
    }

    /// The logical entries recorded in a ledger file.
    fn entries(&self, ledger: &str) -> u64 {
        fs::read_to_string(self.path(ledger))
            .map_or(0, |t| t.lines().filter(|l| l.contains("\"seq\"")).count())
            .try_into()
            .expect("count")
    }
}

fn error(reply: &Value) -> (&str, &str) {
    (
        reply["error"]["code"].as_str().unwrap_or("none"),
        reply["error"]["message"].as_str().unwrap_or(""),
    )
}

/// Every way to adopt on the copy is refused as `ledger-elsewhere`, and
/// nothing is written.
fn assert_adoption_refused(case: &Case, state: &str, copy: &str) {
    let ledger = format!("{copy}.ledger");
    let before = fs::read(case.path(&ledger)).ok();
    let witness = fs::read(case.state(state).join("hallpass/lag-2026-11.witness")).ok();
    let (rc, preview) = case.json_in(state, &["adopt", copy, "--preview"]);
    assert_eq!(
        (rc, error(&preview).0),
        (1, "ledger-elsewhere"),
        "{preview}"
    );
    for reason in ["ledger seemed lost", "restored an older copy"] {
        let (rc, out) = case.json_in(state, &["adopt", copy, "--reason", reason]);
        assert_eq!((rc, error(&out).0), (1, "ledger-elsewhere"), "{out}");
    }
    assert_eq!(fs::read(case.path(&ledger)).ok(), before, "copy's ledger");
    assert_eq!(
        fs::read(case.state(state).join("hallpass/lag-2026-11.witness")).ok(),
        witness,
        "witness"
    );
}

#[test]
fn a_witness_behind_by_a_killed_spend_sends_a_copy_to_the_live_ledger() {
    let case = Case::new();
    assert_eq!(case.spend("c/p.toml").0, 0);
    case.spend_killed_before_witness("c/p.toml");
    fs::copy(case.path("c/p.toml"), case.path("d/p.toml")).expect("copy");
    backdate(&case.path("d/p.toml"));

    let (rc, out) = case.spend("d/p.toml");
    let (code, message) = error(&out);
    assert_eq!((rc, code), (1, "ledger-elsewhere"), "{out}");
    let live = case.path("c/p.toml.ledger");
    for part in [
        "Expected ledger: d/p.toml.ledger (does not exist)",
        &format!("Live ledger: {}, intact", live.display()),
        // The live ledger's totals, not the witness's.
        "(last logical sequence 2, spent: calls 2)",
        "at sequence 1, and 1 later entry.",
        "Do not run `hallpass adopt` on this pass file",
    ] {
        assert!(message.contains(part), "{part:?} not in {message}");
    }
    assert!(!message.contains("if it is really lost"), "{message}");
    let (rc, status) = case.json(&["status", "d/p.toml"]);
    assert_eq!((rc, error(&status).0), (1, "ledger-elsewhere"), "{status}");

    assert_adoption_refused(&case, "state", "d/p.toml");
    assert!(!case.path("d/p.toml.ledger").exists());
    assert_eq!(case.spend_until_refused("state", "d/p.toml"), 0);

    // The original carries on to the ceiling, and no further.
    assert_eq!(case.spend_until_refused("state", "c/p.toml"), CEILING - 2);
    assert_eq!(case.entries("c/p.toml.ledger"), CEILING);
}

#[test]
fn a_second_state_directory_spending_on_the_file_does_not_open_a_second_count() {
    let case = Case::new();
    assert_eq!(case.spend_in("state", "c/p.toml").0, 0);
    for _ in 0..3 {
        assert_eq!(case.spend_in("other", "c/p.toml").0, 0);
    }
    let (_, status) = case.json_in("state", &["status", "c/p.toml"]);
    assert_eq!(status["ledger"]["witness"], "extended", "{status}");
    fs::copy(case.path("c/p.toml"), case.path("d/p.toml")).expect("copy");
    backdate(&case.path("d/p.toml"));

    let (rc, out) = case.spend_in("state", "d/p.toml");
    let (code, message) = error(&out);
    assert_eq!((rc, code), (1, "ledger-elsewhere"), "{out}");
    assert!(
        message.contains("(last logical sequence 4, spent: calls 4)"),
        "{message}"
    );
    assert!(message.contains("and 3 later entries."), "{message}");
    assert_adoption_refused(&case, "state", "d/p.toml");
    assert_eq!(case.spend_until_refused("state", "d/p.toml"), 0);

    let total = case.entries("c/p.toml.ledger") + case.entries("d/p.toml.ledger");
    assert!(
        total <= CEILING,
        "{total} spends against a ceiling of {CEILING}"
    );
}

#[test]
fn a_copy_with_an_older_ledger_is_not_adopted_beside_the_live_one() {
    // ledger-changed is an adoption reason too: the copy's ledger is an
    // older copy of the live one, which went on (and, the second time
    // round, past its witness).
    for lag in [false, true] {
        let case = Case::new();
        assert_eq!(case.spend("c/p.toml").0, 0);
        for name in ["p.toml", "p.toml.ledger"] {
            fs::copy(
                case.path(&format!("c/{name}")),
                case.path(&format!("d/{name}")),
            )
            .expect("copy");
        }
        backdate(&case.path("d/p.toml"));
        assert_eq!(case.spend("c/p.toml").0, 0);
        if lag {
            case.spend_killed_before_witness("c/p.toml");
        }

        let (rc, out) = case.spend("d/p.toml");
        assert_eq!(
            (rc, error(&out).0),
            (1, "ledger-elsewhere"),
            "lag {lag}: {out}"
        );
        let (_, preview) = case.json(&["adopt", "d/p.toml", "--preview"]);
        let (_, message) = error(&preview);
        for part in [
            "Expected ledger: d/p.toml.ledger (it does not hold the line the witness recorded",
            "hallpass will not start a second count",
            "Do not run `hallpass adopt` on this pass file",
        ] {
            assert!(
                message.contains(part),
                "lag {lag}: {part:?} not in {message}"
            );
        }
        assert_adoption_refused(&case, "state", "d/p.toml");
        assert_eq!(case.spend_until_refused("state", "d/p.toml"), 0);
        let spent = case.entries("c/p.toml.ledger");
        assert_eq!(
            case.spend_until_refused("state", "c/p.toml"),
            CEILING - spent
        );
    }
}

#[test]
fn a_current_witness_keeps_its_message() {
    let case = Case::new();
    for _ in 0..2 {
        assert_eq!(case.spend("c/p.toml").0, 0);
    }
    fs::copy(case.path("c/p.toml"), case.path("d/p.toml")).expect("copy");
    backdate(&case.path("d/p.toml"));
    let (rc, out) = case.spend("d/p.toml");
    let (code, message) = error(&out);
    assert_eq!((rc, code), (1, "ledger-elsewhere"), "{out}");
    assert!(
        message.contains(", intact, as last recorded on ")
            && message.contains("(last logical sequence 2, spent: calls 2)."),
        "{message}"
    );
    assert!(!message.contains("later entr"), "{message}");
    assert_adoption_refused(&case, "state", "d/p.toml");
}

#[test]
fn a_last_seen_ledger_that_cannot_be_read_blocks_adoption_until_fixed() {
    let case = Case::new();
    for _ in 0..2 {
        assert_eq!(case.spend("c/p.toml").0, 0);
    }
    case.spend_killed_before_witness("c/p.toml");
    fs::copy(case.path("c/p.toml"), case.path("d/p.toml")).expect("copy");
    backdate(&case.path("d/p.toml"));
    // A ledger others can read is not read, so it is not trusted; but it
    // may be the intact ledger, so no adoption starts a second count.
    let live = case.path("c/p.toml.ledger");
    fs::set_permissions(&live, fs::Permissions::from_mode(0o644)).expect("chmod");
    let witness = fs::read(case.witness()).expect("witness");

    let (rc, out) = case.spend("d/p.toml");
    assert_eq!((rc, error(&out).0), (1, "ledger-missing"), "{out}");
    let fix = format!(
        "run `chmod 600 {}`, then run the command again",
        live.display()
    );
    let (rc, preview) = case.json(&["adopt", "d/p.toml", "--preview"]);
    let (code, message) = error(&preview);
    assert_eq!((rc, code), (1, "insecure-permissions"), "{preview}");
    for part in [
        fix.as_str(),
        "would start a second count",
        "Nothing was recorded",
    ] {
        assert!(message.contains(part), "{part:?} not in {message}");
    }
    let (rc, out) = case.json(&["adopt", "d/p.toml", "--reason", "seemed lost"]);
    assert_eq!((rc, error(&out).0), (1, "insecure-permissions"), "{out}");
    assert!(!case.path("d/p.toml.ledger").exists());
    assert_eq!(fs::read(case.witness()).expect("witness"), witness);

    // Once it is private again it verifies, and the adoption is refused as
    // ledger-elsewhere.
    fs::set_permissions(&live, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_adoption_refused(&case, "state", "d/p.toml");
}

#[test]
fn a_last_seen_file_that_is_not_the_ledger_is_named_in_the_adoption_preview() {
    let case = Case::new();
    for _ in 0..2 {
        assert_eq!(case.spend("c/p.toml").0, 0);
    }
    fs::copy(case.path("c/p.toml"), case.path("d/p.toml")).expect("copy");
    backdate(&case.path("d/p.toml"));
    // Read and found damaged: not this pass's intact ledger, so the
    // adoption is allowed, with a warning that the witness may be behind it.
    let live = case.path("c/p.toml.ledger");
    fs::write(&live, "not a ledger\n").expect("damage");

    let (rc, out) = case.spend("d/p.toml");
    assert_eq!((rc, error(&out).0), (1, "ledger-missing"), "{out}");
    let (rc, preview) = case.json(&["adopt", "d/p.toml", "--preview"]);
    assert_eq!(
        (rc, &preview["case"]),
        (0, &"ledger-missing".into()),
        "{preview}"
    );
    let warnings = preview["warnings"].to_string();
    for part in [
        "come from the witness alone",
        &format!(
            "The witness last saw the ledger at {}, and a file is there that hallpass could not check",
            live.display()
        ),
        "the witness may be behind that ledger",
    ] {
        assert!(warnings.contains(part), "{part:?} not in {warnings}");
    }
}
