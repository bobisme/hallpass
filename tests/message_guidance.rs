//! Charge, adopt-preview and ledger-damage messages name the input, say what
//! is wrong and end with what to do (bn-110). `--json` is listed in help.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use hallpass::Digest;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";

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
calls = 5
bytes = 1000
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let case = Self { dir };
        let pass = case.path("p.toml");
        fs::write(&pass, PASS).expect("write pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        // A pass is read again when it was modified a moment ago.
        fs::File::options()
            .write(true)
            .open(&pass)
            .expect("open")
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))
            .expect("backdate");
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass")
    }

    /// The error message of a command that must fail with exit code 1.
    fn error(&self, args: &[&str]) -> String {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        assert_eq!(out.status.code(), Some(1), "{all:?}");
        let reply: Value = serde_json::from_slice(&out.stdout).expect("JSON");
        reply["error"]["message"]
            .as_str()
            .expect("message")
            .to_owned()
    }

    fn charge(&self, charge: &str) -> String {
        self.error(&["spend", "p.toml", "--charge", charge, "--to", TO])
    }
}

#[test]
fn a_zero_charge_names_the_charge_and_the_least_amount() {
    let message = Case::new().charge("bytes=0");
    assert!(message.contains(r#""bytes=0""#), "{message}");
    assert!(message.contains("zero"), "{message}");
    assert!(message.contains("from 1 to 1000000000000"), "{message}");
    assert!(message.contains("nothing was recorded"), "{message}");
}

#[test]
fn a_charge_over_the_limit_names_the_charge_and_the_limit() {
    let message = Case::new().charge("bytes=1000000000001");
    assert!(message.contains(r#""bytes=1000000000001""#), "{message}");
    assert!(message.contains("over the limit"), "{message}");
    assert!(message.contains("1000000000000"), "{message}");
    assert!(message.contains("nothing was recorded"), "{message}");
}

#[test]
fn a_charge_beyond_the_largest_whole_number_states_the_limit() {
    let message = Case::new().charge("bytes=18446744073709551616");
    assert!(
        message.contains("--charge bytes=18446744073709551616"),
        "{message}"
    );
    assert!(message.contains("over the limit"), "{message}");
    assert!(message.contains("from 1 to 1000000000000"), "{message}");
}

#[test]
fn a_charge_that_is_not_a_number_or_has_a_bad_counter_says_what_to_write() {
    let case = Case::new();
    let message = case.charge("bytes=x");
    assert!(message.contains("--charge bytes=x"), "{message}");
    assert!(message.contains("digits only"), "{message}");
    assert!(message.contains("bytes=100"), "{message}");
    let message = case.charge("Bad=1");
    assert!(message.contains(r#""Bad""#), "{message}");
    assert!(message.contains("lower-case"), "{message}");
}

#[test]
fn adopt_preview_on_a_matching_ledger_says_why_and_what_to_do() {
    let case = Case::new();
    let spent = case.run(&["spend", "p.toml", "calls", "--to", TO]);
    assert_eq!(spent.status.code(), Some(0));
    let preview = case.error(&["adopt", "p.toml", "--preview", "--reason", "x"]);
    let adopt = case.error(&["adopt", "p.toml", "--reason", "x"]);
    for message in [&preview, &adopt] {
        assert!(message.contains("p.toml.ledger"), "{message}");
        assert!(message.contains("matches its witness"), "{message}");
        assert!(message.contains("nothing to adopt"), "{message}");
        assert!(message.contains("`hallpass status`"), "{message}");
    }
    assert_eq!(preview, adopt);
}

#[test]
fn a_complete_but_invalid_ledger_line_is_never_called_cut_short() {
    let case = Case::new();
    let spent = case.run(&["spend", "p.toml", "calls", "--to", TO]);
    assert_eq!(spent.status.code(), Some(0));
    let ledger = case.path("p.toml.ledger");
    let mut text = fs::read_to_string(&ledger).expect("ledger");
    let last = text.lines().last().expect("a line").to_owned();
    let forged = json!({
        "seq": 3,
        "time": NOW,
        "event": "adopt",
        "reason": "forged",
        "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "carried": {"calls": -6},
        "witness": null,
        "prev": Digest::of(last.as_bytes()).to_string(),
    });
    text += &forged.to_string();
    text.push('\n');
    fs::write(&ledger, text).expect("write ledger");
    let message = case.error(&["status", "p.toml"]);
    assert!(message.contains("line 3"), "{message}");
    assert!(message.contains("complete adoption record"), "{message}");
    assert!(message.contains(r#""carried.calls""#), "{message}");
    assert!(message.contains("-6"), "{message}");
    assert!(
        message.contains("Restore the ledger from a backup"),
        "{message}"
    );
    assert!(message.contains("do not remove it"), "{message}");
    assert!(
        !message.contains("not a complete ledger entry"),
        "{message}"
    );
    assert!(!message.contains("remove only a final line"), "{message}");
}

#[test]
fn a_symlinked_witness_message_has_one_full_stop() {
    let case = Case::new();
    let spent = case.run(&["spend", "p.toml", "calls", "--to", TO]);
    assert_eq!(spent.status.code(), Some(0));
    let witness = case.path("home/state/hallpass/acme-2026-11.witness");
    let real = case.path("real.witness");
    fs::rename(&witness, &real).expect("move witness");
    std::os::unix::fs::symlink(&real, &witness).expect("link");
    let message = case.error(&["spend", "p.toml", "calls", "--to", TO]);
    assert!(message.contains("symbolic link"), "{message}");
    assert!(!message.contains(".."), "{message}");
}

#[test]
fn json_is_listed_where_the_global_options_are_shown() {
    let case = Case::new();
    for args in [&["help"][..], &["status", "--help"], &["spend", "--help"]] {
        let out = case.run(args);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(text.contains("--json"), "{args:?}: {text}");
        assert!(text.contains("--format json"), "{args:?}: {text}");
    }
    let out = case.run(&["--format", "json", "help", "status"]);
    let reply: Value = serde_json::from_slice(&out.stdout).expect("JSON");
    let listed = reply["arguments"]
        .as_array()
        .expect("arguments")
        .iter()
        .any(|a| a["long"] == "json");
    assert!(listed, "{reply}");
}
