//! `hallpass repair --restore-final-newline` adds the line end that a failed
//! write left off a counted last ledger line, and refuses anything else
//! (bn-ulz6). Also the minimal caller's COUNTER argument.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"format = 1
id = "newline-2026-11"
name = "Example voice edge"

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
ports = [5060]

[ceilings]
calls = 200
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let pass = dir.path().join("p.toml");
        fs::write(&pass, PASS).expect("write");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        fs::File::options()
            .write(true)
            .open(&pass)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(10)))
            .expect("backdate");
        Self { dir }
    }

    fn ledger(&self) -> PathBuf {
        self.dir.path().join("p.toml.ledger")
    }

    fn witness(&self) -> PathBuf {
        self.dir
            .path()
            .join("home/state/hallpass/newline-2026-11.witness")
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let home = self.dir.path().join("home");
        let out = Command::new(BIN)
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .arg("--json")
            .args(args)
            .output()
            .expect("run");
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().unwrap_or(-1), v)
    }

    fn spend(&self) {
        let (rc, v) = self.json(&["spend", "p.toml", "calls"]);
        assert_eq!(rc, 0, "{v}");
    }

    fn preview(&self) -> (i32, Value) {
        self.json(&["repair", "p.toml", "--restore-final-newline", "--preview"])
    }

    fn drop_last_byte(&self) {
        let mut bytes = fs::read(self.ledger()).expect("ledger");
        assert_eq!(bytes.pop(), Some(b'\n'));
        fs::write(self.ledger(), bytes).expect("write");
    }
}

fn message(v: &Value) -> String {
    v["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_counted_last_line_gets_its_line_end_back_and_nothing_else_changes() {
    let case = Case::new();
    case.spend();
    case.spend();
    let whole = fs::read(case.ledger()).expect("ledger");
    case.drop_last_byte();

    let (rc, v) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 1, "{v}");
    assert!(
        message(&v).contains("--restore-final-newline --preview"),
        "{v}"
    );

    let (rc, preview) = case.preview();
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["result"], "preview");
    assert_eq!(preview["seq"], 2);
    let token = preview["token"].as_str().expect("token");
    assert!(token.starts_with("newline1:sha256:"), "{token}");
    assert_eq!(
        fs::read(case.ledger()).expect("ledger").len() + 1,
        whole.len(),
        "a preview changes nothing"
    );

    // The old repair still refuses: the witness counted the line.
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"]);
    assert_eq!(rc, 1, "{v}");
    assert!(
        message(&v).contains("--restore-final-newline --preview"),
        "{v}"
    );

    // A drop-torn-tail token is not accepted here.
    let (rc, v) = case.json(&[
        "repair",
        "p.toml",
        "--restore-final-newline",
        "--token",
        "tail1:sha256:00",
    ]);
    assert_eq!(rc, 1, "{v}");

    let (rc, done) = case.json(&[
        "repair",
        "p.toml",
        "--restore-final-newline",
        "--token",
        token,
    ]);
    assert_eq!(rc, 0, "{done}");
    assert_eq!(done["result"], "repaired");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), whole);
    let (rc, v) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 0, "{v}");
    case.spend();

    // The ledger ends with a line end again: nothing to restore.
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("already ends with a line end"), "{v}");
}

#[test]
fn a_stale_token_is_refused() {
    let case = Case::new();
    case.spend();
    case.drop_last_byte();
    let (_, preview) = case.preview();
    let token = preview["token"].as_str().expect("token").to_owned();
    // The witness moves on (as another machine's spend would not, so edit the
    // ledger length instead): the token no longer fits.
    let mut bytes = fs::read(case.ledger()).expect("ledger");
    let before = bytes.clone();
    bytes.push(b'\n');
    fs::write(case.ledger(), &bytes).expect("write");
    let (rc, v) = case.json(&[
        "repair",
        "p.toml",
        "--restore-final-newline",
        "--token",
        &token,
    ]);
    assert_eq!(rc, 1, "{v}");
    assert_eq!(
        fs::read(case.ledger()).expect("ledger").len(),
        before.len() + 1
    );
}

#[test]
fn a_line_the_witness_did_not_record_is_refused() {
    // The witness is one line behind: the whole last line was never counted.
    let case = Case::new();
    case.spend();
    let witness = fs::read(case.witness()).expect("witness");
    case.spend();
    fs::write(case.witness(), witness).expect("old witness");
    case.drop_last_byte();
    let cut = fs::read(case.ledger()).expect("ledger");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert!(
        message(&v).contains("not the line the witness recorded"),
        "{v}"
    );
    assert_eq!(fs::read(case.ledger()).expect("ledger"), cut);
}

#[test]
fn no_witness_a_cut_line_and_a_damaged_chain_are_refused() {
    let case = Case::new();
    case.spend();
    case.spend();
    let good = fs::read(case.ledger()).expect("ledger");

    // A line cut in the middle is not whole.
    let mut cut = good.clone();
    cut.truncate(cut.len() - 20);
    fs::write(case.ledger(), &cut).expect("write");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), cut);

    // A whole last line with a changed byte does not chain or hash.
    let mut changed = good.clone();
    changed.pop();
    let at = changed.len() - 30;
    changed[at] = if changed[at] == b'0' { b'1' } else { b'0' };
    fs::write(case.ledger(), &changed).expect("write");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), changed);

    // No witness: nothing proves the line was counted.
    let mut whole = good;
    whole.pop();
    fs::write(case.ledger(), &whole).expect("write");
    fs::remove_file(case.witness()).expect("remove witness");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("no witness"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), whole);
}

#[test]
fn one_repair_flag_is_required_and_they_do_not_mix() {
    let case = Case::new();
    let (rc, _) = case.json(&["repair", "p.toml", "--preview"]);
    assert_eq!(rc, 1);
    let (rc, _) = case.json(&[
        "repair",
        "p.toml",
        "--preview",
        "--drop-torn-tail",
        "--restore-final-newline",
    ]);
    assert_eq!(rc, 1);
}
