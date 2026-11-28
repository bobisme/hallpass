//! `hallpass repair --drop-blank-tail` removes empty lines added after the
//! last witnessed ledger line, and refuses anything else (bn-1otp). Also
//! doctor's `compare-backups` exit status and its words for a ledger moved
//! aside as `.damaged`.

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
id = "blank-tail-2026-11"
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

struct Run {
    code: i32,
    text: String,
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

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn ledger(&self) -> PathBuf {
        self.path("p.toml.ledger")
    }

    fn run(&self, args: &[&str]) -> Run {
        let home = self.path("home");
        let out = Command::new(BIN)
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .args(args)
            .output()
            .expect("run");
        Run {
            code: out.status.code().unwrap_or(-1),
            text: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let home = self.path("home");
        let out = Command::new(BIN)
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .args(&all)
            .output()
            .expect("run");
        let v = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
        (out.status.code().unwrap_or(-1), v)
    }

    fn spend(&self, times: usize) {
        for _ in 0..times {
            let r = self.run(&["spend", "p.toml", "calls"]);
            assert_eq!(r.code, 0, "{}", r.text);
        }
    }

    fn append(&self, bytes: &[u8]) {
        use std::io::Write as _;
        fs::File::options()
            .append(true)
            .open(self.ledger())
            .expect("open")
            .write_all(bytes)
            .expect("append");
    }

    fn token(&self) -> String {
        let (rc, v) = self.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
        assert_eq!(rc, 0, "{v}");
        v["token"].as_str().expect("token").to_owned()
    }
}

fn message(v: &Value) -> String {
    v["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_blank_line_after_the_witnessed_tail_is_removed_and_the_pass_spends_again() {
    let case = Case::new();
    case.spend(3);
    let whole = fs::read(case.ledger()).expect("ledger");
    case.append(b"\n");

    let status = case.run(&["status", "p.toml"]);
    assert_eq!(status.code, 1, "{}", status.text);
    assert!(
        status.text.contains("--drop-blank-tail --preview"),
        "{}",
        status.text
    );

    let doctor = case.run(&["doctor", "p.toml"]);
    assert!(
        doctor
            .text
            .contains("Next: hallpass repair p.toml --drop-blank-tail --preview"),
        "{}",
        doctor.text
    );

    let (rc, preview) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["result"], "preview");
    assert_eq!(preview["seq"], 3);
    assert_eq!(preview["removed_bytes"], 1);
    let token = preview["token"].as_str().expect("token");
    assert!(token.starts_with("blank1:sha256:"), "{token}");
    assert_eq!(
        fs::read(case.ledger()).expect("ledger").len(),
        whole.len() + 1
    );

    let (rc, done) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--token", token]);
    assert_eq!(rc, 0, "{done}");
    assert_eq!(done["result"], "repaired");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), whole);
    let healthy = case.run(&["doctor", "p.toml"]);
    assert_eq!(healthy.code, 0, "{}", healthy.text);
    case.spend(1);
}

#[test]
fn several_blank_lines_and_white_space_are_removed_too() {
    let case = Case::new();
    case.spend(2);
    let whole = fs::read(case.ledger()).expect("ledger");
    case.append(b"\n  \n\t\r\n\n   ");
    let token = case.token();
    let (rc, done) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--token", &token]);
    assert_eq!(rc, 0, "{done}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), whole);
}

#[test]
fn anything_but_a_blank_tail_after_the_witnessed_line_is_refused() {
    // No blank tail.
    let case = Case::new();
    case.spend(2);
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
    assert_eq!(rc, 1, "{v}");
    assert!(
        message(&v).contains("does not end with an empty line"),
        "{v}"
    );

    // Something that is not blank after the blank line.
    let case = Case::new();
    case.spend(2);
    case.append(b"\ngarbage\n");
    let before = fs::read(case.ledger()).expect("ledger");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("Nothing was changed"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);

    // A last line that the witness did not record: the witness is ahead.
    let case = Case::new();
    case.spend(2);
    let old = fs::read(case.ledger()).expect("ledger");
    case.spend(1);
    fs::write(case.ledger(), [old, b"\n".to_vec()].concat()).expect("write");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
    assert_eq!(rc, 1, "{v}");
    assert!(
        message(&v).contains("not the line the witness recorded"),
        "{v}"
    );

    // A real last line that was edited: it does not chain.
    let case = Case::new();
    case.spend(2);
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    fs::write(
        case.ledger(),
        format!("{}\n\n", text.trim_end().replacen("\"n\":1", "\"n\":0", 1)),
    )
    .expect("write");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
    assert_eq!(rc, 1, "{v}");

    // No witness.
    let case = Case::new();
    case.spend(2);
    case.append(b"\n");
    fs::remove_file(case.path("home/state/hallpass/blank-tail-2026-11.witness")).expect("rm");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--preview"]);
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("no witness"), "{v}");
}

#[test]
fn a_malformed_or_stale_token_changes_nothing() {
    let case = Case::new();
    case.spend(2);
    case.append(b"\n");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--token", "nope"]);
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("is not a repair token"), "{v}");

    let token = case.token();
    case.append(b"\n");
    let before = fs::read(case.ledger()).expect("ledger");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-blank-tail", "--token", &token]);
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("stale"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);
}

#[test]
fn compare_backups_does_not_count_the_damaged_live_ledger_as_a_failed_backup() {
    let case = Case::new();
    case.spend(2);
    fs::copy(case.ledger(), case.path("friday.ledger")).expect("copy");
    case.spend(1);
    fs::copy(case.ledger(), case.path("saturday.ledger")).expect("copy");
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    fs::write(case.ledger(), text.replacen("\"n\":1", "\"n\":0", 3)).expect("edit");

    let r = case.run(&[
        "compare-backups",
        "p.toml",
        "p.toml.ledger",
        "saturday.ledger",
    ]);
    assert_eq!(r.code, 0, "{}", r.text);
    assert!(r.text.contains("Backup assessment preserved"), "{}", r.text);
    assert!(
        r.text.contains("ledger-corrupt"),
        "the row stays: {}",
        r.text
    );
    let (rc, v) = case.json(&[
        "compare-backups",
        "p.toml",
        "p.toml.ledger",
        "saturday.ledger",
    ]);
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["errors"], 0);

    // With only an older copy the answer is no-match, not a partial error.
    let r = case.run(&[
        "compare-backups",
        "p.toml",
        "p.toml.ledger",
        "friday.ledger",
    ]);
    assert_eq!(r.code, 2, "{}", r.text);

    // A backup that cannot be read still makes the run a partial error.
    fs::write(case.path("bad.ledger"), "not a ledger\n").expect("bad");
    let r = case.run(&[
        "compare-backups",
        "p.toml",
        "p.toml.ledger",
        "saturday.ledger",
        "bad.ledger",
    ]);
    assert_eq!(r.code, 1, "{}", r.text);
}

#[test]
fn doctor_after_moving_the_damaged_ledger_aside_goes_on_to_the_adoption_preview() {
    let case = Case::new();
    case.spend(2);
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    fs::write(case.ledger(), text.replacen("\"n\":1", "\"n\":0", 2)).expect("edit");
    let before = case.run(&["doctor", "p.toml"]);
    assert!(
        before.text.contains("p.toml.ledger.damaged"),
        "{}",
        before.text
    );

    fs::rename(case.ledger(), case.path("p.toml.ledger.damaged")).expect("mv");
    let after = case.run(&["doctor", "p.toml"]);
    assert!(
        !after.text.contains("First put the ledger back"),
        "{}",
        after.text
    );
    assert!(
        after
            .text
            .contains("You moved the damaged ledger aside (p.toml.ledger.damaged)"),
        "{}",
        after.text
    );
    assert!(
        after.text.contains("Next: hallpass adopt p.toml --preview"),
        "{}",
        after.text
    );

    // Another one, numbered.
    fs::write(case.path("p.toml.ledger.damaged-2"), "x\n").expect("second");
    let after = case.run(&["doctor", "p.toml"]);
    assert!(
        after
            .text
            .contains("p.toml.ledger.damaged, p.toml.ledger.damaged-2"),
        "{}",
        after.text
    );
}

#[test]
fn a_missing_ledger_with_nothing_moved_aside_keeps_the_put_it_back_step() {
    let case = Case::new();
    case.spend(2);
    fs::remove_file(case.ledger()).expect("rm");
    let r = case.run(&["doctor", "p.toml"]);
    assert!(r.text.contains("First put the ledger back"), "{}", r.text);
}
