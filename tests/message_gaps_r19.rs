//! Message gaps (bn-22ra): a ledger given as a pass, a first spend whose
//! ledger header cannot be written, the next step of `archive-corrupt`, an
//! option placed after `--`, and the restore step of `compare-backups`.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"format = 1
id = "gaps-2026-11"
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
        let case = Self { dir };
        case.write("p.toml", PASS);
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated back so that hallpass reads it at once.
    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(10)))
            .expect("backdate");
    }

    fn command(&self, program: &str) -> Command {
        let home = self.path("home");
        let mut command = Command::new(program);
        command
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("TMPDIR", self.dir.path())
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(BIN)
            .arg("--json")
            .args(args)
            .output()
            .expect("run hallpass")
    }

    fn json(&self, args: &[&str]) -> Value {
        json(&self.run(args))
    }

    fn spend(&self) {
        let reply = self.json(&["spend", "p.toml", "calls"]);
        assert_eq!(reply["result"], "allowed", "{reply}");
    }
}

fn json(out: &Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn message(reply: &Value) -> String {
    reply["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn a_ledger_given_as_a_pass_says_what_it_is_and_which_file_to_give() {
    let case = Case::new();
    case.spend();
    let reply = case.json(&["check", "p.toml.ledger"]);
    assert_eq!(reply["error"]["code"], "invalid-pass", "{reply}");
    let text = reply.to_string();
    assert!(!text.contains("not valid TOML"), "{text}");
    assert!(!text.contains("fix the syntax"), "{text}");
    let problem = reply["problems"][0]["message"].as_str().unwrap_or_default();
    assert!(
        problem.contains("the ledger of pass \"gaps-2026-11\""),
        "{problem}"
    );
    assert!(problem.contains("give the pass file"), "{problem}");
    assert!(problem.contains("\"p.toml\""), "{problem}");
    let next = reply["error"]["next"].as_str().unwrap_or_default();
    assert!(next.contains("give the pass file"), "{next}");

    // A spend given the ledger says the same, and records nothing more.
    let spent = case.json(&["spend", "p.toml.ledger", "calls"]);
    assert_eq!(spent["error"]["code"], "invalid-pass", "{spent}");
    assert!(spent.to_string().contains("the ledger of pass"), "{spent}");
    let ledger = fs::read_to_string(case.path("p.toml.ledger")).expect("ledger");
    assert_eq!(ledger.lines().count(), 2, "{ledger}");
}

#[test]
fn a_witness_or_checkpoint_given_as_a_pass_is_named() {
    let case = Case::new();
    case.write(
        "w.json",
        "{\"hallpass_witness\":1,\"pass_id\":\"gaps-2026-11\",\"seq\":1}\n",
    );
    let reply = case.json(&["check", "w.json"]);
    assert!(
        reply.to_string().contains("the witness record of pass"),
        "{reply}"
    );
    case.write(
        "c.json",
        "{\"version\":1,\"pass_id\":\"gaps-2026-11\",\"seq\":1,\"hash\":\"sha256:00\"}\n",
    );
    let reply = case.json(&["check", "c.json"]);
    assert!(
        reply.to_string().contains("a checkpoint of pass"),
        "{reply}"
    );
    // Another file that is not TOML keeps the TOML message.
    case.write("x.json", "{\"hello\":1}\n");
    let reply = case.json(&["check", "x.json"]);
    assert!(reply.to_string().contains("not valid TOML"), "{reply}");
}

#[test]
fn a_first_spend_that_cannot_write_the_header_is_not_recorded() {
    let case = Case::new();
    let out = case
        .command("bash")
        .args(["-c", "ulimit -f 0; exec \"$@\"", "limit", BIN, "--json"])
        .args(["spend", "p.toml", "calls"])
        .output()
        .expect("bash");
    let reply = json(&out);
    assert_eq!(out.status.code(), Some(1), "{reply}");
    assert_eq!(reply["error"]["code"], "ledger-append-failed", "{reply}");
    assert_eq!(reply["error"]["recording"], "not-recorded", "{reply}");
    let next = reply["error"]["next"].as_str().unwrap_or_default();
    assert!(next.contains("raise the file size limit"), "{next}");
    assert!(!case.path("p.toml.ledger").exists());
    // Without the limit the first spend works.
    case.spend();
}

#[test]
fn archive_corrupt_has_a_next_step() {
    let case = Case::new();
    fs::create_dir(case.path("arch")).expect("archive");
    fs::set_permissions(case.path("arch"), fs::Permissions::from_mode(0o700)).expect("private");
    let archived = case.json(&["archive", "p.toml", "arch"]);
    let digest = archived["digest"].as_str().expect("digest").to_owned();
    let entry = case.path("arch").join(&digest);
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o600)).expect("writable");
    fs::write(&entry, PASS.replace("calls = 200", "calls = 900")).expect("edit");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o400)).expect("read only");

    let reply = case.json(&["retrieve", "arch", &digest]);
    assert_eq!(reply["error"]["code"], "archive-corrupt", "{reply}");
    let next = reply["error"]["next"].as_str().unwrap_or_default();
    assert!(
        next.contains("restore that entry from its backup"),
        "{next}"
    );
    assert!(next.contains("never edit"), "{next}");
    let out = case
        .command(BIN)
        .args(["retrieve", "arch", &digest])
        .output()
        .expect("run");
    let text =
        String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Next: restore that entry from its backup"),
        "{text}"
    );
}

#[test]
fn an_option_after_double_dash_gets_a_hint() {
    let case = Case::new();
    let reply = case.json(&[
        "spend",
        "--",
        "p.toml",
        "calls",
        "--to",
        "192.0.2.10:5060/udp",
    ]);
    assert_eq!(reply["error"]["code"], "usage", "{reply}");
    assert!(
        message(&reply).contains("options go before `--`; everything after `--` is a FILE"),
        "{reply}"
    );
    // An unknown option before `--` gets no such hint.
    let reply = case.json(&["spend", "p.toml", "calls", "--too", "x"]);
    assert!(!message(&reply).contains("options go before"), "{reply}");
}

/// A pass with three spends, and an exact copy of its ledger as `bk`.
fn with_backup() -> Case {
    let case = Case::new();
    for _ in 0..3 {
        case.spend();
    }
    fs::copy(case.path("p.toml.ledger"), case.path("bk")).expect("copy");
    case
}

fn advice_of(reply: &Value) -> Vec<Value> {
    reply["advice"].as_array().cloned().unwrap_or_default()
}

fn argv_of(advice: &Value) -> Vec<String> {
    advice["argv"]
        .as_array()
        .expect("argv")
        .iter()
        .map(|w| w.as_str().expect("word").to_owned())
        .collect()
}

#[test]
fn an_exact_copy_is_advised_when_the_ledger_is_damaged() {
    let case = with_backup();
    let ledger = fs::read_to_string(case.path("p.toml.ledger")).expect("ledger");
    let damaged = ledger.replacen("\"n\":1", "\"n\":0", 1);
    assert_ne!(ledger, damaged);
    fs::write(case.path("p.toml.ledger"), damaged).expect("damage");
    let reply = case.json(&["compare-backups", "p.toml", "bk"]);
    assert_eq!(reply["assessment"], "preserved", "{reply}");
    let advice = advice_of(&reply);
    assert_eq!(advice.len(), 1, "{reply}");
    assert_eq!(argv_of(&advice[0]), ["cp", "-p", "bk", "p.toml.ledger"]);
    assert!(
        advice[0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("hallpass doctor"),
        "{reply}"
    );
    // Following the advice makes the pass usable again.
    let cp = argv_of(&advice[0]);
    let done = Command::new(&cp[0])
        .args(&cp[1..])
        .current_dir(case.dir.path())
        .status()
        .expect("cp");
    assert!(done.success());
    case.spend();
}

#[test]
fn an_exact_copy_is_advised_when_the_ledger_is_missing() {
    let case = with_backup();
    fs::remove_file(case.path("p.toml.ledger")).expect("remove");
    let reply = case.json(&["compare-backups", "p.toml", "bk"]);
    let advice = advice_of(&reply);
    assert_eq!(advice.len(), 1, "{reply}");
    assert_eq!(argv_of(&advice[0])[..3], ["cp", "-p", "bk"]);
}

#[test]
fn an_exact_copy_is_never_advised_over_an_intact_ledger() {
    let case = with_backup();
    let reply = case.json(&["compare-backups", "p.toml", "bk"]);
    assert_eq!(reply["assessment"], "preserved", "{reply}");
    assert!(advice_of(&reply).is_empty(), "{reply}");
}
