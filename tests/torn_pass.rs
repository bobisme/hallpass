#![cfg(feature = "cli")]
//! A pass read while it is being saved in place (bn-23h).
//!
//! A save that truncates the file and then writes it in pieces leaves a
//! prefix on disk for a moment. A prefix that ends at a line boundary can be
//! a valid pass that grants more than the whole file: here, the pass without
//! its last line, which restricts the address to one name. hallpass reads a
//! pass modified in the last quarter second again once it has gone that long
//! unchanged, and refuses it as `invalid-pass` if anything changed. It also
//! refuses a pass whose last line has no newline.

use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const UNNAMED: &str = "203.0.113.10:443/tcp";
const NAMED: &str = "203.0.113.10:443/tcp@shop.example.com";

/// The last line is the only thing that keeps an unnamed request out.
const PASS: &str = r#"format = 1
id = "torn-2026-11"
name = "Torn write"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[ceilings]
requests = 100

[[destination]]
label = "shop-cdn"
address = "203.0.113.10"
protocol = "tcp"
ports = 443
names = ["shop.example.com"]
"#;

/// The pass without its last line: what a read between two writes sees.
fn prefix() -> &'static str {
    let cut = PASS.trim_end().rfind('\n').expect("lines") + 1;
    &PASS[..cut]
}

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("state")).expect("state");
        Self { dir }
    }

    fn pass(&self) -> PathBuf {
        self.dir.path().join("pass.toml")
    }

    /// Save `text` in place, as an editor or `cat >` does: truncate, write.
    fn save(&self, text: &str) {
        let mut file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.pass())
            .expect("open");
        file.write_all(text.as_bytes()).expect("write");
        fs::set_permissions(self.pass(), fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    /// Save `text` and date it a minute back: a pass nobody is writing.
    fn settled(&self, text: &str) {
        self.save(text);
        let earlier = SystemTime::now() - Duration::from_secs(60);
        File::options()
            .write(true)
            .open(self.pass())
            .and_then(|file| file.set_modified(earlier))
            .expect("date back");
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(["--format", "json"])
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW);
        command
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        reply(&self.command(args).output().expect("run hallpass"))
    }

    fn spend(&self, to: &str) -> (i32, Value) {
        self.json(&["spend", "--to", to, "--", "pass.toml", "requests"])
    }

    /// The debits in the ledger, if there is one.
    fn debits(&self) -> usize {
        let ledger = Path::new(&self.pass()).with_extension("toml.ledger");
        fs::read_to_string(ledger).map_or(0, |text| text.lines().count().saturating_sub(1))
    }
}

fn reply(out: &Output) -> (i32, Value) {
    let value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "not JSON ({e}): {} / {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().expect("exit code"), value)
}

fn file_problem(reply: &Value) -> &str {
    assert_eq!(reply["error"]["code"], "invalid-pass", "{reply}");
    assert_eq!(reply["problems"][0]["field"], "(file)", "{reply}");
    reply["problems"][0]["message"].as_str().expect("message")
}

#[test]
fn the_prefix_alone_would_allow_an_unnamed_spend() {
    // Why a torn read matters: settled, the prefix is a valid, wider pass.
    let case = Case::new();
    case.settled(prefix());
    let (code, reply) = case.spend(UNNAMED);
    assert_eq!((code, &reply["result"]), (0, &Value::from("allowed")));
    case.settled(PASS);
    let (code, reply) = case.spend(UNNAMED);
    assert_eq!(code, 2, "{reply}");
    assert_eq!(reply["refusal"]["code"], "name-required");
}

#[test]
fn a_prefix_completed_while_hallpass_waits_is_refused() {
    let case = Case::new();
    let mut seen = Vec::new();
    // The spend must read before the last line arrives; a slow start reads
    // the whole pass instead, so try a few times.
    for _ in 0..5 {
        case.save(prefix());
        let child = case
            .command(&["spend", "--to", UNNAMED, "--", "pass.toml", "requests"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        std::thread::sleep(Duration::from_millis(100));
        let mut file = File::options()
            .append(true)
            .open(case.pass())
            .expect("open");
        file.write_all(&PASS.as_bytes()[prefix().len()..])
            .expect("the rest of the save");
        let (code, reply) = reply(&child.wait_with_output().expect("wait"));
        assert_ne!(reply["result"], "allowed", "{reply}");
        if code == 1 {
            assert!(
                file_problem(&reply).starts_with("the file changed while hallpass was reading it"),
                "{reply}"
            );
            let message = reply["error"]["message"].as_str().expect("message");
            assert!(
                message.contains("run the command again once the save has finished")
                    && !message.contains("fix each one"),
                "{reply}"
            );
        } else {
            assert_eq!(reply["refusal"]["code"], "name-required", "{reply}");
        }
        seen.push(code);
        if code == 1 {
            break;
        }
    }
    assert!(seen.contains(&1), "never read the prefix: {seen:?}");
    assert_eq!(case.debits(), 0);
}

#[test]
fn a_fresh_pass_is_used_once_it_has_gone_a_quarter_second_unchanged() {
    let case = Case::new();
    let start = Instant::now();
    case.save(PASS);
    let (code, reply) = case.json(&["check", "pass.toml"]);
    assert_eq!((code, &reply["result"]), (0, &Value::from("ok")), "{reply}");
    // The modification time can trail the clock by a timer tick.
    assert!(
        start.elapsed() >= Duration::from_millis(200),
        "{:?}",
        start.elapsed()
    );
    let (code, reply) = case.spend(NAMED);
    assert_eq!(
        (code, &reply["result"]),
        (0, &Value::from("allowed")),
        "{reply}"
    );
    assert_eq!(case.debits(), 1);
}

#[test]
fn a_pass_without_a_final_newline_is_refused() {
    let case = Case::new();
    case.settled(PASS.trim_end());
    let (code, reply) = case.json(&["check", "pass.toml"]);
    assert_eq!(code, 1, "{reply}");
    assert!(
        file_problem(&reply).starts_with("the file does not end with a newline"),
        "{reply}"
    );
    // A cut inside a line can still parse, and move the port: 443 becomes 44.
    let cut = &PASS[..PASS.find("ports = 443").expect("ports") + "ports = 44".len()];
    case.settled(&format!("{cut}\n"));
    let (code, reply) = case.json(&["permits", "--to", "203.0.113.10:44/tcp", "--", "pass.toml"]);
    assert_eq!(
        (code, &reply["result"]),
        (0, &Value::from("allowed")),
        "{reply}"
    );
    case.settled(cut);
    let (code, reply) = case.json(&["permits", "--to", "203.0.113.10:44/tcp", "--", "pass.toml"]);
    assert_eq!(code, 1, "{reply}");
    assert!(file_problem(&reply).starts_with("the file does not end with a newline"));
    for (what, args) in [
        (
            "spend",
            vec!["spend", "--to", NAMED, "--", "pass.toml", "requests"],
        ),
        ("digest", vec!["digest", "pass.toml"]),
        ("status", vec!["status", "pass.toml"]),
    ] {
        let (code, reply) = case.json(&args);
        assert_eq!(code, 1, "{what}: {reply}");
        assert!(file_problem(&reply).starts_with("the file does not end with a newline"));
    }
    assert_eq!(case.debits(), 0);
}
