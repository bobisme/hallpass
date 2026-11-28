//! Short headlines (bn-jyl7): in text mode an error starts with
//! `hallpass CMD: error: CODE: HEADLINE`, then `Next: STEP` when there is
//! one, then the full message indented; doctor's verdict line is the same
//! headline, with `Next:` and then `Details:`. JSON keeps `message` and adds
//! `headline` and `next`.

#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";

const PASS: &str = r#"format = 1
id = "headline-2026-11"
name = "Headline fixture"

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

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let case = Self { dir };
        let path = case.path("p.toml");
        fs::write(&path, PASS).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        settle(&path);
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str], clock: Option<&str>) -> Output {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"));
        if let Some(now) = clock {
            command.env("HALLPASS_UNSAFE_TEST_CLOCK", now);
        }
        command.output().expect("run hallpass")
    }

    /// The text reply (stdout and stderr) and the JSON reply of one command.
    fn both(&self, args: &[&str], clock: Option<&str>) -> (String, Value) {
        let mut text = vec!["--format", "text"];
        text.extend_from_slice(args);
        let out = self.run(&text, clock);
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let mut json = vec!["--format", "json"];
        json.extend_from_slice(args);
        let out = self.run(&json, clock);
        let reply = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (shown, reply)
    }
}

fn settle(path: &Path) {
    let then = SystemTime::now() - Duration::from_secs(5);
    fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_modified(then))
        .expect("backdate");
}

/// The lines of an error from its first line on, up to the closing line.
fn error_lines<'a>(shown: &'a str, prefix: &str) -> Vec<&'a str> {
    let start = shown.find(prefix).unwrap_or_else(|| panic!("{shown}"));
    shown[start..]
        .lines()
        .take_while(|l| *l != "Nothing was permitted.")
        .collect()
}

/// Text lines as the one-line message they show: each step's line has its
/// indent and `- ` taken off, and the steps are joined with a space.
fn joined(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|l| {
            let l = l.trim_start();
            l.strip_prefix("- ").unwrap_or(l)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn an_error_starts_with_its_code_a_headline_and_the_next_step() {
    let case = Case::new();
    fs::set_permissions(case.path("p.toml"), fs::Permissions::from_mode(0o664)).expect("chmod");
    let (shown, reply) = case.both(
        &["--verbose", "spend", "p.toml", "calls", "--to", TO],
        Some(NOW),
    );
    let lines = error_lines(&shown, "hallpass spend: error:");
    let prefix = "hallpass spend: error: insecure-permissions: ";
    let headline = lines[0]
        .strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{shown}"));
    assert!(headline.len() < 100, "{headline}");
    assert!(!headline.contains("p.toml"), "{headline}");
    assert_eq!(lines[1], "Next: run `chmod 600 p.toml`", "{shown}");
    // The full message follows, indented, one step per line, and its
    // words unchanged.
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(lines[2].starts_with("  p.toml has mode 0664"), "{shown}");
    assert!(lines[3].starts_with("    - If you saved it"), "{shown}");
    assert_eq!(joined(&lines[2..]), message, "{shown}");
    assert_eq!(reply["error"]["code"], "insecure-permissions");
    assert_eq!(reply["error"]["headline"].as_str(), Some(headline));
    assert_eq!(reply["error"]["next"], "run `chmod 600 p.toml`");
}

#[test]
fn an_error_without_a_headline_of_its_own_shows_its_message_first() {
    let case = Case::new();
    let (shown, reply) = case.both(&["spend", "p.toml", "calls", "--n", "0"], Some(NOW));
    let lines = error_lines(&shown, "hallpass spend: error:");
    let message = reply["error"]["message"].as_str().expect("message");
    assert_eq!(
        lines,
        [format!("hallpass spend: error: usage: {message}")],
        "{shown}"
    );
    assert_eq!(reply["error"]["headline"].as_str(), Some(message));
    assert_eq!(reply["error"]["next"], Value::Null);
}

#[test]
fn a_rehearsal_ledger_under_the_real_clock_gets_a_short_headline() {
    let case = Case::new();
    let out = case.run(&["spend", "p.toml", "calls", "--to", TO], Some(NOW));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let (shown, reply) = case.both(&["--verbose", "spend", "p.toml", "calls", "--to", TO], None);
    let lines = error_lines(&shown, "hallpass spend: error:");
    assert_eq!(
        lines[0],
        "hallpass spend: error: ledger-clock-mix: the ledger holds rehearsal (test-clock) entries, and this command uses the real clock",
        "{shown}"
    );
    assert_eq!(
        lines[1],
        "Next: run `hallpass doctor p.toml`, which names the safe step"
    );
    assert_eq!(
        Some(joined(&lines[2..]).as_str()),
        reply["error"]["message"].as_str()
    );
    assert!(shown.ends_with("Nothing was permitted.\n"), "{shown}");
}

#[test]
fn a_read_only_command_never_names_adopt_as_the_next_step() {
    let case = Case::new();
    for _ in 0..2 {
        let out = case.run(&["spend", "p.toml", "calls", "--to", TO], Some(NOW));
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    }
    // Put back an older ledger: one line fewer than the witness recorded.
    let ledger = case.path("p.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("ledger");
    let cut: String = text.lines().take(2).flat_map(|l| [l, "\n"]).collect();
    fs::write(&ledger, cut).expect("cut");
    let (shown, reply) = case.both(&["permits", "p.toml", "--to", TO], Some(NOW));
    let lines = error_lines(&shown, "hallpass permits: error:");
    assert!(
        lines[0].starts_with("hallpass permits: error: ledger-changed: "),
        "{shown}"
    );
    assert!(
        lines[1].starts_with("Next: run `hallpass doctor p.toml`"),
        "{shown}"
    );
    assert!(!shown.contains("adopt"), "{shown}");
    assert!(
        !reply["error"]["next"]
            .as_str()
            .unwrap_or_default()
            .contains("adopt")
    );
}

#[test]
fn doctor_puts_the_headline_then_next_then_the_details() {
    let case = Case::new();
    for _ in 0..3 {
        let out = case.run(&["spend", "p.toml", "calls", "--to", TO], Some(NOW));
        assert_eq!(out.status.code(), Some(0), "{out:?}");
    }
    // Damage a middle line.
    let ledger = case.path("p.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("ledger");
    fs::write(&ledger, text.replacen("\"n\":1", "\"n\":0", 1)).expect("damage");
    let (shown, reply) = case.both(&["--verbose", "doctor", "p.toml"], Some(NOW));
    let lines: Vec<&str> = shown.lines().collect();
    assert!(
        lines[0].starts_with("BLOCKED: ledger-corrupt: the ledger is damaged at line "),
        "{shown}"
    );
    assert!(lines[0].len() < 100, "{shown}");
    assert_eq!(
        lines[1],
        "Next: hallpass compare-backups p.toml p.toml.ledger"
    );
    assert!(lines[2].starts_with("  Add each backup copy"), "{shown}");
    assert!(lines[3].starts_with("    - Restore that copy"), "{shown}");
    let details = lines
        .iter()
        .position(|l| *l == "Details:")
        .expect("details");
    let message = reply["message"].as_str().expect("message");
    let rest: Vec<&str> = lines[details + 1..]
        .iter()
        .copied()
        .take_while(|l| l.starts_with("  "))
        .collect();
    // The details are the message's own sentences, without those that
    // repeat the advice under `Next:`.
    assert!(!rest.is_empty(), "{shown}");
    for line in &rest {
        let step = line.trim_start().trim_start_matches("- ");
        assert!(message.contains(step), "{step}: {message}");
    }
    assert!(
        !rest.iter().any(|l| l.contains("compare-backups")),
        "{shown}"
    );
    assert_eq!(
        reply["headline"].as_str(),
        lines[0].strip_prefix("BLOCKED: ledger-corrupt: ")
    );
}
