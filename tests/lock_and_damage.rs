//! The writer-lock wait notice, the lock-timeout advice, and the advice for
//! a damaged ledger by where the damage is.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"format = 1
id = "example-2026-11"
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
calls = 20
"#;

struct Case {
    dir: tempfile::TempDir,
    pass: PathBuf,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let pass = dir.path().join("p.toml");
        fs::write(&pass, PASS).expect("write");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        Self { dir, pass }
    }

    fn command(&self, args: &[&str]) -> Command {
        let home = self.dir.path().join("home");
        let mut command = Command::new(BIN);
        command
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> (i32, Output) {
        let output = self.command(args).output().expect("run");
        (output.status.code().expect("code"), output)
    }

    fn spend_json(&self) -> (i32, Value) {
        let (rc, out) = self.run(&["--format", "json", "spend", s(&self.pass), "calls"]);
        let v = serde_json::from_slice(&out.stdout).expect("one JSON object");
        (rc, v)
    }

    fn lock_path(&self) -> PathBuf {
        self.dir
            .path()
            .join("home/state/hallpass/example-2026-11.lock")
    }

    fn ledger(&self) -> PathBuf {
        self.dir.path().join("p.toml.ledger")
    }
}

fn s(path: &Path) -> &str {
    path.to_str().expect("utf8")
}

fn message(v: &Value) -> String {
    v["error"]["message"].as_str().expect("message").to_owned()
}

#[test]
fn a_waiting_spend_says_so_on_stderr_and_keeps_json_stdout_clean() {
    waiting_spend_says_so(&["calls"]);
}

/// A debit (`--charge`, or a caller reference) takes the lock on its own
/// path, and must say so too.
#[test]
fn a_waiting_debit_says_so_too() {
    waiting_spend_says_so(&["--charge", "calls=1", "--caller-ref", "unit-1"]);
}

fn waiting_spend_says_so(unit: &[&str]) {
    let case = Case::new();
    assert_eq!(case.spend_json().0, 0);
    let holder = fs::OpenOptions::new()
        .write(true)
        .open(case.lock_path())
        .expect("lock file");
    holder.lock().expect("hold the writer lock");
    let mut args = vec!["--format", "json", "spend", s(&case.pass)];
    args.extend_from_slice(unit);
    let child = case
        .command(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(3200));
    drop(holder);
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("waiting for the writer lock").count(),
        1,
        "{stderr}"
    );
    assert!(stderr.contains(s(&case.lock_path())), "{stderr}");
    if cfg!(target_os = "linux") {
        // Under a loaded parallel run /proc/locks can briefly name another
        // process sharing the open file, or no process yet, so accept either
        // form of the holder line rather than this exact process.
        assert!(
            stderr.contains("held by process ") || stderr.contains("held by another process"),
            "{stderr}"
        );
    } else {
        assert!(stderr.contains("fuser"), "{stderr}");
    }
    let v: Value = serde_json::from_slice(&out.stdout).expect("stdout is one JSON object");
    assert_eq!(v["result"], "allowed");
}

#[test]
fn a_quick_spend_prints_no_waiting_notice() {
    let case = Case::new();
    let (rc, out) = case.run(&["spend", s(&case.pass), "calls"]);
    assert_eq!(rc, 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("waiting for the writer lock"), "{stderr}");
}

#[test]
fn a_lock_timeout_says_what_to_do() {
    let case = Case::new();
    assert_eq!(case.spend_json().0, 0);
    let holder = fs::OpenOptions::new()
        .write(true)
        .open(case.lock_path())
        .expect("lock file");
    holder.lock().expect("hold");
    let (rc, out) = case.run(&[
        "--format",
        "json",
        "spend",
        s(&case.pass),
        "calls",
        "--lock-timeout-ms",
        "300",
    ]);
    assert_eq!(rc, 1);
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["error"]["code"], "lock-timeout");
    assert_eq!(v["error"]["recording"], "not-recorded");
    let m = message(&v);
    assert!(m.contains("Retry, or find and stop the process"), "{m}");
    assert!(m.contains("fuser"), "{m}");
    assert!(m.contains("released automatically"), "{m}");
}

#[test]
fn a_mid_file_edit_names_both_lines_and_advises_a_backup() {
    let case = Case::new();
    for _ in 0..5 {
        assert_eq!(case.spend_json().0, 0);
    }
    let text = fs::read_to_string(case.ledger()).expect("ledger");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 6);
    lines[2] = lines[2].replace("\"n\":1", "\"n\":9");
    fs::write(case.ledger(), lines.join("\n") + "\n").expect("damage");
    let (rc, v) = case.spend_json();
    assert_eq!(rc, 1);
    assert_eq!(v["error"]["code"], "ledger-corrupt");
    assert_eq!(v["error"]["line"], 4);
    assert_eq!(v["error"]["last_line"], false);
    let m = message(&v);
    assert!(m.contains("line 4 does not follow line 3"), "{m}");
    assert!(m.contains("hallpass compare-backups"), "{m}");
    assert!(m.contains("do not edit lines by hand"), "{m}");
    assert!(!m.contains("cut short"), "{m}");
}

#[test]
fn a_cut_short_last_line_keeps_the_cut_short_advice() {
    let case = Case::new();
    for _ in 0..3 {
        assert_eq!(case.spend_json().0, 0);
    }
    let bytes = fs::read(case.ledger()).expect("ledger");
    fs::write(case.ledger(), &bytes[..bytes.len() - 3]).expect("cut");
    let (rc, v) = case.spend_json();
    assert_eq!(rc, 1);
    assert_eq!(v["error"]["code"], "ledger-corrupt");
    assert_eq!(v["error"]["line"], 4);
    assert_eq!(v["error"]["last_line"], true);
    let m = message(&v);
    assert!(m.contains("--drop-torn-tail --preview"), "{m}");
    assert!(m.contains("Do not edit the ledger by hand"), "{m}");
}
