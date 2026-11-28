//! A file size limit (`ulimit -f`, `RLIMIT_FSIZE`) is handled like a full
//! disk even when `SIGXFSZ` keeps its default action, which ends a process
//! that writes past the limit: hallpass checks the limit before each write
//! and refuses, so it replies and leaves every file as it was (bn-gr5).
//!
//! These tests run the command from `bash` without `trap '' XFSZ`, as a
//! shell or Python's `subprocess` would. `tests/torn_tail_repair.rs` keeps the
//! case with the signal ignored.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"format = 1
id = "fsize-2026-11"
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

    fn command(&self, program: &str) -> Command {
        let home = self.dir.path().join("home");
        let mut command = Command::new(program);
        command
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW);
        command
    }

    /// Run hallpass with `--json` and no file size limit.
    fn json(&self, args: &[&str]) -> (i32, Value) {
        parse(
            &self
                .command(BIN)
                .arg("--json")
                .args(args)
                .output()
                .expect("run"),
        )
    }

    /// Run hallpass with `--json` under `ulimit -f blocks` (1024-byte
    /// blocks), with `SIGXFSZ` left at its default action.
    fn limited(&self, blocks: u64, args: &[&str]) -> (i32, Value) {
        let out = self
            .command("bash")
            .args(["-c", "ulimit -f \"$1\"; shift; exec \"$@\"", "limit"])
            .arg(blocks.to_string())
            .arg(BIN)
            .arg("--json")
            .args(args)
            .output()
            .expect("bash");
        parse(&out)
    }

    fn spend(&self) -> (i32, Value) {
        self.json(&["spend", "p.toml", "calls"])
    }

    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.dir.path())
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn parse(out: &Output) -> (i32, Value) {
    // A process ended by SIGXFSZ has no exit code and no reply.
    let code = out.status.code().unwrap_or_else(|| {
        panic!(
            "ended by a signal ({:?}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (code, v)
}

fn message(v: &Value) -> &str {
    v["error"]["message"].as_str().expect("message")
}

fn size(path: &Path) -> u64 {
    fs::metadata(path).expect("size").len()
}

#[test]
fn a_spend_past_the_file_size_limit_replies_and_records_nothing() {
    let case = Case::new();
    assert_eq!(case.spend().0, 0);
    // Grow the ledger until a line with a long note crosses the next 1 KiB
    // block.
    let blocks = size(&case.ledger()).div_ceil(1024).max(1);
    while size(&case.ledger()) + 200 < blocks * 1024 {
        assert_eq!(case.spend().0, 0);
    }
    let before = fs::read(case.ledger()).expect("ledger");
    let note = "x".repeat(300);
    let (rc, v) = case.limited(blocks, &["spend", "p.toml", "calls", "--note", &note]);
    assert_eq!(rc, 1, "{v}");
    assert_eq!(v["result"], "error", "{v}");
    assert_eq!(v["error"]["code"], "ledger-append-failed", "{v}");
    assert_eq!(v["error"]["recording"], "not-recorded", "{v}");
    assert_eq!(v["error"]["ledger"], "p.toml.ledger", "{v}");
    assert!(message(&v).contains("nothing was recorded"), "{v}");
    assert!(
        message(&v).contains(&format!("file size limit of {} bytes", blocks * 1024)),
        "{v}"
    );
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);

    let (rc, v) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 0, "the ledger is not damaged: {v}");
    let (rc, v) = case.spend();
    assert_eq!(rc, 0, "the next spend succeeds: {v}");
    // A spend whose line fits under the same limit is recorded.
    let (rc, v) = case.limited(blocks + 1, &["spend", "p.toml", "calls"]);
    assert_eq!(rc, 0, "{v}");
}

#[test]
fn a_new_ledger_past_the_file_size_limit_is_not_started() {
    let case = Case::new();
    let (rc, v) = case.limited(0, &["spend", "p.toml", "calls"]);
    assert_eq!(rc, 1, "{v}");
    assert_eq!(v["result"], "error", "{v}");
    assert!(message(&v).contains("file size limit of 0 bytes"), "{v}");
    assert_eq!(
        case.entries(),
        ["home", "p.toml"],
        "no ledger and no temporary file"
    );
    let (rc, v) = case.spend();
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["seq"], 1, "{v}");
}

#[test]
fn a_repair_copy_past_the_file_size_limit_changes_nothing() {
    let case = Case::new();
    for _ in 0..3 {
        assert_eq!(case.spend().0, 0);
    }
    let mut torn = fs::read(case.ledger()).expect("ledger");
    torn.extend_from_slice(br#"{"seq":4,"time":"2026-11-20T09:0"#);
    fs::write(case.ledger(), &torn).expect("tear");
    let (rc, preview) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    let token = preview["token"].as_str().expect("token");

    let (rc, v) = case.limited(
        0,
        &["repair", "p.toml", "--drop-torn-tail", "--token", token],
    );
    assert_eq!(rc, 1, "{v}");
    assert_eq!(v["result"], "error", "{v}");
    assert!(message(&v).contains("file size limit of 0 bytes"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), torn);
    assert_eq!(
        case.entries(),
        ["home", "p.toml", "p.toml.ledger"],
        "no copy is left"
    );

    let (rc, v) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--token", token]);
    assert_eq!(rc, 0, "the same token still works: {v}");
}
