//! Doctor is BLOCKED when a required counter is at its ceiling, and
//! `--drop-torn-tail` removes a tail of only NUL bytes (bn-2m96).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
const NOW: &str = "2026-11-20T09:00:00Z";

fn pass_text(extra: &str, ceilings: &str) -> String {
    format!(
        r#"format = 1
id = "nul-tail-2026-11"
name = "Example voice edge"
{extra}
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
{ceilings}
"#
    )
}

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new(extra: &str, ceilings: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let pass = dir.path().join("p.toml");
        fs::write(&pass, pass_text(extra, ceilings)).expect("write");
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

    fn witness(&self) -> PathBuf {
        self.path("home/state/hallpass/nul-tail-2026-11.witness")
    }

    fn run(&self, args: &[&str]) -> (i32, String) {
        let home = self.path("home");
        let out = Command::new(BIN)
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .args(args)
            .output()
            .expect("run");
        (
            out.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
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
            let (rc, text) = self.run(&["spend", "p.toml", "calls"]);
            assert_eq!(rc, 0, "{text}");
        }
    }
}

#[test]
fn a_required_counter_at_its_ceiling_blocks_doctor() {
    let case = Case::new(
        "required_counters_v1 = [\"calls\", \"bytes\"]",
        "calls = 5\nbytes = 10",
    );
    let (rc, text) = case.run(&[
        "spend",
        "--charge",
        "calls=1",
        "--charge",
        "bytes=10",
        "--to",
        "192.0.2.10:5060/udp",
        "--",
        "p.toml",
    ]);
    assert_eq!(rc, 0, "{text}");
    let (rc, text) = case.run(&["--verbose", "doctor", "p.toml"]);
    assert_eq!(rc, 2, "{text}");
    assert!(
        text.starts_with("BLOCKED: ceiling-reached: required counter bytes"),
        "{text}"
    );
    assert!(text.contains("required_counters_v1"), "{text}");
    assert!(!text.contains("HEALTHY"), "{text}");
    let (rc, v) = case.json(&["doctor", "p.toml"]);
    assert_eq!(rc, 2, "{v}");
    assert_eq!(v["result"], "blocked");
    let (rc, text) = case.run(&[
        "capacity",
        "p.toml",
        "--charge",
        "calls=1",
        "--charge",
        "bytes=1",
        "--to",
        "192.0.2.10:5060/udp",
    ]);
    assert_eq!(rc, 0, "{text}");
    assert!(text.contains("0 unit(s)"), "{text}");
}

#[test]
fn a_required_counter_with_a_ceiling_of_zero_blocks_doctor() {
    let case = Case::new(
        "required_counters_v1 = [\"calls\", \"bytes\"]",
        "calls = 5\nbytes = 0",
    );
    let (rc, text) = case.run(&["doctor", "p.toml"]);
    assert_eq!(rc, 2, "{text}");
    assert!(text.contains("required counter bytes"), "{text}");
}

#[test]
fn an_optional_counter_at_its_ceiling_stays_healthy() {
    let case = Case::new("required_counters_v1 = [\"calls\"]", "calls = 5\nbytes = 0");
    let (rc, text) = case.run(&["doctor", "p.toml"]);
    assert_eq!(rc, 0, "{text}");
    assert!(text.starts_with("HEALTHY"), "{text}");
}

/// Keep the witness one spend behind, as when the process died before
/// updating it, then replace the last line by `tail(last)`.
fn crash_with(case: &Case, tail: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    case.spend(3);
    let behind = fs::read(case.witness()).expect("witness");
    case.spend(1);
    fs::write(case.witness(), behind).expect("witness back");
    let bytes = fs::read(case.ledger()).expect("ledger");
    let body = &bytes[..bytes.len() - 1];
    let cut = body.iter().rposition(|b| *b == b'\n').expect("line") + 1;
    let (head, last) = bytes.split_at(cut);
    fs::write(case.ledger(), [head, &tail(last)].concat()).expect("write");
    last.to_vec()
}

fn repair(case: &Case) -> (i32, Value) {
    let (rc, preview) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"]);
    if rc != 0 {
        return (rc, preview);
    }
    let token = preview["token"].as_str().expect("token").to_owned();
    case.json(&["repair", "p.toml", "--drop-torn-tail", "--token", &token])
}

#[test]
fn a_nul_filled_last_line_is_dropped_and_its_bytes_kept() {
    let case = Case::new("", "calls = 10");
    let last = crash_with(&case, |last| vec![0; last.len()]);
    let (rc, text) = case.run(&["doctor", "p.toml"]);
    assert_eq!(rc, 2, "{text}");
    assert!(text.contains("--drop-torn-tail --preview"), "{text}");
    assert!(text.contains("NUL bytes"), "{text}");
    let (rc, done) = repair(&case);
    assert_eq!(rc, 0, "{done}");
    assert_eq!(done["result"], "repaired");
    assert_eq!(done["nul_only"], true);
    assert_eq!(done["removed_bytes"], last.len());
    let copy = fs::read(case.path(done["copy"].as_str().expect("copy"))).expect("copy");
    assert_eq!(copy, vec![0; last.len()]);
    case.spend(1);
    assert_eq!(case.run(&["doctor", "p.toml"]).0, 0);
}

#[test]
fn nul_bytes_then_a_line_end_and_white_space_are_dropped_too() {
    let case = Case::new("", "calls = 10");
    crash_with(&case, |_| b"\0\0\0\0\n \n".to_vec());
    let (rc, done) = repair(&case);
    assert_eq!(rc, 0, "{done}");
    assert_eq!(done["removed_bytes"], 7);
    let copy = fs::read(case.path(done["copy"].as_str().expect("copy"))).expect("copy");
    assert_eq!(copy, b"\0\0\0\0\n \n");
    case.spend(1);
}

#[test]
fn nul_bytes_after_the_last_witnessed_line_are_dropped() {
    let case = Case::new("", "calls = 10");
    case.spend(3);
    let mut bytes = fs::read(case.ledger()).expect("ledger");
    bytes.extend_from_slice(b"\0\0\0\n");
    fs::write(case.ledger(), bytes).expect("write");
    let (rc, done) = repair(&case);
    assert_eq!(rc, 0, "{done}");
    assert_eq!(done["seq"], 3);
    assert_eq!(done["removed_bytes"], 4);
    case.spend(1);
}

#[test]
fn a_nul_tail_the_witness_counted_is_refused() {
    let case = Case::new("", "calls = 10");
    case.spend(4);
    let bytes = fs::read(case.ledger()).expect("ledger");
    let body = &bytes[..bytes.len() - 1];
    let cut = body.iter().rposition(|b| *b == b'\n').expect("line") + 1;
    let mut damaged = bytes[..cut].to_vec();
    damaged.extend_from_slice(&vec![0; bytes.len() - cut]);
    fs::write(case.ledger(), &damaged).expect("write");
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"]);
    assert_ne!(rc, 0, "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), damaged);
}

#[test]
fn mixed_bytes_and_a_whole_line_with_nuls_are_still_refused() {
    let case = Case::new("", "calls = 10");
    crash_with(&case, |last| {
        let mut v = last[..last.len() - 1].to_vec();
        v.extend_from_slice(b"\0\0\n");
        v
    });
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"]);
    assert_ne!(rc, 0, "{v}");
    let case = Case::new("", "calls = 10");
    crash_with(&case, |_| b"x\0\0".to_vec());
    let (rc, v) = case.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"]);
    assert_ne!(rc, 0, "{v}");
}

#[test]
fn a_nul_line_names_the_torn_tail_repair() {
    let case = Case::new("", "calls = 10");
    case.spend(2);
    let mut bytes = fs::read(case.ledger()).expect("read ledger");
    bytes.extend_from_slice(&[0u8; 40]);
    bytes.push(b'\n');
    fs::write(case.ledger(), bytes).expect("write ledger");
    let (rc, text) = case.run(&["spend", "p.toml", "calls"]);
    assert_ne!(rc, 0, "{text}");
    assert!(text.contains("holds only NUL bytes"), "{text}");
    assert!(text.contains("--drop-torn-tail --preview"), "{text}");
}
