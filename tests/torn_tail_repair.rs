//! A failed ledger append is rolled back (`ledger-append-failed`, nothing
//! recorded), and `hallpass repair --drop-torn-tail` removes a last line cut
//! short, only when the witness proves it was never counted (bn-2pi).

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
id = "torn-2026-11"
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
            .join("home/state/hallpass/torn-2026-11.witness")
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

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = self
            .command(BIN)
            .arg("--json")
            .args(args)
            .output()
            .expect("run");
        parse(&out)
    }

    fn spend(&self) -> (i32, Value) {
        self.json(&["spend", "p.toml", "calls"])
    }

    fn preview(&self) -> (i32, Value) {
        self.json(&["repair", "p.toml", "--drop-torn-tail", "--preview"])
    }

    fn repair(&self, token: &str) -> (i32, Value) {
        self.json(&["repair", "p.toml", "--drop-torn-tail", "--token", token])
    }

    /// Three spends, so the ledger has a header and lines 1 to 3, and the
    /// witness recorded sequence 3.
    fn three_spends(&self) -> Vec<u8> {
        for _ in 0..3 {
            assert_eq!(self.spend().0, 0);
        }
        fs::read(self.ledger()).expect("ledger")
    }

    fn append(&self, bytes: &[u8]) {
        let mut all = fs::read(self.ledger()).expect("ledger");
        all.extend_from_slice(bytes);
        fs::write(self.ledger(), all).expect("write");
    }
}

fn parse(out: &Output) -> (i32, Value) {
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().expect("code"), v)
}

fn message(v: &Value) -> &str {
    v["error"]["message"].as_str().expect("message")
}

fn size(path: &Path) -> u64 {
    fs::metadata(path).expect("size").len()
}

#[test]
fn a_spend_that_hits_the_file_size_limit_leaves_the_ledger_as_it_was() {
    let case = Case::new();
    assert_eq!(case.spend().0, 0);
    // Grow the ledger until a line with a long note crosses the next 1 KiB
    // block, which `ulimit -f` (in 1024-byte blocks) refuses. SIGXFSZ is
    // ignored here; tests/file_size_limit.rs runs with its default action.
    let blocks = size(&case.ledger()).div_ceil(1024).max(1);
    while size(&case.ledger()) + 200 < blocks * 1024 {
        assert_eq!(case.spend().0, 0);
    }
    let before = fs::read(case.ledger()).expect("ledger");
    let note = "x".repeat(300);
    let out = case
        .command("bash")
        .args([
            "-c",
            "trap '' XFSZ; ulimit -f \"$1\"; shift; exec \"$@\"",
            "limit",
            &blocks.to_string(),
            BIN,
            "--json",
            "spend",
            "p.toml",
            "calls",
            "--note",
            &note,
        ])
        .output()
        .expect("bash");
    let (rc, v) = parse(&out);
    assert_eq!(rc, 1, "{v}");
    assert_eq!(v["error"]["code"], "ledger-append-failed", "{v}");
    assert_eq!(v["error"]["recording"], "not-recorded", "{v}");
    assert_eq!(v["error"]["ledger"], "p.toml.ledger", "{v}");
    assert!(message(&v).contains("nothing was recorded"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);
    let (rc, v) = case.spend();
    assert_eq!(rc, 0, "the next spend succeeds: {v}");
}

#[test]
fn a_torn_last_line_is_removed_and_kept_beside_the_ledger() {
    let case = Case::new();
    let before = case.three_spends();
    case.append(br#"{"seq":4,"time":"2026-11-20T09:0"#);
    let (rc, v) = case.spend();
    assert_eq!(rc, 1);
    assert_eq!(v["error"]["code"], "ledger-corrupt");
    assert!(
        message(&v).contains("hallpass repair") && message(&v).contains("--drop-torn-tail"),
        "{v}"
    );

    let (rc, preview) = case.preview();
    assert_eq!(rc, 0, "{preview}");
    assert_eq!(preview["command"], "repair");
    assert_eq!(preview["result"], "preview");
    assert_eq!(preview["seq"], 3);
    assert_eq!(preview["witness_seq"], 3);
    assert_eq!(preview["removed_bytes"], 32);
    assert_eq!(preview["copy"], Value::Null);
    let token = preview["token"].as_str().expect("token");
    assert!(token.starts_with("tail1:sha256:"), "{token}");

    let (rc, v) = case.repair(token);
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["result"], "repaired");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);
    assert_eq!(v["copy"], "p.toml.ledger.torn-4");
    let copy = case.dir.path().join("p.toml.ledger.torn-4");
    assert_eq!(
        fs::read(&copy).expect("copy"),
        br#"{"seq":4,"time":"2026-11-20T09:0"#
    );
    assert_eq!(
        fs::metadata(&copy).expect("copy").permissions().mode() & 0o777,
        0o600
    );

    // A second torn line at the same sequence keeps its own copy.
    case.append(b"{\"seq\":4");
    let (_, preview) = case.preview();
    let (rc, v) = case.repair(preview["token"].as_str().expect("token"));
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["copy"], "p.toml.ledger.torn-4.2");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);

    let (rc, v) = case.spend();
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["seq"], 4);
}

#[test]
fn a_torn_line_with_a_sequence_the_witness_saw_is_refused() {
    let case = Case::new();
    case.three_spends();
    case.append(br#"{"seq":2,"time":"2026"#);
    let torn = fs::read(case.ledger()).expect("ledger");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert_eq!(v["error"]["code"], "usage");
    assert_eq!(v["error"]["recording"], "not-recorded");
    let m = message(&v);
    assert!(m.contains("has sequence 2"), "{m}");
    assert!(m.contains("must have sequence 4"), "{m}");
    assert!(m.contains("Nothing was changed"), "{m}");
    assert!(m.contains("compare-backups"), "{m}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), torn);
}

#[test]
fn a_torn_line_the_witness_counted_is_refused() {
    let case = Case::new();
    let full = case.three_spends();
    // The witness recorded line 3; cut that line short.
    fs::write(case.ledger(), &full[..full.len() - 10]).expect("cut");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    let m = message(&v);
    assert!(
        m.contains("the witness recorded sequence 3")
            && m.contains("end at sequence 2")
            && m.contains("would lower the count"),
        "{m}"
    );
}

#[test]
fn a_complete_but_invalid_last_line_is_refused() {
    let case = Case::new();
    case.three_spends();
    case.append(b"{\"seq\":4,\"bogus\":1}\n");
    let damaged = fs::read(case.ledger()).expect("ledger");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    let m = message(&v);
    assert!(
        m.contains("ends with a line end, so it is not cut short"),
        "{m}"
    );
    assert!(m.contains("hallpass status p.toml"), "{m}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), damaged);
    // Also with a well-formed token: the repair checks everything again.
    let (rc, v) = case.repair(&format!("tail1:sha256:{}", "0".repeat(64)));
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("not cut short"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), damaged);
}

#[test]
fn damage_before_the_torn_line_is_refused() {
    let case = Case::new();
    let full = case.three_spends();
    let text = String::from_utf8(full).expect("utf-8");
    let edited = text.replacen("\"n\":1", "\"n\":2", 1);
    assert_ne!(edited, text);
    fs::write(case.ledger(), edited).expect("edit");
    case.append(b"{\"seq\":4,");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    let m = message(&v);
    assert!(m.contains("before its cut-short last line"), "{m}");
    assert!(m.contains("compare-backups"), "{m}");
}

#[test]
fn no_witness_and_a_stale_or_malformed_token_are_refused() {
    let case = Case::new();
    case.three_spends();
    case.append(b"{\"seq\":4,\"ti");
    let (_, preview) = case.preview();
    let token = preview["token"].as_str().expect("token").to_owned();

    case.append(b"me");
    let torn = fs::read(case.ledger()).expect("ledger");
    let (rc, v) = case.repair(&token);
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("the repair token is stale"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), torn);

    let (rc, v) = case.repair("v1:sha256:0");
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("is not a repair token"), "{v}");

    fs::remove_file(case.witness()).expect("remove witness");
    fs::remove_file(case.witness().with_extension("recorded")).expect("and its copy");
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("there is no witness"), "{v}");
    assert_eq!(fs::read(case.ledger()).expect("ledger"), torn);
}

#[test]
fn repair_needs_the_flag_and_a_preview_or_token() {
    let case = Case::new();
    for args in [
        &["repair", "p.toml", "--preview"][..],
        &["repair", "p.toml", "--drop-torn-tail"][..],
    ] {
        let (rc, v) = case.json(args);
        assert_eq!(rc, 1, "{v}");
        assert_eq!(v["error"]["code"], "usage", "{v}");
    }
    let (rc, v) = case.preview();
    assert_eq!(rc, 1, "{v}");
    assert!(message(&v).contains("there is no ledger"), "{v}");
}
