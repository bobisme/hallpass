//! Recovery messages (bn-2bg): the moved-or-copied warning promises a refusal
//! only for a copy that shares the witness, and a damaged counted last line
//! names the last-resort path.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"format = 1
id = "moves-2026-11"
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

fn pass_at(path: &Path) {
    fs::write(path, PASS).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
    fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(10)))
        .expect("backdate");
}

fn run(dir: &Path, state: &Path, args: &[&str]) -> (i32, Value) {
    let out = Command::new(BIN)
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", state)
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .arg("--json")
        .args(args)
        .output()
        .expect("run");
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().expect("code"), v)
}

#[test]
fn the_moved_warning_does_not_promise_a_refusal_for_another_witness() {
    let root = tempfile::tempdir().expect("tempdir");
    let a = root.path().join("a");
    fs::create_dir_all(&a).expect("a");
    pass_at(&a.join("p.toml"));
    let state_a = root.path().join("state-a");
    for _ in 0..2 {
        assert_eq!(run(&a, &state_a, &["spend", "p.toml", "calls"]).0, 0);
    }
    // A second machine: the pass, the ledger and a copy of the state.
    let b = root.path().join("b");
    fs::create_dir_all(&b).expect("b");
    pass_at(&b.join("p.toml"));
    fs::copy(a.join("p.toml.ledger"), b.join("p.toml.ledger")).expect("ledger");
    fs::set_permissions(b.join("p.toml.ledger"), fs::Permissions::from_mode(0o600)).expect("chmod");
    let state_b = root.path().join("state-b");
    fs::create_dir_all(state_b.join("hallpass")).expect("state");
    fs::set_permissions(state_b.join("hallpass"), fs::Permissions::from_mode(0o700))
        .expect("chmod");
    fs::copy(
        state_a.join("hallpass/moves-2026-11.witness"),
        state_b.join("hallpass/moves-2026-11.witness"),
    )
    .expect("witness");
    let (rc, v) = run(&b, &state_b, &["spend", "p.toml", "calls"]);
    assert_eq!(rc, 0, "{v}");
    let text = v["warnings"].to_string();
    assert!(text.contains("moved or copied"), "{text}");
    assert!(
        text.contains("same state directory will now be refused"),
        "{text}"
    );
    assert!(
        text.contains("has its own witness and is not refused"),
        "{text}"
    );
    assert!(text.contains("ledger-missing"), "{text}");
    // The old copy keeps its own witness and is in fact still live.
    let (rc, v) = run(&a, &state_a, &["spend", "p.toml", "calls"]);
    assert_eq!(rc, 0, "{v}");
}

#[test]
fn a_damaged_counted_last_line_names_the_last_resort() {
    let root = tempfile::tempdir().expect("tempdir");
    let d = root.path().join("d");
    fs::create_dir_all(&d).expect("d");
    pass_at(&d.join("p.toml"));
    let state = root.path().join("state");
    for _ in 0..3 {
        assert_eq!(run(&d, &state, &["spend", "p.toml", "calls"]).0, 0);
    }
    let bytes = fs::read(d.join("p.toml.ledger")).expect("ledger");
    // Cut the counted last line in half.
    fs::write(d.join("p.toml.ledger"), &bytes[..bytes.len() - 60]).expect("cut");
    let (rc, v) = run(
        &d,
        &state,
        &["repair", "p.toml", "--drop-torn-tail", "--preview"],
    );
    assert_eq!(rc, 1, "{v}");
    let m = v["error"]["message"].as_str().expect("message");
    assert!(m.contains("was counted"), "{m}");
    assert!(m.contains("last resort"), "{m}");
    assert!(m.contains("hallpass adopt p.toml"), "{m}");
    let (rc, v) = run(&d, &state, &["spend", "p.toml", "calls"]);
    assert_eq!(rc, 1, "{v}");
    assert_eq!(v["error"]["code"], "ledger-corrupt");
    let m = v["error"]["message"].as_str().expect("message");
    assert!(m.contains("last resort"), "{m}");
    assert!(m.contains("hallpass adopt"), "{m}");
    // The path works: moved aside, adopt carries the witness totals.
    fs::rename(d.join("p.toml.ledger"), d.join("p.toml.ledger.damaged")).expect("move");
    let (rc, v) = run(
        &d,
        &state,
        &["adopt", "p.toml", "--reason", "damaged counted last line"],
    );
    assert_eq!(rc, 0, "{v}");
    let (rc, v) = run(&d, &state, &["spend", "p.toml", "calls"]);
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["spent"], 4, "{v}");
}
