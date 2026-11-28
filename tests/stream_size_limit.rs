#![cfg(feature = "cli")]
//! bn-bei5: a reply or message written to a regular file past `ulimit -f` must
//! not kill hallpass with SIGXFSZ. After a debit the status is 1 and stderr says
//! "IS recorded"; a message that does not fit is dropped and the status is kept.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const PASS: &str = r#"format = 1
id = "web-2026-11"
name = "Web edge"

[approval]
owner = "Pat Owner"
reference = "email of 2026-11-19"
operator = "Sam Tester"
valid_from = 2020-01-01T00:00:00Z
valid_until = 2090-01-01T00:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
requests = 50
"#;

fn setup() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = dir.path().join("state");
    fs::create_dir(&state).expect("state");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("mode");
    let pass = dir.path().join("p.toml");
    fs::write(&pass, PASS).expect("pass");
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("mode");
    File::options()
        .write(true)
        .open(&pass)
        .expect("open")
        .set_modified(SystemTime::now() - Duration::from_secs(10))
        .expect("backdate");
    let path = pass.to_str().expect("utf8").to_string();
    (dir, path)
}

/// Run hallpass under `ulimit -f 2` (2048 bytes) with stdout and stderr appended
/// to the two files; the files start 3000 bytes long, past the limit.
fn run(dir: &std::path::Path, args: &[&str]) -> (Option<i32>, String, String) {
    let out = dir.join("out.log");
    let err = dir.join("err.log");
    fs::write(&out, "x".repeat(3000)).expect("out");
    fs::write(&err, "x".repeat(3000)).expect("err");
    let status = Command::new("sh")
        .arg("-c")
        .arg("ulimit -f 2; exec \"$0\" \"$@\" >>\"$OUT\" 2>>\"$ERR\"")
        .arg(BIN)
        .args(args)
        .env("OUT", &out)
        .env("ERR", &err)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
        .stdin(Stdio::null())
        .status()
        .expect("run");
    (
        status.code(),
        fs::read_to_string(&out).expect("out"),
        fs::read_to_string(&err).expect("err"),
    )
}

#[test]
fn a_reply_past_the_size_limit_exits_1_and_says_the_debit_is_recorded() {
    let (dir, pass) = setup();
    // Stderr is a fresh small file here so the message fits.
    let out = dir.path().join("out.log");
    fs::write(&out, "x".repeat(3000)).expect("out");
    let status = Command::new("sh")
        .arg("-c")
        .arg("ulimit -f 2; exec \"$0\" \"$@\" >>\"$OUT\"")
        .arg(BIN)
        .args([
            "--json",
            "spend",
            "--to",
            "192.0.2.10:443/tcp",
            "--caller-ref",
            "r-1",
            "--require-new-ref",
            "--",
            &pass,
            "requests",
        ])
        .env("OUT", &out)
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
        .stderr(Stdio::piped())
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert_eq!(status.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("the debit IS recorded"), "{stderr}");
    assert_eq!(fs::metadata(&out).expect("meta").len(), 3000);
    let found = Command::new(BIN)
        .args(["receipt", &pass, "--caller-ref", "r-1"])
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .output()
        .expect("receipt");
    assert!(String::from_utf8_lossy(&found.stdout).contains("Receipt found"));
}

#[test]
fn messages_past_the_size_limit_do_not_kill_the_process() {
    let (dir, _pass) = setup();
    let missing = dir.path().join("none.toml");
    let (code, _out, err) = run(dir.path(), &["check", missing.to_str().expect("utf8")]);
    assert_eq!(code, Some(1), "killed by a signal? {err}");
    assert_eq!(err.len(), 3000, "nothing may be appended past the limit");
}
