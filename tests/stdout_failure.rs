#![cfg(feature = "cli")]
//! bn-1yo: a reply that cannot be written never panics. After something was
//! recorded, stderr says so and the status is 1; a read-only command whose
//! reader closed the pipe is quiet and keeps its own status.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
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
    let old = SystemTime::now() - Duration::from_secs(10);
    File::options()
        .write(true)
        .open(&pass)
        .expect("open")
        .set_modified(old)
        .expect("backdate");
    let path = pass.to_str().expect("utf8").to_string();
    (dir, path)
}

/// Run with stdout on a device or a pipe whose reader is gone.
fn run(dir: &Path, args: &[&str], closed_pipe: bool) -> (Option<i32>, String) {
    let mut command = Command::new(BIN);
    command
        .args(args)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
        .stderr(Stdio::piped());
    if closed_pipe {
        // A pipe whose read end is closed before the child writes.
        let (reader, writer) = std::io::pipe().expect("pipe");
        drop(reader);
        command.stdout(Stdio::from(writer));
    } else {
        command.stdout(
            OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full"),
        );
    }
    let out = command.output().expect("run");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const SPEND: [&str; 9] = [
    "--json",
    "spend",
    "--to",
    "192.0.2.10:443/tcp",
    "--caller-ref",
    "run-1",
    "--require-new-ref",
    "--",
    "PASS",
];

fn spend_args(pass: &str) -> Vec<&str> {
    let mut args: Vec<&str> = SPEND.to_vec();
    args[8] = pass;
    args.push("requests");
    args
}

#[test]
fn a_recorded_spend_with_an_unwritable_reply_says_so_and_exits_1() {
    for closed in [false, true] {
        let (dir, pass) = setup();
        let (code, stderr) = run(dir.path(), &spend_args(&pass), closed);
        assert_eq!(code, Some(1), "{stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
        assert!(
            stderr.contains("the reply could not be written")
                && stderr.contains("the debit IS recorded as ledger entry 1")
                && stderr.contains("\"run-1\"")
                && stderr.contains("reconcile before retrying"),
            "{stderr}"
        );
        let found = Command::new(BIN)
            .args(["receipt", &pass, "--caller-ref", "run-1"])
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .output()
            .expect("receipt");
        assert!(String::from_utf8_lossy(&found.stdout).contains("Receipt found"));
    }
}

#[test]
fn read_only_commands_never_panic_on_a_closed_pipe_or_a_full_device() {
    let (dir, pass) = setup();
    for args in [
        vec!["help", "--json"],
        vec!["--json", "status", pass.as_str()],
        vec!["--json", "check", pass.as_str()],
    ] {
        let (code, stderr) = run(dir.path(), &args, true);
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert!(stderr.is_empty(), "{args:?}: {stderr}");
        assert!(matches!(code, Some(0 | 2)), "{args:?}: {code:?}");
        let (code, stderr) = run(dir.path(), &args, false);
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
        assert!(
            stderr.contains("nothing was recorded"),
            "{args:?}: {stderr}"
        );
        assert!(matches!(code, Some(1 | 2)), "{args:?}: {code:?}");
    }
}
