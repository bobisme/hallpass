//! A pass whose modification time is in the future is reported, not silently waited for (bn-134).
#![cfg(feature = "cli")]

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

fn pass_dated(dir: &Path, modified: SystemTime) -> std::path::PathBuf {
    let pass = dir.join("approval");
    let body = format!(
        "{}\n[ceilings]\ncalls = 10\n",
        include_str!("../docs/review-approval.toml")
    );
    fs::write(&pass, body).expect("pass");
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("private pass");
    File::options()
        .write(true)
        .open(&pass)
        .and_then(|file| file.set_modified(modified))
        .expect("date the pass");
    pass
}

fn spend(dir: &Path, pass: &Path) -> Output {
    run(dir, pass, true)
}

fn run(dir: &Path, pass: &Path, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
    if json {
        command.arg("--json");
    }
    command
        .arg("spend")
        .arg(pass)
        .arg("calls")
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
        .output()
        .expect("run hallpass")
}

fn warnings(out: &Output) -> Vec<String> {
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json reply");
    assert_eq!(reply["result"], "allowed", "{reply}");
    reply["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .map(|w| w.as_str().expect("text").to_owned())
        .collect()
}

#[test]
fn a_pass_dated_in_the_future_warns_and_is_still_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ahead = SystemTime::now() + Duration::from_secs(3600);
    let pass = pass_dated(dir.path(), ahead);
    // Twice: the second call has a ledger and a witness already.
    for _ in 0..2 {
        let out = spend(dir.path(), &pass);
        let found = warnings(&out);
        assert!(
            found.iter().any(|w| w.contains("which is in the future")
                && w.contains("modification time")
                && w.contains("`touch`")),
            "{found:?}"
        );
        // In text mode the same warning is on stderr.
        let text = run(dir.path(), &pass, false);
        let stderr = String::from_utf8_lossy(&text.stderr);
        assert!(
            stderr.contains("warning: the pass file") && stderr.contains("which is in the future"),
            "{stderr}"
        );
    }
}

#[test]
fn a_pass_dated_in_the_past_or_just_ahead_does_not_warn() {
    let dir = tempfile::tempdir().expect("tempdir");
    for modified in [
        SystemTime::now() - Duration::from_secs(60),
        SystemTime::now() + Duration::from_millis(500),
    ] {
        let pass = pass_dated(dir.path(), modified);
        let out = spend(dir.path(), &pass);
        let found = warnings(&out);
        assert!(
            !found.iter().any(|w| w.contains("in the future")),
            "{found:?}"
        );
    }
}
