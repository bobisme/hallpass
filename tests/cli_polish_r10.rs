//! Round 10 CLI polish: an oversized `--n` or `--charge` names the real
//! bound, and a repeated `--format` or `--json` is a usage error.

use std::{fs, path::PathBuf, process::Command, time::SystemTime};

use serde_json::Value;

const METERED: &str = include_str!("../docs/required-counters.toml");
const NOW: &str = "2026-11-20T09:00:00Z";
const WEB: &str = "192.0.2.10:443/tcp@app.example.org";
const BOUND: &str = "from 1 to 1000000000000";

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("directory");
        let pass = dir.path().join("pass");
        fs::write(&pass, METERED).expect("write pass");
        let file = fs::File::options()
            .write(true)
            .open(&pass)
            .expect("open pass");
        file.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
            .expect("backdate pass");
        Self { dir, pass }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> (Option<i32>, String, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        command
            .args(args)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .envs(env.iter().copied())
            .current_dir(self.dir.path());
        let out = command.output().expect("hallpass");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn json(&self, args: &[&str]) -> (Option<i32>, Value) {
        let (code, stdout, _) = self.run(args, &[]);
        let value = serde_json::from_str(&stdout).expect("one JSON object");
        (code, value)
    }
}

#[test]
fn oversized_n_states_the_real_bound() {
    let f = Fixture::new();
    let pass = f.pass.to_str().expect("utf-8 path");
    let (code, reply) = f.json(&[
        "--format",
        "json",
        "spend",
        "--to",
        WEB,
        "--n",
        "18446744073709551616",
        "--",
        pass,
        "requests",
    ]);
    assert_ne!(code, Some(0));
    assert_eq!(reply["error"]["code"], "usage");
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(message.contains("18446744073709551616"), "{message}");
    assert!(message.contains(BOUND), "{message}");
}

#[test]
fn oversized_charge_states_the_real_bound() {
    let f = Fixture::new();
    let pass = f.pass.to_str().expect("utf-8 path");
    let (code, reply) = f.json(&[
        "--format",
        "json",
        "spend",
        "--to",
        WEB,
        "--charge",
        "requests=18446744073709551616",
        "--",
        pass,
    ]);
    assert_ne!(code, Some(0));
    assert_eq!(reply["error"]["code"], "usage");
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(message.contains(BOUND), "{message}");
}

#[test]
fn repeated_format_is_a_usage_error() {
    let f = Fixture::new();
    let pass = f.pass.to_str().expect("utf-8 path");
    for args in [
        vec![
            "--format", "json", "--format", "text", "permits", "--to", WEB, "--", pass,
        ],
        vec![
            "--format=json",
            "--format",
            "json",
            "permits",
            "--to",
            WEB,
            "--",
            pass,
        ],
    ] {
        let (code, reply) = f.json(&args);
        assert_ne!(code, Some(0), "{args:?}");
        assert_eq!(reply["error"]["code"], "usage", "{args:?}");
        let message = reply["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("`--format` is given more than once"),
            "{message}"
        );
    }
}

#[test]
fn repeated_json_is_a_usage_error() {
    let f = Fixture::new();
    let pass = f.pass.to_str().expect("utf-8 path");
    let (code, reply) = f.json(&["--json", "--json", "permits", "--to", WEB, "--", pass]);
    assert_ne!(code, Some(0));
    assert_eq!(reply["error"]["code"], "usage");
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("`--json` is given more than once"),
        "{message}"
    );
}

#[test]
fn environment_format_with_one_flag_is_allowed() {
    let f = Fixture::new();
    let pass = f.pass.to_str().expect("utf-8 path");
    let tail = ["permits", "--to", WEB, "--", pass];

    // The flag overrides the variable: text output, not JSON.
    let mut args = vec!["--format", "text"];
    args.extend(tail);
    let (code, stdout, _) = f.run(&args, &[("HALLPASS_FORMAT", "json")]);
    assert_eq!(code, Some(0));
    assert!(!stdout.starts_with('{'), "{stdout}");

    // One --json with the variable set is still allowed.
    let mut args = vec!["--json"];
    args.extend(tail);
    let (code, stdout, _) = f.run(&args, &[("HALLPASS_FORMAT", "text")]);
    assert_eq!(code, Some(0));
    assert!(serde_json::from_str::<Value>(&stdout).is_ok(), "{stdout}");
}
