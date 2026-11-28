//! Message fixes of round 8: clap value errors in the usual error format,
//! a top-level key written under a table, the lock-wait line, checkpoint
//! "entries" and the atomic-batch ceiling refusal (bn-3cf, bn-235).

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
const NOW: &str = "2026-11-20T09:00:00Z";

const PASS: &str = r#"format = 1
id = "example-2026-11"
name = "Example voice edge"
require_target_v1 = true

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
}

impl Case {
    fn new(pass: &str) -> Self {
        let case = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        fs::create_dir(case.path("home")).expect("home");
        let path = case.path("p.toml");
        fs::write(&path, pass).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(3600)))
            .expect("backdate");
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn command(&self, args: &[&str]) -> Command {
        let home = self.path("home");
        let mut command = Command::new(BIN);
        command
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .env_remove("HALLPASS_FORMAT")
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run")
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn both(out: &Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn a_bad_value_uses_the_usual_error_format() {
    let case = Case::new(PASS);
    let out = case.run(&["spend", "p.toml", "calls", "--n", "1.5"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stdout(&out), "");
    assert_eq!(
        stderr(&out),
        "hallpass spend: error: usage: invalid value '1.5' for '--n <N>': N must be a positive integer, not `1.5`\nNothing was permitted.\n"
    );

    let out = case.run(&["--json", "spend", "p.toml", "calls", "--n", "1.5"]);
    assert_eq!(out.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["error"]["code"], "usage");
    assert_eq!(v["error"]["recording"], "not-recorded");
    assert_eq!(
        v["error"]["message"],
        "invalid value '1.5' for '--n <N>': N must be a positive integer, not `1.5`"
    );

    // Help, version and other parse errors keep clap's behaviour.
    let out = case.run(&["spend", "--help"]);
    assert_eq!(out.status.code(), Some(0));
    let out = case.run(&["spend", "p.toml", "calls", "--bogus"]);
    assert!(stderr(&out).starts_with("hallpass spend: error: usage: unexpected argument"));
}

#[test]
fn a_top_level_key_under_a_table_says_where_it_goes() {
    let moved = PASS
        .replace("require_target_v1 = true\n", "")
        .replace("[ceilings]\n", "[ceilings]\nrequire_target_v1 = true\n");
    let case = Case::new(&moved);
    let out = case.run(&["check", "p.toml"]);
    let text = both(&out);
    assert!(
        text.contains(
            "ceilings.require_target_v1: `require_target_v1` is a top-level key, but it sits under `[ceilings]`; top-level keys must come before the first `[table]` header; move `require_target_v1` up above it"
        ),
        "{text}"
    );
    assert!(!text.contains("must be a whole number"), "{text}");

    // The same for a key under `[approval]`.
    let moved = PASS
        .replace("require_target_v1 = true\n", "")
        .replace("[approval]\n", "[approval]\nrequire_target_v1 = true\n");
    let case = Case::new(&moved);
    let text = both(&case.run(&["check", "p.toml"]));
    assert!(
        text.contains(
            "`require_target_v1` is a top-level key: top-level keys must come before the first `[table]` header; move `require_target_v1` up above it."
        ),
        "{text}"
    );
}

#[test]
fn verify_checkpoint_counts_entries() {
    let case = Case::new(PASS);
    let spend = |n: &str| {
        let out = case.run(&["spend", "p.toml", "calls", "--to", "192.0.2.10:5060/udp", n]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}{}",
            stdout(&out),
            stderr(&out)
        );
    };
    spend("--n=1");
    let checkpoint = case.run(&["checkpoint", "p.toml"]);
    fs::write(case.path("checkpoint.json"), &checkpoint.stdout).expect("checkpoint");
    spend("--n=1");
    spend("--n=1");
    let out = case.run(&["verify-checkpoint", "p.toml.ledger", "checkpoint.json"]);
    let text = stdout(&out);
    assert!(text.contains("extended (2 later entries)"), "{text}");
    assert!(!text.contains("later lines"), "{text}");
}

/// Hold the ledger lock for `hold`, and run `args` meanwhile.
fn run_with_lock_held(case: &Case, args: &[&str], hold: Duration) -> Output {
    let ledger = File::options()
        .read(true)
        .open(case.path("p.toml.ledger"))
        .expect("ledger");
    ledger.lock().expect("hold the lock");
    let child = case
        .command(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    std::thread::sleep(hold);
    drop(ledger);
    child.wait_with_output().expect("output")
}

fn case_with_ledger() -> Case {
    let case = Case::new(PASS);
    let out = case.run(&["spend", "p.toml", "calls", "--to", "192.0.2.10:5060/udp"]);
    assert_eq!(out.status.code(), Some(0));
    case
}

#[test]
fn the_lock_wait_line_offers_the_flag_only_when_it_is_not_set() {
    let case = case_with_ledger();
    let args = ["spend", "p.toml", "calls", "--to", "192.0.2.10:5060/udp"];
    let out = run_with_lock_held(&case, &args, Duration::from_millis(2600));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains(
            "Nothing is recorded yet; press Ctrl-C to give up, or use --lock-timeout-ms to stop waiting."
        ),
        "{err}"
    );

    let mut with_flag = args.to_vec();
    with_flag.extend(["--lock-timeout-ms", "2500"]);
    let out = run_with_lock_held(&case, &with_flag, Duration::from_millis(3500));
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("Nothing is recorded yet; giving up in "),
        "{err}"
    );
    assert!(
        err.contains(" ms (--lock-timeout-ms); press Ctrl-C to stop sooner."),
        "{err}"
    );
    assert!(!err.contains("or use --lock-timeout-ms"), "{err}");
}
