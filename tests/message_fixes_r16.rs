//! Three message fixes (bn-3bk7): a witness error is not wrapped twice, the
//! compare-backups headline leads with a partial error, and a header-only
//! ledger left by a failed first spend does not claim a pass came from
//! another machine.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const PASS: &str = r#"format = 1
id = "msgs-2026-11"
name = "Messages fixture"

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
ports = 5060

[ceilings]
calls = 100
"#;

fn command(dir: &Path, program: &str, args: &[&str]) -> Command {
    let mut c = Command::new(program);
    c.args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
        .env("XDG_STATE_HOME", dir.join("state"));
    c
}

fn finish(mut c: Command) -> (i32, String) {
    let out = c.output().expect("run");
    let mut text = String::from_utf8(out.stdout).expect("utf8");
    text.push_str(&String::from_utf8(out.stderr).expect("utf8"));
    (out.status.code().expect("exit"), text)
}

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    finish(command(dir, env!("CARGO_BIN_EXE_hallpass"), args))
}

fn write_pass(dir: &Path, file: &str, body: &str) {
    let path = dir.join(file);
    fs::write(&path, body).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn spend(dir: &Path, file: &str) -> (i32, String) {
    run(
        dir,
        &["spend", "--to", "192.0.2.10:5060/udp", "--", file, "calls"],
    )
}

#[test]
fn a_witness_error_in_diff_budget_impact_is_said_once() {
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    write_pass(d, "p.toml", PASS);
    assert_eq!(spend(d, "p.toml").0, 0);
    write_pass(d, "new.toml", &PASS.replace("calls = 100", "calls = 50"));
    let mut c = command(
        d,
        env!("CARGO_BIN_EXE_hallpass"),
        &["--verbose", "diff", "p.toml", "new.toml", "--budget-impact"],
    );
    c.env_remove("XDG_STATE_HOME").env("HOME", "rel");
    let (code, text) = finish(c);
    assert_ne!(code, 0, "{text}");
    assert_eq!(text.matches("cannot be used").count(), 1, "{text}");
    assert_eq!(
        text.matches("Make that directory exist").count(),
        1,
        "{text}"
    );
    assert!(text.contains("there is no state directory"), "{text}");
}

#[test]
fn compare_backups_text_leads_with_a_partial_error() {
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    write_pass(d, "p.toml", PASS);
    assert_eq!(spend(d, "p.toml").0, 0);
    fs::copy(d.join("p.toml.ledger"), d.join("good.ledger")).expect("copy");
    fs::write(d.join("bad.ledger"), "not a ledger\n").expect("bad");
    let (code, text) = run(
        d,
        &["compare-backups", "p.toml", "good.ledger", "bad.ledger"],
    );
    assert_eq!(code, 1, "{text}");
    let first = text.lines().next().expect("line");
    assert!(
        first.starts_with("Partial error: 1 candidate unreadable"),
        "{text}"
    );
    assert!(first.contains("assessment of the rest: "), "{text}");
    let (code, json) = run(
        d,
        &[
            "--json",
            "compare-backups",
            "p.toml",
            "good.ledger",
            "bad.ledger",
        ],
    );
    assert_eq!(code, 1);
    assert!(json.contains("\"result\":\"partial-error\""), "{json}");
    // Without a damaged candidate the headline is unchanged.
    let (code, text) = run(d, &["compare-backups", "p.toml", "good.ledger"]);
    assert_eq!(code, 0, "{text}");
    assert!(text.starts_with("Backup assessment preserved."), "{text}");
}

#[test]
fn a_header_only_ledger_from_a_failed_first_spend_warns_of_nothing() {
    if Command::new("prlimit").arg("--version").output().is_err() {
        return;
    }
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    write_pass(d, "p.toml", PASS);
    let (code, text) = finish(command(
        d,
        "prlimit",
        &[
            "--fsize=100",
            "--",
            env!("CARGO_BIN_EXE_hallpass"),
            "spend",
            "--to",
            "192.0.2.10:5060/udp",
            "--",
            "p.toml",
            "calls",
        ],
    ));
    assert_ne!(code, 0, "{text}");
    let ledger = fs::read_to_string(d.join("p.toml.ledger")).expect("header-only ledger");
    assert_eq!(ledger.lines().count(), 1, "{ledger}");
    let (code, text) = spend(d, "p.toml");
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("there was no witness"), "{text}");
    assert!(!text.contains("another machine"), "{text}");
}
