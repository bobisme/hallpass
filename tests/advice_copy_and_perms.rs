//! A copied pass and ledger that is spent from leaves the original refused as
//! `ledger-elsewhere` (never advised to adopt), and a ledger that cannot be
//! created or written names the directory or file and the `chmod` to run.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const PASS: &str = r#"format = 1
id = "advice-2026-11"
name = "Advice fixture"

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

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run");
    let mut text = String::from_utf8(out.stdout).expect("utf8");
    text.push_str(&String::from_utf8(out.stderr).expect("utf8"));
    (out.status.code().expect("exit"), text)
}

fn write_pass(dir: &Path, file: &str) {
    let path = dir.join(file);
    fs::write(&path, PASS).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn spend(dir: &Path, file: &str) -> (i32, String) {
    run(
        dir,
        &["spend", "--to", "192.0.2.10:5060/udp", "--", file, "calls"],
    )
}

fn is_root() -> bool {
    fs::metadata("/proc/self").is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
}

fn copied() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    fs::create_dir(d.join("a")).expect("a");
    fs::create_dir(d.join("b")).expect("b");
    write_pass(d, "a/p.pass.toml");
    assert_eq!(spend(d, "a/p.pass.toml").0, 0);
    for f in ["p.pass.toml", "p.pass.toml.ledger"] {
        fs::copy(d.join("a").join(f), d.join("b").join(f)).expect("copy");
    }
    assert_eq!(spend(d, "b/p.pass.toml").0, 0, "the copy spends");
    tmp
}

#[test]
fn a_copied_ledger_that_spent_is_elsewhere_not_changed() {
    let tmp = copied();
    let d = tmp.path();
    let (_, text) = spend(d, "a/p.pass.toml");
    assert!(
        text.contains("ledger-elsewhere") || text.contains("intact elsewhere"),
        "{text}"
    );
    assert!(
        !text.contains("if this ledger is the one to keep"),
        "{text}"
    );
    assert!(!text.contains("run `hallpass adopt a/"), "{text}");
    assert!(text.contains("b/p.pass.toml.ledger"), "{text}");
    let to = "192.0.2.10:5060/udp";
    let each: [&[&str]; 2] = [
        &["status", "a/p.pass.toml"],
        &["permits", "--to", to, "a/p.pass.toml"],
    ];
    for args in each {
        let (_, text) = run(d, args);
        assert!(text.contains("intact elsewhere"), "{args:?}: {text}");
        assert!(!text.contains("one to keep"), "{args:?}: {text}");
        assert!(!text.contains("hallpass adopt a/"), "{args:?}: {text}");
    }
    let (code, text) = run(d, &["adopt", "a/p.pass.toml", "--preview"]);
    assert_ne!(code, 0, "{text}");
}

#[test]
fn a_changed_ledger_with_no_intact_copy_keeps_the_adopt_advice() {
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    write_pass(d, "p.pass.toml");
    assert_eq!(spend(d, "p.pass.toml").0, 0);
    let ledger = d.join("p.pass.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("ledger");
    let cut: String = text.lines().take(1).collect::<Vec<_>>().join("\n") + "\n";
    fs::write(&ledger, cut).expect("cut");
    let (_, text) = spend(d, "p.pass.toml");
    assert!(text.contains("hallpass adopt"), "{text}");
    assert!(!text.contains("intact elsewhere"), "{text}");
}

#[test]
fn an_unwritable_directory_is_named_with_the_chmod() {
    if is_root() {
        return;
    }
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    fs::create_dir(d.join("eng")).expect("eng");
    write_pass(d, "eng/p.pass.toml");
    fs::set_permissions(d.join("eng"), fs::Permissions::from_mode(0o500)).expect("mode");
    let (code, text) = spend(d, "eng/p.pass.toml");
    fs::set_permissions(d.join("eng"), fs::Permissions::from_mode(0o700)).expect("mode");
    assert_ne!(code, 0, "{text}");
    assert!(text.contains("chmod u+w \"eng\""), "{text}");
    assert!(!text.contains("owner and mode"), "{text}");
}

#[test]
fn a_read_only_ledger_gets_the_chmod_600() {
    if is_root() {
        return;
    }
    let tmp = tempfile::tempdir().expect("dir");
    let d = tmp.path();
    write_pass(d, "p.pass.toml");
    assert_eq!(spend(d, "p.pass.toml").0, 0);
    let ledger = d.join("p.pass.toml.ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o400)).expect("mode");
    let (code, text) = spend(d, "p.pass.toml");
    assert_ne!(code, 0, "{text}");
    assert!(text.contains("chmod 600 \"p.pass.toml.ledger\""), "{text}");
}
