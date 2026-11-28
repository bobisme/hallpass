#![cfg(feature = "cli")]
//! Both example callers report hallpass's own error (exit 1) in hallpass's
//! words, not as a test-clock problem or a target problem (bn-kbt6).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const PASS: &str = r#"format = 1
id = "errors-2026-11"
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
requests = 5
"#;

fn run_python(
    dir: &Path,
    script: &str,
    rehearsal: bool,
    args: &[&str],
) -> (Option<i32>, String, String) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(script);
    let bin_dir = Path::new(BIN).parent().expect("binary directory");
    let mut paths = vec![bin_dir.to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let home = dir.join("home");
    let mut cmd = Command::new("python3");
    cmd.arg("-I").arg("-B").arg(script);
    if rehearsal {
        cmd.arg("--rehearsal");
    }
    let output = cmd
        .args(args)
        .current_dir(dir)
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .env_remove("HALLPASS_FORMAT")
        .env_remove("HALLPASS_REVIEWED_DIGEST")
        .output()
        .expect("run the caller");
    (
        output.status.code(),
        String::from_utf8(output.stdout).expect("utf8"),
        String::from_utf8(output.stderr).expect("utf8"),
    )
}

fn minimal(dir: &Path, pass: &str, to: &str, r: &str) -> (Option<i32>, String, String) {
    run_python(
        dir,
        "docs/minimal-caller/minimal_caller.py",
        true,
        &[pass, to, r],
    )
}

fn reference(dir: &Path, pass: &str, to: &str, r: &str) -> (Option<i32>, String, String) {
    run_python(
        dir,
        "docs/reference-caller/caller.py",
        false,
        &[
            "run",
            "j.jsonl",
            pass,
            r,
            "--to",
            to,
            "--charge",
            "requests=1",
            "--rehearsal",
        ],
    )
}

fn setup() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fs::create_dir(root.join("home")).expect("home");
    fs::set_permissions(root.join("home"), fs::Permissions::from_mode(0o700)).expect("mode");
    fs::write(root.join("p.toml"), PASS).expect("pass");
    fs::set_permissions(root.join("p.toml"), fs::Permissions::from_mode(0o600)).expect("mode");
    drop(filetime_back(&root.join("p.toml")));
    dir
}

/// Backdate the pass so the settle re-read does not apply.
fn filetime_back(path: &Path) -> fs::File {
    let file = fs::File::options().write(true).open(path).expect("open");
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(10))
        .expect("backdate");
    file
}

/// One spend straight through hallpass, so the pass has a ledger.
fn seed(root: &Path) {
    let out = Command::new(BIN)
        .args([
            "--format",
            "json",
            "spend",
            "--caller-ref",
            "seed",
            "--n",
            "1",
            "--",
            "p.toml",
            "requests",
        ])
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env("XDG_STATE_HOME", root.join("home/state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .output()
        .expect("seed");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

type Caller = fn(&Path, &str, &str, &str) -> (Option<i32>, String, String);

fn both() -> [(&'static str, Caller); 2] {
    [("minimal", minimal), ("reference", reference)]
}

/// The failure line of a caller, wherever it prints it.
fn said(stdout: &str, stderr: &str) -> String {
    format!("{stdout}{stderr}")
}

#[test]
fn a_missing_pass_is_hallpass_io_error_not_a_clock_problem() {
    for (name, call) in both() {
        let dir = setup();
        let (code, out, err) = call(dir.path(), "nosuch.toml", TO, "u1");
        let said = said(&out, &err);
        assert_eq!(code, Some(1), "{name}: {said}");
        assert!(said.contains("no such file"), "{name}: {said}");
        assert!(said.contains("io"), "{name}: {said}");
        assert!(!said.contains("reports a test clock"), "{name}: {said}");
        assert!(
            !said.contains("would not take these targets"),
            "{name}: {said}"
        );
    }
}

#[test]
fn a_damaged_ledger_is_reported_with_its_code_and_message() {
    for (name, call) in both() {
        let dir = setup();
        let root = dir.path();
        seed(root);
        let ledger = root.join("p.toml.ledger");
        let text = fs::read_to_string(&ledger).expect("ledger");
        let damaged = text.replacen("\"n\":1", "\"n\":0", 1);
        assert_ne!(text, damaged, "{text}");
        fs::write(&ledger, damaged).expect("damage");
        let (code, out, err) = call(root, "p.toml", TO, "u9");
        let said = said(&out, &err);
        assert_eq!(code, Some(1), "{name}: {said}");
        assert!(said.contains("ledger-corrupt"), "{name}: {said}");
        assert!(!said.contains("reports a test clock"), "{name}: {said}");
        assert!(
            !said.contains("would not take these targets"),
            "{name}: {said}"
        );
    }
}

#[test]
fn a_ledger_open_to_others_is_reported_as_hallpass_says_it() {
    for (name, call) in both() {
        let dir = setup();
        let root = dir.path();
        seed(root);
        let ledger = root.join("p.toml.ledger");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).expect("mode");
        let (code, out, err) = call(root, "p.toml", TO, "u9");
        let said = said(&out, &err);
        assert_eq!(code, Some(1), "{name}: {said}");
        assert!(said.contains("hallpass error"), "{name}: {said}");
        assert!(!said.contains("reports a test clock"), "{name}: {said}");
        assert!(
            !said.contains("would not take these targets"),
            "{name}: {said}"
        );
    }
}

#[test]
fn a_bad_target_is_a_target_error_in_the_reference_caller_only() {
    for (name, call) in both() {
        let dir = setup();
        let (code, out, err) = call(dir.path(), "p.toml", "host.example.com:5060/udp", "u1");
        let said = said(&out, &err);
        assert_eq!(code, Some(1), "{name}: {said}");
        assert!(said.contains("host name"), "{name}: {said}");
        assert!(!said.contains("reports a test clock"), "{name}: {said}");
        if name == "reference" {
            assert!(said.contains("would not take these targets"), "{said}");
        }
    }
}

#[test]
fn a_refusal_through_the_minimal_caller_shows_code_and_message() {
    let dir = setup();
    let (code, out, err) = minimal(dir.path(), "p.toml", "192.0.2.99:5060/udp", "u1");
    assert_eq!(code, Some(2), "{err}");
    assert_eq!(out, "");
    assert!(err.contains("address-not-listed"), "{err}");
    assert!(err.contains("not in any destination"), "{err}");
}
