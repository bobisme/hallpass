//! Wording and checks from the second evaluation: a missing archive directory
//! in the audit commands, the window-too-short boundary, numeric IPv4
//! spellings, ledger file modes, and full stops before the refusal suffix.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");

const PASS: &str = r#"format = 1
id = "polish-1"
name = "polish"

[approval]
owner = "O"
reference = "R"
operator = "P"
valid_from = 2026-11-21T00:00:00Z
valid_until = 2026-11-22T00:01:00Z
revoked = false

[[destination]]
label = "a"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
req = 5
"#;

const NOW: &str = "2026-11-22T00:00:00Z";

/// A temporary directory with its own home and state directory.
struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a pass file, mode 0600.
    fn pass(&self) -> PathBuf {
        let path = self.path("pass.toml");
        write_private(&path, PASS);
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        let home = self.path("home");
        fs::create_dir_all(&home).expect("home");
        Command::new(BIN)
            .env_remove("FORMAT")
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .args(args)
            .output()
            .expect("run hallpass")
    }
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn all_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

#[test]
fn audit_commands_report_a_missing_archive_directory_as_an_error() {
    let case = Case::new();
    let pass = case.pass();
    let missing = case.path("nonexist");
    let missing = missing.to_str().expect("utf-8 path");
    for command in ["audit-charges", "audit-receipts"] {
        let output = case.run(&[command, pass.to_str().expect("utf-8"), missing]);
        let text = all_text(&output);
        assert_eq!(code(&output), Some(1), "{command}: {text}");
        assert!(text.contains("no such file; check the path."), "{text}");
        assert!(!text.contains("archive-missing"), "{text}");
    }
}

#[test]
fn audit_commands_reject_a_file_given_as_the_archive_directory() {
    let case = Case::new();
    let pass = case.pass();
    let file = case.path("not-a-dir");
    write_private(&file, "x");
    let file = file.to_str().expect("utf-8 path");
    for command in ["audit-charges", "audit-receipts"] {
        let output = case.run(&[command, pass.to_str().expect("utf-8"), file]);
        let text = all_text(&output);
        assert_eq!(code(&output), Some(1), "{command}: {text}");
        assert!(text.contains("must be a real directory"), "{text}");
    }
}

#[test]
fn audit_commands_reject_a_world_readable_archive_directory() {
    let case = Case::new();
    let pass = case.pass();
    let dir = case.path("archive");
    fs::create_dir_all(&dir).expect("mkdir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
    let dir = dir.to_str().expect("utf-8 path");
    for command in ["audit-charges", "audit-receipts"] {
        let output = case.run(&[command, pass.to_str().expect("utf-8"), dir]);
        let text = all_text(&output);
        assert_eq!(code(&output), Some(1), "{command}: {text}");
        assert!(text.contains("chmod 700"), "{text}");
    }
}

#[test]
fn window_boundary_refusal_says_the_work_would_end_at_the_close() {
    let case = Case::new();
    let pass = case.pass();
    let pass = pass.to_str().expect("utf-8");
    let target = "192.0.2.10:443/tcp";

    let refused = case.run(&["permits", pass, "--to", target, "--duration", "60"]);
    let text = all_text(&refused);
    assert_eq!(code(&refused), Some(2), "{text}");
    assert!(
        text.contains(
            "the work may take up to 60 s and would end at or after the window closes (valid until 2026-11-22T00:01:00Z; 60 s remain)"
        ),
        "{text}"
    );
    assert!(!text.contains("but only"), "{text}");

    let allowed = case.run(&["permits", pass, "--to", target, "--duration", "59"]);
    assert_eq!(code(&allowed), Some(0), "{}", all_text(&allowed));
}

#[test]
fn hexadecimal_ipv4_spelling_is_named_as_non_standard() {
    let case = Case::new();
    let pass = case.pass();
    let pass = pass.to_str().expect("utf-8");
    for spelling in ["0xcb007101:443/tcp", "0x7f.0.0.1:443/tcp"] {
        let output = case.run(&["permits", pass, "--to", spelling]);
        let text = all_text(&output);
        assert_eq!(code(&output), Some(1), "{text}");
        assert!(text.contains("is a non-standard IPv4 spelling; write it in dotted decimal, four parts (for example 10.0.0.1)."), "{text}");
        assert!(!text.contains("host name"), "{text}");
        assert!(!text.contains("resolve the name yourself"), "{text}");
    }
}

#[test]
fn refusal_messages_end_with_a_full_stop_before_the_suffix() {
    let case = Case::new();
    let pass = case.pass();
    let pass = pass.to_str().expect("utf-8");
    let output = case.run(&["permits", pass, "--to", "10.1:443/tcp"]);
    let text = all_text(&output);
    assert!(
        text.contains("write all four parts (for example 10.0.0.1).\nNothing was permitted."),
        "{text}"
    );

    let name = case.run(&["permits", pass, "--to", "sip.example.net:443/tcp"]);
    let text = all_text(&name);
    assert!(
        text.contains("pass the name with --name.\nNothing was permitted."),
        "{text}"
    );
}

#[test]
fn insecure_ledger_mode_gives_ledger_advice() {
    let case = Case::new();
    let pass = case.pass();
    let pass = pass.to_str().expect("utf-8");
    let spend = case.run(&["spend", pass, "req"]);
    assert_eq!(code(&spend), Some(0), "{}", all_text(&spend));
    let ledger = case.path("pass.toml.ledger");
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).expect("chmod");
    let output = case.run(&["ledger", pass]);
    let text = all_text(&output);
    assert!(
        text.contains("check that no other user or process changed it"),
        "{text}"
    );
    assert!(!text.contains("approved"), "{text}");
}
