//! Round 14 polish: `repair`'s usage line names its real required arguments
//! (and no global flag leaks into it), a leap second is refused in every
//! spelling with one message, and a fraction of a second is shown.

use std::{fs, path::PathBuf, process::Command, time::SystemTime};

const TEMPLATE: &str = include_str!("../docs/required-counters.toml");
const NOW: &str = "2026-11-20T09:00:00Z";

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("directory"),
        }
    }

    /// Write a pass whose `valid_until` line is `until` (already TOML text).
    fn pass(&self, until: &str) -> PathBuf {
        let text = TEMPLATE.replace(
            "valid_until = 2026-11-20T17:00:00Z",
            &format!("valid_until = {until}"),
        );
        assert_ne!(
            text, TEMPLATE,
            "the template has the line this test replaces"
        );
        let path = self.dir.path().join("pass.toml");
        fs::write(&path, text).expect("write pass");
        let file = fs::File::options()
            .write(true)
            .open(&path)
            .expect("open pass");
        file.set_modified(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
            .expect("backdate pass");
        path
    }

    fn run(&self, args: &[&str]) -> (Option<i32>, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(args)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .current_dir(self.dir.path())
            .output()
            .expect("hallpass");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

#[test]
fn repair_usage_names_the_required_arguments_and_no_global_flag() {
    let f = Fixture::new();
    let (code, _, stderr) = f.run(&["repair", "pass.toml", "--drop-torn-tail", "--reason", "x"]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(!stderr.contains("'--version'"), "{stderr}");
    assert!(!stderr.contains("--version"), "{stderr}");
    assert!(stderr.contains("Usage: hallpass repair"), "{stderr}");
    assert!(stderr.contains("<--preview|--token <TOKEN>>"), "{stderr}");
    assert!(
        stderr.contains("<--drop-torn-tail|--restore-final-newline>"),
        "{stderr}"
    );
}

#[test]
fn repair_without_preview_or_token_says_so() {
    let f = Fixture::new();
    let (code, _, stderr) = f.run(&["repair", "pass.toml", "--drop-torn-tail"]);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("<--preview|--token <TOKEN>>"), "{stderr}");
}

#[test]
fn version_flag_is_not_accepted_after_a_subcommand() {
    let f = Fixture::new();
    let (code, stdout, stderr) = f.run(&["repair", "--version"]);
    assert_eq!(code, Some(1), "{stdout}{stderr}");
    assert!(
        stderr.contains("unexpected argument '--version'"),
        "{stderr}"
    );
    let (code, stdout, _) = f.run(&["--version"]);
    assert_eq!(code, Some(0));
    assert!(stdout.starts_with("hallpass "), "{stdout}");
}

#[test]
fn leap_second_is_refused_in_both_spellings_with_one_message() {
    let f = Fixture::new();
    let mut messages = Vec::new();
    for (until, shown) in [
        ("2026-12-31T23:59:60Z", "2026-12-31T23:59:60Z"),
        ("\"2026-12-31T23:59:60+00:00\"", "2026-12-31T23:59:60+00:00"),
    ] {
        let pass = f.pass(until);
        let (code, stdout, stderr) = f.run(&["check", pass.to_str().expect("utf-8 path")]);
        let out = format!("{stdout}{stderr}");
        assert_ne!(code, Some(0), "{until}: {out}");
        assert!(out.contains(&format!("\"{shown}\" has second 60")), "{out}");
        let line = out
            .lines()
            .find(|l| l.contains("has second 60"))
            .unwrap_or_default();
        messages.push(line.replace(&format!("\"{shown}\""), "X"));
    }
    assert_eq!(messages[0], messages[1]);
    assert!(
        messages[0].contains("which hallpass does not accept"),
        "{}",
        messages[0]
    );
}

#[test]
fn a_fraction_of_a_second_is_shown() {
    let f = Fixture::new();
    for until in ["2026-11-20T17:00:00.5Z", "\"2026-11-20T17:00:00.5+00:00\""] {
        let pass = f.pass(until);
        let (code, stdout, stderr) = f.run(&["status", pass.to_str().expect("utf-8 path")]);
        assert_eq!(code, Some(0), "{until}: {stderr}");
        assert!(
            stdout.contains("2026-11-20T17:00:00.5Z"),
            "{until}: {stdout}"
        );
    }
}
