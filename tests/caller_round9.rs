#![cfg(feature = "cli")]
//! Reference and minimal caller fixes of round 9:
//! - bn-ykr: a torn journal record is cut off before the next record, and a
//!   damaged line is refused with its number, never a traceback;
//! - bn-yi9: `handoff` matches the journal to the pass by resolved path;
//! - bn-2kr: a rehearsal refuses a hallpass that ignores the test clock, and
//!   the ignored variable shows in the JSON `warnings` of a release build.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASSFILE: &str = "engagement.pass.toml";
const TO: &str = "192.0.2.10:443/tcp";
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

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

struct Shift {
    dir: tempfile::TempDir,
    /// A directory put first on PATH. When it holds a `hallpass` wrapper, the
    /// wrapper hides the test clock, as a release build does.
    bin: PathBuf,
}

impl Shift {
    fn new(release_like: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        for name in ["home", "approval-archive", "bin"] {
            fs::create_dir(root.join(name)).expect("directory");
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).expect("mode");
        }
        let bin = root.join("bin");
        if release_like {
            let wrapper = bin.join("hallpass");
            fs::write(
                &wrapper,
                format!("#!/bin/sh\nunset HALLPASS_UNSAFE_TEST_CLOCK\nexec '{BIN}' \"$@\"\n"),
            )
            .expect("wrapper");
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).expect("mode");
        } else {
            std::os::unix::fs::symlink(BIN, bin.join("hallpass")).expect("link");
        }
        let shift = Self { dir, bin };
        shift.write(PASSFILE, PASS);
        shift
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
    }

    fn python(&self, script: &str, args: &[&str]) -> Out {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join(script);
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![self.bin.clone()];
        paths.extend(std::env::split_paths(&path));
        let home = self.path("home");
        let output = Command::new("python3")
            .arg("-I")
            .arg("-B")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(script)
            .args(args)
            .current_dir(self.dir.path())
            .env("PATH", std::env::join_paths(paths).expect("PATH"))
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .output()
            .expect("run the caller");
        let out = Out {
            code: output.status.code(),
            stdout: String::from_utf8(output.stdout).expect("utf8"),
            stderr: String::from_utf8(output.stderr).expect("utf8"),
        };
        eprintln!("{args:?}\n{}{}", out.stdout, out.stderr);
        out
    }

    fn caller(&self, args: &[&str]) -> Out {
        self.python("docs/reference-caller/caller.py", args)
    }

    fn pin(&self) {
        let out = self.caller(&["pin", "shift.jsonl", PASSFILE, "approval-archive"]);
        assert_eq!(out.code, Some(0), "{}", out.stderr);
    }

    fn run(&self, reference: &str, rehearsal: bool) -> Out {
        let mut args = vec!["run", "shift.jsonl", PASSFILE, reference];
        if rehearsal {
            args.push("--rehearsal");
        }
        args.extend(["--to", TO, "--charge", "requests=1"]);
        self.caller(&args)
    }

    fn outbox(&self) -> String {
        fs::read_to_string(self.path("outbox.jsonl")).unwrap_or_default()
    }
}

#[test]
fn a_torn_journal_record_is_cut_off_and_both_units_are_accounted_for() {
    let shift = Shift::new(false);
    shift.pin();
    assert_eq!(shift.run("s1/u1", true).code, Some(0));
    // A crash cuts the next record short, before its newline.
    let journal = shift.path("shift.jsonl");
    let mut text = fs::read_to_string(&journal).expect("journal");
    text.push_str(r#"{"at": "2026-11-20T09:01:00Z", "ref": "s1/u2", "event": "int"#);
    fs::write(&journal, text).expect("torn");

    let next = shift.run("s1/u3", true);
    assert_eq!(next.code, Some(0), "{}", next.stderr);
    assert!(
        next.stderr.contains("unfinished record") && next.stderr.contains("s1/u2"),
        "{}",
        next.stderr
    );
    let text = fs::read_to_string(&journal).expect("journal");
    assert!(text.ends_with('\n') && !text.contains("\"int\n"), "{text}");
    for line in text.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("every line is a record");
    }
    let handoff = shift.caller(&["handoff", "shift.jsonl", PASSFILE]);
    assert_eq!(handoff.code, Some(0), "{}", handoff.stderr);
    assert!(handoff.stdout.contains("s1/u1") && handoff.stdout.contains("s1/u3"));
    assert!(
        !handoff.stdout.contains("s1/u2"),
        "the torn unit was never acted on"
    );
    assert!(
        handoff.stdout.ends_with("Nothing needs attention.\n"),
        "{}",
        handoff.stdout
    );
}

#[test]
fn a_fragment_alone_in_the_journal_is_cut_off_too() {
    let shift = Shift::new(false);
    shift.write("shift.jsonl", r#"{"ref": "x", "ev"#);
    shift.pin();
    let text = fs::read_to_string(shift.path("shift.jsonl")).expect("journal");
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.contains("\"pin\""), "{text}");
}

#[test]
fn a_damaged_line_is_refused_with_its_number_and_no_traceback() {
    let shift = Shift::new(false);
    shift.pin();
    assert_eq!(shift.run("s1/u1", true).code, Some(0));
    let journal = shift.path("shift.jsonl");
    let text = fs::read_to_string(&journal).expect("journal");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.insert(1, "{not json");
    fs::write(&journal, lines.join("\n") + "\n").expect("damage");
    for out in [
        shift.run("s1/u2", true),
        shift.caller(&["handoff", "shift.jsonl", PASSFILE]),
    ] {
        assert_eq!(out.code, Some(1));
        assert!(
            out.stderr.contains("line 2 is not a journal record"),
            "{}",
            out.stderr
        );
        assert!(
            out.stderr.contains("fix or remove that line"),
            "{}",
            out.stderr
        );
        assert!(!out.stderr.contains("Traceback"), "{}", out.stderr);
    }
}

#[test]
fn handoff_gives_the_same_verdict_for_every_spelling_of_the_pass_path() {
    let shift = Shift::new(false);
    shift.pin();
    assert_eq!(shift.run("s1/u1", true).code, Some(0));
    let interrupted = {
        // The unit runs but its completion is never recorded.
        let mut args = vec!["run", "shift.jsonl", PASSFILE, "s1/u2", "--rehearsal"];
        args.extend(["--to", TO, "--charge", "requests=1"]);
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let bin = shift.bin.display().to_string();
        let path = std::env::var("PATH").unwrap_or_default();
        Command::new("python3")
            .args(["-I", "-B"])
            .arg(script)
            .args(args)
            .current_dir(shift.dir.path())
            .env("PATH", format!("{bin}:{path}"))
            .env("HOME", shift.path("home"))
            .env("XDG_STATE_HOME", shift.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("REFERENCE_CALLER_INTERRUPT", "after-callback")
            .output()
            .expect("interrupted run")
    };
    assert_eq!(interrupted.status.code(), Some(3));
    let absolute = shift.path(PASSFILE).display().to_string();
    let dotted = format!("./{PASSFILE}");
    for spelling in [PASSFILE, dotted.as_str(), absolute.as_str()] {
        let handoff = shift.caller(&["handoff", "shift.jsonl", spelling]);
        assert_eq!(handoff.code, Some(2), "{spelling}: {}", handoff.stdout);
        assert!(handoff.stdout.contains("s1/u2"), "{}", handoff.stdout);
        assert!(
            handoff.stdout.ends_with("1 need attention.\n"),
            "{}",
            handoff.stdout
        );
    }
    // A later run with another spelling finds the pin.
    let out = shift.caller(&[
        "run",
        "shift.jsonl",
        &dotted,
        "s1/u3",
        "--rehearsal",
        "--to",
        TO,
        "--charge",
        "requests=1",
    ]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
}

#[test]
fn handoff_judges_a_moved_pass_by_its_id_and_says_where_the_records_were_written() {
    let shift = Shift::new(false);
    shift.pin();
    assert_eq!(shift.run("s1/u1", true).code, Some(0));
    // The pass and its ledger move together; the journal's records name the old path.
    for suffix in ["", ".ledger"] {
        fs::rename(
            shift.path(&format!("{PASSFILE}{suffix}")),
            shift.path(&format!("moved.pass.toml{suffix}")),
        )
        .expect("move");
    }
    let handoff = shift.caller(&["handoff", "shift.jsonl", "moved.pass.toml"]);
    assert_eq!(handoff.code, Some(0), "{}", handoff.stdout);
    assert!(handoff.stdout.contains("s1/u1"), "{}", handoff.stdout);
    assert!(
        handoff
            .stdout
            .contains("Note: the journal has records for pass web-2026-11 written under"),
        "{}",
        handoff.stdout
    );
}

#[test]
fn a_rehearsal_refuses_a_hallpass_that_ignores_the_test_clock() {
    let shift = Shift::new(true);
    shift.pin();
    let out = shift.run("r/u1", true);
    assert_eq!(out.code, Some(1), "{}", out.stdout);
    assert!(
        out.stderr.contains("uses the real clock") && out.stderr.contains("release build"),
        "{}",
        out.stderr
    );
    assert_eq!(shift.outbox(), "", "the callback must not run");
    let ledger = Command::new(BIN)
        .args(["--format", "json", "ledger", PASSFILE])
        .current_dir(shift.dir.path())
        .env("HOME", shift.path("home"))
        .env("XDG_STATE_HOME", shift.path("home/state"))
        .output()
        .expect("ledger");
    let json: serde_json::Value = serde_json::from_slice(&ledger.stdout).expect("json");
    assert_eq!(json["entries"].as_array().map(Vec::len), Some(0), "{json}");

    let minimal = shift.python(
        "docs/minimal-caller/minimal_caller.py",
        &["--rehearsal", PASSFILE, TO, "r/u2"],
    );
    assert_eq!(minimal.code, Some(1));
    assert!(
        minimal.stderr.contains("uses the real clock"),
        "{}",
        minimal.stderr
    );
    assert!(!minimal.stdout.contains("sent"), "{}", minimal.stdout);
}

#[test]
fn a_live_run_refuses_a_hallpass_that_reports_a_test_clock() {
    // A debug build honours the variable when the caller does not remove it.
    // The caller removes it, so make the wrapper put it back.
    let shift = Shift::new(false);
    let wrapper = shift.bin.join("hallpass");
    fs::remove_file(&wrapper).expect("unlink");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\nHALLPASS_UNSAFE_TEST_CLOCK={NOW}\nexport HALLPASS_UNSAFE_TEST_CLOCK\nexec '{BIN}' \"$@\"\n"),
    )
    .expect("wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).expect("mode");
    shift.write(
        PASSFILE,
        &PASS
            .replace("2020-01-01", "2026-11-20")
            .replace("2090-01-01T00:00:00Z", "2026-11-21T00:00:00Z"),
    );
    shift.pin();
    let out = shift.run("l/u1", false);
    assert_eq!(out.code, Some(1), "{}", out.stdout);
    assert!(
        out.stderr.contains("reports a test clock"),
        "{}",
        out.stderr
    );
    assert_eq!(shift.outbox(), "");
}

/// Only in a release build without the `test-clock` feature. Run with
/// `cargo test --release --test caller_round9`.
#[cfg(not(any(debug_assertions, feature = "test-clock")))]
#[test]
fn an_ignored_test_clock_is_a_json_warning_on_every_command() {
    let shift = Shift::new(false);
    for args in [
        vec!["permits", "--to", TO, "--", PASSFILE],
        vec!["digest", "--", PASSFILE],
        vec!["ledger", "--", PASSFILE],
    ] {
        let output = Command::new(BIN)
            .arg("--format")
            .arg("json")
            .args(&args)
            .current_dir(shift.dir.path())
            .env("HOME", shift.path("home"))
            .env("XDG_STATE_HOME", shift.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run");
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        let warnings = json["warnings"].as_array().expect("warnings");
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().is_some_and(|w| w.contains("is set but ignored"))),
            "{args:?}: {json}"
        );
    }
}
