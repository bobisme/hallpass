//! The directory that holds the pass, its ledger and its lock file: another
//! user who can write it can rename a file over them, which the file-mode
//! checks do not see. hallpass warns, in `check`, `status`, `spend` and
//! `adopt`, unless the directory has the sticky bit.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");

const PASS: &str = r#"format = 1
id = "dirperm-1"
name = "dirperm"

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

/// A work directory holding `engagement/` (the directory under test), and
/// a home with its own private state directory.
struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new(mode: u32) -> Self {
        let case = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        let engagement = case.engagement();
        fs::create_dir(&engagement).expect("mkdir");
        let pass = engagement.join("pass.toml");
        fs::write(&pass, PASS).expect("write pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod pass");
        // Date the pass back so reading it does not wait for it to settle.
        fs::File::options()
            .write(true)
            .open(&pass)
            .and_then(|f| {
                f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60))
            })
            .expect("date back");
        fs::set_permissions(&engagement, fs::Permissions::from_mode(mode)).expect("chmod dir");
        case
    }

    fn engagement(&self) -> PathBuf {
        self.dir.path().join("engagement")
    }

    fn pass(&self) -> String {
        self.engagement()
            .join("pass.toml")
            .to_str()
            .expect("utf-8")
            .to_owned()
    }

    fn run(&self, args: &[&str]) -> Output {
        let home = self.dir.path().join("home");
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

    /// Run `command` on the pass and return its stdout and stderr together.
    fn text(&self, args: &[&str]) -> (Option<i32>, String) {
        let pass = self.pass();
        let mut all = vec![args[0], pass.as_str()];
        all.extend_from_slice(&args[1..]);
        let out = self.run(&all);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), text)
    }
}

fn warned(text: &str, dir: &Path) -> bool {
    text.contains("warning:")
        && text.contains("sticky bit")
        && text.contains(&format!("chmod go-w {}", dir.display()))
}

fn assert_warned_everywhere(case: &Case, who: &str, mode: &str) {
    let dir = case.engagement();
    for args in [
        vec!["check"],
        vec!["status"],
        vec!["spend", "req"],
        vec!["spend", "req", "--dry-run"],
    ] {
        let (code, text) = case.text(&args);
        assert_eq!(code, Some(0), "{args:?}: {text}");
        assert!(warned(&text, &dir), "{args:?}: {text}");
        assert!(text.contains(who), "{args:?}: {text}");
        assert!(text.contains(mode), "{args:?}: {text}");
    }
}

fn assert_quiet_everywhere(case: &Case) {
    for args in [vec!["check"], vec!["status"], vec!["spend", "req"]] {
        let (code, text) = case.text(&args);
        assert_eq!(code, Some(0), "{args:?}: {text}");
        assert!(!text.contains("sticky bit"), "{args:?}: {text}");
    }
}

/// Forget the witness so that an adoption has something to adopt.
fn forget_witness(case: &Case) {
    let state = case.dir.path().join("home").join("state").join("hallpass");
    for entry in fs::read_dir(&state).expect("state") {
        let path = entry.expect("entry").path();
        if path.is_file() && !path.to_string_lossy().ends_with(".lock") {
            fs::remove_file(path).expect("remove witness");
        }
    }
}

fn ledger_files(case: &Case) -> Vec<PathBuf> {
    fs::read_dir(case.engagement())
        .expect("list")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().contains("ledger"))
        .collect()
}

#[test]
fn a_world_writable_directory_refuses_spend_and_records_nothing() {
    let case = Case::new(0o777);
    let dir = case.engagement();
    let pass = case.pass();
    let out = case.run(&["--format", "json", "spend", &pass, "req"]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(out.status.code(), Some(1), "{json}");
    assert_eq!(json["error"]["code"], "shared-directory", "{json}");
    assert_eq!(json["error"]["recording"], "not-recorded", "{json}");
    let message = json["error"]["message"].as_str().expect("message");
    assert!(
        message.contains(&format!("chmod o-w {}", dir.display())),
        "{message}"
    );
    assert!(message.contains("chmod +t"), "{message}");
    assert!(ledger_files(&case).is_empty(), "nothing is recorded");
    // The same pass in the same directory, now private, spends.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let (code, text) = case.text(&["spend", "req"]);
    assert_eq!(code, Some(0), "{text}");
}

#[test]
fn a_world_writable_directory_refuses_adopt_and_reconcile_but_not_the_preview() {
    let case = Case::new(0o700);
    let (code, text) = case.text(&["spend", "req"]);
    assert_eq!(code, Some(0), "{text}");
    forget_witness(&case);
    let (code, text) = case.text(&["adopt", "--reason", "first"]);
    assert_eq!(code, Some(0), "{text}");
    let dir = case.engagement();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).expect("chmod");
    let snapshot = || {
        ledger_files(&case)
            .iter()
            .map(|p| fs::read(p).expect("read"))
            .collect::<Vec<_>>()
    };
    let before = snapshot();
    assert!(!before.is_empty(), "the spend made a ledger");
    let (code, text) = case.text(&["adopt", "--reason", "test"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("chmod o-w"), "{text}");
    let list = case.dir.path().join("refs");
    fs::write(
        &list,
        r#"{"version": 1, "pass_id": "dirperm-1", "references": ["ref-1"]}"#,
    )
    .expect("refs");
    let list = list.to_str().expect("utf-8");
    let (code, text) = case.text(&[
        "reconcile-references",
        "--adoption",
        "2",
        "--references",
        list,
        "--reason",
        "test",
    ]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("chmod o-w"), "{text}");
    assert_eq!(before, snapshot(), "nothing was recorded");
}

#[test]
fn an_adoption_preview_warns_in_a_world_writable_directory() {
    let case = Case::new(0o700);
    let (code, text) = case.text(&["spend", "req"]);
    assert_eq!(code, Some(0), "{text}");
    forget_witness(&case);
    let dir = case.engagement();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).expect("chmod");
    let (code, text) = case.text(&["adopt", "--preview"]);
    assert_eq!(code, Some(0), "{text}");
    assert!(warned(&text, &dir), "{text}");
}

#[test]
fn a_world_writable_directory_warns_in_check_status_and_a_dry_run() {
    let case = Case::new(0o777);
    let dir = case.engagement();
    for args in [
        vec!["check"],
        vec!["status"],
        vec!["spend", "req", "--dry-run"],
    ] {
        let (code, text) = case.text(&args);
        assert_eq!(code, Some(0), "{args:?}: {text}");
        assert!(warned(&text, &dir), "{args:?}: {text}");
        assert!(text.contains("any user"), "{args:?}: {text}");
    }
    assert!(ledger_files(&case).is_empty(), "nothing is recorded");
}

#[test]
fn a_sticky_world_writable_directory_is_not_warned_about() {
    let case = Case::new(0o1777);
    assert_quiet_everywhere(&case);
}

#[test]
fn a_group_writable_directory_is_warned_about_as_the_pass_file_rule_does() {
    let case = Case::new(0o775);
    assert_warned_everywhere(&case, "users in its group", "0775");
}

#[test]
fn a_sticky_group_writable_directory_is_not_warned_about() {
    let case = Case::new(0o1775);
    assert_quiet_everywhere(&case);
}

#[test]
fn a_normal_directory_is_not_warned_about() {
    for mode in [0o700, 0o755] {
        let case = Case::new(mode);
        assert_quiet_everywhere(&case);
    }
}

#[test]
fn the_warning_is_in_the_json_warnings_of_check_and_status() {
    let case = Case::new(0o777);
    let pass = case.pass();
    for command in ["check", "status"] {
        let out = case.run(&["--format", "json", command, &pass]);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let json: serde_json::Value = serde_json::from_str(&text).expect("json");
        let warnings = json["warnings"].as_array().expect("warnings");
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().is_some_and(|w| w.contains("chmod go-w"))),
            "{command}: {text}"
        );
    }
}

#[test]
fn the_state_directory_is_refused_when_other_users_can_reach_it() {
    // The witness's own directory is checked already: a mode with any group
    // or other bit is an error, not a warning, and it names the fix.
    let case = Case::new(0o700);
    let state = case.dir.path().join("home").join("state").join("hallpass");
    let (code, _) = case.text(&["spend", "req"]);
    assert_eq!(code, Some(0));
    fs::set_permissions(&state, fs::Permissions::from_mode(0o770)).expect("chmod state");
    let (code, text) = case.text(&["spend", "req"]);
    assert_ne!(code, Some(0), "{text}");
    assert!(text.contains("chmod 700"), "{text}");
}
