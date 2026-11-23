//! Wording of the messages that name a problem with a question or a pass:
//! backslashes shown once, advice that fits the query or the pass file, and
//! duplicate labels reported next to other destination problems.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");

const BASE: &str = r#"format = 1
id = "repro-1"
name = "repro"

[approval]
owner = "O"
reference = "R"
operator = "P"
valid_from = 2026-11-20T00:00:00Z
valid_until = 2026-12-31T00:00:00Z
revoked = false

[[destination]]
label = "a"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
req = 5
"#;

/// A temporary directory with its own state directory for the binary.
struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    /// Write a pass file, mode 0600, with `text`.
    fn pass(&self, text: &str) -> PathBuf {
        let path = self.dir.path().join("pass.toml");
        write_private(&path, text);
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        let home = self.dir.path().join("home");
        fs::create_dir_all(&home).expect("home");
        Command::new(BIN)
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .args(args)
            .output()
            .expect("run hallpass")
    }
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("chmod");
}

/// Standard output and standard error together, so the test does not depend
/// on which stream a message uses.
fn all_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn name_error_shows_one_backslash_in_text() {
    let case = Case::new();
    let file = case.pass(BASE);
    let out = case.run(&[
        "permits",
        file.to_str().expect("utf8 path"),
        "--to",
        "192.0.2.10:443/tcp",
        "--name",
        "bücher.example.com",
    ]);
    let text = all_text(&out);
    assert!(text.contains(r"b\u{fc}cher.example.com"), "message: {text}");
    assert!(!text.contains(r"\\u{fc}"), "doubled escape: {text}");
}

#[test]
fn name_error_has_one_backslash_in_json_message() {
    let case = Case::new();
    let file = case.pass(BASE);
    let out = case.run(&[
        "--format",
        "json",
        "permits",
        file.to_str().expect("utf8 path"),
        "--to",
        "192.0.2.10:443/tcp",
        "--name",
        "bücher.example.com",
    ]);
    let value: Value = serde_json::from_slice(&out.stdout).expect("json");
    let message = value["error"]["message"].as_str().expect("message");
    assert_eq!(message.matches('\\').count(), 1, "message: {message}");
    assert!(message.contains(r"b\u{fc}cher"), "message: {message}");
}

#[test]
fn escape_refusal_shows_single_backslashes_in_text() {
    let case = Case::new();
    // An escaped spelling of `1...` (each dot written as a unicode escape):
    // the escape is what gets refused here.
    let bs = '\\';
    let escaped = format!("address = \"1{bs}u002e{bs}u002e{bs}u002e\"");
    let file = case.pass(&BASE.replace(r#"address = "192.0.2.10""#, &escaped));
    let out = case.run(&["check", file.to_str().expect("utf8 path")]);
    let text = all_text(&out);
    assert!(
        text.contains(r#"Only \" and \\ are accepted"#),
        "message: {text}"
    );
    assert!(!text.contains(r#"Only \\""#), "doubled backslash: {text}");
}

#[test]
fn query_host_name_gets_query_advice() {
    let case = Case::new();
    let file = case.pass(BASE);
    let out = case.run(&[
        "permits",
        file.to_str().expect("utf8 path"),
        "--to",
        "localhost:8080/tcp",
    ]);
    let text = all_text(&out);
    assert!(
        text.contains("resolve the name yourself"),
        "message: {text}"
    );
    assert!(text.contains("literal IP address"), "message: {text}");
    assert!(text.contains("--name"), "message: {text}");
    assert!(!text.contains("informational"), "pass-file advice: {text}");
}

#[test]
fn pass_host_name_gets_names_and_hostname_advice() {
    let case = Case::new();
    let file = case.pass(&BASE.replace(
        r#"address = "192.0.2.10""#,
        r#"address = "app.example.com""#,
    ));
    let out = case.run(&["check", file.to_str().expect("utf8 path")]);
    let text = all_text(&out);
    assert!(text.contains("names = ["), "message: {text}");
    assert!(text.contains("`hostname`"), "message: {text}");
    assert!(text.contains("grants nothing"), "message: {text}");
}

#[test]
fn duplicate_label_is_reported_with_other_destination_problems() {
    let case = Case::new();
    let second = "[[destination]]\nlabel = \"a\"\nnetwork = \"10.0.0.0/7\"\nprotocol = \"tcp\"\nports = 443\n\n[ceilings]";
    let text = BASE.replace("[ceilings]", second);
    let file = case.pass(&text);
    let out = case.run(&["check", file.to_str().expect("utf8 path")]);
    let shown = all_text(&out);
    assert!(
        shown.contains("destination[2].label") && shown.contains("labels must be unique"),
        "duplicate label missing: {shown}"
    );
    assert!(
        shown.contains("destination[2].network"),
        "breadth problem missing: {shown}"
    );
}
