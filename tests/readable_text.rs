//! Readable text output (bn-2va1): text and pretty output show a path under
//! the current directory relative to it, and put a long message one step
//! per line (the first sentence, then `- ` lines). The words are the JSON
//! message's; JSON keeps absolute paths and one-line messages, and does not
//! depend on the directory hallpass runs in.

#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";

const PASS: &str = r#"format = 1
id = "readable-2026-11"
name = "Readable fixture"

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
calls = 5
"#;

struct Case {
    dir: tempfile::TempDir,
    elsewhere: tempfile::TempDir,
}

impl Case {
    /// A pass with three spends, then its last ledger line removed.
    fn changed() -> Self {
        let case = Self {
            dir: tempfile::tempdir().expect("tempdir"),
            elsewhere: tempfile::tempdir().expect("tempdir"),
        };
        fs::create_dir(case.path("home")).expect("home");
        let pass = case.path("p.toml");
        fs::write(&pass, PASS).expect("write pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        settle(&pass);
        for _ in 0..3 {
            let out = case.run(
                case.dir.path(),
                &["spend", &case.arg("p.toml"), "calls", "--to", TO],
            );
            assert_eq!(out.status.code(), Some(0), "{out:?}");
        }
        let ledger = case.path("p.toml.ledger");
        let text = fs::read_to_string(&ledger).expect("ledger");
        let kept: String = text.lines().take(3).flat_map(|l| [l, "\n"]).collect();
        fs::write(&ledger, kept).expect("cut");
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The absolute path of a file in the case directory, as an argument.
    fn arg(&self, name: &str) -> String {
        self.path(name).to_str().expect("utf-8").to_owned()
    }

    /// The case directory with a trailing slash: the prefix text output
    /// drops when it runs there.
    fn prefix(&self) -> String {
        format!("{}/", self.dir.path().display())
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(cwd)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env_remove("PWD")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .output()
            .expect("run hallpass")
    }

    fn text(&self, cwd: &Path, args: &[&str]) -> (Option<i32>, String) {
        let mut all = vec!["--format", "text"];
        all.extend_from_slice(args);
        let out = self.run(cwd, &all);
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), shown)
    }

    fn json(&self, cwd: &Path, args: &[&str]) -> (Vec<u8>, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run(cwd, &all);
        let reply = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)));
        (out.stdout, reply)
    }
}

/// Backdate a file so that hallpass reads it at once.
fn settle(path: &Path) {
    let then = SystemTime::now() - Duration::from_secs(5);
    fs::File::options()
        .write(true)
        .open(path)
        .and_then(|f| f.set_modified(then))
        .expect("backdate");
}

/// Text lines as the one-line message they show.
fn joined(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|l| {
            let l = l.trim_start();
            l.strip_prefix("- ").unwrap_or(l)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The indented lines after the line that starts with `after`.
fn block<'a>(shown: &'a str, after: &str) -> Vec<&'a str> {
    shown
        .lines()
        .skip_while(|l| !l.starts_with(after))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .collect()
}

#[test]
fn an_error_shows_short_paths_and_one_step_per_line() {
    let case = Case::changed();
    let here = case.dir.path();
    let args = ["spend", &case.arg("p.toml"), "calls", "--to", TO];
    let (code, shown) = case.text(here, &args);
    assert_eq!(code, Some(1), "{shown}");
    assert!(!shown.contains(&case.prefix()), "{shown}");
    assert!(
        shown.contains("\nNext: run `hallpass doctor p.toml`, which"),
        "{shown}"
    );
    let detail = block(&shown, "Next: ");
    assert!(
        detail[0].starts_with("  the ledger p.toml.ledger was changed outside hallpass: "),
        "{shown}"
    );
    assert!(
        detail[0].contains("(witness: home/state/hallpass/"),
        "{shown}"
    );
    assert!(
        detail[1..].iter().all(|l| l.starts_with("    - ")),
        "{shown}"
    );
    assert!(detail.len() >= 3, "{shown}");
    assert!(shown.lines().all(|l| l.len() < 300), "{shown}");
    // The JSON message keeps its absolute paths, on one line; the text has
    // the same words.
    let (_, reply) = case.json(here, &args);
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(message.contains(&format!("the ledger {}p.toml.ledger ", case.prefix())));
    assert!(!message.contains('\n'));
    assert_eq!(joined(&detail), message.replace(&case.prefix(), ""));
}

#[test]
fn doctor_details_are_bullets_and_its_next_command_pastes() {
    let case = Case::changed();
    let here = case.dir.path();
    let (code, shown) = case.text(here, &["doctor", &case.arg("p.toml")]);
    assert_eq!(code, Some(2), "{shown}");
    assert!(!shown.contains(&case.prefix()), "{shown}");
    let next = shown
        .lines()
        .find_map(|l| l.strip_prefix("Next: "))
        .unwrap_or_else(|| panic!("{shown}"));
    assert_eq!(
        next, "hallpass compare-backups p.toml p.toml.ledger",
        "{shown}"
    );
    let details = block(&shown, "Details:");
    assert!(
        details[0].starts_with("  the ledger p.toml.ledger was changed"),
        "{shown}"
    );
    assert!(
        details[1..].iter().all(|l| l.starts_with("    - ")),
        "{shown}"
    );
    assert!(
        details
            .iter()
            .any(|l| l.contains("`hallpass adopt p.toml --preview`")),
        "{shown}"
    );
    // The command as shown runs in this directory and does what the JSON
    // argument list does.
    let (_, reply) = case.json(here, &["doctor", &case.arg("p.toml")]);
    let argv: Vec<&str> = reply["next"]
        .as_array()
        .expect("next")
        .iter()
        .map(|w| w.as_str().expect("word"))
        .collect();
    assert_eq!(argv[2], case.arg("p.toml"));
    let pasted: Vec<&str> = next.split(' ').skip(1).collect();
    let (pasted_code, pasted_shown) = case.text(here, &pasted);
    let (argv_code, argv_shown) = case.text(here, &argv[1..]);
    assert_eq!(pasted_code, argv_code, "{pasted_shown}");
    assert_eq!(pasted_shown, argv_shown);
}

#[test]
fn a_path_outside_the_current_directory_stays_absolute() {
    let case = Case::changed();
    let (_, shown) = case.text(case.elsewhere.path(), &["doctor", &case.arg("p.toml")]);
    assert!(
        shown.contains(&format!(
            "Next: hallpass compare-backups {0}p.toml {0}p.toml.ledger",
            case.prefix()
        )),
        "{shown}"
    );
    assert!(!shown.contains("../"), "{shown}");
}

#[test]
fn json_does_not_depend_on_the_current_directory() {
    let case = Case::changed();
    for args in [
        vec!["doctor", &case.arg("p.toml")],
        vec!["spend", &case.arg("p.toml"), "calls", "--to", TO],
        vec!["permits", &case.arg("p.toml"), "--to", TO],
    ] {
        let (inside, reply) = case.json(case.dir.path(), &args);
        let (outside, _) = case.json(case.elsewhere.path(), &args);
        assert_eq!(
            String::from_utf8_lossy(&inside),
            String::from_utf8_lossy(&outside),
            "{args:?}"
        );
        let text = String::from_utf8_lossy(&inside);
        assert!(text.contains(&case.prefix()), "{text}");
        assert!(reply.is_object());
    }
}

#[test]
fn data_in_text_output_is_shown_as_it_is() {
    let case = Case::changed();
    let here = case.dir.path();
    // A pass that names a path under the current directory in a comment.
    let text = format!("# notes: {}notes.txt\n{PASS}", case.prefix());
    let pass = case.path("q.toml");
    fs::write(&pass, &text).expect("write pass");
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
    settle(&pass);
    fs::create_dir(case.path("archive")).expect("archive");
    fs::set_permissions(case.path("archive"), fs::Permissions::from_mode(0o700)).expect("chmod");
    let (_, archived) = case.json(
        here,
        &["archive", &case.arg("q.toml"), &case.arg("archive")],
    );
    let digest = archived["digest"].as_str().expect("digest").to_owned();
    let out = case.run(here, &["retrieve", &case.arg("archive"), &digest]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), text);
}
