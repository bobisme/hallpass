//! Short text messages (bn-u8fo): without `--verbose`, an error, a spend
//! refusal and doctor's report are a headline, `Next:`, at most three
//! bullets and a pointer to the full text; `--verbose` prints them in full,
//! and JSON always has the full text. Help lists the agent workflow as
//! numbered steps.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
/// The longest a short message may be.
const SHORT: usize = 600;

const PASS: &str = r#"format = 1
id = "short-2026-11"
name = "Short messages"

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
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let case = Self { dir };
        case.pass("p.toml");
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The pass, written with mode 0600 and backdated so it reads at once.
    fn pass(&self, name: &str) {
        let path = self.path(name);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).expect("dir");
        }
        fs::write(&path, PASS).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let file = fs::File::options().write(true).open(&path).expect("open");
        file.set_modified(SystemTime::now() - Duration::from_secs(60))
            .expect("backdate");
    }

    /// Exit code and stdout and stderr together.
    fn run(&self, args: &[&str]) -> (Option<i32>, String) {
        let out = Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(
            &String::from_utf8_lossy(&out.stderr)
                .lines()
                .filter(|l| !l.starts_with("hallpass: WARNING: test clock"))
                .flat_map(|l| [l, "\n"])
                .collect::<String>(),
        );
        (out.status.code(), text)
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let out = Command::new(BIN)
            .args(&all)
            .current_dir(self.dir.path())
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass");
        serde_json::from_slice(&out.stdout).expect("json")
    }

    fn spend(&self) -> (Option<i32>, String) {
        self.run(&["spend", "p.toml", "calls", "--to", TO])
    }
}

/// A short message: at most `SHORT` characters, a `Next:` line, at most
/// three bullets, and the pointer to the full text.
fn assert_short(text: &str, more: &str) {
    assert!(text.len() <= SHORT, "{} characters: {text}", text.len());
    assert!(text.lines().any(|l| l.starts_with("Next: ")), "{text}");
    let bullets = text.lines().filter(|l| l.starts_with("  - ")).count();
    assert!(bullets <= 3, "{text}");
    assert!(text.contains(more), "{text}");
}

/// The pointer of a short error whose next step is doctor.
const TO_DOCTOR: &str = "which names the safe step (add --verbose for the full text)\n";

#[test]
fn a_missing_ledger_is_short_and_full_with_verbose() {
    let case = Case::new();
    assert_eq!(case.spend().0, Some(0));
    fs::rename(case.path("p.toml.ledger"), case.path("gone.ledger")).expect("move");

    let (code, short) = case.spend();
    assert_eq!(code, Some(1), "{short}");
    assert!(
        short.starts_with("hallpass spend: error: ledger-missing: "),
        "{short}"
    );
    assert_short(&short, TO_DOCTOR);
    assert!(short.contains("Nothing was permitted."), "{short}");
    assert!(
        short.contains("`hallpass adopt p.toml --preview`"),
        "{short}"
    );

    // --verbose prints the whole message, whose words JSON has too.
    let (_, full) = case.run(&["--verbose", "spend", "p.toml", "calls", "--to", TO]);
    assert!(full.len() > short.len(), "{full}");
    assert!(
        full.contains("hallpass will not count from zero."),
        "{full}"
    );
    assert!(!full.contains("More: "), "{full}");
    let reply = case.json(&["spend", "p.toml", "calls", "--to", TO]);
    let verbose = case.json(&["--verbose", "spend", "p.toml", "calls", "--to", TO]);
    assert_eq!(reply["error"], verbose["error"]);
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(message.contains("hallpass will not count from zero."));

    // A command that only reads never advises adopting, short or not.
    let (_, permits) = case.run(&["permits", "p.toml", "--to", TO]);
    assert!(!permits.contains("hallpass adopt"), "{permits}");
    assert_short(&permits, TO_DOCTOR);
}

#[test]
fn doctor_shows_details_and_findings_only_with_verbose() {
    let case = Case::new();
    assert_eq!(case.spend().0, Some(0));
    fs::rename(case.path("p.toml.ledger"), case.path("gone.ledger")).expect("move");

    let (code, short) = case.run(&["doctor", "p.toml"]);
    assert_eq!(code, Some(2), "{short}");
    assert!(short.starts_with("BLOCKED: ledger-missing: "), "{short}");
    assert!(!short.contains("Details:"), "{short}");
    assert!(!short.contains("Also:"), "{short}");
    assert!(short.len() <= SHORT, "{short}");
    assert!(
        short.ends_with("More: `hallpass --verbose doctor p.toml`.\n"),
        "{short}"
    );

    let (code, full) = case.run(&["--verbose", "doctor", "p.toml"]);
    assert_eq!(code, Some(2), "{full}");
    assert!(full.contains("\nDetails:\n"), "{full}");
    assert!(!full.contains("More: "), "{full}");
    // The details never repeat a sentence of the advice under `Next:`.
    let details = &full[full.find("Details:").expect("details")..];
    assert!(!details.contains("First put the ledger back"), "{full}");

    // JSON is the same either way.
    assert_eq!(
        case.json(&["doctor", "p.toml"]),
        case.json(&["--verbose", "doctor", "p.toml"])
    );
}

#[test]
fn a_second_pass_file_gets_a_short_error() {
    let case = Case::new();
    assert_eq!(case.spend().0, Some(0));
    case.pass("other/p.toml");
    let (code, short) = case.run(&["spend", "other/p.toml", "calls", "--to", TO]);
    assert_eq!(code, Some(1), "{short}");
    assert_short(&short, TO_DOCTOR);
    assert!(
        short.contains("the intact ledger is p.toml.ledger"),
        "{short}"
    );
    assert!(short.contains("Do not run `hallpass adopt`"), "{short}");
    let (code, doctor) = case.run(&["doctor", "other/p.toml"]);
    assert_eq!(code, Some(2), "{doctor}");
    assert!(doctor.len() <= SHORT, "{doctor}");
}

#[test]
fn a_damaged_or_changed_ledger_names_the_last_resort_and_its_receipts() {
    let case = Case::new();
    for _ in 0..2 {
        assert_eq!(case.spend().0, Some(0));
    }
    let ledger = case.path("p.toml.ledger");
    let whole = fs::read_to_string(&ledger).expect("ledger");
    // A middle line edited: the ledger is not a chain.
    fs::write(&ledger, whole.replacen("\"n\":1", "\"n\":0", 1)).expect("edit");
    let (_, short) = case.spend();
    assert_short(&short, "More: `hallpass --verbose doctor p.toml`.");
    assert!(
        short.contains("the receipts in the moved ledger are not in the new chain"),
        "{short}"
    );
    let (_, doctor) = case.run(&["doctor", "p.toml"]);
    assert!(doctor.len() <= SHORT, "{doctor}");
    assert!(
        doctor.contains("`mv -n p.toml.ledger p.toml.ledger.damaged`"),
        "{doctor}"
    );
    assert!(
        doctor.contains("the receipts in the moved ledger"),
        "{doctor}"
    );
    // An older copy put back: the chain verifies, so it is adopted in place.
    let first: String = whole.lines().take(2).flat_map(|l| [l, "\n"]).collect();
    fs::write(&ledger, first).expect("rewind");
    let (_, short) = case.spend();
    assert_short(&short, TO_DOCTOR);
    assert!(
        short.contains("`hallpass adopt p.toml --preview` adopts it in place"),
        "{short}"
    );
    assert!(short.contains("as receipts"), "{short}");
    let (_, doctor) = case.run(&["doctor", "p.toml"]);
    assert!(doctor.len() <= SHORT, "{doctor}");
    assert!(doctor.contains("adopt this ledger in place"), "{doctor}");
}

#[test]
fn a_short_error_is_shown_whole() {
    let case = Case::new();
    let (code, text) = case.run(&["spend", "nope.toml", "calls"]);
    assert_eq!(code, Some(1), "{text}");
    assert!(!text.contains("More: "), "{text}");
    let (_, full) = case.run(&["--verbose", "spend", "nope.toml", "calls"]);
    assert_eq!(text, full);
}

#[test]
fn help_lists_the_agent_workflow_as_numbered_steps() {
    let case = Case::new();
    let (code, text) = case.run(&["help", "diff"]);
    assert_eq!(code, Some(0), "{text}");
    let workflow: Vec<&str> = text
        .lines()
        .skip_while(|l| *l != "Agent workflow")
        .skip(1)
        .take_while(|l| !l.is_empty())
        .collect();
    assert!(workflow.len() > 5, "{text}");
    for (n, line) in workflow.iter().enumerate() {
        assert!(line.starts_with(&format!("  {}. ", n + 1)), "{line}");
    }
    // JSON keeps the workflow as one paragraph with the same words.
    let page = case.json(&["help", "diff"]);
    let paragraph = page["workflow"].as_str().expect("workflow");
    assert!(!paragraph.contains('\n'));
    for line in workflow {
        let step = line.split_once(". ").expect("number").1;
        assert!(paragraph.contains(step), "{step}");
    }
}
