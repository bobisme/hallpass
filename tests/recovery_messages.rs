//! Recovery messages say only what is true (bn-ujk): the layout of
//! `ledger-elsewhere` in text mode, the next step for each cause of
//! `witness-unavailable`, the no-witness warning against what really records a
//! witness, and the two bad adoption tokens.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";

const PASS: &str = r#"format = 1
id = "acme-2026-11"
name = "Acme voice edge"

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
        case.pass("p.toml", PASS);
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn pass(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    fn state(&self) -> PathBuf {
        self.path("home/state")
    }

    fn witness(&self) -> PathBuf {
        self.state().join("hallpass/acme-2026-11.witness")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.state())
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass")
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    fn spend(&self, extra: &[&str]) -> (i32, Value) {
        let mut args = vec!["spend", "p.toml", "calls", "--to", TO];
        args.extend_from_slice(extra);
        self.json(&args)
    }
}

fn message(reply: &Value) -> &str {
    reply["error"]["message"].as_str().expect("error message")
}

#[test]
fn ledger_elsewhere_prints_a_short_first_line_and_the_rest_indented() {
    let case = Case::new();
    assert_eq!(case.spend(&[]).0, 0);
    case.pass("q.toml", &PASS.replace("calls = 5", "calls = 9"));
    let shown = case.run(&["--verbose", "spend", "q.toml", "calls", "--to", TO]);
    assert_eq!(shown.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&shown.stderr).into_owned();
    let start = stderr.find("hallpass spend: error:").expect("error line");
    let lines: Vec<&str> = stderr[start..]
        .lines()
        .take_while(|l| *l != "Nothing was permitted.")
        .collect();
    assert!(lines.len() >= 8, "{stderr}");
    // A short headline with the code, the next step, then the full
    // message indented.
    assert!(
        lines[0]
            .starts_with("hallpass spend: error: ledger-elsewhere: the ledger for this pass id"),
        "{stderr}"
    );
    assert!(lines[0].len() < 120, "{}", lines[0]);
    assert!(
        lines[1].starts_with("Next: run `hallpass doctor q.toml`"),
        "{stderr}"
    );
    for line in &lines[2..] {
        assert!(line.starts_with("  "), "{line:?} in {stderr}");
    }
    assert!(lines[2].starts_with("  the ledger for pass"), "{stderr}");
    assert!(stderr.contains("  Do not run `hallpass adopt`"), "{stderr}");

    // JSON keeps one message string with the same words, and the headline
    // and next step as their own fields.
    let (_, out) = case.json(&["spend", "q.toml", "calls", "--to", TO]);
    let one = message(&out);
    assert!(!one.contains('\n'), "{one}");
    assert!(one.starts_with(lines[2].trim_start()));
    assert_eq!(
        out["error"]["headline"].as_str(),
        lines[0].strip_prefix("hallpass spend: error: ledger-elsewhere: ")
    );
    assert_eq!(
        out["error"]["next"].as_str(),
        lines[1].strip_prefix("Next: ")
    );
}

#[test]
fn each_witness_cause_gets_only_its_own_next_step() {
    // A state directory that cannot be written: the directory step only.
    let case = Case::new();
    assert_eq!(case.spend(&[]).0, 0);
    let dir = case.state().join("hallpass");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).expect("chmod");
    let (rc, out) = case.spend(&[]);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("witness-unavailable")),
        "{out}"
    );
    let unwritable = message(&out);
    assert!(unwritable.contains("is not writable"), "{unwritable}");
    assert!(
        unwritable.ends_with(
            "Make that directory exist and be writable by this user, then run the command again."
        ),
        "{unwritable}"
    );
    assert!(!unwritable.contains("adopt"), "{unwritable}");
    assert_eq!(out["error"]["recording"], "not-recorded");

    // A damaged witness: move it aside and adopt, and no directory step.
    fs::write(case.witness(), "not a witness").expect("damage");
    fs::set_permissions(case.witness(), fs::Permissions::from_mode(0o600)).expect("chmod");
    let (rc, out) = case.spend(&[]);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("witness-unavailable")),
        "{out}"
    );
    let damaged = message(&out);
    assert!(damaged.contains("is damaged"), "{damaged}");
    assert!(
        damaged.contains("move it aside and run `hallpass adopt`"),
        "{damaged}"
    );
    assert!(!damaged.contains("Make that directory"), "{damaged}");
    // A read-only command reports the same cause as a warning, with no
    // directory step either.
    let (rc, out) = case.json(&["permits", "p.toml", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    let warning = out["warnings"][0].as_str().expect("warning");
    assert!(warning.contains("is damaged"), "{warning}");
    assert!(!warning.contains("Make that directory"), "{warning}");
}

/// Whether the witness file exists, as a spend leaves it.
fn witness_recorded(case: &Case) -> bool {
    case.witness().exists()
}

/// The ledger and no witness: a pass brought from another state directory.
fn without_witness() -> Case {
    let case = Case::new();
    assert_eq!(case.spend(&[]).0, 0);
    fs::remove_file(case.witness()).expect("remove witness");
    fs::remove_file(case.witness().with_extension("recorded")).expect("and its copy");
    case
}

#[test]
fn the_no_witness_warning_matches_what_records_a_witness() {
    let case = without_witness();
    let (rc, status) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 0, "{status}");
    let warning = status["warnings"][0].as_str().expect("warning").to_owned();
    assert!(warning.contains("no witness"), "{warning}");
    for claim in [
        "an allowed spend records one",
        "so does a spend refused by the pass itself (a ceiling, a destination, the dates)",
        "a spend that --require-new-ref refuses for want of a witness, and a --dry-run preview, record none",
    ] {
        assert!(warning.contains(claim), "{claim:?} not in {warning}");
    }
    assert!(!witness_recorded(&case), "status records nothing");

    // A --dry-run preview: no witness.
    let (rc, out) = case.spend(&["--dry-run"]);
    assert_eq!(rc, 0, "{out}");
    assert!(!witness_recorded(&case), "--dry-run records no witness");

    // A spend refused by --require-new-ref (no witness to show the reference is new).
    let (_, out) = case.spend(&["--caller-ref", "r-1", "--require-new-ref"]);
    assert_eq!(out["result"], "refused", "{out}");
    assert!(
        !witness_recorded(&case),
        "a guarded refusal records no witness: {out}"
    );

    // An ordinary refusal does record one.
    let (_, out) = case.spend(&["--n", "1000"]);
    assert_eq!(out["refusal"]["code"], "ceiling-reached", "{out}");
    assert!(
        witness_recorded(&case),
        "an ordinary refusal records a witness"
    );

    // So does an allowed spend.
    let case = without_witness();
    let (rc, out) = case.spend(&[]);
    assert_eq!((rc, &out["result"]), (0, &"allowed".into()), "{out}");
    assert!(
        witness_recorded(&case),
        "an allowed spend records a witness"
    );
}

#[test]
fn a_malformed_adoption_token_is_told_from_a_stale_one() {
    let case = Case::new();
    assert_eq!(case.spend(&[]).0, 0);
    fs::remove_file(case.path("p.toml.ledger")).expect("lose ledger");
    let (rc, preview) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    let token = preview["token"].as_str().expect("token").to_owned();

    let (rc, out) = case.json(&["adopt", "p.toml", "--reason", "x", "--token", "garbage"]);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("usage")),
        "{out}"
    );
    let malformed = message(&out);
    assert!(
        malformed.contains("`garbage` is not an adoption token"),
        "{malformed}"
    );
    assert!(
        malformed.contains("hallpass adopt p.toml --preview"),
        "{malformed}"
    );
    assert!(!malformed.contains("stale"), "{malformed}");

    // A well-formed token for another state is stale.
    let other = format!("v1:sha256:{}", "0".repeat(64));
    let (rc, out) = case.json(&["adopt", "p.toml", "--reason", "x", "--token", &other]);
    assert_eq!(
        (rc, out["error"]["code"].as_str()),
        (1, Some("usage")),
        "{out}"
    );
    let stale = message(&out);
    assert!(stale.contains("is stale"), "{stale}");
    assert!(stale.contains("hallpass adopt p.toml --preview"), "{stale}");
    assert!(!stale.contains("is not an adoption token"), "{stale}");

    // Nothing was recorded, and the real token still works.
    assert!(!case.path("p.toml.ledger").exists());
    let (rc, out) = case.json(&["adopt", "p.toml", "--reason", "x", "--token", &token]);
    assert_eq!(rc, 0, "{out}");
}
