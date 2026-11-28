//! A second pass file with the id of a live ledger (bn-11m).
//!
//! An amended approval saved next to the original with the same id has no
//! ledger beside it. When the ledger where the witness last saw it is intact,
//! that is `ledger-elsewhere`, not a lost ledger: the message names the live
//! ledger and its pass file, and `adopt` refuses, because adopting would fork
//! the history. A last-seen ledger that cannot be read or verified, or that
//! disagrees with the witness, falls back to `ledger-missing` and its advice.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
calls = 100
"#;

struct Case {
    dir: tempfile::TempDir,
    state_home: PathBuf,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let state_home = dir.path().join("home").join("state");
        Self { dir, state_home }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn pass(&self, name: &str, text: &str) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, text).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        path
    }

    fn witness(&self) -> PathBuf {
        self.state_home
            .join("hallpass")
            .join("acme-2026-11.witness")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.dir.path().join("home"))
            .env("XDG_STATE_HOME", &self.state_home)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass")
    }

    /// Run with `--format json`: the exit code and the reply.
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

    fn spend(&self, pass: &str) -> (i32, Value) {
        self.json(&["spend", pass, "calls", "--to", TO])
    }

    /// `p.toml` with three recorded calls, and the amended `q.toml` beside it
    /// with the same id and a raised ceiling.
    fn amended() -> Self {
        let case = Self::new();
        case.pass("p.toml", PASS);
        for n in 1..=3 {
            let (rc, out) = case.spend("p.toml");
            assert_eq!((rc, &out["seq"]), (0, &Value::from(n)), "{out}");
        }
        case.pass("q.toml", &PASS.replace("calls = 100", "calls = 200"));
        case
    }
}

fn error(reply: &Value) -> (&str, &str) {
    (
        reply["error"]["code"].as_str().unwrap_or("none"),
        reply["error"]["message"].as_str().unwrap_or(""),
    )
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn bytes(path: &Path) -> Vec<u8> {
    fs::read(path).expect("read")
}

#[test]
fn a_second_pass_file_is_sent_to_the_live_ledger_and_never_adopted() {
    let case = Case::amended();
    let live = case.path("p.toml.ledger");
    let (ledger, witness) = (bytes(&live), bytes(&case.witness()));

    let (rc, out) = case.spend("q.toml");
    let (code, message) = error(&out);
    assert_eq!((rc, code), (1, "ledger-elsewhere"), "{out}");
    for part in [
        "the ledger for pass `acme-2026-11` is not beside this pass file, but an intact one exists elsewhere",
        "This pass file: q.toml.",
        "Expected ledger: q.toml.ledger (does not exist)",
        &format!("Live ledger: {}", live.display()),
        "(last logical sequence 3, spent: calls 3)",
        &format!(
            "Pass file beside the live ledger: {}, so this pass file is a second pass file with the same id",
            case.path("p.toml").display()
        ),
        "copy it beside the live pass file, `mv` the copy over that file and spend from it",
        "move the live ledger to the expected ledger path",
        "Do not run `hallpass adopt` on this pass file",
        "give it its own id",
    ] {
        assert!(message.contains(part), "{part:?} not in {message}");
    }
    // Short and plain: every path once, and well under the old 1,400 characters.
    for path in [
        live.display().to_string(),
        "q.toml.ledger".to_owned(),
        format!("{}, so", case.path("p.toml").display()),
    ] {
        assert_eq!(message.matches(&*path).count(), 1, "{message}");
    }
    assert!(
        message.len() < 1100,
        "{} characters: {message}",
        message.len()
    );
    assert!(!message.contains("if it is really lost"), "{message}");
    assert_eq!(out["error"]["recording"], Value::Null);

    // status says the same, with the same advice; text goes to stderr.
    let (rc, status) = case.json(&["status", "q.toml"]);
    assert_eq!((rc, error(&status)), (1, ("ledger-elsewhere", message)));
    let shown = case.run(&["status", "q.toml"]);
    assert_eq!(shown.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&shown.stderr).contains("`mv` the copy over that file"),
        "{}",
        text(&shown)
    );

    // adopt --preview and adopt agree, and both refuse.
    let (rc, preview) = case.json(&["adopt", "q.toml", "--preview"]);
    assert_eq!((rc, error(&preview)), (1, ("ledger-elsewhere", message)));
    let (rc, adopted) = case.json(&["adopt", "q.toml", "--reason", "amended approval"]);
    assert_eq!((rc, error(&adopted)), (1, ("ledger-elsewhere", message)));
    let shown = case.run(&["adopt", "q.toml", "--reason", "amended approval"]);
    assert_eq!(shown.status.code(), Some(1));
    assert!(!text(&shown).contains("ADOPTED"), "{}", text(&shown));

    // Nothing was created, appended or rewritten.
    assert!(!case.path("q.toml.ledger").exists());
    assert_eq!(bytes(&live), ledger);
    assert_eq!(bytes(&case.witness()), witness);

    // Applying the revision as advised continues the count, with no fork.
    // A copy renamed over the live pass, as the message advises, is not a
    // pass changed in place, so the spend warns of nothing.
    fs::copy(case.path("q.toml"), case.path("p.toml.new")).expect("copy");
    fs::rename(case.path("p.toml.new"), case.path("p.toml")).expect("revise by rename");
    let (rc, out) = case.spend("p.toml");
    assert_eq!(rc, 0, "{out}");
    assert_eq!((&out["spent"], &out["total"]), (&4.into(), &200.into()));
    assert_eq!(out["warnings"], Value::Array(Vec::new()), "{out}");
    let (_, status) = case.json(&["status", "p.toml"]);
    assert_eq!(status["ledger"]["witness"], "matches");
    assert_eq!(status["ledger"]["adoptions"], 0);
}

#[test]
fn read_only_commands_name_the_live_ledger_without_advising_adopt() {
    let case = Case::amended();
    let commands: [&[&str]; 6] = [
        &["permits", "q.toml", "--to", TO],
        &["ledger", "q.toml"],
        &["capacity", "q.toml", "--charge", "calls=1", "--to", TO],
        &["receipt", "q.toml", "--caller-ref", "unit-1"],
        &["checkpoint", "q.toml"],
        &["diff", "q.toml", "q.toml", "--budget-impact"],
    ];
    for args in commands {
        let (rc, out) = case.json(args);
        let (code, message) = error(&out);
        assert_eq!((rc, code), (1, "ledger-elsewhere"), "{args:?}: {out}");
        assert!(message.contains("Live ledger:"), "{args:?}: {message}");
        assert!(
            message.contains("This command only reads and changed nothing"),
            "{args:?}: {message}"
        );
        let shown = case.run(args);
        assert!(
            !text(&shown).contains("adopt"),
            "{args:?}: {}",
            text(&shown)
        );
        assert!(!out.to_string().contains("adopt"), "{args:?}: {out}");
    }
    // These may stop at their own inputs first; whatever they say, they
    // never send the reader to adopt.
    let evidence: [&[&str]; 4] = [
        &["reconcile", "q.toml", "missing-manifest.json"],
        &["audit-receipts", "q.toml", "."],
        &["audit-charges", "q.toml", "."],
        &["compare-backups", "q.toml", "p.toml.ledger"],
    ];
    for args in evidence {
        for shown in [
            case.run(args),
            case.run(&[&["--format", "json"], args].concat()),
        ] {
            assert!(
                !text(&shown).contains("adopt"),
                "{args:?}: {}",
                text(&shown)
            );
        }
    }
}

#[test]
fn a_pass_moved_without_its_ledger_is_told_to_move_the_ledger() {
    let case = Case::new();
    case.pass("p.toml", PASS);
    assert_eq!(case.spend("p.toml").0, 0);
    fs::create_dir(case.path("archive")).expect("mkdir");
    fs::rename(case.path("p.toml"), case.path("archive/p.toml")).expect("move pass");
    let (rc, out) = case.spend("archive/p.toml");
    let (code, message) = error(&out);
    assert_eq!((rc, code), (1, "ledger-elsewhere"), "{out}");
    assert!(
        message.contains("No pass file is beside the live ledger"),
        "{message}"
    );
    assert!(
        message.contains("Move the live ledger to the expected ledger path")
            && message.contains("Expected ledger: archive/p.toml.ledger")
            && message.contains(&format!(
                "Live ledger: {}",
                case.path("p.toml.ledger").display()
            )),
        "{message}"
    );
    let (rc, out) = case.json(&["adopt", "archive/p.toml", "--preview"]);
    assert_eq!((rc, error(&out).0), (1, "ledger-elsewhere"), "{out}");
    fs::rename(
        case.path("p.toml.ledger"),
        case.path("archive/p.toml.ledger"),
    )
    .expect("move ledger");
    let (rc, out) = case.spend("archive/p.toml");
    assert_eq!((rc, &out["spent"]), (0, &2.into()), "{out}");
}

#[test]
fn a_really_lost_ledger_keeps_the_adopt_advice_and_warns_about_references() {
    let case = Case::amended();
    fs::remove_file(case.path("p.toml.ledger")).expect("lose the ledger");
    for pass in ["p.toml", "q.toml"] {
        let (rc, out) = case.spend(pass);
        let (code, message) = error(&out);
        assert_eq!((rc, code), (1, "ledger-missing"), "{out}");
        assert!(message.contains("is missing"), "{message}");
        assert!(
            message.contains(&format!(
                "if it is really lost, run `hallpass adopt {pass} --reason"
            )),
            "{message}"
        );
        assert!(!message.contains("intact"), "{message}");
    }

    // The preview warns before anything is recorded; adopt repeats it.
    let (rc, preview) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(
        (rc, &preview["case"]),
        (0, &"ledger-missing".into()),
        "{preview}"
    );
    let warning = preview["warnings"][0].as_str().expect("preview warning");
    assert!(
        warning.starts_with("after this adoption, guarded spends (--require-new-ref)"),
        "{warning}"
    );
    assert!(warning.contains("reference-inconclusive"), "{warning}");
    assert_eq!(preview["advice"][0]["message"], warning);
    let shown = case.run(&["adopt", "p.toml", "--preview"]);
    assert!(
        String::from_utf8_lossy(&shown.stderr).contains("hallpass: warning: after this adoption"),
        "{}",
        text(&shown)
    );
    let token = preview["token"].as_str().expect("token");
    let (rc, adopted) = case.json(&[
        "adopt",
        "p.toml",
        "--reason",
        "ledger lost",
        "--token",
        token,
    ]);
    assert_eq!(
        (rc, &adopted["carried"]["calls"]),
        (0, &3.into()),
        "{adopted}"
    );
    let warning = adopted["warnings"][0].as_str().expect("adopt warning");
    assert!(
        warning.starts_with("from this adoption on, guarded spends"),
        "{warning}"
    );

    // The warning is true: a guarded spend is now inconclusive.
    let (rc, out) = case.json(&[
        "spend",
        "p.toml",
        "calls",
        "--to",
        TO,
        "--caller-ref",
        "unit-9",
        "--require-new-ref",
    ]);
    assert_eq!(
        (rc, &out["refusal"]["code"]),
        (2, &"reference-inconclusive".into()),
        "{out}"
    );
}

#[test]
fn an_adoption_that_keeps_every_line_does_not_warn() {
    let case = Case::new();
    case.pass("p.toml", PASS);
    assert_eq!(case.spend("p.toml").0, 0);
    // The same ledger under another state directory has no witness.
    fs::remove_dir_all(&case.state_home).expect("forget the witness");
    let (rc, preview) = case.json(&["adopt", "p.toml", "--preview"]);
    assert_eq!(
        (rc, &preview["case"]),
        (0, &"no-witness".into()),
        "{preview}"
    );
    assert_eq!(preview["warnings"], Value::Array(Vec::new()));
    let (rc, adopted) = case.json(&["adopt", "p.toml", "--reason", "moved machines"]);
    assert_eq!(rc, 0, "{adopted}");
    assert_eq!(adopted["warnings"], Value::Array(Vec::new()));
}

/// Each way the last-seen ledger can fail to be the witnessed history falls
/// back to `ledger-missing`, and adopt --preview with it.
#[test]
fn a_last_seen_ledger_that_does_not_verify_falls_back_to_ledger_missing() {
    let case = Case::amended();
    let live = case.path("p.toml.ledger");
    let good = bytes(&live);
    let text = String::from_utf8(good.clone()).expect("utf8");
    let lines: Vec<&str> = text.lines().collect();
    let last_edited = text.replacen(lines[3], &lines[3].replace("\"n\":1", "\"n\":2"), 1);
    assert_ne!(last_edited, text);
    let middle_edited = text.replacen(lines[2], &lines[2].replace("\"n\":1", "\"n\":2"), 1);
    assert_ne!(middle_edited, text);
    let shorter = format!("{}\n{}\n", lines[0], lines[1]);

    let check = |what: &str| {
        let (rc, out) = case.spend("q.toml");
        let (code, message) = error(&out);
        assert_eq!((rc, code), (1, "ledger-missing"), "{what}: {out}");
        assert!(
            message.contains("if it is really lost"),
            "{what}: {message}"
        );
        let (rc, preview) = case.json(&["adopt", "q.toml", "--preview"]);
        assert_eq!(
            (rc, &preview["case"]),
            (0, &"ledger-missing".into()),
            "{what}: {preview}"
        );
        assert!(!case.path("q.toml.ledger").exists(), "{what}");
    };
    let restore = || {
        let _ = fs::remove_file(&live);
        fs::write(&live, &good).expect("restore");
        fs::set_permissions(&live, fs::Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(error(&case.spend("q.toml").1).0, "ledger-elsewhere");
    };

    for (what, content) in [
        ("an edited last line", last_edited.as_str()),
        ("a broken chain", middle_edited.as_str()),
        ("an older copy", shorter.as_str()),
        ("not a ledger", "not a ledger\n"),
    ] {
        fs::write(&live, content).expect("damage");
        check(what);
        restore();
    }

    fs::set_permissions(&live, fs::Permissions::from_mode(0o644)).expect("chmod");
    check("a ledger others can read");
    restore();

    let aside = case.path("aside.ledger");
    fs::rename(&live, &aside).expect("move aside");
    std::os::unix::fs::symlink(&aside, &live).expect("symlink");
    check("a symbolic link");
    fs::remove_file(&live).expect("remove link");
    fs::rename(&aside, &live).expect("move back");
    restore();

    // Another pass id's ledger at that path.
    case.pass("other.toml", &PASS.replace("acme-2026-11", "other-2026-11"));
    assert_eq!(case.spend("other.toml").0, 0);
    fs::copy(case.path("other.toml.ledger"), &live).expect("swap in");
    check("a ledger of another pass id");
    restore();

    // A ledger that grew past the witness (a spend that stopped before its
    // witness update) does not agree with the witness either.
    let witness = bytes(&case.witness());
    assert_eq!(case.spend("p.toml").0, 0);
    fs::write(case.witness(), &witness).expect("rewind the witness");
    check("a ledger past the witness");
}

#[test]
fn a_reviewed_token_cannot_adopt_once_the_ledger_is_back() {
    let case = Case::amended();
    let live = case.path("p.toml.ledger");
    let aside = case.path("aside.ledger");
    fs::rename(&live, &aside).expect("move aside");
    let (rc, preview) = case.json(&["adopt", "q.toml", "--preview"]);
    assert_eq!(
        (rc, &preview["case"]),
        (0, &"ledger-missing".into()),
        "{preview}"
    );
    let token = preview["token"].as_str().expect("token").to_owned();
    fs::rename(&aside, &live).expect("move back");
    let (rc, out) = case.json(&["adopt", "q.toml", "--reason", "reviewed", "--token", &token]);
    assert_eq!((rc, error(&out).0), (1, "ledger-elsewhere"), "{out}");
    assert!(!case.path("q.toml.ledger").exists());
}
