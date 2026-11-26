#![cfg(feature = "cli")]
//! The reference guard (`--require-new-ref`) after a ledger moves to a state
//! directory without its witness, and after each kind of adoption. An
//! adoption that kept the ledger as it stood loses no reference, so the
//! guard checks new references again. An adoption that accepted a ledger
//! without lines hallpass had recorded keeps every new reference
//! inconclusive.

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = include_str!("../docs/review-approval.toml");
const TO: &str = "192.0.2.10:443/tcp@app.example.com";

/// A pass with its ledger in `dir`, used from the state directory `state`
/// (one machine or account).
struct Engagement {
    dir: PathBuf,
    state: PathBuf,
}

impl Engagement {
    fn new(dir: PathBuf, state: PathBuf) -> Self {
        fs::create_dir_all(&dir).expect("pass directory");
        let e = Self { dir, state };
        fs::write(e.pass(), format!("{PASS}\n[ceilings]\ncalls = 100\n")).expect("pass");
        fs::set_permissions(e.pass(), fs::Permissions::from_mode(0o600)).expect("private pass");
        e
    }

    /// Copy the pass and its ledger to `dir`, to be used from `state`.
    fn copy_to(&self, dir: PathBuf, state: PathBuf) -> Self {
        fs::create_dir_all(&dir).expect("pass directory");
        let copy = Self { dir, state };
        fs::copy(self.pass(), copy.pass()).expect("copy the pass");
        fs::copy(self.ledger(), copy.ledger()).expect("copy the ledger");
        copy
    }

    fn pass(&self) -> PathBuf {
        self.dir.join("engagement.pass.toml")
    }

    fn ledger(&self) -> PathBuf {
        hallpass::ledger_path(&self.pass())
    }

    fn witness(&self) -> PathBuf {
        hallpass::StateDir::new(self.state.join("hallpass"))
            .witness_path("review-example")
            .expect("witness path")
    }

    fn command(&self, name: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.args(["--format", "json", name])
            .arg(self.pass())
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", &self.state);
        cmd
    }

    fn guarded(&self, reference: &str) -> Command {
        let mut cmd = self.command("spend");
        cmd.args([
            "calls",
            "--to",
            TO,
            "--caller-ref",
            reference,
            "--require-new-ref",
        ]);
        cmd
    }

    fn adopt(&self, reason: &str) -> Value {
        reply(
            &self
                .command("adopt")
                .args(["--reason", reason])
                .output()
                .expect("adopt"),
            0,
        )
    }
}

fn reply(out: &Output, code: i32) -> Value {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("JSON")
}

fn recorded(cmd: &mut Command, seq: u64) {
    let value = reply(&cmd.output().expect("spend"), 0);
    assert_eq!(value["result"], "allowed");
    assert_eq!(value["seq"], seq);
}

fn assert_duplicate(cmd: &mut Command, reference: &str, sequences: &[u64]) {
    let value = reply(&cmd.output().expect("spend"), 2);
    assert_eq!(value["refusal"]["code"], "duplicate-reference", "{value}");
    assert!(value["seq"].is_null());
    assert_eq!(value["reference_evidence"]["caller_ref"], reference);
    assert_eq!(value["reference_evidence"]["sequences"], json!(sequences));
}

/// Refused as inconclusive with empty match details; returns the message.
fn inconclusive(cmd: &mut Command, reference: &str) -> String {
    let value = reply(&cmd.output().expect("spend"), 2);
    assert_eq!(value["command"], "spend");
    assert_eq!(value["result"], "refused");
    assert_eq!(
        value["refusal"]["code"], "reference-inconclusive",
        "{value}"
    );
    assert!(value["seq"].is_null());
    assert_eq!(
        value["reference_evidence"],
        json!({"caller_ref": reference, "match_count": 0, "sequences": [], "truncated": false})
    );
    value["refusal"]["message"]
        .as_str()
        .expect("message")
        .to_owned()
}

#[test]
fn a_moved_ledger_adopted_as_it_stands_checks_new_references_again() {
    let root = tempfile::tempdir().expect("directory");
    let first = Engagement::new(root.path().join("lab"), root.path().join("lab-state"));
    recorded(&mut first.guarded("unit-1"), 1);
    recorded(&mut first.guarded("unit-2"), 2);

    // The engagement moves to another machine: a state directory with no
    // witness for this pass. The guard cannot tell a complete ledger from a
    // partial copy, refuses, records no witness, and names the way out.
    let moved = first.copy_to(root.path().join("field"), root.path().join("field-state"));
    let before = fs::read(moved.ledger()).expect("ledger");
    for flags in [&["--dry-run"][..], &[], &[]] {
        let message = inconclusive(moved.guarded("unit-3").args(flags), "unit-3");
        assert!(message.contains("no local witness"), "{message}");
        let adopt = format!("run `hallpass adopt {} --reason", moved.pass().display());
        assert!(message.contains(&adopt), "{message}");
        assert_eq!(fs::read(moved.ledger()).expect("ledger"), before);
        assert!(!moved.witness().exists());
    }
    assert_duplicate(&mut moved.guarded("unit-1"), "unit-1", &[1]);

    let adopted = moved.adopt("moved with the pass from the lab");
    assert_eq!(adopted["case"], "no-witness");
    assert_eq!(adopted["seq"], 3);
    assert_eq!(adopted["carried"], json!({}));
    assert!(adopted["previous"].is_null());

    // The adoption kept every line, so the guard checks new references again.
    let preview = reply(
        &moved
            .guarded("unit-3")
            .arg("--dry-run")
            .output()
            .expect("preview"),
        0,
    );
    assert_eq!(preview["result"], "would-allow");
    recorded(&mut moved.guarded("unit-3"), 4);
    assert_duplicate(&mut moved.guarded("unit-3"), "unit-3", &[4]);
    assert_duplicate(&mut moved.guarded("unit-1"), "unit-1", &[1]);
    assert_duplicate(&mut moved.guarded("unit-2"), "unit-2", &[2]);

    // A second move and adoption lose nothing either.
    let again = moved.copy_to(root.path().join("office"), root.path().join("office-state"));
    inconclusive(&mut again.guarded("unit-4"), "unit-4");
    assert_eq!(again.adopt("moved back to the office")["seq"], 5);
    recorded(&mut again.guarded("unit-4"), 6);
    assert_duplicate(&mut again.guarded("unit-3"), "unit-3", &[4]);
}

#[test]
fn an_adoption_that_carried_lost_totals_keeps_new_references_inconclusive() {
    let root = tempfile::tempdir().expect("directory");
    let e = Engagement::new(root.path().join("pass"), root.path().join("state"));
    recorded(&mut e.guarded("unit-1"), 1);
    recorded(&mut e.guarded("unit-2"), 2);

    fs::remove_file(e.ledger()).expect("lose the ledger");
    let missing = reply(&e.guarded("unit-3").output().expect("spend"), 1);
    assert_eq!(missing["error"]["code"], "ledger-missing");
    let adopted = e.adopt("ledger lost");
    assert_eq!(adopted["case"], "ledger-missing");
    assert_eq!(adopted["seq"], 1);
    assert_eq!(adopted["carried"], json!({"calls": 2}));

    // unit-1 was spent, and only the lost ledger showed it. No new reference
    // can be shown to be new, and the message names the next step.
    let before = fs::read(e.ledger()).expect("ledger");
    for (reference, flags) in [
        ("unit-1", &[][..]),
        ("unit-3", &[]),
        ("unit-3", &["--dry-run"]),
    ] {
        let message = inconclusive(e.guarded(reference).args(flags), reference);
        for part in [
            "the adoption at ledger sequence 1",
            "run record",
            "without --require-new-ref",
        ] {
            assert!(message.contains(part), "{message}");
        }
    }
    assert_eq!(fs::read(e.ledger()).expect("ledger"), before);

    // The next step: once the run record shows the unit is new, a debit
    // without the guard records it, and a guarded repeat is a duplicate.
    let mut unguarded = e.command("spend");
    unguarded.args(["calls", "--to", TO, "--caller-ref", "unit-3"]);
    recorded(&mut unguarded, 2);
    assert_duplicate(&mut e.guarded("unit-3"), "unit-3", &[2]);

    // A later adoption that loses nothing does not bring the lost
    // references back.
    fs::remove_file(e.witness()).expect("a fresh state directory");
    assert_eq!(e.adopt("new state directory")["case"], "no-witness");
    let message = inconclusive(&mut e.guarded("unit-4"), "unit-4");
    assert!(
        message.contains("the adoption at ledger sequence 1"),
        "{message}"
    );
}

#[test]
fn adopting_a_changed_ledger_that_carried_nothing_keeps_new_references_inconclusive() {
    let root = tempfile::tempdir().expect("directory");
    let here = Engagement::new(root.path().join("here"), root.path().join("here-state"));
    recorded(&mut here.guarded("unit-1"), 1);

    // A copy goes its own way elsewhere and spends more.
    let there = here.copy_to(root.path().join("there"), root.path().join("there-state"));
    let mut more = there.command("spend");
    more.args(["calls", "--n", "5", "--to", TO]);
    recorded(&mut more, 2);
    recorded(&mut here.guarded("unit-2"), 2);

    // The copy replaces this ledger. It does not hold the witnessed line
    // that recorded unit-2, but spent more, so the adoption carries nothing.
    fs::copy(there.ledger(), here.ledger()).expect("replace the ledger");
    let changed = reply(&here.guarded("unit-3").output().expect("spend"), 1);
    assert_eq!(changed["error"]["code"], "ledger-changed");
    let adopted = here.adopt("kept the other copy");
    assert_eq!(adopted["case"], "ledger-changed");
    assert_eq!(adopted["carried"], json!({}));
    assert_eq!(adopted["previous"]["seq"], 2);

    inconclusive(&mut here.guarded("unit-2"), "unit-2");
    let message = inconclusive(&mut here.guarded("unit-3"), "unit-3");
    assert!(
        message.contains("the adoption at ledger sequence 3"),
        "{message}"
    );
    assert_duplicate(&mut here.guarded("unit-1"), "unit-1", &[1]);
}

#[test]
fn an_adoption_line_that_carries_amounts_without_a_witness_keeps_new_references_inconclusive() {
    let root = tempfile::tempdir().expect("directory");
    let e = Engagement::new(root.path().join("pass"), root.path().join("state"));
    recorded(&mut e.guarded("unit-1"), 1);

    // hallpass never writes this line (an adoption without a witness carries
    // nothing), but its carried amount stands for lines this ledger lacks.
    // It is marked as the test-clock line before it is (bn-2mm).
    let text = fs::read_to_string(e.ledger()).expect("ledger");
    let last = text.lines().last().expect("last line");
    let digest = hallpass::load(&e.pass()).expect("pass").digest;
    let line = format!(
        r#"{{"seq":2,"time":"{NOW}","event":"adopt","reason":"written by another tool","digest":"{digest}","carried":{{"calls":3}},"witness":null,"test_clock":true,"prev":"{}"}}"#,
        hallpass::Digest::of(last.as_bytes())
    );
    let mut ledger = fs::OpenOptions::new()
        .append(true)
        .open(e.ledger())
        .expect("ledger");
    writeln!(ledger, "{line}").expect("append");

    let message = inconclusive(&mut e.guarded("unit-2"), "unit-2");
    assert!(
        message.contains("the adoption at ledger sequence 2"),
        "{message}"
    );
}

#[test]
fn a_preview_and_a_spend_agree_on_an_unwitnessed_ledger_of_adoptions_only() {
    let root = tempfile::tempdir().expect("directory");
    let e = Engagement::new(root.path().join("pass"), root.path().join("state"));
    fs::write(
        e.ledger(),
        "{\"hallpass_ledger\":1,\"pass_id\":\"review-example\"}\n",
    )
    .expect("header");
    fs::set_permissions(e.ledger(), fs::Permissions::from_mode(0o600)).expect("private ledger");
    assert_eq!(e.adopt("brought from elsewhere")["seq"], 1);

    // Without a witness again, the one line could be the start of a longer
    // ledger, whatever kind of line it is.
    fs::remove_file(e.witness()).expect("a fresh state directory");
    for flags in [&["--dry-run"][..], &[]] {
        inconclusive(e.guarded("unit-1").args(flags), "unit-1");
    }
}

/// The reference caller always passes `--require-new-ref`. After its
/// engagement moves to a new state directory and the ledger is adopted as it
/// stands, it sends again.
#[test]
fn the_reference_caller_sends_again_after_a_moved_ledger_is_adopted() {
    let root = tempfile::tempdir().expect("directory");
    for dir in ["archive", "lab-home", "field-home"] {
        fs::create_dir(root.path().join(dir)).expect("directory");
        fs::set_permissions(root.path().join(dir), fs::Permissions::from_mode(0o700))
            .expect("private directory");
    }
    let lab = Engagement::new(root.path().to_owned(), root.path().join("lab-home/state"));
    let field = Engagement {
        dir: root.path().to_owned(),
        state: root.path().join("field-home/state"),
    };
    let pass = lab.pass().display().to_string();
    let caller = |home: &str, args: &[&str]| -> (Option<i32>, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let bin = Path::new(env!("CARGO_BIN_EXE_hallpass"));
        let mut paths = vec![bin.parent().expect("binary directory").to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let home = root.path().join(home);
        let out = Command::new("python3")
            .arg("-I")
            .arg("-B")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(&script)
            .args(args)
            .current_dir(root.path())
            .env("PATH", std::env::join_paths(paths).expect("PATH"))
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env_remove("REFERENCE_CALLER_INTERRUPT")
            .output()
            .expect("run the reference caller");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        eprintln!("{args:?}\n{stdout}{}", String::from_utf8_lossy(&out.stderr));
        (out.status.code(), stdout)
    };
    let unit = |home: &str, reference: &str| {
        caller(
            home,
            &[
                "run",
                "journal.jsonl",
                &pass,
                reference,
                "--rehearsal",
                "--to",
                TO,
                "--charge",
                "calls=1",
            ],
        )
    };

    assert_eq!(
        caller("lab-home", &["pin", "journal.jsonl", &pass, "archive"]).0,
        Some(0)
    );
    assert_eq!(unit("lab-home", "unit-1").0, Some(0));

    let (code, stdout) = unit("field-home", "unit-2");
    assert_eq!(code, Some(2));
    assert!(
        stdout.contains("refused reference-inconclusive"),
        "{stdout}"
    );
    assert!(!field.witness().exists());

    field.adopt("moved with the pass to the field machine");
    let (code, stdout) = unit("field-home", "unit-3");
    assert_eq!(code, Some(0), "{stdout}");
    assert!(stdout.contains("unit sent"), "{stdout}");
    let outbox = fs::read_to_string(root.path().join("outbox.jsonl")).expect("outbox");
    let sent: Vec<Value> = outbox
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSON line"))
        .collect();
    assert_eq!(
        sent.iter().map(|s| s["ref"].clone()).collect::<Vec<_>>(),
        [json!("unit-1"), json!("unit-3")]
    );
}
