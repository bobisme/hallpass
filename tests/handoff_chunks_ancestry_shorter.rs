#![cfg(feature = "cli")]
//! bn-3cie: the reference caller's `handoff` asks `hallpass reconcile` in
//! manifests of at most 1,024 rows, so a journal with more units works; and
//! `compare-backups --ancestry` groups the copies behind the witness too,
//! so a fork and the newest backup do not look alike.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = include_str!("../docs/review-approval.toml");
const TO: &str = "192.0.2.10:443/tcp@app.example.com";

struct Run {
    root: tempfile::TempDir,
}

impl Run {
    fn new(calls: u32) -> Self {
        let run = Self {
            root: tempfile::tempdir().expect("directory"),
        };
        for dir in ["archive", "home"] {
            fs::create_dir(run.path(dir)).expect("directory");
            fs::set_permissions(run.path(dir), fs::Permissions::from_mode(0o700)).expect("mode");
        }
        fs::write(
            run.path("p.toml"),
            format!("{PASS}\n[ceilings]\ncalls = {calls}\n"),
        )
        .expect("pass");
        fs::set_permissions(run.path("p.toml"), fs::Permissions::from_mode(0o600)).expect("mode");
        run
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn hallpass(&self, state: &str, args: &[&str]) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(args)
            .current_dir(self.root.path())
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path(state))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_FORMAT")
            .output()
            .expect("hallpass");
        (
            out.status.code().expect("exit code"),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    fn caller(&self, args: &[&str]) -> (i32, String, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let bin = Path::new(env!("CARGO_BIN_EXE_hallpass"));
        let mut paths = vec![bin.parent().expect("binary directory").to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let out = Command::new("python3")
            .args(["-I", "-B"])
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(&script)
            .args(args)
            .current_dir(self.root.path())
            .env("PATH", std::env::join_paths(paths).expect("PATH"))
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("TMPDIR", self.path("home"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_FORMAT")
            .env_remove("REFERENCE_CALLER_INTERRUPT")
            .output()
            .expect("run the reference caller");
        (
            out.status.code().expect("exit code"),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn run_unit(&self, journal: &str, reference: &str) {
        let (code, out, err) = self.caller(&[
            "run",
            journal,
            "p.toml",
            reference,
            "--rehearsal",
            "--to",
            TO,
            "--charge",
            "calls=1",
        ]);
        assert_eq!(code, 0, "{out}{err}");
    }
}

/// The words of the handoff line for `reference`, without the padding.
fn words_of(output: &str, reference: &str) -> Vec<String> {
    output
        .lines()
        .find(|l| l.split_whitespace().next() == Some(reference))
        .unwrap_or_else(|| panic!("no line for {reference} in {output}"))
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

#[test]
fn handoff_judges_more_units_than_one_manifest_holds() {
    let run = Run::new(10);
    let (code, out, err) = run.caller(&["pin", "j.jsonl", "p.toml", "archive"]);
    assert_eq!(code, 0, "{out}{err}");
    run.run_unit("j.jsonl", "u1");
    // The first and last units are real debits, in the first and last
    // manifest. The units between are intents with no spend: fast to make.
    let journal = fs::read_to_string(run.path("j.jsonl")).expect("journal");
    let intent = journal
        .lines()
        .find(|l| l.contains("\"event\": \"intent\""))
        .expect("intent line")
        .to_owned();
    let total = 1_030;
    let mut extra = String::new();
    for n in 2..total {
        extra.push_str(&intent.replace("\"u1\"", &format!("\"u{n}\"")));
        extra.push('\n');
    }
    let path = run.path("j.jsonl");
    let mut text = fs::read_to_string(&path).expect("journal");
    text.push_str(&extra);
    fs::write(&path, text).expect("journal");
    run.run_unit("j.jsonl", &format!("u{total}"));

    let (code, out, err) = run.caller(&["handoff", "j.jsonl", "p.toml", "--ref-prefix", "u"]);
    assert!(!err.contains("reconcile failed"), "{err}");
    assert_eq!(code, 2, "units with no debit need attention: {out}{err}");
    let lines = out.lines().filter(|l| l.starts_with('u')).count();
    assert_eq!(lines, total, "one line per unit");
    // Debits in the first and the second chunk are both found.
    assert!(words_of(&out, "u1").contains(&"seq".to_owned()), "{out}");
    let last = words_of(&out, &format!("u{total}"));
    assert!(last.windows(2).any(|w| w == ["debit", "seq"]), "{last:?}");
    assert!(
        words_of(&out, "u1025").join(" ").contains("no debit"),
        "{out}"
    );

    // The line of a unit is the same whether its journal has 3 units or 1,030.
    let small = Run::new(10);
    small.caller(&["pin", "j.jsonl", "p.toml", "archive"]);
    small.run_unit("j.jsonl", "u1");
    let (_, small_out, _) = small.caller(&["handoff", "j.jsonl", "p.toml", "--ref-prefix", "u"]);
    assert_eq!(words_of(&small_out, "u1"), words_of(&out, "u1"));
}

#[test]
fn ancestry_among_shorter_copies_shows_branches_and_the_newest() {
    let run = Run::new(20);
    let spend = |state: &str, dir: &str| {
        let (code, out) = run.hallpass(state, &["spend", "--to", TO, "--", dir, "calls"]);
        assert_eq!(code, 0, "{out}");
    };
    let state = "home/state";
    let ledger = run.path("p.toml.ledger");
    spend(state, "p.toml");
    spend(state, "p.toml");
    fs::copy(&ledger, run.path("b-old.ledger")).expect("old");
    spend(state, "p.toml");
    fs::copy(&ledger, run.path("b-mid.ledger")).expect("mid");
    // A fork: the mid copy took a spend on another machine's state.
    fs::create_dir(run.path("other")).expect("other");
    fs::copy(run.path("p.toml"), run.path("other/p.toml")).expect("pass");
    fs::copy(run.path("b-mid.ledger"), run.path("other/p.toml.ledger")).expect("ledger");
    let other = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .args(args)
            .current_dir(run.path("other"))
            .env("HOME", run.path("home"))
            .env("XDG_STATE_HOME", run.path("state2"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_FORMAT")
            .output()
            .expect("hallpass");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (_, preview) = other(&["--json", "adopt", "p.toml", "--preview"]);
    let token = serde_json::from_str::<Value>(&preview).expect("JSON")["token"]
        .as_str()
        .expect("token")
        .to_owned();
    let (code, out) = other(&["adopt", "p.toml", "--reason", "fork", "--token", &token]);
    assert_eq!(code, Some(0), "{out}");
    let (code, out) = other(&["spend", "--to", TO, "--", "p.toml", "calls"]);
    assert_eq!(code, Some(0), "{out}");
    fs::copy(run.path("other/p.toml.ledger"), run.path("b-fork.ledger")).expect("fork");
    spend(state, "p.toml");
    spend(state, "p.toml");
    fs::copy(&ledger, run.path("b-new.ledger")).expect("new");
    spend(state, "p.toml");
    fs::remove_file(&ledger).expect("lose the ledger");

    let args = [
        "compare-backups",
        "p.toml",
        "b-old.ledger",
        "b-fork.ledger",
        "b-mid.ledger",
        "b-new.ledger",
        "--ancestry",
    ];
    let (code, text) = run.hallpass(state, &args);
    assert!(text.contains("Backup assessment no-match."), "{text}");
    assert_eq!(code, 2, "{text}");
    assert!(!text.contains("Nothing to compare"), "{text}");
    assert!(text.contains("group 1 is a prefix of group 2"), "{text}");
    assert!(text.contains("group 3 is a prefix of group 2"), "{text}");
    assert!(text.contains("group 3 is a prefix of group 4"), "{text}");
    assert!(
        text.contains("Newest copy on each branch (not a prefix of any other): 2, 4"),
        "{text}"
    );

    let mut json_args = vec!["--format", "json"];
    json_args.extend_from_slice(&args);
    let (_, json) = run.hallpass(state, &json_args);
    let json: Value = serde_json::from_str(&json).expect("JSON");
    assert_eq!(
        json["assessment"], "no-match",
        "adoption advice is unchanged"
    );
    assert_eq!(
        json["ancestry"]["maximal_groups"],
        serde_json::json!([2, 4])
    );
    assert_eq!(
        json["ancestry"]["prefix_links"],
        serde_json::json!([[1, 2], [1, 3], [1, 4], [3, 2], [3, 4]])
    );

    // The same copies without --ancestry carry no grouping.
    let (_, plain) = run.hallpass(state, &args[..6]);
    assert!(!plain.contains("Ancestry"), "{plain}");
}
