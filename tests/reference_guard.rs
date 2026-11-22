#![cfg(feature = "cli")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = include_str!("../docs/review-approval.toml");
const CALLER_REF: &str = "batch-42";

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("directory");
        let pass = dir.path().join("pass");
        let f = Self { dir, pass };
        f.revise("initial revision");
        fs::set_permissions(&f.pass, fs::Permissions::from_mode(0o600)).expect("private pass");
        f
    }

    fn revise(&self, note: &str) {
        fs::write(
            &self.pass,
            format!("{PASS}\n[ceilings]\ncalls = 100\n# {note}\n"),
        )
        .expect("write pass");
    }

    fn command(&self, name: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.args(["--format", "json", name])
            .arg(&self.pass)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.dir.path().join("state"));
        cmd
    }

    fn guarded(&self, reference: &str) -> Command {
        let mut cmd = self.command("spend");
        cmd.args(["calls", "--caller-ref", reference, "--require-new-ref"]);
        cmd
    }

    fn ledger(&self) -> PathBuf {
        hallpass::ledger_path(&self.pass)
    }

    fn witness(&self) -> PathBuf {
        hallpass::StateDir::new(self.dir.path().join("state/hallpass"))
            .witness_path("review-example")
            .expect("witness path")
    }
}

fn reply(out: &Output, code: i32) -> Value {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).expect("JSON")
}

fn assert_duplicate(value: &Value) {
    assert_eq!(value["command"], "spend");
    assert_eq!(value["result"], "refused");
    assert_eq!(value["refusal"]["code"], "duplicate-reference");
    assert!(value["receipt"].is_null());
    assert!(value["seq"].is_null());
    assert_eq!(
        value["reference_evidence"],
        json!({
            "caller_ref": CALLER_REF,
            "match_count": 1,
            "sequences": [1],
            "truncated": false,
        })
    );
}

#[test]
fn concurrent_guards_record_only_once_and_revision_changes_keep_the_same_ref() {
    let f = Fixture::new();
    let invalid = reply(
        &f.command("spend")
            .args(["calls", "--require-new-ref"])
            .output()
            .expect("CLI"),
        1,
    );
    assert_eq!(invalid["result"], "error");
    let preview = reply(
        &f.guarded(CALLER_REF)
            .arg("--dry-run")
            .output()
            .expect("preview"),
        0,
    );
    assert_eq!(preview["result"], "would-allow");
    assert!(preview["seq"].is_null());
    assert!(!f.ledger().exists());
    assert!(!f.witness().exists());
    let original = hallpass::load(&f.pass).expect("pass").digest.to_string();
    let mut cmd = f.guarded(CALLER_REF);
    cmd.args([
        "--to",
        "192.0.2.10:443/tcp@app.example.com",
        "--digest",
        &original,
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let a = cmd.spawn().expect("first process");
    let b = cmd.spawn().expect("second process");
    let mut replies = [
        a.wait_with_output().expect("first reply"),
        b.wait_with_output().expect("second reply"),
    ];
    replies.sort_by_key(|r| r.status.code());
    let [allowed, refused] = replies;
    let allowed = reply(&allowed, 0);
    assert_eq!(allowed["result"], "allowed");
    assert_eq!(allowed["seq"], 1);
    assert_eq!(allowed["receipt"]["caller_ref"], CALLER_REF);
    assert_duplicate(&reply(&refused, 2));

    f.revise("new revision of the same pass");
    let new_digest = hallpass::load(&f.pass)
        .expect("new pass")
        .digest
        .to_string();
    let before = fs::read(f.ledger()).expect("ledger");
    let changed = reply(
        &f.guarded(CALLER_REF)
            .args([
                "--digest",
                &new_digest,
                "--n",
                "100",
                "--to",
                "192.0.2.99:443/tcp",
            ])
            .output()
            .expect("same ref under the new revision"),
        2,
    );
    assert_duplicate(&changed);
    let preview = reply(
        &f.guarded(CALLER_REF)
            .arg("--dry-run")
            .output()
            .expect("preview"),
        2,
    );
    assert_duplicate(&preview);
    let stale = reply(
        &f.guarded(CALLER_REF)
            .args(["--digest", &original])
            .output()
            .expect("stale revision"),
        2,
    );
    assert_eq!(stale["refusal"]["code"], "pass-changed");
    assert!(stale["reference_evidence"].is_null());
    let late = reply(
        &f.guarded(CALLER_REF)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-22T09:00:00Z")
            .output()
            .expect("expired"),
        2,
    );
    assert_eq!(late["refusal"]["code"], "expired");
    assert_eq!(fs::read(f.ledger()).expect("ledger"), before);

    // Reference matching is exact and case sensitive.
    let next = reply(&f.guarded("Batch-42").output().expect("distinct ref"), 0);
    assert_eq!(next["seq"], 2);
}

#[test]
fn unknown_references_remain_inconclusive_without_an_anchor_or_after_adoption() {
    let f = Fixture::new();
    let first = reply(&f.guarded(CALLER_REF).output().expect("first debit"), 0);
    assert_eq!(first["seq"], 1);
    let ledger = f.ledger();
    let witness = f.witness();
    fs::remove_file(&witness).expect("remove fixture witness");
    let before = fs::read(&ledger).expect("ledger");
    for flags in [&["--dry-run"][..], &[], &[]] {
        let value = reply(
            &f.guarded("absent")
                .args(flags)
                .output()
                .expect("inconclusive"),
            2,
        );
        assert_eq!(value["refusal"]["code"], "reference-inconclusive");
        assert_eq!(value["reference_evidence"]["match_count"], 0);
        assert!(value["seq"].is_null());
        assert_eq!(fs::read(&ledger).expect("ledger"), before);
        assert!(!witness.exists());
    }
    assert_duplicate(&reply(
        &f.guarded(CALLER_REF).output().expect("known match"),
        2,
    ));
    assert!(!witness.exists());

    reply(
        &f.command("adopt")
            .args(["--reason", "accept imported accounting"])
            .output()
            .expect("adopt"),
        0,
    );
    let after = fs::read(&ledger).expect("ledger");
    assert!(witness.exists());
    let unknown = reply(
        &f.guarded("after-adoption").output().expect("inconclusive"),
        2,
    );
    assert_eq!(unknown["refusal"]["code"], "reference-inconclusive");
    assert_eq!(unknown["reference_evidence"]["sequences"], json!([]));
    assert_duplicate(&reply(
        &f.guarded(CALLER_REF).output().expect("known match"),
        2,
    ));
    assert_eq!(fs::read(ledger).expect("ledger"), after);
}
