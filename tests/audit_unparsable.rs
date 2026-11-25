//! An archived revision whose exact bytes break a pass rule added since it
//! was archived is an audit gap, `revision-unparsable`, and not an error
//! (bn-39u).
//!
//! Archived bytes are never edited, so an audit must not stop at them and
//! must not advise fixing them. This hallpass refuses to spend under such
//! bytes, so each test writes the archive entry by hand, by its digest, and
//! rewrites the ledger as the older hallpass that spent under them wrote it.
//!
//! The test that signs needs OpenSSH `ssh-keygen` and returns early without it.
#![cfg(feature = "cli")]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use hallpass::evidence::{self, AsOf, Recheck, Reverify, SignatureToCheck};
use hallpass::{Digest, Error, StateDir, archive_verified_signature};
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";

/// The revision in use now: 19 lines.
fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

/// The revision an older hallpass archived and spent under: a comment with
/// a right-to-left override, which this hallpass refuses anywhere in a pass.
fn bidi() -> String {
    format!("{}# note \u{202e}\n", pass())
}

/// What this hallpass finds in [`bidi`], without the advice to edit it.
const FINDING: &str = "line 20, column 8 holds a bidirectional text control (U+202E), which can make the file display as something else";

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        let archive = env.path("arch");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated back so that hallpass reads it at once.
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.path(name);
        if path.exists() {
            fs::remove_file(&path).expect("replace");
        }
        fs::write(&path, bytes).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
    }

    /// Run hallpass with the witness in the state directory `state`.
    fn run(&self, state: &str, format: &str, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path(state))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", format])
            .args(args)
            .output()
            .expect("run hallpass");
        (
            out.status.code().expect("exit code"),
            String::from_utf8(out.stdout).expect("utf8"),
            String::from_utf8(out.stderr).expect("utf8"),
        )
    }

    /// An audit's JSON reply. The ledger was rewritten, so the witness of
    /// the spends no longer matches it: audit with no witness, as a copy of
    /// the ledger is read.
    fn json(&self, args: &[&str], code: i32) -> Value {
        let (actual, out, err) = self.run("audit", "json", args);
        assert_eq!(actual, code, "{args:?}: {out}{err}");
        serde_json::from_str(out.trim()).expect("one JSON object")
    }

    fn text(&self, args: &[&str], code: i32) -> String {
        let (actual, out, err) = self.run("audit", "text", args);
        assert_eq!(actual, code, "{args:?}: {out}{err}");
        format!("{out}{err}")
    }

    fn spend(&self) {
        let (code, out, err) = self.run(
            "state",
            "json",
            &[
                "spend",
                "p.toml",
                "--charge",
                "requests=1",
                "--to",
                WEB,
                "--record-target",
            ],
        );
        assert_eq!(code, 0, "{out}{err}");
    }

    /// Spend twice under the revision now in use, then make the first spend
    /// one under `old`: archive its exact bytes by hand under their digest,
    /// and rewrite the ledger as the older hallpass that spent under them
    /// wrote it. Returns the digests of `old` and of the revision in use.
    fn spent_under(&self, old: &str) -> (Digest, Digest) {
        self.write("p.toml", pass().as_bytes());
        let (code, out, err) = self.run("state", "json", &["archive", "p.toml", "arch"]);
        assert_eq!(code, 0, "{out}{err}");
        let current = Digest::of(pass().as_bytes());
        self.spend();
        self.spend();
        let digest = Digest::of(old.as_bytes());
        self.write(&format!("arch/{digest}"), old.as_bytes());
        let ledger = self.path("p.toml.ledger");
        let text = fs::read_to_string(&ledger).expect("ledger");
        let before: Vec<&str> = text.lines().collect();
        assert_eq!(before.len(), 3, "{text}");
        let first = before[1].replace(&current.to_string(), &digest.to_string());
        let second = before[2].replace(
            &Digest::of(before[1].as_bytes()).to_string(),
            &Digest::of(first.as_bytes()).to_string(),
        );
        fs::write(&ledger, format!("{}\n{first}\n{second}\n", before[0])).expect("rewrite");
        (digest, current)
    }
}

/// Phrases that would tell the auditor to edit the archived bytes.
fn assert_no_edit_advice(text: &str) {
    for phrase in [
        "fix each one",
        "hallpass check",
        "delete it",
        "edited file",
        "not a valid pass",
        "\u{202e}",
    ] {
        assert!(!text.contains(phrase), "{phrase:?} in {text}");
    }
}

#[test]
fn an_archived_revision_that_breaks_a_newer_rule_is_a_gap_not_an_error() {
    let env = Env::new();
    let (old, current) = env.spent_under(&bidi());
    // This hallpass refuses those bytes as a pass.
    env.write("old.toml", bidi().as_bytes());
    let (code, out, err) = env.run("state", "text", &["check", "old.toml"]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(err.contains("U+202E"), "{err}");

    let unparsable = json!({
        "count": 1,
        "sequences": [1],
        "truncated": false,
        "digests": [{
            "digest": old.to_string(),
            "count": 1,
            "sequences": [1],
            "truncated": false,
            "problems": [{"field": "(file)", "message": FINDING}],
            "problem_count": 1,
        }],
        "digests_truncated": false,
    });
    for command in ["audit-receipts", "audit-charges"] {
        let audit = env.json(&[command, "p.toml", "arch"], 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        assert_eq!(
            audit["gaps"]["revision-unparsable"], unparsable,
            "{command}"
        );
        // The other revision still replays.
        assert_eq!(audit["gaps"]["archive-missing"], Value::Null, "{command}");
        // Both revisions were archived with no signature record.
        let unsigned = &audit["gaps"]["approval-unverified"]["digests"];
        assert_eq!(unsigned[0]["digest"], old.to_string(), "{command}");
        assert_eq!(unsigned[1]["digest"], current.to_string(), "{command}");
        assert_eq!(unsigned[0].get("problems"), None, "{command}");
        let rows = &audit["revisions"]["details"];
        assert_eq!(rows[0]["digest"], old.to_string(), "{command}");
        assert_eq!(rows[0]["provenance"], "unsigned", "{command}");
        assert_eq!(rows[1]["digest"], current.to_string(), "{command}");

        let text = env.text(&[command, "p.toml", "arch"], 2);
        for expected in [
            "Gap revision-unparsable 1: decided under a revision that was archived before a pass rule it breaks, so this hallpass cannot replay it; never edit archived bytes, which record what the work was decided under: re-run the audit with the hallpass version that recorded the work, or accept the gap. Sequences [1]\n".to_owned(),
            format!("  {old} 1 line(s). Sequences [1]\n    This hallpass finds 1 problem(s) in it:\n    - (file): {FINDING}\n"),
        ] {
            assert!(text.contains(&expected), "{command}: {expected}\nin {text}");
        }
        assert_no_edit_advice(&text);
    }
    let receipts = env.json(&["audit-receipts", "p.toml", "arch"], 2);
    assert_eq!(receipts["corroborated"]["count"], 1, "{receipts}");
    assert_eq!(receipts["corroborated"]["details"][0]["seq"], 2);
    assert_eq!(receipts["mismatches"]["count"], 0);
    let charges = env.json(&["audit-charges", "p.toml", "arch"], 2);
    assert_eq!(charges["checked_debits"], 1, "{charges}");
    assert_eq!(charges["mismatches"]["count"], 0);
}

#[test]
fn many_problems_show_the_first_four_and_count_the_rest() {
    let env = Env::new();
    let mut text = pass();
    for i in 0..6 {
        let _ = writeln!(text, "# note {i} \u{202e}");
    }
    let (old, _) = env.spent_under(&text);
    let audit = env.json(&["audit-charges", "p.toml", "arch"], 2);
    let row = &audit["gaps"]["revision-unparsable"]["digests"][0];
    assert_eq!(row["digest"], old.to_string(), "{audit}");
    assert_eq!(row["problem_count"], 6, "{audit}");
    let problems = row["problems"].as_array().expect("problems");
    assert_eq!(problems.len(), 4, "{audit}");
    assert!(
        problems[3]["message"]
            .as_str()
            .expect("message")
            .starts_with("line 23, column 10 holds"),
        "{audit}"
    );
    let text = env.text(&["audit-charges", "p.toml", "arch"], 2);
    assert!(
        text.contains("This hallpass finds 6 problem(s) in it:\n"),
        "{text}"
    );
    assert_eq!(text.matches("\n    - (file): line ").count(), 4, "{text}");
    assert!(
        text.contains("    Additional problems omitted.\n"),
        "{text}"
    );
    assert_no_edit_advice(&text);
}

#[test]
fn archived_bytes_that_do_not_match_their_digest_are_still_an_error() {
    let env = Env::new();
    let (old, _) = env.spent_under(&bidi());
    env.write(
        &format!("arch/{old}"),
        bidi().replace("note", "nope").as_bytes(),
    );
    for command in ["audit-receipts", "audit-charges"] {
        let error = env.json(&[command, "p.toml", "arch"], 1);
        let message = error["error"]["message"].as_str().expect("message");
        assert!(message.contains("does not match its digest"), "{error}");
    }
}

#[test]
fn an_unparsable_revision_of_another_pass_is_still_an_error() {
    let env = Env::new();
    let other = bidi().replace("id = \"review-example\"", "id = \"other\u{2066}\"");
    env.spent_under(&other);
    for command in ["audit-receipts", "audit-charges"] {
        let error = env.json(&[command, "p.toml", "arch"], 1);
        let message = error["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("belongs to pass \"other\\u{2066}\", expected review-example"),
            "{error}"
        );
        let text = env.text(&[command, "p.toml", "arch"], 1);
        assert!(!text.contains('\u{2066}'), "{text}");
    }
}

/// Verify for the owner, as of first use, with `check`.
fn reverify(
    trust: Digest,
    check: &mut dyn FnMut(&SignatureToCheck<'_>) -> Result<Recheck, Error>,
) -> Option<Reverify<'_>> {
    Some(Reverify {
        allowed_signers: trust,
        principals: &[OWNER],
        as_of: AsOf::FirstUse,
        check,
    })
}

/// The signature of an unparsable revision is still verified: it shows who
/// approved those exact bytes. The verifier here is a stand-in, so this test
/// needs no `ssh-keygen`.
#[test]
fn the_signature_of_an_unparsable_revision_is_still_verified() {
    let env = Env::new();
    let (old, current) = env.spent_under(&bidi());
    let arch = env.path("arch");
    let trust = Digest::of(b"trusted signers");
    for digest in [old, current] {
        archive_verified_signature(&arch, digest, b"signature", OWNER, trust).expect("record");
    }
    let loaded = hallpass::load(&env.path("p.toml")).expect("pass");
    let state = StateDir::new(env.path("audit"));
    let audit = |reject: Option<Digest>| {
        let mut seen = Vec::new();
        let mut check = |s: &SignatureToCheck<'_>| -> Result<Recheck, Error> {
            seen.push((s.digest, s.bytes.to_vec()));
            Ok(if Some(s.digest) == reject {
                Recheck::Rejected("untrusted-key")
            } else {
                Recheck::Verified
            })
        };
        let charges =
            evidence::audit_charges_with(&loaded, &state, &arch, reverify(trust, &mut check))
                .expect("charge audit");
        let receipts =
            evidence::audit_receipts_with(&loaded, &state, &arch, reverify(trust, &mut check))
                .expect("receipt audit");
        (json!(charges), json!(receipts), seen)
    };

    let (charges, receipts, seen) = audit(None);
    // Each audit verified the archived bytes of both revisions, as they are.
    let verified = vec![(old, bidi().into_bytes()), (current, pass().into_bytes())];
    assert_eq!(seen, [verified.clone(), verified].concat());
    for audit in [&charges, &receipts] {
        assert_eq!(audit["result"], "incomplete", "{audit}");
        let gaps: Vec<&String> = audit["gaps"].as_object().expect("gaps").keys().collect();
        assert_eq!(gaps, ["revision-unparsable"], "{audit}");
        assert_eq!(audit["revisions"]["unverified"], 0, "{audit}");
        for row in audit["revisions"]["details"].as_array().expect("rows") {
            assert_eq!(row["provenance"], "signature-verified", "{audit}");
            assert_eq!(row["verified_for"], OWNER, "{audit}");
        }
    }
    assert_eq!(
        receipts["corroborated"]["details"][0]["provenance"],
        "signature-verified"
    );

    // A rejected signature is its own gap, beside the one for the rules.
    let (charges, receipts, _) = audit(Some(old));
    for audit in [&charges, &receipts] {
        assert_eq!(audit["result"], "incomplete", "{audit}");
        let gaps: Vec<&String> = audit["gaps"].as_object().expect("gaps").keys().collect();
        assert_eq!(
            gaps,
            ["revision-unparsable", "signature-rejected"],
            "{audit}"
        );
        let rejected = &audit["gaps"]["signature-rejected"]["digests"][0];
        assert_eq!(rejected["digest"], old.to_string(), "{audit}");
        assert_eq!(rejected["reason"], "untrusted-key", "{audit}");
        assert_eq!(
            audit["revisions"]["details"][0]["provenance"],
            "signature-rejected"
        );
    }
}

/// With `ssh-keygen`: the owner signed the revision before the rule was
/// added. Without `--principal`, the revisions line says that no revision
/// is verified for a principal named, instead of reading as fully verified.
#[test]
fn a_signed_unparsable_revision_audits_with_ssh_keygen() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (old, current) = env.spent_under(&bidi());
    let keygen = |args: &[&str]| {
        let out = Command::new("ssh-keygen")
            .args(args)
            .current_dir(env.path(""))
            .output()
            .expect("ssh-keygen");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "owner"]);
    let public = fs::read_to_string(env.path("owner.pub")).expect("public key");
    let trust = format!("{OWNER} {public}");
    env.write("trust", trust.as_bytes());
    env.write("old.toml", bidi().as_bytes());
    for (file, digest) in [("old.toml", old), ("p.toml", current)] {
        keygen(&[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner",
            "-n",
            "hallpass-approval-v1",
            file,
        ]);
        let signature = fs::read(env.path(&format!("{file}.sig"))).expect("signature");
        // As an older verify-approval --archive recorded it.
        archive_verified_signature(
            &env.path("arch"),
            digest,
            &signature,
            OWNER,
            Digest::of(trust.as_bytes()),
        )
        .expect("record");
    }

    let unpinned = ["--allowed-signers", "trust"];
    let pinned = ["--allowed-signers", "trust", "--principal", OWNER];
    for command in ["audit-receipts", "audit-charges"] {
        let all = [&[command, "p.toml", "arch"][..], &pinned[..]].concat();
        let audit = env.json(&all, 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        let gaps: Vec<&String> = audit["gaps"].as_object().expect("gaps").keys().collect();
        assert_eq!(gaps, ["revision-unparsable"], "{command}: {audit}");
        let rows = &audit["revisions"]["details"];
        assert_eq!(rows[0]["digest"], old.to_string());
        assert_eq!(rows[0]["provenance"], "signature-verified", "{audit}");
        let text = env.text(&all, 2);
        assert!(
            text.contains("Revisions used 2, 0 without a verified signature\n"),
            "{text}"
        );
        assert_no_edit_advice(&text);

        let all = [&[command, "p.toml", "arch"][..], &unpinned[..]].concat();
        let audit = env.json(&all, 2);
        let gaps: Vec<&String> = audit["gaps"].as_object().expect("gaps").keys().collect();
        assert_eq!(
            gaps,
            ["revision-unparsable", "signer-not-pinned"],
            "{audit}"
        );
        assert_eq!(audit["revisions"]["unverified"], 0, "{audit}");
        let text = env.text(&all, 2);
        assert!(
            text.contains("Revisions used 2, 0 without a verified signature, 2 not verified for a principal named with --principal\n"),
            "{text}"
        );
    }
    // Without --allowed-signers nothing is verified, and the line is as it was.
    let text = env.text(&["audit-charges", "p.toml", "arch"], 2);
    assert!(
        text.contains("Revisions used 2, 2 without a verified signature\n"),
        "{text}"
    );
}
