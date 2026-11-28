//! Ledger lines written under the test clock are marked, and a ledger never
//! mixes them with real-clock lines (bn-2mm).
//!
//! A debug build that honoured `HALLPASS_UNSAFE_TEST_CLOCK` wrote its debits
//! into a live ledger with nothing to tell them apart, and a signed audit
//! then called the ledger `complete`. Now each such line carries
//! `"test_clock":true` in the hash chain; a write that would mix the two
//! kinds is refused in both directions; `ledger`, `receipt` and the audits
//! show the marker; and an audit of a marked line is never `complete`.
//!
//! The pass window here surrounds the real time, so a spend without the
//! test clock is allowed too.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use hallpass::evidence::{self, AsOf, Recheck, Reverify};
use hallpass::time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use hallpass::{
    Charge, Digest, Error, SpendChargesRequest, SpendRequest, StateDir, Target,
    archive_verified_signature,
};
use serde_json::Value;

const TARGET: &str = "192.0.2.30:443/tcp";
const OWNER: &str = "owner@example.org";

fn stamp(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .expect("whole second")
        .format(&Rfc3339)
        .expect("RFC 3339")
}

/// A pass open from an hour ago until two days from now.
fn pass() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        r#"format = 1
id = "clock-marker"
name = "Clock marker"

[approval]
owner = "Pat Owner"
reference = "email of today"
operator = "Eve Operator"
valid_from = {}
valid_until = {}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.30"
protocol = "tcp"
ports = 443

[ceilings]
requests = 50
"#,
        stamp(now - Duration::hours(1)),
        stamp(now + Duration::days(2)),
    )
}

/// An hour from now: inside the window, and later than the real time.
fn ahead() -> String {
    stamp(OffsetDateTime::now_utc() + Duration::hours(1))
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().expect("directory"),
        };
        let path = env.pass();
        fs::write(&path, pass()).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - std::time::Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the pass back");
        env
    }

    fn pass(&self) -> PathBuf {
        self.dir.path().join("p.toml")
    }

    fn ledger(&self) -> String {
        fs::read_to_string(hallpass::ledger_path(&self.pass())).expect("ledger")
    }

    fn state(&self) -> StateDir {
        StateDir::new(self.dir.path().join("state/hallpass"))
    }

    /// Run hallpass, with the test clock at `clock` when it is given.
    fn run(&self, args: &[&str], clock: Option<&str>) -> (i32, Value, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        command
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", "json"])
            .args(args);
        if let Some(clock) = clock {
            command.env("HALLPASS_UNSAFE_TEST_CLOCK", clock);
        }
        let out = command.output().expect("run hallpass");
        let text = String::from_utf8(out.stdout).expect("utf8");
        let value = serde_json::from_str(text.trim()).expect("one JSON object");
        (out.status.code().expect("exit code"), value, text)
    }

    fn text(&self, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", "text"])
            .args(args)
            .output()
            .expect("run hallpass");
        String::from_utf8(out.stdout).expect("utf8")
    }

    fn spend(&self, reference: &str, clock: Option<&str>) -> (i32, Value) {
        let (code, value, _) = self.run(
            &[
                "spend",
                "p.toml",
                "requests",
                "--to",
                TARGET,
                "--record-target",
                "--caller-ref",
                reference,
            ],
            clock,
        );
        (code, value)
    }

    /// The library debit of the CLI spend above, at `now`.
    fn library_spend(&self, now: OffsetDateTime) -> Result<u64, Error> {
        let charges = [Charge {
            counter: "requests",
            amount: 1,
        }];
        let mut request = SpendChargesRequest::new(&charges);
        request.policy.target = Some(TARGET.parse::<Target>().map_err(Error::Usage)?);
        request.record_targets = true;
        let outcome = hallpass::spend_charges_in(&self.pass(), &request, now, &self.state())?;
        assert!(outcome.refusal.is_none(), "{:?}", outcome.refusal);
        Ok(outcome.seq.expect("seq"))
    }

    /// Archive the pass with a signature record, so that an audit that
    /// accepts every signature can be `complete`.
    fn archive(&self) -> PathBuf {
        let archive = self.dir.path().join("arch");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
        let digest = hallpass::archive_pass(&self.pass(), &archive).expect("archive");
        archive_verified_signature(
            &archive,
            digest,
            b"signature",
            OWNER,
            Digest::of(b"trusted signers"),
        )
        .expect("signature record");
        archive
    }

    /// Both audits, with every signature accepted for the owner.
    fn audits(&self, archive: &Path) -> Vec<(&'static str, Vec<&'static str>)> {
        let loaded = hallpass::load(&self.pass()).expect("pass");
        let mut check = |_: &evidence::SignatureToCheck<'_>| Ok(Recheck::Verified);
        let receipts = evidence::audit_receipts_with(
            &loaded,
            &self.state(),
            archive,
            Some(Reverify {
                allowed_signers: Digest::of(b"trusted signers"),
                principals: &[OWNER],
                as_of: AsOf::FirstUse,
                allow_pattern_principals: false,
                check: &mut check,
            }),
        )
        .expect("receipt audit");
        let charges = evidence::audit_charges_with(
            &loaded,
            &self.state(),
            archive,
            Some(Reverify {
                allowed_signers: Digest::of(b"trusted signers"),
                principals: &[OWNER],
                as_of: AsOf::FirstUse,
                allow_pattern_principals: false,
                check: &mut check,
            }),
        )
        .expect("charge audit");
        vec![
            (receipts.result, receipts.gaps.keys().copied().collect()),
            (charges.result, charges.gaps.keys().copied().collect()),
        ]
    }
}

#[test]
fn a_test_clock_debit_is_refused_on_a_live_ledger() {
    let env = Env::new();
    let (code, live) = env.spend("live-1", None);
    assert_eq!(code, 0, "{live}");
    assert_eq!(live["test_clock"], false);
    let before = env.ledger();
    assert!(!before.contains("test_clock"), "{before}");

    // The evaluator's step 2: a debug build with a test clock a day ahead.
    let clock = ahead();
    let (code, refused) = env.spend("rehearsal-1", Some(&clock));
    assert_eq!(code, 1, "{refused}");
    assert_eq!(refused["error"]["code"], "ledger-clock-mix", "{refused}");
    assert_eq!(refused["error"]["recording"], "not-recorded", "{refused}");
    let message = refused["error"]["message"].as_str().expect("message");
    for part in [
        "is a live ledger: entry 1 was recorded at the real time",
        "runs under a test clock (HALLPASS_UNSAFE_TEST_CLOCK)",
        "Rehearsal and live lines must not mix in one ledger, so nothing was recorded",
        "Unset HALLPASS_UNSAFE_TEST_CLOCK",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    // A preview says the same, and so does every other writer.
    let (code, preview, _) = env.run(
        &["spend", "p.toml", "requests", "--to", TARGET, "--dry-run"],
        Some(&clock),
    );
    assert_eq!(code, 1, "{preview}");
    assert_eq!(preview["error"]["code"], "ledger-clock-mix", "{preview}");
    let (code, scalar, _) = env.run(&["spend", "p.toml", "requests"], Some(&clock));
    assert_eq!(
        (code, &scalar["error"]["code"]),
        (1, &"ledger-clock-mix".into())
    );
    let list = env.dir.path().join("refs");
    fs::write(
        &list,
        r#"{"version": 1, "pass_id": "clock-marker", "references": []}"#,
    )
    .expect("reference list");
    fs::set_permissions(&list, fs::Permissions::from_mode(0o600)).expect("private");
    for args in [
        &["adopt", "p.toml", "--preview"][..],
        &["adopt", "p.toml", "--reason", "rehearsal"],
        &[
            "reconcile-references",
            "p.toml",
            "--adoption",
            "1",
            "--references",
            "refs",
            "--reason",
            "rehearsal",
        ],
    ] {
        let (code, reply, _) = env.run(args, Some(&clock));
        assert_eq!(code, 1, "{args:?}: {reply}");
        assert_eq!(
            reply["error"]["code"], "ledger-clock-mix",
            "{args:?}: {reply}"
        );
    }
    assert_eq!(env.ledger(), before);

    // A library caller that marks its writes is refused in the same way.
    let marked = hallpass::with_test_clock(|| {
        let mut request = SpendRequest::new("requests", 1);
        request.target = Some(TARGET.parse().expect("target"));
        hallpass::spend_in(
            &env.pass(),
            &request,
            OffsetDateTime::now_utc(),
            &env.state(),
        )
    });
    assert!(
        matches!(
            marked,
            Err(Error::LedgerClockMix {
                seq: 1,
                rehearsal: false,
                ..
            })
        ),
        "{marked:?}"
    );
    assert_eq!(env.ledger(), before);
}

#[test]
fn a_real_clock_debit_is_refused_on_a_rehearsal_ledger() {
    let env = Env::new();
    let clock = ahead();
    let (code, rehearsal) = env.spend("rehearsal-1", Some(&clock));
    assert_eq!(code, 0, "{rehearsal}");
    assert_eq!(rehearsal["test_clock"], true);
    let before = env.ledger();
    let line = before.lines().nth(1).expect("debit line");
    assert!(
        line.contains(r#"]},"test_clock":true,"prev":"sha256:"#),
        "{line}"
    );

    let (code, refused) = env.spend("live-1", None);
    assert_eq!(code, 1, "{refused}");
    assert_eq!(refused["error"]["code"], "ledger-clock-mix", "{refused}");
    let message = refused["error"]["message"].as_str().expect("message");
    for part in [
        "is a rehearsal ledger: entry 1 was recorded under a test clock",
        "this command uses the real clock",
        "move the rehearsal ledger aside and keep it",
        "--preview --drop-rehearsal",
        "If it refuses, use a pass with a new id, with no ledger yet",
    ] {
        assert!(message.contains(part), "{part}: {message}");
    }
    assert!(matches!(
        env.library_spend(OffsetDateTime::now_utc()),
        Err(Error::LedgerClockMix {
            seq: 1,
            rehearsal: true,
            ..
        })
    ));
    assert_eq!(env.ledger(), before);

    // More rehearsal lines are fine, marked too.
    let (code, again) = env.spend("rehearsal-2", Some(&clock));
    assert_eq!((code, &again["seq"]), (0, &2.into()), "{again}");
    assert_eq!(env.ledger().matches(r#""test_clock":true"#).count(), 2);
}

#[test]
fn ledger_receipt_and_audits_show_the_marker() {
    let env = Env::new();
    let archive = env.archive();
    let clock = ahead();
    assert_eq!(env.spend("rehearsal-1", Some(&clock)).0, 0);

    let (code, ledger, _) = env.run(&["ledger", "p.toml"], None);
    assert_eq!(code, 0, "{ledger}");
    assert_eq!(ledger["test_clock_from"], 1, "{ledger}");
    assert_eq!(ledger["entries"][0]["test_clock"], true, "{ledger}");
    let text = env.text(&["ledger", "p.toml"]);
    assert!(
        text.contains("REHEARSAL: from entry 1, this ledger was recorded under a test clock"),
        "{text}"
    );

    let (code, receipt, _) = env.run(&["receipt", "p.toml", "--caller-ref", "rehearsal-1"], None);
    assert_eq!(code, 0, "{receipt}");
    assert_eq!(receipt["matches"][0]["test_clock"], true, "{receipt}");
    assert!(
        receipt["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .any(|w| w
                .as_str()
                .is_some_and(|w| w.contains("recorded under a test clock"))),
        "{receipt}"
    );
    let text = env.text(&["receipt", "p.toml", "--caller-ref", "rehearsal-1"]);
    assert!(text.contains("  TEST CLOCK\n"), "{text}");

    // Every signature verifies for the owner and every target replays, but
    // the line is a rehearsal and its time is after the audit's clock.
    for (result, gaps) in env.audits(&archive) {
        assert_eq!(result, "incomplete");
        assert_eq!(gaps, ["entry-in-future", "test-clock-entry"]);
    }
    for command in ["audit-receipts", "audit-charges"] {
        let (code, audit, _) = env.run(&[command, "p.toml", "arch"], None);
        assert_eq!(code, 2, "{audit}");
        assert_eq!(
            audit["gaps"]["test-clock-entry"]["sequences"],
            serde_json::json!([1])
        );
        let text = env.text(&[command, "p.toml", "arch"]);
        assert!(
            text.contains("Gap test-clock-entry 1: the line was recorded under a test clock"),
            "{text}"
        );
    }
}

#[test]
fn a_live_ledger_audits_complete_and_a_marked_one_never_does() {
    // The same debit at the same past instant, live and then marked.
    let at = OffsetDateTime::now_utc() - Duration::minutes(5);
    let live = Env::new();
    let archive = live.archive();
    assert_eq!(live.library_spend(at).expect("spend"), 1);
    assert!(!live.ledger().contains("test_clock"));
    for (result, gaps) in live.audits(&archive) {
        assert_eq!((result, gaps), ("complete", vec![]));
    }

    let marked = Env::new();
    let archive = marked.archive();
    let seq = hallpass::with_test_clock(|| marked.library_spend(at)).expect("spend");
    assert_eq!(seq, 1);
    for (result, gaps) in marked.audits(&archive) {
        assert_eq!((result, gaps), ("incomplete", vec!["test-clock-entry"]));
    }
}

#[test]
fn a_live_line_dated_after_the_audit_is_a_gap() {
    let env = Env::new();
    let archive = env.archive();
    let later = OffsetDateTime::now_utc() + Duration::hours(2);
    assert_eq!(env.library_spend(later).expect("spend"), 1);
    for (result, gaps) in env.audits(&archive) {
        assert_eq!((result, gaps), ("incomplete", vec!["entry-in-future"]));
    }
}

#[test]
fn a_line_a_little_ahead_of_the_audit_is_ordinary_skew() {
    // A recording host two minutes ahead of the auditing host is within the
    // five-minute allowance.
    let env = Env::new();
    let archive = env.archive();
    let ahead = OffsetDateTime::now_utc() + Duration::minutes(2);
    assert_eq!(env.library_spend(ahead).expect("spend"), 1);
    for (result, gaps) in env.audits(&archive) {
        assert_eq!((result, gaps), ("complete", vec![]));
    }
}

#[test]
fn the_marker_is_true_or_absent() {
    let env = Env::new();
    assert_eq!(
        env.library_spend(OffsetDateTime::now_utc()).expect("spend"),
        1
    );
    let text = env.ledger();
    let lines: Vec<&str> = text.lines().collect();
    // A line spelled with `false` is not one hallpass writes: the ledger is
    // damaged at that line, even with the hash chain intact.
    let edited = lines[1].replacen(r#","prev":"#, r#","test_clock":false,"prev":"#, 1);
    fs::write(
        hallpass::ledger_path(&env.pass()),
        format!("{}\n{edited}\n", lines[0]),
    )
    .expect("edit");
    let (code, reply, _) = env.run(&["ledger", "p.toml"], None);
    assert_eq!(code, 1, "{reply}");
    assert_eq!(reply["error"]["code"], "ledger-corrupt", "{reply}");
    assert_eq!(reply["error"]["line"], 2, "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("test_clock")),
        "{reply}"
    );
}

/// Only in a release build without the `test-clock` feature: the variable
/// is ignored, so the line is a real-clock line with no marker. Run with
/// `cargo test --release --test test_clock_marker`.
#[cfg(not(any(debug_assertions, feature = "test-clock")))]
#[test]
fn a_release_build_never_writes_the_marker() {
    let env = Env::new();
    let (code, reply) = env.spend("live-1", Some(&ahead()));
    assert_eq!(code, 0, "{reply}");
    assert_eq!(reply["test_clock"], false);
    assert!(!env.ledger().contains("test_clock"));
    let (_, ledger, _) = env.run(&["ledger", "p.toml"], None);
    assert!(ledger["test_clock_from"].is_null(), "{ledger}");
}
