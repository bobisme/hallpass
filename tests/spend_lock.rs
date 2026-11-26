#![cfg(feature = "cli")]

use hallpass::{RefusalCode, SpendRequest, StateDir, ledger_path, spend_with_clock_in};
use std::fs::{self, File, TryLockError};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use time::macros::datetime;

struct Fixture {
    dir: tempfile::TempDir,
    pass: PathBuf,
    state: StateDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("private tempdir");
        let pass = dir.path().join("approval");
        let body = format!(
            "{}\n[ceilings]\ncalls = 10\n",
            include_str!("../docs/review-approval.toml")
        );
        fs::write(&pass, body).expect("pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("private pass");
        let state = StateDir::new(dir.path().join("state/hallpass"));
        let result = Self { dir, pass, state };
        assert!(
            result
                .command()
                .args(["calls", "--lock-timeout-ms", "0"])
                .output()
                .expect("initial spend")
                .status
                .success()
        );
        result
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.args(["--json", "spend"])
            .arg(&self.pass)
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z");
        cmd
    }

    fn witness_lock(&self) -> File {
        File::open(self.dir.path().join("state/hallpass/review-example.lock"))
            .expect("witness lock")
    }

    fn ledger(&self) -> File {
        File::open(ledger_path(&self.pass)).expect("ledger")
    }

    fn assert_entries(&self, expected: u64) {
        let view = hallpass::read_ledger(&hallpass::load(&self.pass).expect("pass"), &self.state)
            .expect("replay");
        assert_eq!(view.tally.entries, expected);
        assert_eq!(view.tally.spent("calls"), expected);
    }
}

// Observe the acquisition of the first lock while the parent owns the second.
// This barrier lets the parent release the ledger only after the writer is queued.
fn wait_for_writer(witness: &File) {
    let start = Instant::now();
    loop {
        match witness.try_lock() {
            Err(TryLockError::WouldBlock) => return,
            Ok(()) => witness.unlock().expect("unlock probe"),
            Err(e) => panic!("probe: {e}"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "writer failed to reach ledger lock"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn held_locks_return_pre_append_error_and_release_the_first_lock() {
    let f = Fixture::new();
    for (file, args) in [
        (f.witness_lock(), vec!["calls", "--lock-timeout-ms", "0"]),
        (
            f.ledger(),
            vec!["--charge", "calls=1", "--lock-timeout-ms", "20"],
        ),
    ] {
        file.lock().expect("parent holds lock");
        let out = f.command().args(args).output().expect("run contender");
        assert_eq!(out.status.code(), Some(1));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON error");
        assert_eq!(json["error"]["code"], "lock-timeout");
        assert_eq!(json["error"]["recording"], "not-recorded");
        file.unlock().expect("release parent lock");
        f.witness_lock()
            .try_lock()
            .expect("waiter released witness");
        f.assert_entries(1);
    }
}

#[test]
fn release_within_deadline_commits_once() {
    let f = Fixture::new();
    let ledger = f.ledger();
    ledger.lock().expect("hold ledger");
    let child = f
        .command()
        .args(["--charge", "calls=1", "--lock-timeout-ms", "10000"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("contender");
    wait_for_writer(&f.witness_lock());
    ledger.unlock().expect("release");
    let out = child.wait_with_output().expect("result");
    assert!(out.status.success());
    let reply: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(reply["seq"], 2);
    f.assert_entries(2);
}

#[test]
fn window_that_expires_while_queued_is_refused() {
    let f = Fixture::new();
    let ledger = f.ledger();
    ledger.lock().expect("hold ledger");
    let expired = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut req = SpendRequest::new("calls", 1);
            req.lock_timeout = Some(Duration::from_secs(10));
            // A pinned clock, on the ledger the test clock started (bn-2mm).
            hallpass::with_test_clock(|| {
                spend_with_clock_in(&f.pass, &req, &f.state, || {
                    if expired.load(Ordering::SeqCst) {
                        datetime!(2026-11-20 17:00 UTC)
                    } else {
                        datetime!(2026-11-20 09:00 UTC)
                    }
                })
            })
            .expect("decision")
        });
        wait_for_writer(&f.witness_lock());
        expired.store(true, Ordering::SeqCst);
        ledger.unlock().expect("release");
        let result = worker.join().expect("join");
        assert_eq!(result.refusal.expect("expired").code, RefusalCode::Expired);
        assert_eq!(result.seq, None);
    });
    f.assert_entries(1);
}
