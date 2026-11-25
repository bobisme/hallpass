//! Every command that takes the ledger lock bounds its wait with
//! `--lock-timeout-ms`, says on stderr when it has waited a while, and fails
//! with `lock-timeout` at the limit (bn-3d2). The library's reads are bounded
//! by `with_lock_wait`, and a preview by its request's `lock_timeout`.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use hallpass::{Error, LockWait, SpendRequest, StateDir, with_lock_wait};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const CLOCK: &str = "HALLPASS_UNSAFE_TEST_CLOCK";
const NOW: &str = "2026-11-20T09:00:00Z";
const TARGET: &str = "192.0.2.10:5060/udp";

const PASS: &str = r#"format = 1
id = "example-2026-11"
name = "Example voice edge"

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
ports = [5060]

[ceilings]
calls = 20
"#;

/// A pass with one recorded spend, and an input file for every command.
struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let case = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        fs::create_dir(case.path("home")).expect("home");
        case.private("p.toml", PASS);
        case.private("q.toml", PASS);
        fs::create_dir(case.path("archive")).expect("archive");
        fs::set_permissions(case.path("archive"), fs::Permissions::from_mode(0o700))
            .expect("chmod archive");
        let spent = case.run(&["spend", "p.toml", "calls", "--to", TARGET]);
        assert_eq!(spent.status.code(), Some(0), "{}", text(&spent));
        let checkpoint = case.run(&["checkpoint", "p.toml"]);
        assert_eq!(checkpoint.status.code(), Some(0), "{}", text(&checkpoint));
        fs::write(case.path("checkpoint.json"), &checkpoint.stdout).expect("checkpoint");
        let manifest = serde_json::json!({
            "version": 1,
            "pass_id": "example-2026-11",
            "units": [{
                "caller_ref": "run-1",
                "digest": hallpass::Digest::of(PASS.as_bytes()).to_string(),
                "charges": [{"counter": "calls", "n": 1}],
            }],
        });
        fs::write(case.path("manifest.json"), manifest.to_string()).expect("manifest");
        fs::write(
            case.path("references.json"),
            r#"{"version": 1, "pass_id": "example-2026-11", "references": []}"#,
        )
        .expect("references");
        fs::write(
            case.path("scenario.toml"),
            "version = 1\n\n[[step]]\nid = \"one\"\nat = \"2026-11-20T09:00:00Z\"\ncharges = [{ counter = \"calls\", n = 1 }]\n",
        )
        .expect("scenario");
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated well in the past so that a pass read
    /// does not wait for it to settle.
    fn private(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(3600)))
            .expect("backdate");
    }

    fn ledger(&self) -> PathBuf {
        self.path("p.toml.ledger")
    }

    fn state(&self) -> StateDir {
        StateDir::new(self.path("home/state/hallpass"))
    }

    fn command(&self, args: &[&str]) -> Command {
        let home = self.path("home");
        let mut command = Command::new(BIN);
        command
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env(CLOCK, NOW)
            .env_remove("HALLPASS_FORMAT")
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run")
    }

    /// Hold the ledger lock exclusively, as a writer does.
    fn hold(&self) -> File {
        let file = File::options()
            .read(true)
            .open(self.ledger())
            .expect("ledger");
        file.lock().expect("hold the ledger lock");
        file
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(out)))
}

/// One command of each kind that takes the ledger lock, with valid inputs.
fn locking_commands() -> Vec<Vec<&'static str>> {
    vec![
        vec!["permits", "p.toml", "--to", TARGET],
        vec!["status", "p.toml"],
        vec!["ledger", "p.toml"],
        vec!["capacity", "p.toml", "calls"],
        vec!["rehearse", "p.toml", "scenario.toml"],
        vec!["spend", "p.toml", "calls"],
        vec!["spend", "p.toml", "calls", "--dry-run"],
        vec!["spend", "p.toml", "--charge", "calls=1", "--dry-run"],
        vec!["receipt", "p.toml", "--caller-ref", "run-1"],
        vec!["audit-receipts", "p.toml", "archive"],
        vec!["audit-charges", "p.toml", "archive"],
        vec!["reconcile", "p.toml", "manifest.json"],
        vec!["compare-backups", "p.toml", "p.toml.ledger"],
        vec!["checkpoint", "p.toml"],
        vec!["verify-checkpoint", "p.toml.ledger", "checkpoint.json"],
        vec!["adopt", "p.toml", "--preview"],
        vec!["adopt", "p.toml", "--reason", "restored from backup"],
        vec![
            "reconcile-references",
            "p.toml",
            "--adoption",
            "1",
            "--references",
            "references.json",
            "--reason",
            "every reference in the run journal",
        ],
        vec!["diff", "p.toml", "q.toml", "--budget-impact"],
    ]
}

/// A JSON reply that is a lock timeout with nothing recorded.
fn assert_lock_timeout(args: &[&str], out: &Output) {
    assert_eq!(out.status.code(), Some(1), "{args:?}: {}", text(out));
    let v = json(out);
    assert_eq!(v["error"]["code"], "lock-timeout", "{args:?}: {v}");
    assert_eq!(v["error"]["recording"], "not-recorded", "{args:?}: {v}");
    let message = v["error"]["message"].as_str().expect("message");
    assert!(
        message.contains("timed out waiting for the lock on")
            && message.contains("p.toml.ledger")
            && message.contains("Retry, or find and stop the process")
            && message.contains("fuser"),
        "{args:?}: {message}"
    );
}

#[test]
fn every_locking_command_gives_up_at_once_with_a_zero_limit() {
    let case = Case::new();
    let before = fs::read(case.ledger()).expect("ledger");
    let _held = case.hold();
    for command in locking_commands() {
        let mut args = vec!["--json"];
        args.extend(&command);
        args.extend(["--lock-timeout-ms", "0"]);
        let started = Instant::now();
        let out = case.run(&args);
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{args:?} took {:?}",
            started.elapsed()
        );
        assert_lock_timeout(&args, &out);
        assert!(
            !text(&out).contains("hallpass: waiting for the"),
            "{args:?}"
        );
    }
    assert_eq!(fs::read(case.ledger()).expect("ledger"), before);
}

/// With the lock held, the command says it is waiting after about two
/// seconds, names the holder, and fails with `lock-timeout` at the limit.
fn waits_notices_and_times_out(case: &Case, command: &[&str]) {
    const LIMIT: Duration = Duration::from_millis(2300);
    let mut args = vec!["--json"];
    args.extend(command);
    args.extend(["--lock-timeout-ms", "2300"]);
    let started = Instant::now();
    let out = case.run(&args);
    let took = started.elapsed();
    assert!(
        took >= LIMIT && took < LIMIT + Duration::from_millis(1500),
        "{args:?} took {took:?}"
    );
    assert_lock_timeout(&args, &out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("waiting for the ledger lock on").count(),
        1,
        "{args:?}: {stderr}"
    );
    assert!(stderr.contains("p.toml.ledger"), "{stderr}");
    assert!(stderr.contains("--lock-timeout-ms"), "{stderr}");
    if cfg!(target_os = "linux") {
        assert!(
            stderr.contains(&format!("held by process {}", std::process::id())),
            "{stderr}"
        );
    }
}

#[test]
fn a_preflight_waits_then_times_out() {
    let case = Case::new();
    let _held = case.hold();
    waits_notices_and_times_out(&case, &["permits", "p.toml", "--to", TARGET]);
}

#[test]
fn status_and_ledger_wait_then_time_out() {
    let case = Case::new();
    let _held = case.hold();
    std::thread::scope(|scope| {
        scope.spawn(|| waits_notices_and_times_out(&case, &["status", "p.toml"]));
        scope.spawn(|| waits_notices_and_times_out(&case, &["ledger", "p.toml"]));
    });
}

#[test]
fn a_receipt_lookup_waits_then_times_out() {
    let case = Case::new();
    let _held = case.hold();
    waits_notices_and_times_out(&case, &["receipt", "p.toml", "--caller-ref", "run-1"]);
}

#[test]
fn an_audit_waits_then_times_out() {
    let case = Case::new();
    let _held = case.hold();
    waits_notices_and_times_out(&case, &["audit-charges", "p.toml", "archive"]);
}

#[test]
fn a_reader_without_a_limit_says_it_is_waiting_and_then_reads() {
    let case = Case::new();
    let held = case.hold();
    let child = case
        .command(&["--json", "status", "p.toml"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    std::thread::sleep(Duration::from_millis(2600));
    drop(held);
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stderr.matches("waiting for the ledger lock on").count(),
        1,
        "{stderr}"
    );
    assert_eq!(json(&out)["result"], "ok");
}

#[test]
fn without_a_holder_the_output_is_unchanged() {
    let case = Case::new();
    for command in [
        vec!["permits", "p.toml", "--to", TARGET],
        vec!["status", "p.toml"],
        vec!["ledger", "p.toml"],
        vec!["receipt", "p.toml", "--caller-ref", "run-1"],
        vec!["audit-charges", "p.toml", "archive"],
        vec!["checkpoint", "p.toml"],
    ] {
        for format in ["text", "json"] {
            let mut plain = vec!["--format", format];
            plain.extend(&command);
            let mut bounded = plain.clone();
            bounded.extend(["--lock-timeout-ms", "5000"]);
            let (a, b) = (case.run(&plain), case.run(&bounded));
            assert_eq!(a.status.code(), b.status.code(), "{bounded:?}");
            assert_eq!(a.stdout, b.stdout, "{bounded:?}");
            assert_eq!(a.stderr, b.stderr, "{bounded:?}");
            assert!(
                !text(&b).contains("hallpass: waiting for the"),
                "{bounded:?}"
            );
        }
    }
}

#[test]
fn a_dry_run_accepts_a_lock_timeout() {
    let case = Case::new();
    let out = case.run(&[
        "--json",
        "spend",
        "p.toml",
        "calls",
        "--dry-run",
        "--lock-timeout-ms",
        "1000",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(json(&out)["result"], "would-allow");
}

#[test]
fn only_a_budget_impact_diff_takes_a_lock_timeout() {
    let case = Case::new();
    let out = case.run(&["diff", "p.toml", "q.toml", "--lock-timeout-ms", "10"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("--budget-impact"), "{}", text(&out));
}

static NOTICES: Mutex<Vec<LockWait>> = Mutex::new(Vec::new());

fn note(wait: &LockWait) {
    NOTICES.lock().expect("notices").push(wait.clone());
}

#[test]
fn the_library_bounds_reads_and_previews() {
    let case = Case::new();
    let state = case.state();
    let pass = case.path("p.toml");
    let loaded = hallpass::load(&pass).expect("pass");
    let now = hallpass::time::macros::datetime!(2026-11-20 09:00 UTC);
    let held = case.hold();
    let short = Some(Duration::from_millis(100));
    let timed_out = |result: Result<(), Error>| {
        assert!(
            matches!(&result, Err(Error::LockTimeout { path }) if *path == case.ledger()),
            "{result:?}"
        );
    };
    timed_out(with_lock_wait(short, None, || {
        hallpass::read_summary(&loaded, &state).map(drop)
    }));
    timed_out(with_lock_wait(short, None, || {
        hallpass::read_ledger(&loaded, &state).map(drop)
    }));
    timed_out(with_lock_wait(Some(Duration::ZERO), None, || {
        hallpass::tally(&loaded).map(drop)
    }));
    timed_out(with_lock_wait(short, None, || {
        let targets = [TARGET.parse().expect("target")];
        hallpass::permits_in(
            &pass,
            &targets,
            None,
            now,
            hallpass::time::Duration::ZERO,
            &state,
        )
        .map(drop)
    }));
    timed_out(with_lock_wait(short, None, || {
        hallpass::export_checkpoint_observed(&loaded, &state).map(drop)
    }));
    // A preview's own request carries the limit, as a spend's does; it was a
    // usage error before.
    let mut request = SpendRequest::new("calls", 1);
    request.lock_timeout = short;
    timed_out(hallpass::preview_spend_in(&pass, &request, now, &state).map(drop));
    let charges = [hallpass::Charge {
        counter: "calls",
        amount: 1,
    }];
    timed_out(hallpass::capacity::capacity_in(&pass, &charges, &request, now, &state).map(drop));
    let mut debit = hallpass::SpendChargesRequest::new(&charges);
    debit.dry_run = true;
    debit.policy.lock_timeout = short;
    timed_out(hallpass::spend_charges_in(&pass, &debit, now, &state).map(drop));

    // The notice names the ledger, says the lock is shared, and finds the
    // holder.
    let started = Instant::now();
    timed_out(with_lock_wait(
        Some(Duration::from_millis(2200)),
        Some(note),
        || hallpass::read_summary(&loaded, &state).map(drop),
    ));
    assert!(started.elapsed() >= Duration::from_millis(2200));
    let notices = std::mem::take(&mut *NOTICES.lock().expect("notices"));
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].path, case.ledger());
    assert!(notices[0].shared);
    if cfg!(target_os = "linux") {
        assert_eq!(notices[0].holder_pid, Some(std::process::id()));
    }

    // The scope ends with the call: without the lock, the same read works.
    drop(held);
    with_lock_wait(Some(Duration::ZERO), None, || {
        hallpass::read_summary(&loaded, &state)
    })
    .expect("read without a holder");
}

#[test]
fn one_budget_covers_every_lock_a_read_takes() {
    let case = Case::new();
    let state = case.state();
    let loaded = hallpass::load(&case.path("p.toml")).expect("pass");
    let copy = case.path("copy.ledger");
    fs::copy(case.ledger(), &copy).expect("copy");
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o600)).expect("chmod");
    // Only the second candidate is locked; the first is read at once and
    // costs nothing from the budget.
    let held = File::open(&copy).expect("copy");
    held.lock().expect("hold the copy");
    let started = Instant::now();
    let result = with_lock_wait(Some(Duration::from_millis(300)), None, || {
        hallpass::evidence::compare_backups(&loaded, &state, &[case.ledger(), copy.clone()])
    });
    assert!(
        matches!(&result, Err(Error::LockTimeout { path }) if *path == copy),
        "{result:?}"
    );
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(1300),
        "{took:?}"
    );
    // The time spent waiting is taken from the budget: after one wait used
    // it all, the next lock is tried once.
    let other = case.path("other.ledger");
    fs::copy(case.ledger(), &other).expect("copy");
    fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).expect("chmod");
    let second = File::open(&other).expect("other");
    second.lock().expect("hold the other");
    let started = Instant::now();
    let result = with_lock_wait(Some(Duration::from_millis(300)), None, || {
        let first =
            hallpass::evidence::compare_backups(&loaded, &state, std::slice::from_ref(&copy));
        let second =
            hallpass::evidence::compare_backups(&loaded, &state, std::slice::from_ref(&other));
        (first.map(drop), second.map(drop))
    });
    let took = started.elapsed();
    assert!(
        matches!(result.0, Err(Error::LockTimeout { .. })),
        "{result:?}"
    );
    assert!(
        matches!(result.1, Err(Error::LockTimeout { .. })),
        "{result:?}"
    );
    assert!(took < Duration::from_millis(550), "{took:?}");
}
