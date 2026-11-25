//! The backwards-clock warning compares the decision clock with the latest
//! time recorded anywhere in the ledger, not with the last line, and names
//! that time and its sequence number (bn-d43).

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const TARGET: &str = "192.0.2.10:443/tcp";

const PASS: &str = r#"format = 1
id = "acme-clock"
name = "Clock"

[approval]
owner = "Pat Owner"
reference = "email"
operator = "Sam"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "a"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
bytes = 1000000
requests = 100
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("c.toml");
        fs::write(&path, PASS).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(3600)))
            .expect("backdate");
        fs::create_dir(dir.path().join("home")).expect("home");
        Self { dir }
    }

    fn pass(&self) -> PathBuf {
        self.dir.path().join("c.toml")
    }

    /// Run with the test clock at `hh:mm` on 2026-11-20 and return the reply.
    fn json(&self, at: &str, args: &[&str]) -> Value {
        let home = self.dir.path().join("home");
        let out = Command::new(BIN)
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", format!("2026-11-20T{at}:00Z"))
            .env_remove("HALLPASS_FORMAT")
            .arg("--json")
            .args(args)
            .output()
            .expect("run");
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: {e}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        })
    }
}

/// The backwards-clock warnings of a reply.
fn clock_warnings(reply: &Value) -> Vec<String> {
    reply["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(Value::as_str)
        .filter(|w| w.contains("the decision clock"))
        .map(str::to_owned)
        .collect()
}

/// The warning for a clock at `now` before `latest`, recorded at `seq`.
fn warning(now: &str, latest: &str, seq: u64) -> String {
    format!(
        "the decision clock (2026-11-20T{now}:00Z) precedes 2026-11-20T{latest}:00Z, the latest time recorded in the ledger (sequence {seq}); check the system clock before continuing"
    )
}

#[test]
fn every_spend_before_the_latest_time_warns_until_the_clock_passes_it() {
    let case = Case::new();
    let pass = case.pass();
    let pass = pass.to_str().expect("utf8");
    let spend = ["spend", pass, "requests", "--to", TARGET];
    let debit = ["spend", pass, "--charge", "requests=1", "--to", TARGET];
    // The lead's repro: 12:00, then a clock set back to 09:00.
    for (at, args, warns) in [
        ("12:00", &spend[..], false),
        ("09:00", &spend[..], true),
        ("09:00", &spend[..], true),
        ("09:05", &spend[..], true),
        ("09:10", &debit[..], true),
        ("12:00", &spend[..], false),
        ("12:01", &debit[..], false),
    ] {
        let reply = case.json(at, args);
        assert_eq!(reply["result"], "allowed", "{at}: {reply}");
        let expected = if warns {
            vec![warning(at, "12:00", 1)]
        } else {
            Vec::new()
        };
        assert_eq!(clock_warnings(&reply), expected, "{at}: {reply}");
    }
    // Every command that decides at the clock names the new latest time,
    // the debit at 12:01 (sequence 7).
    for args in [
        vec!["permits", pass, "--to", TARGET],
        vec!["status", pass],
        vec!["spend", pass, "requests", "--dry-run"],
        vec!["spend", pass, "--charge", "requests=1", "--dry-run"],
        vec!["capacity", pass, "requests"],
    ] {
        let reply = case.json("09:00", &args);
        assert_eq!(
            clock_warnings(&reply),
            vec![warning("09:00", "12:01", 7)],
            "{args:?}: {reply}"
        );
        assert!(
            clock_warnings(&case.json("12:01", &args)).is_empty(),
            "{args:?}"
        );
    }
    // A rehearsal judges each step's instant the same way.
    let scenario = case.dir.path().join("steps.toml");
    fs::write(
        &scenario,
        "version = 1\n\n[[step]]\nid = \"early\"\nat = \"2026-11-20T09:00:00Z\"\ncharges = [{ counter = \"requests\", n = 1 }]\n\n[[step]]\nid = \"later\"\nat = \"2026-11-20T12:30:00Z\"\ncharges = [{ counter = \"requests\", n = 1 }]\n",
    )
    .expect("scenario");
    let reply = case.json(
        "12:01",
        &["rehearse", pass, scenario.to_str().expect("utf8")],
    );
    assert_eq!(
        clock_warnings(&reply),
        vec![warning("09:00", "12:01", 7)],
        "{reply}"
    );
}

#[test]
fn the_library_view_names_the_latest_time_and_its_line() {
    use hallpass::time::macros::datetime;
    let case = Case::new();
    let pass = case.pass();
    let state = hallpass::StateDir::new(case.dir.path().join("state"));
    for at in [
        datetime!(2026-11-20 10:00 UTC),
        datetime!(2026-11-20 12:00 UTC),
        datetime!(2026-11-20 09:00 UTC),
    ] {
        hallpass::spend_in(
            &pass,
            &hallpass::SpendRequest::new("requests", 1),
            at,
            &state,
        )
        .expect("spend");
    }
    let view = hallpass::read_summary(&hallpass::load(&pass).expect("pass"), &state).expect("view");
    assert_eq!(view.last_time, Some(datetime!(2026-11-20 09:00 UTC)));
    assert_eq!(view.latest_time, Some((datetime!(2026-11-20 12:00 UTC), 2)));
    assert_eq!(
        view.clock_warning(datetime!(2026-11-20 11:00 UTC)),
        Some(
            "the decision clock (2026-11-20T11:00:00Z) precedes 2026-11-20T12:00:00Z, the latest time recorded in the ledger (sequence 2); check the system clock before continuing"
                .to_owned()
        )
    );
    assert_eq!(view.clock_warning(datetime!(2026-11-20 12:00 UTC)), None);
}
