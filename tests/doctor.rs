//! `hallpass doctor FILE` (bn-21u): one read-only command that diagnoses a
//! pass, its ledger and its witness, and names the one next step.
//!
//! Each case builds a real state with the binary, runs doctor, and checks
//! the verdict, the problem code and the exact next command (with the real
//! paths). Every run also checks that doctor wrote and created nothing, and
//! that it never names `adopt` unless the ledger is really missing.

#![cfg(feature = "cli")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const ID: &str = "doctor-2026-11";

const PASS: &str = r#"format = 1
id = "doctor-2026-11"
name = "Doctor fixture"

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
}

impl Case {
    /// A case with `c/p.toml` and no ledger yet.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        fs::create_dir(dir.path().join("c")).expect("c");
        let case = Self { dir };
        case.pass("c/p.toml", PASS);
        case
    }

    /// A case with `c/p.toml` and `spends` recorded calls.
    fn spent(spends: u64) -> Self {
        let case = Self::new();
        for n in 1..=spends {
            let (rc, out) = case.json(&["spend", "c/p.toml", "calls", "--to", TO]);
            assert_eq!((rc, &out["seq"]), (0, &Value::from(n)), "{out}");
        }
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a pass, private and settled (backdated past the settle wait).
    fn pass(&self, name: &str, text: &str) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, text).expect("write pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        settle(&path);
        path
    }

    fn state(&self) -> PathBuf {
        self.path("home/state/hallpass")
    }

    fn witness(&self) -> PathBuf {
        self.state().join(format!("{ID}.witness"))
    }

    fn command(&self, args: &[&str], now: &str) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", now);
        command
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        self.json_at(args, NOW)
    }

    fn json_at(&self, args: &[&str], now: &str) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.command(&all, now).output().expect("run hallpass");
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    /// Run doctor on `pass` and check that it changed nothing on disk.
    fn doctor(&self, pass: &str) -> (i32, Value) {
        self.doctor_at(pass, NOW)
    }

    fn doctor_at(&self, pass: &str, now: &str) -> (i32, Value) {
        let before = tree(self.dir.path());
        let (rc, reply) = self.json_at(&["doctor", pass], now);
        assert_eq!(
            tree(self.dir.path()),
            before,
            "doctor changed files: {reply}"
        );
        assert_eq!(reply["command"], "doctor", "{reply}");
        let next = next(&reply);
        if reply["problem"] != "ledger-missing" {
            assert!(
                !next.iter().any(|w| w == "adopt"),
                "doctor named adopt for {}: {reply}",
                reply["problem"]
            );
        }
        (rc, reply)
    }

    /// The absolute path hallpass records for a file in the case.
    fn real(&self, name: &str) -> String {
        fs::canonicalize(self.dir.path())
            .expect("canonical")
            .join(name)
            .display()
            .to_string()
    }
}

fn settle(path: &Path) {
    let file = fs::File::options().write(true).open(path).expect("open");
    file.set_modified(SystemTime::now() - Duration::from_secs(3600))
        .expect("backdate");
}

/// Every path under `root` with its mode, size and modification time.
fn tree(root: &Path) -> BTreeMap<PathBuf, (u32, u64, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("entry").path();
            let meta = fs::symlink_metadata(&path).expect("metadata");
            out.insert(
                path.clone(),
                (
                    meta.permissions().mode(),
                    meta.len(),
                    meta.modified().expect("mtime"),
                ),
            );
            if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    out
}

fn next(reply: &Value) -> Vec<String> {
    reply["next"].as_array().map_or_else(Vec::new, |a| {
        a.iter()
            .map(|w| w.as_str().expect("word").to_owned())
            .collect()
    })
}

fn codes(reply: &Value) -> Vec<String> {
    reply["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| f["code"].as_str().expect("code").to_owned())
        .collect()
}

/// Lose the witness update of the last spend, as a crash between the ledger
/// append and the witness update does.
fn spend_with_lost_witness_update(case: &Case, pass: &str) {
    let saved = fs::read(case.witness()).expect("witness");
    let (rc, out) = case.json(&["spend", pass, "calls", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    fs::write(case.witness(), saved).expect("restore witness");
}

#[test]
fn a_healthy_pass_has_nothing_to_do_and_doctor_creates_no_state_directory() {
    let case = Case::new();
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(rc, 0, "{reply}");
    assert_eq!(reply["result"], "healthy", "{reply}");
    assert_eq!(reply["problem"], Value::Null);
    assert_eq!(reply["next"], Value::Null);
    assert_eq!(reply["pass_id"], ID);
    assert!(!case.path("home/state").exists(), "state directory created");

    let case = Case::spent(2);
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["result"]),
        (0, &Value::from("healthy")),
        "{reply}"
    );
    assert!(codes(&reply).is_empty(), "{reply}");

    let text = case
        .command(&["doctor", "c/p.toml"], NOW)
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.starts_with("HEALTHY: "), "{stdout}");
    assert!(stdout.contains("Next: nothing to do."), "{stdout}");
}

#[test]
fn a_torn_tail_names_the_repair_preview() {
    let case = Case::spent(2);
    let ledger = case.path("c/p.toml.ledger");
    let mut bytes = fs::read(&ledger).expect("ledger");
    bytes.extend_from_slice(b"{\"seq\":3,\"ti");
    fs::write(&ledger, bytes).expect("tear");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["result"], "blocked");
    assert_eq!(reply["problem"], "ledger-corrupt");
    assert_eq!(
        next(&reply),
        [
            "hallpass",
            "repair",
            "c/p.toml",
            "--drop-torn-tail",
            "--preview"
        ]
    );
    // The named step works: the preview accepts the tail.
    let (rc, preview) = case.json(&["repair", "c/p.toml", "--drop-torn-tail", "--preview"]);
    assert_eq!(
        (rc, &preview["result"]),
        (0, &Value::from("preview")),
        "{preview}"
    );
}

#[test]
fn damage_before_the_last_line_names_compare_backups() {
    let case = Case::spent(2);
    let ledger = case.path("c/p.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("ledger");
    fs::write(&ledger, text.replacen("\"seq\":1", "\"seq\":7", 1)).expect("damage");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("ledger-corrupt")),
        "{reply}"
    );
    assert_eq!(
        next(&reply),
        ["hallpass", "compare-backups", "c/p.toml", "c/p.toml.ledger"]
    );
}

#[test]
fn a_missing_ledger_names_the_adoption_preview() {
    let case = Case::spent(1);
    fs::remove_file(case.path("c/p.toml.ledger")).expect("lose ledger");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["problem"], "ledger-missing", "{reply}");
    assert_eq!(next(&reply), ["hallpass", "adopt", "c/p.toml", "--preview"]);
}

#[test]
fn a_pass_moved_without_its_ledger_names_the_move() {
    let case = Case::spent(1);
    fs::create_dir(case.path("d")).expect("d");
    fs::rename(case.path("c/p.toml"), case.path("d/p.toml")).expect("move pass");
    let (rc, reply) = case.doctor("d/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["problem"], "ledger-elsewhere", "{reply}");
    assert_eq!(
        next(&reply),
        ["mv", &case.real("c/p.toml.ledger"), "d/p.toml.ledger"]
    );
}

#[test]
fn a_second_pass_file_with_the_id_names_a_diff_with_the_live_one() {
    let case = Case::spent(1);
    fs::create_dir(case.path("d")).expect("d");
    case.pass("d/p.toml", &PASS.replace("calls = 100", "calls = 200"));
    let (rc, reply) = case.doctor("d/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["problem"], "ledger-elsewhere", "{reply}");
    assert_eq!(
        next(&reply),
        ["hallpass", "diff", &case.real("c/p.toml"), "d/p.toml"]
    );
}

/// The witness lags the live ledger by one line, and the pass is copied
/// elsewhere: the live ledger is intact, so doctor must not name adopt
/// (checked in `Case::doctor` for every case). It holds before bn-37e too,
/// because doctor sends a ledger-missing pass whose last-seen ledger still
/// exists to compare-backups.
#[test]
fn a_copy_with_a_lagging_witness_is_never_sent_to_adopt() {
    let case = Case::spent(1);
    spend_with_lost_witness_update(&case, "c/p.toml");
    fs::create_dir(case.path("d")).expect("d");
    case.pass("d/p.toml", PASS);
    let (rc, reply) = case.doctor("d/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["result"], "blocked", "{reply}");
}

/// After bn-37e, a lagging witness no longer hides an intact ledger
/// elsewhere: the copy is `ledger-elsewhere`, and doctor names a diff with
/// the live pass file.
#[test]
fn a_copy_with_a_lagging_witness_is_ledger_elsewhere() {
    let case = Case::spent(1);
    spend_with_lost_witness_update(&case, "c/p.toml");
    fs::create_dir(case.path("d")).expect("d");
    case.pass("d/p.toml", PASS);
    let (rc, reply) = case.doctor("d/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["problem"], "ledger-elsewhere", "{reply}");
    assert_eq!(
        next(&reply),
        ["hallpass", "diff", &case.real("c/p.toml"), "d/p.toml"]
    );
}

#[test]
fn a_lagging_witness_beside_its_ledger_needs_nothing() {
    let case = Case::spent(1);
    spend_with_lost_witness_update(&case, "c/p.toml");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(rc, 0, "{reply}");
    assert_eq!(reply["result"], "healthy", "{reply}");
    assert_eq!(reply["next"], Value::Null);
    assert_eq!(codes(&reply), ["witness-behind"], "{reply}");
}

#[test]
fn damaged_witness_totals_name_moving_the_witness_aside_and_note_nothing() {
    let case = Case::spent(2);
    let text = fs::read_to_string(case.witness()).expect("witness");
    assert!(text.contains("\"calls\":2"), "{text}");
    fs::write(case.witness(), text.replace("\"calls\":2", "\"calls\":9")).expect("damage");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["problem"], "witness-unavailable", "{reply}");
    let witness = case.witness().display().to_string();
    assert_eq!(
        next(&reply),
        ["mv", &witness, &format!("{witness}.damaged")]
    );
    // `status` notes the damage; doctor (checked by `Case::doctor`) did not.
    assert!(!case.state().join(format!("{ID}.witness-damage")).exists());
}

#[test]
fn a_world_writable_directory_names_chmod() {
    let case = Case::spent(1);
    let dir = case.path("c");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).expect("chmod");
    let (rc, reply) = case.doctor("c/p.toml");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod back");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["problem"], "shared-directory", "{reply}");
    assert_eq!(next(&reply), ["chmod", "o-w", "c"]);
    assert!(
        !codes(&reply).contains(&"shared-directory".to_owned()),
        "{reply}"
    );
}

#[test]
fn an_expired_window_blocks_with_no_command() {
    let case = Case::spent(1);
    let (rc, reply) = case.doctor_at("c/p.toml", "2026-11-21T09:00:00Z");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["result"], "blocked");
    assert_eq!(reply["problem"], "expired", "{reply}");
    assert_eq!(reply["next"], Value::Null);
    assert!(
        reply["next_step"]
            .as_str()
            .is_some_and(|s| s.contains("new written approval")),
        "{reply}"
    );
}

#[test]
fn an_insecure_pass_and_an_invalid_pass_name_their_fix() {
    let case = Case::new();
    fs::set_permissions(case.path("c/p.toml"), fs::Permissions::from_mode(0o666)).expect("chmod");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("insecure-permissions")),
        "{reply}"
    );
    assert_eq!(next(&reply), ["chmod", "600", "c/p.toml"]);

    case.pass("c/p.toml", &PASS.replace("calls = 100", "calls = -1"));
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("invalid-pass")),
        "{reply}"
    );
    assert_eq!(next(&reply), ["hallpass", "check", "c/p.toml"]);
}

#[test]
fn an_archive_without_this_revision_needs_action() {
    let case = Case::spent(1);
    let archive = case.path("archive");
    fs::create_dir(&archive).expect("archive");
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("chmod");
    let before = tree(case.dir.path());
    let (rc, reply) = case.json(&["doctor", "c/p.toml", "--archive", "archive"]);
    assert_eq!(tree(case.dir.path()), before);
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["result"], "needs-action", "{reply}");
    assert_eq!(reply["problem"], Value::Null);
    assert_eq!(next(&reply), ["hallpass", "archive", "c/p.toml", "archive"]);
    let (rc, _) = case.json(&["archive", "c/p.toml", "archive"]);
    assert_eq!(rc, 0);
    let (rc, reply) = case.json(&["doctor", "c/p.toml", "--archive", "archive"]);
    assert_eq!(
        (rc, &reply["result"]),
        (0, &Value::from("healthy")),
        "{reply}"
    );
}

#[test]
fn a_pass_path_that_cannot_be_read_is_doctors_own_error() {
    let case = Case::new();
    let (rc, reply) = case.json(&["doctor", "c/missing.toml"]);
    assert_eq!(rc, 1, "{reply}");
    assert_eq!(reply["result"], "error");
    assert_eq!(reply["error"]["code"], "io");
    assert_eq!(reply["error"]["recording"], "not-recorded");
}

#[test]
fn a_pass_modified_in_the_future_is_a_finding() {
    let case = Case::spent(1);
    let file = fs::File::options()
        .write(true)
        .open(case.path("c/p.toml"))
        .expect("open");
    file.set_modified(SystemTime::now() + Duration::from_secs(3600))
        .expect("future mtime");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["result"]),
        (0, &Value::from("healthy")),
        "{reply}"
    );
    assert_eq!(codes(&reply), ["pass-mtime-in-future"], "{reply}");
}
