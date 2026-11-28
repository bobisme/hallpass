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
        let no_witness = reply["result"] == "needs-action"
            && reply["message"]
                .as_str()
                .is_some_and(|m| m.starts_with("there is no witness"));
        let lost_witness = reply["problem"] == "witness-unavailable"
            && reply["message"]
                .as_str()
                .is_some_and(|m| m.contains("so the witness was lost,"));
        if reply["problem"] != "ledger-missing" && !no_witness && !lost_witness {
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

/// What a healthy verdict promises: the next spend goes ahead, guarded
/// (`--require-new-ref`) or plain.
fn assert_next_spends_succeed(case: &Case, pass: &str, now: &str) {
    static REF: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let reference = format!(
        "next-{}",
        REF.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let guarded = [
        "spend",
        pass,
        "calls",
        "--to",
        TO,
        "--caller-ref",
        &reference,
        "--require-new-ref",
    ];
    let (rc, out) = case.json_at(&guarded, now);
    assert_eq!(
        (rc, &out["result"]),
        (0, &Value::from("allowed")),
        "guarded: {out}"
    );
    let (rc, out) = case.json_at(&["spend", pass, "calls", "--to", TO], now);
    assert_eq!(
        (rc, &out["result"]),
        (0, &Value::from("allowed")),
        "plain: {out}"
    );
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
    let message = reply["message"].as_str().expect("message");
    assert!(message.contains("there is no ledger yet"), "{reply}");
    assert!(!message.contains("witness agree"), "{reply}");
    assert_next_spends_succeed(&case, "c/p.toml", NOW);

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
    assert!(stdout.contains("its ledger and witness agree"), "{stdout}");
    assert_next_spends_succeed(&case, "c/p.toml", NOW);
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
        ["mv", "-n", &case.real("c/p.toml.ledger"), "d/p.toml.ledger"]
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
    assert_next_spends_succeed(&case, "c/p.toml", NOW);
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
        ["mv", "-n", &witness, &format!("{witness}.damaged")]
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
    assert_next_spends_succeed(&case, "c/p.toml", NOW);
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
    assert_next_spends_succeed(&case, "c/p.toml", NOW);
}

/// The adoption preview's token, then the adoption with it.
fn adopt(case: &Case, pass: &str) {
    let (rc, preview) = case.json(&["adopt", pass, "--preview"]);
    assert_eq!(rc, 0, "{preview}");
    let token = preview["token"].as_str().expect("token").to_owned();
    let (rc, out) = case.json(&[
        "adopt",
        pass,
        "--reason",
        "complete history",
        "--token",
        &token,
    ]);
    assert_eq!(rc, 0, "{out}");
}

fn assert_healthy(case: &Case, pass: &str) {
    let (rc, reply) = case.doctor(pass);
    assert_eq!(
        (rc, &reply["result"]),
        (0, &Value::from("healthy")),
        "{reply}"
    );
    assert_next_spends_succeed(case, pass, NOW);
}

/// A ledger with entries and no witness: a guarded spend is refused, so it
/// is not healthy. Doctor names the adoption preview, as the spend's own
/// advice does, and after the adoption both spends go ahead.
#[test]
fn a_ledger_without_a_witness_needs_the_adoption_a_guarded_spend_names() {
    let case = Case::spent(2);
    fs::remove_file(case.witness()).expect("lose witness");
    fs::remove_file(case.witness().with_extension("recorded")).expect("and its copy");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(rc, 2, "{reply}");
    assert_eq!(reply["result"], "needs-action", "{reply}");
    assert_eq!(next(&reply), ["hallpass", "adopt", "c/p.toml", "--preview"]);
    assert!(
        reply["next_step"]
            .as_str()
            .is_some_and(|s| s.contains("complete history")),
        "{reply}"
    );
    let (rc, out) = case.json(&[
        "spend",
        "c/p.toml",
        "calls",
        "--to",
        TO,
        "--caller-ref",
        "r1",
        "--require-new-ref",
    ]);
    assert_eq!(rc, 2, "{out}");
    assert_eq!(out["refusal"]["code"], "reference-inconclusive", "{out}");
    assert!(
        out["refusal"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("hallpass adopt c/p.toml")),
        "{out}"
    );
    adopt(&case, "c/p.toml");
    assert_healthy(&case, "c/p.toml");
}

/// Following the damaged-witness step leads to the adoption, never to a
/// verdict that a guarded spend then contradicts.
#[test]
fn moving_a_damaged_witness_aside_leads_to_the_adoption() {
    let case = Case::spent(2);
    fs::write(case.witness(), "{\"hallpass_witness\":1\n").expect("damage");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("witness-unavailable")),
        "{reply}"
    );
    let step = reply["next_step"].as_str().expect("step");
    assert!(
        step.contains("hallpass adopt c/p.toml --preview"),
        "{reply}"
    );
    assert!(!step.contains("next spend records"), "{reply}");
    let words = next(&reply);
    assert_eq!(words[..2], ["mv", "-n"], "{reply}");
    fs::rename(&words[2], &words[3]).expect("move aside");
    // The copy of the witness shows that one was recorded here, so the
    // witness is lost, not absent: a spend is refused until the adoption.
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("witness-unavailable")),
        "{reply}"
    );
    assert_eq!(next(&reply)[..2], ["hallpass", "adopt"], "{reply}");
    adopt(&case, "c/p.toml");
    assert_healthy(&case, "c/p.toml");
}

/// A path in a case.
type Target = fn(&Case) -> PathBuf;

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Run the `chmod` doctor named.
fn run_chmod(case: &Case, reply: &Value) {
    let words = next(reply);
    assert_eq!(words[0], "chmod", "{reply}");
    let status = Command::new("chmod")
        .args(&words[1..])
        .current_dir(case.dir.path())
        .status()
        .expect("chmod");
    assert!(status.success(), "{reply}");
}

/// What a spend writes, unwritable: doctor names the problem code the
/// spend fails with and the exact `chmod`, without writing anything.
#[test]
fn unwritable_state_ledger_and_directory_block_with_the_chmod() {
    if is_root() {
        eprintln!("skipped: root can write anything");
        return;
    }
    // (what to make unwritable, its mode, a ledger first, the problem, the chmod)
    let state = |c: &Case| c.state();
    let ledger = |c: &Case| c.path("c/p.toml.ledger");
    let lock = |c: &Case| c.state().join(format!("{ID}.lock"));
    let dir = |c: &Case| c.path("c");
    let cases: [(Target, u32, u64, &str, &str); 4] = [
        (state, 0o500, 1, "witness-unavailable", "u+w"),
        (lock, 0o400, 1, "witness-unavailable", "600"),
        (ledger, 0o400, 1, "io", "600"),
        (dir, 0o500, 0, "io", "u+w"),
    ];
    for (target, mode, spends, problem, fix) in cases {
        let case = Case::spent(spends);
        let path = target(&case);
        chmod(&path, mode);
        let (rc, out) = case.json(&["spend", "c/p.toml", "calls", "--to", TO]);
        assert_eq!(
            (rc, &out["error"]["code"]),
            (1, &Value::from(problem)),
            "{out}"
        );
        let (rc, reply) = case.doctor("c/p.toml");
        assert_eq!(
            (rc, &reply["result"], &reply["problem"]),
            (2, &Value::from("blocked"), &Value::from(problem)),
            "{reply}"
        );
        let words = next(&reply);
        assert_eq!(words[..2], ["chmod", fix], "{reply}");
        assert_eq!(
            fs::canonicalize(case.dir.path().join(&words[2])).expect("named path"),
            fs::canonicalize(&path).expect("path"),
            "{reply}"
        );
        run_chmod(&case, &reply);
        assert_healthy(&case, "c/p.toml");
    }
}

/// Every ceiling reached: every spend is refused, so it is blocked, not
/// healthy. One of two reached: healthy, and the message says which.
#[test]
fn a_reached_ceiling_is_never_called_nothing_blocks() {
    let case = Case::new();
    case.pass("c/p.toml", &PASS.replace("calls = 100", "calls = 1"));
    let (rc, out) = case.json(&["spend", "c/p.toml", "calls", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["result"], &reply["problem"]),
        (2, &Value::from("blocked"), &Value::from("ceiling-reached")),
        "{reply}"
    );
    assert_eq!(reply["next"], Value::Null);

    let case = Case::new();
    case.pass(
        "c/p.toml",
        &PASS.replace("calls = 100", "calls = 100\nminutes = 1"),
    );
    let (rc, out) = case.json(&["spend", "c/p.toml", "minutes", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["result"]),
        (0, &Value::from("healthy")),
        "{reply}"
    );
    assert!(
        reply["message"]
            .as_str()
            .is_some_and(|m| m.contains("(minutes reached its ceiling)")),
        "{reply}"
    );
    assert_eq!(codes(&reply), ["ceiling-reached"], "{reply}");
    assert_next_spends_succeed(&case, "c/p.toml", NOW);
}

/// A copy of the pass and its ledger, spent from too: the witness last saw
/// the copy's ledger, which is intact, so this ledger is `ledger-elsewhere`
/// (as the spend says), and doctor names a diff with the live pass file.
#[test]
fn a_copy_spent_from_too_is_ledger_elsewhere_and_names_the_live_pass() {
    let case = Case::spent(2);
    fs::create_dir(case.path("d")).expect("d");
    fs::copy(case.path("c/p.toml.ledger"), case.path("d/p.toml.ledger")).expect("copy");
    case.pass("d/p.toml", PASS);
    let (rc, out) = case.json(&["spend", "d/p.toml", "calls", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    let (rc, out) = case.json(&["spend", "c/p.toml", "calls", "--to", TO]);
    assert_eq!(
        (rc, &out["error"]["code"]),
        (1, &Value::from("ledger-elsewhere")),
        "{out}"
    );
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("ledger-elsewhere")),
        "{reply}"
    );
    assert_eq!(
        next(&reply),
        ["hallpass", "diff", &case.real("d/p.toml"), "c/p.toml"]
    );
}

/// A counted last line that lost only its line end: doctor names the
/// newline repair, and after it the pass is healthy and spends go ahead.
#[test]
fn a_last_line_missing_only_its_newline_names_the_newline_repair() {
    let case = Case::spent(2);
    let ledger = case.path("c/p.toml.ledger");
    let mut bytes = fs::read(&ledger).expect("ledger");
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&ledger, bytes).expect("drop newline");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("ledger-corrupt")),
        "{reply}"
    );
    assert_eq!(
        next(&reply),
        [
            "hallpass",
            "repair",
            "c/p.toml",
            "--restore-final-newline",
            "--preview"
        ]
    );
    let (rc, preview) = case.json(
        &next(&reply)[1..]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(rc, 0, "{preview}");
    let token = preview["token"].as_str().expect("token").to_owned();
    let (rc, out) = case.json(&[
        "repair",
        "c/p.toml",
        "--restore-final-newline",
        "--token",
        &token,
    ]);
    assert_eq!(rc, 0, "{out}");
    assert_healthy(&case, "c/p.toml");
}

/// A state directory that does not exist under a directory another user
/// owns (here `/`): doctor names no `chmod` of it, and says to set
/// `XDG_STATE_HOME` instead.
#[test]
fn a_state_directory_under_another_users_directory_names_xdg_state_home() {
    let root = Path::new("/");
    if is_root() || rustix::fs::access(root, rustix::fs::Access::WRITE_OK).is_ok() {
        eprintln!("skipped: / is writable");
        return;
    }
    let case = Case::new();
    let state = "/hallpass-doctor-test-absent";
    let out = case
        .command(&["--format", "json", "doctor", "c/p.toml"], NOW)
        .env("XDG_STATE_HOME", state)
        .output()
        .expect("run");
    let reply: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(out.status.code(), Some(2), "{reply}");
    assert_eq!(reply["problem"], "witness-unavailable", "{reply}");
    assert_eq!(reply["next"], Value::Null, "{reply}");
    assert!(
        reply["next_step"]
            .as_str()
            .is_some_and(|s| s.contains("Set XDG_STATE_HOME")),
        "{reply}"
    );
    assert!(!Path::new(state).exists());
}

/// With no backup, doctor's own steps lead from a damaged ledger to a
/// healthy pass: the step gives the move and the adoption, and the warning.
#[test]
fn a_damaged_ledger_with_no_backup_finishes_through_the_last_resort() {
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
    let step = reply["next_step"].as_str().expect("step");
    assert!(step.contains("If no backup copy exists"), "{reply}");
    assert!(step.contains("not in the new chain"), "{reply}");
    assert!(
        step.contains("`hallpass adopt c/p.toml --reason"),
        "{reply}"
    );
    let mv = step
        .split('`')
        .find(|part| part.starts_with("mv -n "))
        .unwrap_or_else(|| panic!("no mv -n command in {step}"));
    let words: Vec<&str> = mv.split(' ').collect();
    assert_eq!(words.len(), 4, "{mv}");
    fs::rename(case.path(words[2]), case.path(words[3])).expect("move aside");
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (rc, &reply["problem"]),
        (2, &Value::from("ledger-missing")),
        "{reply}"
    );
    assert_eq!(
        next(&reply),
        ["hallpass", "adopt", "c/p.toml", "--preview"],
        "{reply}"
    );
    adopt(&case, "c/p.toml");
    // The moved ledger's lines may hold caller references: doctor names the
    // reconciliation, and with it the pass is healthy.
    let (rc, reply) = case.doctor("c/p.toml");
    assert_eq!(
        (
            rc,
            &reply["result"],
            next(&reply).get(1).map(String::as_str)
        ),
        (
            2,
            &Value::from("needs-action"),
            Some("reconcile-references")
        ),
        "{reply}"
    );
    fs::write(
        case.path("refs.json"),
        format!("{{\"version\": 1, \"pass_id\": \"{ID}\", \"references\": []}}"),
    )
    .expect("references");
    let (rc, out) = case.json(&[
        "reconcile-references",
        "c/p.toml",
        "--adoption",
        "1",
        "--references",
        "refs.json",
        "--reason",
        "no run used a caller reference",
    ]);
    assert_eq!(rc, 0, "{out}");
    assert_healthy(&case, "c/p.toml");
}

/// A damaged ledger with another ledger for the pass id in sight is never
/// sent to the last resort.
#[test]
fn a_damaged_ledger_with_another_ledger_in_sight_never_names_the_adoption() {
    let case = Case::spent(2);
    fs::create_dir(case.path("d")).expect("d");
    fs::copy(case.path("c/p.toml.ledger"), case.path("d/p.toml.ledger")).expect("copy");
    case.pass("d/p.toml", PASS);
    let (rc, out) = case.json(&["spend", "d/p.toml", "calls", "--to", TO]);
    assert_eq!(rc, 0, "{out}");
    let ledger = case.path("c/p.toml.ledger");
    let text = fs::read_to_string(&ledger).expect("ledger");
    fs::write(&ledger, text.replacen("\"seq\":1", "\"seq\":7", 1)).expect("damage");
    let (_, reply) = case.doctor("c/p.toml");
    assert_eq!(reply["problem"], "ledger-corrupt", "{reply}");
    let step = reply["next_step"].as_str().expect("step");
    assert!(!step.contains("hallpass adopt"), "{reply}");
}

/// A writer stopped while it holds the ledger lock does not hold doctor up:
/// doctor tries the lock without waiting and reports `needs-action`
/// (`lock-held`, bn-22sm).
#[test]
fn doctor_bounds_its_own_wait_for_a_held_lock() {
    if Command::new("flock").arg("--version").output().is_err() {
        return;
    }
    let case = Case::spent(1);
    let mut holder = Command::new("flock")
        .args(["-x", "c/p.toml.ledger", "sleep", "20"])
        .current_dir(case.dir.path())
        .spawn()
        .expect("hold the lock");
    std::thread::sleep(Duration::from_millis(500));
    let began = std::time::Instant::now();
    let (rc, reply) = case.json(&["doctor", "c/p.toml"]);
    let waited = began.elapsed();
    holder.kill().expect("stop holder");
    holder.wait().expect("reap holder");
    assert_eq!(
        (rc, &reply["result"], &reply["problem"]),
        (2, &Value::from("needs-action"), &Value::Null),
        "{reply}"
    );
    assert!(waited < Duration::from_secs(15), "{waited:?}");
    assert!(
        reply["headline"]
            .as_str()
            .is_some_and(|s| s.contains("p.toml.ledger")),
        "{reply}"
    );
}
