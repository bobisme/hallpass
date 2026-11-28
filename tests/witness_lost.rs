//! A witness lost from the state directory that recorded it (bn-15w3).
//!
//! Every write of the witness also writes a copy of it,
//! `<pass id>.recorded`. While the witness is missing and that copy is
//! there, the witness was lost here (a cleaned or partly restored state
//! directory). It is not a pass arriving from another machine, user or
//! state directory, so a spend is refused as `witness-unavailable` instead
//! of taking an older copy of the ledger as the count. The adoption checks
//! the ledger against the copy and never lowers the count. A state
//! directory that never recorded a witness for the pass (one where the
//! pass was only checked, or a guarded spend was refused) still takes the
//! ledger as an arrival.

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:5060/udp";
const ID: &str = "lost-2026-11";

const PASS: &str = r#"format = 1
id = "lost-2026-11"
name = "Lost witness"

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
calls = 3
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("mkdir");
        let pass = dir.path().join("p.toml");
        fs::write(&pass, PASS).expect("write pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("chmod");
        File::options()
            .write(true)
            .open(&pass)
            .expect("open")
            .set_modified(SystemTime::now() - Duration::from_secs(60))
            .expect("backdate");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn state(&self) -> PathBuf {
        self.path("home/state/hallpass")
    }

    fn witness(&self) -> PathBuf {
        self.state().join(format!("{ID}.witness"))
    }

    fn copy(&self) -> PathBuf {
        self.state().join(format!("{ID}.recorded"))
    }

    fn ledger(&self) -> PathBuf {
        self.path("p.toml.ledger")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .current_dir(self.dir.path())
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .output()
            .expect("run hallpass")
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.run(&all);
        let reply = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): {} / {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code().expect("exit code"), reply)
    }

    fn spend(&self, extra: &[&str]) -> (i32, Value) {
        let mut args = vec!["spend", "p.toml", "calls", "--to", TO];
        args.extend_from_slice(extra);
        self.json(&args)
    }

    fn spent(&self) -> u64 {
        let (rc, v) = self.json(&["status", "p.toml"]);
        assert_eq!(rc, 0, "{v}");
        v["counters"][0]["spent"].as_u64().expect("spent")
    }

    /// Preview the adoption, check its case, and adopt with its token.
    fn adopt(&self, case: &str) -> Value {
        let (rc, preview) = self.json(&["adopt", "p.toml", "--preview"]);
        assert_eq!(rc, 0, "{preview}");
        assert_eq!(preview["case"], case, "{preview}");
        let token = preview["token"].as_str().expect("token").to_owned();
        let (rc, adopted) = self.json(&[
            "adopt",
            "p.toml",
            "--reason",
            "the witness was lost",
            "--token",
            &token,
        ]);
        assert_eq!(rc, 0, "{adopted}");
        assert_eq!(adopted["case"], case, "{adopted}");
        preview
    }
}

fn error_message(v: &Value) -> &str {
    v["error"]["message"].as_str().expect("error message")
}

/// The copy says the witness was lost.
fn assert_lost(v: &Value) {
    assert_eq!(v["error"]["code"], "witness-unavailable", "{v}");
    let message = error_message(v);
    assert!(
        message.contains("is missing, but")
            && message.contains(&format!("{ID}.recorded"))
            && message.contains("so the witness was lost")
            && message.contains("hallpass adopt"),
        "{message}"
    );
    assert!(!message.contains("Make that directory exist"), "{message}");
}

fn assert_recorded(v: &Value) {
    assert_eq!(v["result"], "allowed", "{v}");
}

/// The evaluation's case: spend 3 of 3, lose the witness, put back the
/// ledger as it was after the first spend. Before, the next spend took the
/// old ledger as an arrival and recorded a fourth call on a ceiling of 3.
#[test]
fn a_lost_witness_and_an_older_ledger_are_refused_and_adoption_keeps_the_count() {
    let case = Case::new();
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 0, "{v}");
    let old = fs::read(case.ledger()).expect("ledger");
    for _ in 0..2 {
        let (rc, v) = case.spend(&[]);
        assert_eq!(rc, 0, "{v}");
    }
    assert!(case.copy().is_file());
    fs::remove_file(case.witness()).expect("lose the witness");
    fs::write(case.ledger(), &old).expect("put back an older ledger");

    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 1, "{v}");
    assert_lost(&v);
    let (rc, v) = case.spend(&["--caller-ref", "r9", "--require-new-ref"]);
    assert_eq!(rc, 1, "{v}");
    assert_lost(&v);
    assert_eq!(
        fs::read(case.ledger()).expect("ledger"),
        old,
        "nothing recorded"
    );
    assert!(!case.witness().exists(), "no witness recorded");

    // A read answers, with the witness not checked.
    let (rc, v) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 0, "{v}");
    assert_eq!(v["ledger"]["witness"], "not-checked", "{v}");

    // Doctor blocks and names the adoption preview.
    let (rc, v) = case.json(&["doctor", "p.toml"]);
    assert_eq!(rc, 2, "{v}");
    assert_eq!(v["problem"], "witness-unavailable", "{v}");
    assert_eq!(
        v["next"],
        serde_json::json!(["hallpass", "adopt", "p.toml", "--preview"]),
        "{v}"
    );
    let step = v["next_step"].as_str().expect("step");
    assert!(step.contains("backup of the state directory"), "{step}");
    assert!(step.contains("--token TOKEN"), "{step}");

    // The adoption carries what the copy recorded beyond the old ledger.
    let preview = case.adopt("ledger-changed");
    assert_eq!(
        preview["carried"],
        serde_json::json!({"calls": 2}),
        "{preview}"
    );
    assert_eq!(case.spent(), 3);
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 2, "{v}");
    assert_eq!(v["refusal"]["code"], "ceiling-reached", "{v}");
    // Lines were lost, so a guarded spend cannot show that a reference is new.
    let (_, doctor) = case.json(&["doctor", "p.toml"]);
    assert!(
        doctor.to_string().contains("reference-inconclusive"),
        "{doctor}"
    );
}

/// The witness is lost but the ledger is the one it recorded: the spend is
/// still refused (hallpass cannot tell that without the adoption's check),
/// and the adoption keeps every line, carries nothing and leaves guarded
/// spends working.
#[test]
fn a_lost_witness_with_its_ledger_intact_is_adopted_without_loss() {
    let case = Case::new();
    for _ in 0..2 {
        let (rc, v) = case.spend(&["--caller-ref", "r1"]);
        assert_eq!(rc, 0, "{v}");
    }
    fs::remove_file(case.witness()).expect("lose the witness");
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 1, "{v}");
    assert_lost(&v);
    let preview = case.adopt("no-witness");
    assert_eq!(preview["carried"], serde_json::json!({}), "{preview}");
    assert_eq!(case.spent(), 2);
    let (rc, v) = case.spend(&["--caller-ref", "r2", "--require-new-ref"]);
    assert_eq!(rc, 0, "{v}");
    assert_recorded(&v);
    assert!(case.witness().is_file());
}

/// The witness and the ledger both lost, the copy left: not a fresh pass.
/// The adoption starts a new ledger carrying the copy's totals.
#[test]
fn a_lost_witness_and_ledger_do_not_restart_the_count() {
    let case = Case::new();
    for _ in 0..2 {
        let (rc, v) = case.spend(&[]);
        assert_eq!(rc, 0, "{v}");
    }
    fs::remove_file(case.witness()).expect("lose the witness");
    fs::remove_file(case.ledger()).expect("lose the ledger");
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 1, "{v}");
    assert_lost(&v);
    assert!(!case.ledger().exists(), "no ledger started");
    let preview = case.adopt("ledger-missing");
    assert_eq!(
        preview["carried"],
        serde_json::json!({"calls": 2}),
        "{preview}"
    );
    assert_eq!(case.spent(), 2);
}

/// A state directory that only checked the pass (`permits`, `status`, a
/// guarded spend refused for want of a witness) writes `.pass-file` and
/// `.lock`, but records no witness and no copy: the ledger is an arrival,
/// and a plain spend records the witness, as before.
#[test]
fn a_state_directory_that_only_checked_the_pass_still_takes_an_arrival() {
    let case = Case::new();
    for _ in 0..2 {
        let (rc, v) = case.spend(&[]);
        assert_eq!(rc, 0, "{v}");
    }
    // Another account: a state directory of its own.
    let state = case.path("home/state");
    fs::rename(&state, case.path("home/elsewhere")).expect("move the state aside");
    let (rc, v) = case.json(&["permits", "p.toml", "--to", TO]);
    assert_eq!(rc, 0, "{v}");
    let (rc, v) = case.json(&["status", "p.toml"]);
    assert_eq!(rc, 0, "{v}");
    let (rc, v) = case.spend(&["--caller-ref", "r1", "--require-new-ref"]);
    assert_eq!(rc, 2, "{v}");
    assert_eq!(v["refusal"]["code"], "reference-inconclusive", "{v}");
    assert!(case.state().join(format!("{ID}.pass-file")).is_file());
    assert!(case.state().join(format!("{ID}.lock")).is_file());
    assert!(!case.copy().exists());
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 0, "{v}");
    assert_recorded(&v);
    assert!(
        v.to_string().contains("there was no witness"),
        "the arrival warning: {v}"
    );
    assert!(case.witness().is_file() && case.copy().is_file());
    assert_eq!(case.spent(), 3);
}

/// The copy is only evidence while it reads as one: a damaged copy, or one
/// for another pass id, gives the behaviour of earlier releases.
#[test]
fn a_damaged_or_foreign_copy_is_not_evidence() {
    for bad in [
        "not json\n".to_owned(),
        fs::read_to_string(Path::new("/dev/null")).expect("empty"),
        format!(
            "{{\"hallpass_recorded\":1,\"pass_id\":\"other\",\"ledger\":\"/x\",\"seq\":2,\"tail\":\"sha256:{}\",\"totals\":{{\"calls\":2}},\"updated\":\"{NOW}\"}}\n",
            "0".repeat(64)
        ),
    ] {
        let case = Case::new();
        let (rc, v) = case.spend(&[]);
        assert_eq!(rc, 0, "{v}");
        fs::remove_file(case.witness()).expect("lose the witness");
        fs::write(case.copy(), &bad).expect("damage the copy");
        let (rc, v) = case.spend(&[]);
        assert_eq!(rc, 0, "{bad}: {v}");
        assert!(v.to_string().contains("there was no witness"), "{v}");
    }
}

/// The copy follows each write of the witness, so it records the latest
/// line, and a rewind past the latest spend is caught.
#[test]
fn the_copy_follows_the_witness() {
    let case = Case::new();
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 0, "{v}");
    let (rc, v) = case.spend(&[]);
    assert_eq!(rc, 0, "{v}");
    let witness: Value =
        serde_json::from_slice(&fs::read(case.witness()).expect("witness")).expect("json");
    let copy: Value = serde_json::from_slice(&fs::read(case.copy()).expect("copy")).expect("json");
    assert_eq!(copy["hallpass_recorded"], 1, "{copy}");
    for key in ["pass_id", "ledger", "seq", "tail", "totals", "updated"] {
        assert_eq!(copy[key], witness[key], "{key}: {copy} / {witness}");
    }
    assert_eq!(
        fs::metadata(case.copy())
            .expect("copy")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
