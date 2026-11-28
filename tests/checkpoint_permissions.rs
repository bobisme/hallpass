//! A retained checkpoint is the trust input against a rollback, so the
//! commands that read one apply the `--allowed-signers` owner and mode rule
//! to it (bn-9qrd); `checkpoint --output FILE` writes it with mode 0600; and
//! the renewal steps that docs/PASS-FORMAT.md names work as written.

#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const TO: &str = "192.0.2.10:443/tcp";

fn pass(id: &str, until: &str) -> String {
    format!(
        r#"format = 1
id = "{id}"
name = "Checkpoint permissions fixture"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = {until}
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443

[ceilings]
requests = 10
"#
    )
}

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        let case = Self { dir };
        case.write("p.toml", &pass("perm-2026-11", "2026-11-20T17:00:00Z"));
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let old = SystemTime::now() - Duration::from_secs(10);
        fs::File::options()
            .write(true)
            .open(&path)
            .expect("open")
            .set_modified(old)
            .expect("backdate");
    }

    fn command(&self) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(["--format", "json"])
            .current_dir(self.dir.path())
            .env_remove("HALLPASS_FORMAT")
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW);
        command
    }

    fn json(&self, args: &[&str]) -> (i32, Value, String) {
        let out = self.command().args(args).output().expect("run");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let value = serde_json::from_str(&text).unwrap_or(Value::Null);
        (
            out.status.code().expect("exit code"),
            value,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Spend once and export a checkpoint with `--output`.
    fn exported(&self) {
        let (code, _, err) = self.json(&["spend", "p.toml", "--charge", "requests=1", "--to", TO]);
        assert_eq!(code, 0, "{err}");
        let (code, reply, err) = self.json(&["checkpoint", "p.toml", "--output", "cp.json"]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(reply["output"], "cp.json");
        assert_eq!(reply["mode"], "0600");
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("meta").permissions().mode() & 0o7777
}

#[test]
fn output_writes_mode_0600_under_a_loose_umask() {
    let case = Case::new();
    let (code, _, err) = case.json(&["spend", "p.toml", "--charge", "requests=1", "--to", TO]);
    assert_eq!(code, 0, "{err}");
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "umask 002; exec {BIN} --format json checkpoint p.toml --output cp.json"
        ))
        .current_dir(case.dir.path())
        .env("HOME", case.path("home"))
        .env("XDG_STATE_HOME", case.path("home/state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(mode(&case.path("cp.json")), 0o600);
    let reply: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(reply["checkpoint"]["pass_id"], "perm-2026-11");
    // The file holds the checkpoint and verifies.
    let (code, reply, err) = case.json(&["verify-checkpoint", "p.toml.ledger", "cp.json"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(reply["result"], "exact");
}

#[test]
fn output_refuses_an_existing_file_and_a_link() {
    let case = Case::new();
    case.exported();
    let (code, _, err) = case.json(&["checkpoint", "p.toml", "--output", "cp.json"]);
    assert_eq!(code, 1, "{err}");
    symlink("cp.json", case.path("link.json")).expect("link");
    let (code, _, _) = case.json(&["checkpoint", "p.toml", "--output", "link.json"]);
    assert_eq!(code, 1);
    // Nothing is written for a pass with no ledger.
    case.write("q.toml", &pass("perm-other", "2026-11-20T17:00:00Z"));
    let (code, _, _) = case.json(&["checkpoint", "q.toml", "--output", "q.json"]);
    assert_eq!(code, 2);
    assert!(!case.path("q.json").exists());
}

#[test]
fn every_checkpoint_input_refuses_a_writable_file() {
    let case = Case::new();
    case.exported();
    fs::set_permissions(case.path("cp.json"), fs::Permissions::from_mode(0o666)).expect("chmod");
    for args in [
        vec!["verify-checkpoint", "p.toml.ledger", "cp.json"],
        vec!["doctor", "p.toml", "--checkpoint", "cp.json"],
        vec!["adopt", "p.toml", "--checkpoint", "cp.json", "--preview"],
    ] {
        let (code, reply, err) = case.json(&args);
        assert_eq!(code, 1, "{args:?}: {reply} {err}");
        let said = format!("{reply}{err}");
        assert!(said.contains("insecure-permissions"), "{args:?}: {said}");
        assert!(said.contains("0666"), "{args:?}: {said}");
        assert!(said.contains("chmod 600"), "{args:?}: {said}");
        assert!(said.contains("checkpoint"), "{args:?}: {said}");
    }
    // Group write alone is refused too; owner-only modes are accepted.
    fs::set_permissions(case.path("cp.json"), fs::Permissions::from_mode(0o620)).expect("chmod");
    let (code, _, _) = case.json(&["verify-checkpoint", "p.toml.ledger", "cp.json"]);
    assert_eq!(code, 1);
    for readable in [0o644, 0o600, 0o400] {
        fs::set_permissions(case.path("cp.json"), fs::Permissions::from_mode(readable))
            .expect("chmod");
        let (code, reply, err) = case.json(&["verify-checkpoint", "p.toml.ledger", "cp.json"]);
        assert_eq!(code, 0, "{readable:o}: {err}");
        assert_eq!(reply["result"], "exact");
    }
}

#[test]
fn a_link_is_resolved_and_its_target_is_checked() {
    let case = Case::new();
    case.exported();
    symlink("cp.json", case.path("link.json")).expect("link");
    let (code, reply, err) = case.json(&["verify-checkpoint", "p.toml.ledger", "link.json"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(reply["result"], "exact");
    fs::set_permissions(case.path("cp.json"), fs::Permissions::from_mode(0o666)).expect("chmod");
    let (code, reply, err) = case.json(&["verify-checkpoint", "p.toml.ledger", "link.json"]);
    assert_eq!(code, 1);
    let said = format!("{reply}{err}");
    assert!(said.contains("insecure-permissions"), "{said}");
    assert!(said.contains("cp.json"), "names the resolved file: {said}");
}

#[test]
fn a_dangling_link_is_an_error() {
    let case = Case::new();
    case.exported();
    symlink("missing.json", case.path("gone.json")).expect("link");
    let (code, _, _) = case.json(&["verify-checkpoint", "p.toml.ledger", "gone.json"]);
    assert_eq!(code, 1);
}

/// The commands docs/PASS-FORMAT.md "Renewing or extending an approval" names.
#[test]
fn a_renewal_under_the_same_id_is_widened_and_keeps_the_budget() {
    let case = Case::new();
    let (code, _, err) = case.json(&["spend", "p.toml", "--charge", "requests=4", "--to", TO]);
    assert_eq!(code, 0, "{err}");
    case.write(
        "renewed.toml",
        &pass("perm-2026-11", "2026-11-23T17:00:00Z"),
    );
    let (code, reply, err) = case.json(&[
        "diff",
        "--containment",
        "--at",
        NOW,
        "p.toml",
        "renewed.toml",
    ]);
    assert_eq!(code, 2, "{err}");
    assert_eq!(reply["result"], "widened");
    let fields: Vec<&str> = reply["containment"]["loosenings"]
        .as_array()
        .expect("loosenings")
        .iter()
        .filter_map(|l| l["field"].as_str())
        .collect();
    assert_eq!(fields, ["approval.valid_until"]);
    // The reviewer overrides; the operator replaces the pass with mv.
    fs::rename(case.path("renewed.toml"), case.path("p.toml")).expect("mv");
    let (code, reply, err) = case.json(&["spend", "p.toml", "--charge", "requests=1", "--to", TO]);
    assert_eq!(code, 0, "{err}");
    assert!(reply.to_string().contains("\"spent\":5"), "{reply}");
}

#[test]
fn a_new_id_starts_a_new_ledger() {
    let case = Case::new();
    let (code, _, err) = case.json(&["spend", "p.toml", "--charge", "requests=4", "--to", TO]);
    assert_eq!(code, 0, "{err}");
    case.write("next.toml", &pass("perm-2026-12", "2026-11-23T17:00:00Z"));
    let (code, reply, err) =
        case.json(&["spend", "next.toml", "--charge", "requests=1", "--to", TO]);
    assert_eq!(code, 0, "{err}");
    assert!(reply.to_string().contains("\"spent\":1"), "{reply}");
    assert!(case.path("next.toml.ledger").exists());
}
