//! `verify-approval --archive` must not report success when the archive kept
//! another principal's record and this signature was not stored (bn-1re).
//!
//! These tests need OpenSSH `ssh-keygen` and return early without it.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const OP: &str = "op@example.org";

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
        let pass = env.path("p.toml");
        fs::write(
            &pass,
            format!(
                "{}[ceilings]\nrequests = 100\n",
                include_str!("../docs/review-approval.toml")
            ),
        )
        .expect("pass");
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("private");
        let old = SystemTime::now() - Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&pass)
            .expect("open")
            .set_modified(old)
            .expect("backdate");
        env.keygen(OWNER, "owner");
        env.keygen(OP, "op");
        env.keygen(OP, "op2");
        let trust = format!(
            "{OWNER} {}{OP} {}{OP} {}",
            fs::read_to_string(env.path("owner.pub")).expect("pub"),
            fs::read_to_string(env.path("op.pub")).expect("pub"),
            fs::read_to_string(env.path("op2.pub")).expect("pub"),
        );
        fs::write(env.path("trust"), trust).expect("trust");
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn keygen(&self, comment: &str, key: &str) {
        let out = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", key])
            .current_dir(self.dir.path())
            .output()
            .expect("ssh-keygen");
        assert!(out.status.success());
        // Sign the pass with this key.
        let out = Command::new("ssh-keygen")
            .args(["-q", "-Y", "sign", "-f", key, "-n", "hallpass-approval-v1"])
            .arg("p.toml")
            .current_dir(self.dir.path())
            .output()
            .expect("ssh-keygen");
        assert!(out.status.success());
        fs::rename(self.path("p.toml.sig"), self.path(&format!("{key}.sig"))).expect("rename");
    }

    fn verify(&self, key: &str, principal: &str, format: &str) -> (i32, String, String) {
        let signature = format!("{key}.sig");
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", format, "verify-approval", "p.toml"])
            .args(["--signature", &signature, "--allowed-signers", "trust"])
            .args(["--principal", principal, "--archive", "arch"])
            .output()
            .expect("run hallpass");
        (
            out.status.code().expect("exit code"),
            String::from_utf8(out.stdout).expect("utf8"),
            String::from_utf8(out.stderr).expect("utf8"),
        )
    }
}

#[test]
fn a_signature_the_archive_did_not_keep_is_not_reported_as_success() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (code, _, _) = env.verify("op", OP, "text");
    assert_eq!(code, 0);

    let (code, text, stderr) = env.verify("owner", OWNER, "text");
    assert_eq!(code, 2, "{text}{stderr}");
    assert!(text.contains(&format!(
        "NOT stored: the archive in arch keeps the record of \"{OP}\""
    )));
    assert!(
        text.contains(".sig and arch/sha256:") && text.contains(".approval aside"),
        "{text}"
    );
    assert!(!text.contains("Retained"), "{text}");
    assert!(stderr.contains("it was kept, and this signature was not stored"));

    let (code, out, _) = env.verify("owner", OWNER, "json");
    assert_eq!(code, 2, "{out}");
    let json: Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(json["provenance"], "signature-not-stored");
    assert_eq!(json["principal"], OWNER);
    assert_eq!(json["approval"]["principal"], OP);
}

#[test]
fn repeating_the_stored_principal_is_still_success() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (code, _, _) = env.verify("op", OP, "text");
    assert_eq!(code, 0);
    let (code, out, _) = env.verify("op", OP, "json");
    assert_eq!(code, 0, "{out}");
    let json: Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(json["provenance"], "signature-recorded");
}

#[test]
fn a_second_signature_by_the_stored_principal_is_success() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (code, _, _) = env.verify("op", OP, "text");
    assert_eq!(code, 0);
    let (code, text, _) = env.verify("op2", OP, "text");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(&format!(
            "the archive keeps an earlier signature record of \"{OP}\""
        )),
        "{text}"
    );
    assert!(!text.contains("NOT stored"), "{text}");
    let (code, out, _) = env.verify("op2", OP, "json");
    assert_eq!(code, 0, "{out}");
    let json: Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(json["provenance"], "signature-recorded");
    assert_eq!(json["approval"]["principal"], OP);
}
