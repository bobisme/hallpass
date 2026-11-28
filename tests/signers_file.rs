//! The trusted signers file follows the pass file's owner and mode rule; a
//! key that the file limits to other namespaces has a reason of its own; and
//! `HALLPASS_SSH_KEYGEN` pins the verifier (bn-11g7).
//!
//! At mode 0666 another local user could add a key under the owner's
//! principal, sign a widened pass, and have `verify-approval` say `verified`
//! and `audit-receipts` say `complete`.
//!
//! Tests that sign need OpenSSH `ssh-keygen` and return early without it.
#![cfg(feature = "cli")]

mod live_spend;

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";

fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// The absolute path of the `ssh-keygen` on PATH.
fn real_ssh_keygen() -> String {
    let out = Command::new("sh")
        .args(["-c", "command -v ssh-keygen"])
        .output()
        .expect("find ssh-keygen");
    String::from_utf8(out.stdout)
        .expect("path")
        .trim()
        .to_owned()
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
        env.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "owner"]);
        env.write("p.toml", &pass());
        env.keygen(&[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner",
            "-n",
            "hallpass-approval-v1",
            "p.toml",
        ]);
        env.signers("trust", "");
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated back so that hallpass reads it at once.
    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
    }

    /// A trusted signers file `name` with the owner's key for OWNER, with
    /// `options` before the key.
    fn signers(&self, name: &str, options: &str) {
        let public = fs::read_to_string(self.path("owner.pub")).expect("public key");
        self.write(name, &format!("{OWNER} {options}{public}"));
    }

    fn chmod(&self, name: &str, mode: u32) {
        fs::set_permissions(self.path(name), fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn keygen(&self, args: &[&str]) {
        let out = Command::new("ssh-keygen")
            .args(args)
            .current_dir(self.dir.path())
            .output()
            .expect("ssh-keygen");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> (i32, Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        command
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_SSH_KEYGEN")
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", "json"])
            .args(args);
        for (key, value) in env {
            command.env(key, value);
        }
        let out = command.output().expect("run hallpass");
        let text = String::from_utf8(out.stdout).expect("utf8");
        (
            out.status.code().expect("exit code"),
            serde_json::from_str(text.trim()).expect("one JSON object"),
        )
    }

    fn verify(&self, signature: &str, trust: &str, env: &[(&str, &Path)]) -> (i32, Value) {
        self.run(
            &[
                "verify-approval",
                "p.toml",
                "--signature",
                signature,
                "--allowed-signers",
                trust,
                "--principal",
                OWNER,
            ],
            env,
        )
    }
}

#[test]
fn a_signers_file_others_can_write_is_refused_by_verify_and_the_audits() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (code, reply) = env.run(
        &[
            "verify-approval",
            "p.toml",
            "--signature",
            "p.toml.sig",
            "--allowed-signers",
            "trust",
            "--principal",
            OWNER,
            "--archive",
            "arch",
        ],
        &[],
    );
    assert_eq!(code, 0, "{reply}");
    live_spend::spend(&env.path("p.toml"), &env.path("state"), WEB, 1, NOW);
    let audit = |command: &str| {
        env.run(
            &[
                command,
                "p.toml",
                "arch",
                "--allowed-signers",
                "trust",
                "--principal",
                OWNER,
            ],
            &[],
        )
    };
    for command in ["audit-receipts", "audit-charges"] {
        let (code, reply) = audit(command);
        assert_eq!((code, &reply["result"]), (0, &"complete".into()), "{reply}");
    }
    // Group write is enough: the rule is the pass file's.
    for mode in [0o666, 0o620] {
        env.chmod("trust", mode);
        let (code, reply) = env.verify("p.toml.sig", "trust", &[]);
        assert_eq!(code, 1, "{reply}");
        assert_eq!(reply["error"]["code"], "insecure-permissions", "{reply}");
        let message = reply["error"]["message"].as_str().expect("message");
        assert!(message.contains("chmod 600"), "{message}");
        assert!(message.contains("add a key"), "{message}");
        for command in ["audit-receipts", "audit-charges"] {
            let (code, reply) = audit(command);
            assert_eq!(code, 1, "{reply}");
            assert_eq!(reply["error"]["code"], "insecure-permissions", "{reply}");
        }
    }
    // Readable by others is fine, as for a pass.
    env.chmod("trust", 0o644);
    let (code, reply) = env.verify("p.toml.sig", "trust", &[]);
    assert_eq!((code, &reply["result"]), (0, &"verified".into()), "{reply}");
}

#[test]
fn a_key_limited_to_another_namespace_says_so() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.signers("file-only", "namespaces=\"file\" ");
    let (code, reply) = env.verify("p.toml.sig", "file-only", &[]);
    assert_eq!(code, 2, "{reply}");
    assert_eq!(
        reply["reason"], "key-not-permitted-for-namespace",
        "{reply}"
    );
    let next = reply["next_step"].as_str().expect("next step");
    assert!(next.contains("namespaces="), "{next}");
    // A line that permits the namespace verifies.
    env.signers("approvals", "namespaces=\"file,hallpass-approval-v1\" ");
    let (code, reply) = env.verify("p.toml.sig", "approvals", &[]);
    assert_eq!((code, &reply["result"]), (0, &"verified".into()), "{reply}");
}

#[test]
fn hallpass_ssh_keygen_pins_the_verifier_past_path() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.write("junk.sig", "garbage\n");
    let bin = env.path("bin");
    fs::create_dir(&bin).expect("bin");
    let fake = bin.join("ssh-keygen");
    fs::write(&fake, "#!/bin/sh\nexit 0\n").expect("fake");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("executable");

    // A fake ssh-keygen first on PATH: hallpass runs what PATH names.
    let (code, reply) = env.verify("junk.sig", "trust", &[("PATH", &bin)]);
    assert_eq!((code, &reply["result"]), (0, &"verified".into()), "{reply}");

    // Pinned, the fake is never run.
    let real = PathBuf::from(real_ssh_keygen());
    let pinned = [("PATH", bin.as_path()), ("HALLPASS_SSH_KEYGEN", &real)];
    let (code, reply) = env.verify("junk.sig", "trust", &pinned);
    assert_eq!(code, 2, "{reply}");
    assert_eq!(reply["reason"], "malformed-signature", "{reply}");
    let (code, reply) = env.verify("p.toml.sig", "trust", &pinned);
    assert_eq!((code, &reply["result"]), (0, &"verified".into()), "{reply}");

    // A relative name would be looked up on PATH again.
    let (code, reply) = env.verify(
        "p.toml.sig",
        "trust",
        &[("HALLPASS_SSH_KEYGEN", Path::new("ssh-keygen"))],
    );
    assert_eq!(code, 1, "{reply}");
    assert_eq!(reply["error"]["code"], "usage", "{reply}");
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(message.contains("absolute path"), "{message}");

    // A pinned path that does not run names the variable.
    let missing = env.path("no-such-ssh-keygen");
    let (code, reply) = env.verify("p.toml.sig", "trust", &[("HALLPASS_SSH_KEYGEN", &missing)]);
    assert_eq!(code, 1, "{reply}");
    let message = reply["error"]["message"].as_str().expect("message");
    assert!(message.contains("HALLPASS_SSH_KEYGEN"), "{message}");
}

#[test]
fn the_reference_caller_refuses_a_signers_file_others_can_write() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.chmod("trust", 0o664);
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_hallpass"))
        .parent()
        .expect("binary directory");
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin_dir.to_path_buf()];
    paths.extend(std::env::split_paths(&path));
    let out = Command::new("python3")
        .args(["-I", "-B"])
        .arg(script)
        .args(["pin", "shift.jsonl", "p.toml", "arch"])
        .args(["--require-signature", OWNER, "--allowed-signers", "trust"])
        .current_dir(env.dir.path())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", env.dir.path())
        .env("XDG_STATE_HOME", env.path("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .output()
        .expect("run the reference caller");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("mode 0664"), "{stderr}");
    assert!(stderr.contains("chmod 600 trust"), "{stderr}");
    assert!(!env.path("shift.jsonl").exists(), "{stderr}");
}
