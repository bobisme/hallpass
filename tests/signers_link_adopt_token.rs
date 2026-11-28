//! Two decisions of round 19 (bn-37q2).
//!
//! A trusted signers file (`--allowed-signers`) is read only, so it may be a
//! symbolic link, as a Kubernetes `ConfigMap` or `Secret` mount is. The link
//! is resolved, the owner and mode rule applies to the file it reaches, each
//! directory above that file must not be writable by others, and messages
//! name the resolved path.
//!
//! An adoption that carries totals or may lose lines is refused without the
//! token of a reviewed preview; a plain adoption (nothing carried, nothing
//! lost) needs none.
//!
//! The signer tests need OpenSSH `ssh-keygen` and return early without it.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const TO: &str = "192.0.2.10:443/tcp@app.example.com";

fn pass() -> String {
    format!(
        "{}[ceilings]\ncalls = 100\n",
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

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        fs::create_dir(env.path("state")).expect("state");
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

    fn chmod(&self, name: &str, mode: u32) {
        fs::set_permissions(self.path(name), fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn run(&self, state: &str, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path(state))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_SSH_KEYGEN")
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", "json"])
            .args(args)
            .output()
            .expect("run hallpass");
        let text = String::from_utf8(out.stdout).expect("utf8");
        (
            out.status.code().expect("exit code"),
            serde_json::from_str(text.trim()).expect("one JSON object"),
        )
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        self.run("state", args)
    }

    // The signer side.

    /// A pass, its signature and a trusted signers file `trust` in the
    /// directory.
    fn signed() -> Self {
        let env = Self::new();
        let keygen = |args: &[&str]| {
            let out = Command::new("ssh-keygen")
                .args(args)
                .current_dir(env.dir.path())
                .output()
                .expect("ssh-keygen");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "owner"]);
        env.write("p.toml", &pass());
        keygen(&[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner",
            "-n",
            "hallpass-approval-v1",
            "p.toml",
        ]);
        let public = fs::read_to_string(env.path("owner.pub")).expect("public key");
        env.write("trust", &format!("{OWNER} {public}"));
        env
    }

    fn verify(&self, trust: &str) -> (i32, Value) {
        self.json(&[
            "verify-approval",
            "p.toml",
            "--signature",
            "p.toml.sig",
            "--allowed-signers",
            trust,
            "--principal",
            OWNER,
        ])
    }

    // The adoption side.

    fn engagement() -> Self {
        let env = Self::new();
        env.write("p.toml", &pass());
        env
    }

    fn spend(&self, state: &str) {
        let (code, reply) = self.run(state, &["spend", "p.toml", "calls", "--to", TO]);
        assert_eq!(code, 0, "{reply}");
    }

    fn lose_the_ledger(&self) {
        fs::rename(self.path("p.toml.ledger"), self.path("lost.ledger")).expect("lose the ledger");
    }
}

fn message(value: &Value) -> &str {
    value["error"]["message"].as_str().expect("message")
}

fn code_of(value: &Value) -> &str {
    value["error"]["code"].as_str().expect("code")
}

#[test]
fn a_link_to_the_trusted_signers_file_is_followed() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::signed();
    symlink("trust", env.path("trust-link")).expect("link");
    let (code, reply) = env.verify("trust-link");
    assert_eq!(code, 0, "{reply}");
    assert_eq!(reply["result"], "verified", "{reply}");
}

#[test]
fn a_configmap_style_mount_is_followed() {
    if !have_ssh_keygen() {
        return;
    }
    // mnt/trust -> ..data/trust, ..data -> ..2026_11_20, as kubelet lays it out.
    let env = Env::signed();
    let mount = env.path("mnt");
    fs::create_dir_all(mount.join("..2026_11_20")).expect("mount");
    fs::copy(env.path("trust"), mount.join("..2026_11_20/trust")).expect("copy");
    symlink("..2026_11_20", mount.join("..data")).expect("data link");
    symlink("..data/trust", mount.join("trust")).expect("file link");
    let (code, reply) = env.verify("mnt/trust");
    assert_eq!(code, 0, "{reply}");
}

#[test]
fn a_link_to_a_file_others_can_write_is_refused_and_names_the_target() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::signed();
    symlink("trust", env.path("trust-link")).expect("link");
    env.chmod("trust", 0o666);
    let (code, reply) = env.verify("trust-link");
    assert_eq!(
        (code, code_of(&reply)),
        (1, "insecure-permissions"),
        "{reply}"
    );
    let target = fs::canonicalize(env.path("trust")).expect("target");
    let text = message(&reply);
    assert!(text.contains(&target.display().to_string()), "{text}");
    assert!(!text.contains("trust-link"), "{text}");
    assert!(text.contains("chmod 600"), "{text}");
}

#[test]
fn a_link_into_a_directory_others_can_write_is_refused() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::signed();
    let shared = env.path("shared");
    fs::create_dir(&shared).expect("shared");
    fs::copy(env.path("trust"), shared.join("trust")).expect("copy");
    symlink("shared/trust", env.path("trust-link")).expect("link");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).expect("mode");
    let (code, reply) = env.verify("trust-link");
    assert_eq!(
        (code, code_of(&reply)),
        (1, "insecure-permissions"),
        "{reply}"
    );
    let text = message(&reply);
    let dir = fs::canonicalize(&shared).expect("directory");
    assert!(text.contains(&dir.display().to_string()), "{text}");
    assert!(text.contains("chmod go-w"), "{text}");
    // The same directory is no matter for a path that is not a link.
    let (code, reply) = env.verify("shared/trust");
    assert_eq!(code, 0, "{reply}");
    // A sticky directory is allowed, as /tmp is.
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).expect("sticky");
    let (code, reply) = env.verify("trust-link");
    assert_eq!(code, 0, "{reply}");
}

#[test]
fn a_link_that_goes_nowhere_is_refused() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::signed();
    symlink("absent", env.path("dangling")).expect("link");
    let (code, reply) = env.verify("dangling");
    assert_eq!(code, 1, "{reply}");
    assert!(message(&reply).contains("dangling"), "{}", message(&reply));
}

#[test]
fn a_link_in_the_library_is_resolved_the_same_way() {
    let env = Env::new();
    env.write("trust", "owner@example.org ssh-ed25519 AAAA\n");
    symlink("trust", env.path("trust-link")).expect("link");
    assert!(hallpass::open_trusted_signers(&env.path("trust-link")).is_ok());
    env.chmod("trust", 0o664);
    let refused = hallpass::open_trusted_signers(&env.path("trust-link")).expect_err("refused");
    assert_eq!(refused.code(), "insecure-permissions");
    // Other inputs are never read through a link.
    let refused = hallpass::open_input(&env.path("trust-link")).expect_err("a link");
    assert_eq!(refused.code(), "symlink");
}

// A lossy adoption needs the token.

#[test]
fn an_adoption_of_a_lost_ledger_is_refused_without_the_token() {
    let env = Env::engagement();
    env.spend("state");
    env.spend("state");
    env.lose_the_ledger();
    let (code, reply) = env.json(&["adopt", "p.toml", "--reason", "ledger lost"]);
    assert_eq!((code, code_of(&reply)), (1, "usage"), "{reply}");
    let text = message(&reply);
    assert!(text.contains("hallpass adopt p.toml --preview"), "{text}");
    assert!(text.contains("--token"), "{text}");
    assert!(text.contains("nothing was recorded"), "{text}");
    assert!(!env.path("p.toml.ledger").exists(), "no ledger was started");

    let (_, preview) = env.json(&["adopt", "p.toml", "--preview"]);
    let token = preview["token"].as_str().expect("token");
    let (code, reply) = env.json(&[
        "adopt",
        "p.toml",
        "--reason",
        "ledger lost",
        "--token",
        token,
    ]);
    assert_eq!(code, 0, "{reply}");
    assert_eq!(reply["carried"]["calls"], 2, "{reply}");
}

#[test]
fn the_refusal_names_the_flags_the_preview_needs() {
    let env = Env::engagement();
    env.spend("state");
    env.lose_the_ledger();
    let (code, reply) = env.json(&[
        "adopt",
        "p.toml",
        "--reason",
        "ledger lost",
        "--carry-rehearsal",
    ]);
    assert_eq!((code, code_of(&reply)), (1, "usage"), "{reply}");
    assert!(
        message(&reply).contains("hallpass adopt p.toml --preview --carry-rehearsal"),
        "{}",
        message(&reply)
    );
}

#[test]
fn an_adoption_of_a_changed_ledger_is_refused_without_the_token() {
    let env = Env::engagement();
    env.spend("state");
    let older = fs::read(env.path("p.toml.ledger")).expect("ledger");
    env.spend("state");
    fs::write(env.path("p.toml.ledger"), older).expect("rewind");
    let (code, reply) = env.json(&["adopt", "p.toml", "--reason", "restored"]);
    assert_eq!((code, code_of(&reply)), (1, "usage"), "{reply}");
    assert!(message(&reply).contains("--preview"), "{}", message(&reply));
}

#[test]
fn a_plain_adoption_needs_no_token() {
    // The ledger moved to another state directory with its pass: it has no
    // witness there, and the adoption carries nothing and loses nothing.
    let env = Env::engagement();
    env.spend("state");
    fs::create_dir(env.path("other")).expect("other state");
    let (code, reply) = env.run("other", &["adopt", "p.toml", "--reason", "moved here"]);
    assert_eq!(code, 0, "{reply}");
    assert_eq!(reply["case"], "no-witness", "{reply}");
    assert_eq!(reply["carried"], serde_json::json!({}), "{reply}");
}

#[test]
fn a_bad_reason_is_still_named_first() {
    let env = Env::engagement();
    env.spend("state");
    env.lose_the_ledger();
    let (code, reply) = env.json(&["adopt", "p.toml", "--reason", " "]);
    assert_eq!((code, code_of(&reply)), (1, "usage"), "{reply}");
    assert!(
        message(&reply).contains("the reason"),
        "{}",
        message(&reply)
    );
}

#[test]
fn a_stale_token_is_still_refused() {
    let env = Env::engagement();
    env.spend("state");
    env.lose_the_ledger();
    let (_, preview) = env.json(&["adopt", "p.toml", "--preview"]);
    let token = preview["token"].as_str().expect("token").to_owned();
    env.write("p.toml", &pass().replace("calls = 100", "calls = 99"));
    let (code, reply) = env.json(&["adopt", "p.toml", "--reason", "x", "--token", &token]);
    assert_eq!(code, 1, "{reply}");
    assert!(message(&reply).contains("stale"), "{}", message(&reply));
}
