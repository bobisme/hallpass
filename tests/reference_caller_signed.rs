#![cfg(feature = "cli")]
//! The reference caller's `pin --require-signature PRINCIPAL` (bn-20i).
//!
//! The pin must rest on a signature the caller verified itself with the
//! operator's signers file, not on whatever is on disk. A signed pass is
//! pinned and spent under; a pass edited after signing is refused at pin
//! time, and nothing is journaled.
//!
//! Tests need OpenSSH `ssh-keygen` and return early without it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASSFILE: &str = "engagement.pass.toml";
const OWNER: &str = "owner@example.org";
const TO: &str = "192.0.2.10:443/tcp@app.example.org";
const PASS: &str = r#"format = 1
id = "web-2026-11"
name = "Web edge"
require_target_v1 = true
required_counters_v1 = ["requests"]

[approval]
owner = "Pat Owner"
reference = "email of 2026-11-19"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[ceilings]
requests = 5
"#;

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

struct Shift {
    dir: tempfile::TempDir,
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Shift {
    /// A signed pass, an archive, and a signers file that trusts the key for `OWNER`.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let shift = Self { dir };
        for name in ["home", "approval-archive"] {
            let path = shift.path(name);
            fs::create_dir(&path).expect("directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        shift.write(PASSFILE, PASS);
        shift.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "owner_key"]);
        let public = fs::read_to_string(shift.path("owner_key.pub")).expect("public key");
        shift.write("trusted_signers", &format!("{OWNER} {public}"));
        shift.sign();
        shift
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated back so that hallpass reads it at once.
    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        if path.exists() {
            fs::remove_file(&path).expect("replace");
        }
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        let earlier = SystemTime::now() - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
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

    fn sign(&self) {
        let signature = self.path(&format!("{PASSFILE}.sig"));
        if signature.exists() {
            fs::remove_file(signature).expect("replace the signature");
        }
        self.keygen(&[
            "-q",
            "-Y",
            "sign",
            "-f",
            "owner_key",
            "-n",
            "hallpass-approval-v1",
            PASSFILE,
        ]);
    }

    fn caller(&self, args: &[&str]) -> Run {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
        let bin_dir = Path::new(BIN).parent().expect("binary directory");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![bin_dir.to_path_buf()];
        paths.extend(std::env::split_paths(&path));
        let home = self.path("home");
        let output = Command::new("python3")
            .arg("-I")
            .arg("-B")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg(script)
            .args(args)
            .current_dir(self.dir.path())
            .env("PATH", std::env::join_paths(paths).expect("PATH"))
            .env("HOME", &home)
            .env("XDG_STATE_HOME", home.join("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .output()
            .expect("run the reference caller");
        let run = Run {
            code: output.status.code(),
            stdout: String::from_utf8(output.stdout).expect("utf8"),
            stderr: String::from_utf8(output.stderr).expect("utf8"),
        };
        eprintln!("{args:?}\n{}{}", run.stdout, run.stderr);
        run
    }

    fn pin(&self, extra: &[&str]) -> Run {
        let mut args = vec!["pin", "shift.jsonl", PASSFILE, "approval-archive"];
        args.extend_from_slice(extra);
        self.caller(&args)
    }

    fn signed_pin(&self, principal: &str) -> Run {
        self.pin(&[
            "--require-signature",
            principal,
            "--allowed-signers",
            "trusted_signers",
        ])
    }

    fn journal(&self) -> Vec<Value> {
        fs::read_to_string(self.path("shift.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("journal line"))
            .collect()
    }
}

#[test]
fn a_signed_pin_is_accepted_and_the_unit_runs_under_it() {
    if !have_ssh_keygen() {
        return;
    }
    let shift = Shift::new();
    let run = shift.signed_pin(OWNER);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.starts_with("pinned web-2026-11 sha256:")
            && run
                .stdout
                .trim_end()
                .ends_with(&format!("signed by {OWNER}")),
        "{}",
        run.stdout
    );
    let journal = shift.journal();
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0]["event"], "pin");
    assert_eq!(journal[0]["signed_by"], OWNER);

    let unit = shift.caller(&[
        "run",
        "shift.jsonl",
        PASSFILE,
        "unit-1",
        "--rehearsal",
        "--to",
        TO,
        "--charge",
        "requests=1",
    ]);
    assert_eq!(unit.code, Some(0), "{}", unit.stderr);
    assert!(
        unit.stdout.contains("debit seq 1 verified"),
        "{}",
        unit.stdout
    );
}

#[test]
fn an_unsigned_edit_after_signing_is_refused_at_pin_time() {
    if !have_ssh_keygen() {
        return;
    }
    let shift = Shift::new();
    // The edit keeps every term: only a comment is added. The signature no
    // longer covers the bytes on disk.
    shift.write(PASSFILE, &format!("{PASS}# edited after signing\n"));
    let run = shift.signed_pin(OWNER);
    assert_eq!(run.code, Some(1), "{}", run.stdout);
    assert!(
        run.stderr.contains("is not signed by owner@example.org"),
        "{}",
        run.stderr
    );
    assert_eq!(shift.journal().len(), 0, "nothing is pinned");

    // Plain pin, which asks for no signature, still pins the edited bytes.
    let plain = shift.pin(&[]);
    assert_eq!(plain.code, Some(0), "{}", plain.stderr);
    assert!(shift.journal()[0].get("signed_by").is_none());

    // Signing the new bytes again lets the signed pin through.
    shift.sign();
    let again = shift.signed_pin(OWNER);
    assert_eq!(again.code, Some(0), "{}", again.stderr);
}

#[test]
fn a_signature_by_another_principal_and_a_missing_signers_file_are_refused() {
    if !have_ssh_keygen() {
        return;
    }
    let shift = Shift::new();
    let other = shift.signed_pin("other@example.org");
    assert_eq!(other.code, Some(1), "{}", other.stdout);
    assert!(other.stderr.contains("is not signed by other@example.org"));

    let bare = shift.pin(&["--require-signature", OWNER]);
    assert_eq!(bare.code, Some(1));
    assert!(
        bare.stderr.contains("needs --allowed-signers"),
        "{}",
        bare.stderr
    );

    let stray = shift.pin(&["--allowed-signers", "trusted_signers"]);
    assert_eq!(stray.code, Some(1));
    assert!(stray.stderr.contains("only with --require-signature"));
    assert_eq!(shift.journal().len(), 0);
}
