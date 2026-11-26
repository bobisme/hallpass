#![cfg(feature = "cli")]
//! The reference caller's `handoff` flags a pass that differs from the pinned
//! digest (bn-37z), and `pin --require-signature` says how to recover when the
//! archive keeps another principal's record (bn-1re).
//!
//! The signature test needs OpenSSH `ssh-keygen` and returns early without it.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASSFILE: &str = "engagement.pass.toml";
const TO: &str = "192.0.2.10:443/tcp@app.example.org";
const PASS: &str = r#"format = 1
id = "web-2026-11"
name = "Web edge"
require_target_v1 = true
required_counters_v1 = ["requests", "bytes"]

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
bytes = 100
"#;

struct Shift {
    dir: tempfile::TempDir,
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Shift {
    fn new() -> Self {
        let shift = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        for name in ["home", "approval-archive"] {
            let path = shift.path(name);
            fs::create_dir(&path).expect("directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
        }
        shift.write(PASSFILE, PASS);
        shift
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

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

    fn pin_and_spend(&self) {
        let run = self.caller(&["pin", "shift.jsonl", PASSFILE, "approval-archive"]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        let run = self.caller(&[
            "run",
            "shift.jsonl",
            PASSFILE,
            "s1/u1",
            "--rehearsal",
            "--to",
            TO,
            "--charge",
            "requests=1",
            "--charge",
            "bytes=24",
            "--duration",
            "60",
        ]);
        assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    }
}

#[test]
fn handoff_flags_a_pass_that_differs_from_the_pinned_digest() {
    let shift = Shift::new();
    shift.pin_and_spend();
    let same = shift.caller(&["handoff", "shift.jsonl", PASSFILE]);
    assert_eq!(same.code, Some(0), "{}", same.stderr);
    assert!(same.stdout.contains("Nothing needs attention."));
    assert!(!same.stdout.contains("pinned revision"));

    shift.write(PASSFILE, &PASS.replace("bytes = 100", "bytes = 1000"));
    let changed = shift.caller(&["handoff", "shift.jsonl", PASSFILE]);
    assert_eq!(changed.code, Some(2), "{}", changed.stderr);
    assert!(
        changed
            .stdout
            .contains("ATTENTION: the pass on disk (sha256:")
            && changed.stdout.contains("is not the last pinned revision"),
        "{}",
        changed.stdout
    );
    assert!(
        changed
            .stdout
            .contains("ceilings below come from the file on disk")
    );
    assert!(changed.stdout.contains("1 need attention."));
    assert!(!changed.stdout.contains("Nothing needs attention"));
}

fn ssh(dir: &Path, args: &[&str]) -> bool {
    Command::new("ssh-keygen")
        .args(args)
        .current_dir(dir)
        .output()
        .is_ok_and(|out| out.status.success())
}

#[test]
fn a_pin_refused_for_a_kept_record_of_another_principal_says_how_to_recover() {
    let shift = Shift::new();
    let dir = shift.dir.path();
    let mut trust = String::new();
    for (key, principal) in [
        ("op_key", "op@example.org"),
        ("owner_key", "owner@example.org"),
    ] {
        if !ssh(dir, &["-q", "-t", "ed25519", "-N", "", "-f", key]) {
            return; // no ssh-keygen
        }
        let public = fs::read_to_string(shift.path(&format!("{key}.pub"))).expect("public key");
        let _ = write!(trust, "{principal} {public}");
        assert!(ssh(
            dir,
            &[
                "-q",
                "-Y",
                "sign",
                "-f",
                key,
                "-n",
                "hallpass-approval-v1",
                PASSFILE
            ]
        ));
        fs::rename(
            shift.path(&format!("{PASSFILE}.sig")),
            shift.path(&format!("{key}.sig")),
        )
        .expect("rename");
    }
    shift.write("trusted_signers", &trust);
    let pin = |key: &str, principal: &str| {
        let signature = format!("{key}.sig");
        shift.caller(&[
            "pin",
            "shift.jsonl",
            PASSFILE,
            "approval-archive",
            "--require-signature",
            principal,
            "--allowed-signers",
            "trusted_signers",
            "--signature",
            &signature,
        ])
    };
    let first = pin("op_key", "op@example.org");
    assert_eq!(first.code, Some(0), "{}", first.stderr);
    let second = pin("owner_key", "owner@example.org");
    assert_ne!(second.code, Some(0));
    assert!(
        second
            .stderr
            .contains("no signature record of owner@example.org")
    );
    assert!(second.stderr.contains("op@example.org"));
    assert!(second.stderr.contains("approval-archive/sha256:"));
}
