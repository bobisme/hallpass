#![cfg(feature = "cli")]
//! The reference caller's `handoff` flags a fall from a signed pin to an
//! unsigned one (bn-1kc). Needs OpenSSH `ssh-keygen`; returns early without it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");
const NOW: &str = "2026-11-20T09:00:00Z";
const PASSFILE: &str = "engagement.pass.toml";
const PASS: &str = r#"format = 1
id = "web-2026-11"
name = "Web edge"

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

[ceilings]
requests = 5
"#;

fn write(dir: &Path, name: &str, text: &str) {
    let path = dir.join(name);
    if path.exists() {
        fs::remove_file(&path).expect("replace");
    }
    fs::write(&path, text).expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
    fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|file| file.set_modified(SystemTime::now() - Duration::from_secs(60)))
        .expect("date the file back");
}

fn caller(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reference-caller/caller.py");
    let bin_dir = Path::new(BIN).parent().expect("binary directory");
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin_dir.to_path_buf()];
    paths.extend(std::env::split_paths(&path));
    let home = dir.join("home");
    let out = Command::new("python3")
        .args(["-I", "-B"])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(script)
        .args(args)
        .current_dir(dir)
        .env("PATH", std::env::join_paths(paths).expect("PATH"))
        .env("HOME", &home)
        .env("XDG_STATE_HOME", home.join("state"))
        .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
        .env_remove("HALLPASS_FORMAT")
        .output()
        .expect("run the reference caller");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    let stderr = String::from_utf8(out.stderr).expect("utf8");
    eprintln!("{args:?}\n{stdout}{stderr}");
    (out.status.code(), stdout, stderr)
}

fn setup() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().expect("tempdir");
    for name in ["home", "archive"] {
        let path = tmp.path().join(name);
        fs::create_dir(&path).expect("directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    write(tmp.path(), PASSFILE, PASS);
    tmp
}

fn spend(dir: &Path, unit: &str) {
    let (code, out, err) = caller(
        dir,
        &[
            "run",
            "j.jsonl",
            PASSFILE,
            unit,
            "--rehearsal",
            "--to",
            "192.0.2.10:443/tcp",
            "--charge",
            "requests=1",
            "--duration",
            "60",
        ],
    );
    assert_eq!(code, Some(0), "{out}{err}");
}

#[test]
fn handoff_flags_an_unsigned_pin_after_a_signed_one() {
    let tmp = setup();
    let dir = tmp.path();
    let keygen = |args: &[&str]| {
        Command::new("ssh-keygen")
            .args(args)
            .current_dir(dir)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "owner_key"]) {
        return; // no ssh-keygen
    }
    let public = fs::read_to_string(dir.join("owner_key.pub")).expect("public key");
    write(dir, "signers", &format!("owner@example.org {public}"));
    assert!(keygen(&[
        "-q",
        "-Y",
        "sign",
        "-n",
        "hallpass-approval-v1",
        "-f",
        "owner_key",
        PASSFILE
    ]));
    let (code, out, err) = caller(
        dir,
        &[
            "pin",
            "j.jsonl",
            PASSFILE,
            "archive",
            "--require-signature",
            "owner@example.org",
            "--allowed-signers",
            "signers",
        ],
    );
    assert_eq!(code, Some(0), "{out}{err}");
    spend(dir, "u1");
    let (code, out, _) = caller(dir, &["handoff", "j.jsonl", PASSFILE]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("Nothing needs attention."));

    write(
        dir,
        PASSFILE,
        &PASS.replace("requests = 5", "requests = 50"),
    );
    let (code, _, _) = caller(
        dir,
        &[
            "pin",
            "j.jsonl",
            PASSFILE,
            "archive",
            "--require-signature",
            "owner@example.org",
            "--allowed-signers",
            "signers",
        ],
    );
    assert_ne!(code, Some(0), "a signed pin must refuse the unsigned edit");
    let (code, out, err) = caller(dir, &["pin", "j.jsonl", PASSFILE, "archive"]);
    assert_eq!(code, Some(0), "{out}{err}");
    spend(dir, "u2");
    let (code, out, _) = caller(dir, &["handoff", "j.jsonl", PASSFILE]);
    assert_eq!(code, Some(2), "{out}");
    assert!(
        out.contains("ATTENTION: the last pin (sha256:")
            && out.contains("is not signed, but an earlier pin (sha256:")
            && out.contains("was signed by 'owner@example.org'"),
        "{out}"
    );
    assert!(out.contains("1 need attention."), "{out}");
}

#[test]
fn handoff_is_quiet_for_an_always_unsigned_journal() {
    let tmp = setup();
    let dir = tmp.path();
    for _ in 0..2 {
        let (code, out, err) = caller(dir, &["pin", "j.jsonl", PASSFILE, "archive"]);
        assert_eq!(code, Some(0), "{out}{err}");
    }
    spend(dir, "u1");
    let (code, out, _) = caller(dir, &["handoff", "j.jsonl", PASSFILE]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("Nothing needs attention."));
    assert!(!out.contains("is not signed"));
}
