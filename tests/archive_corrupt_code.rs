//! Damaged archive evidence has its own error code, `archive-corrupt`, not
//! `usage`: an archived entry whose bytes no longer match their digest, and a
//! signature record that is damaged. Both still exit 1 and record nothing.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_hallpass");

const PASS: &str = r#"format = 1
id = "archive-corrupt-2026-11"
name = "Example archive"
[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-30T17:00:00Z
revoked = false
[[destination]]
label = "edge"
address = "192.0.2.10"
protocol = "tcp"
ports = [443]
[ceilings]
requests = 5
"#;

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("home")).expect("home");
        fs::create_dir(dir.path().join("arch")).expect("archive");
        fs::set_permissions(dir.path().join("arch"), fs::Permissions::from_mode(0o700))
            .expect("private archive");
        let case = Self { dir };
        case.write("p.toml", PASS);
        case
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write a private file, dated back so that hallpass reads it at once.
    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(SystemTime::now() - Duration::from_secs(10)))
            .expect("backdate");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .current_dir(self.dir.path())
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("TMPDIR", self.dir.path())
            .env_remove("HALLPASS_UNSAFE_TEST_CLOCK")
            .arg("--json")
            .args(args)
            .output()
            .expect("run hallpass")
    }

    /// Archive the pass and return its digest, as `archive` reports it.
    fn archive(&self) -> String {
        let out = self.run(&["archive", "p.toml", "arch"]);
        let reply = json(&out);
        assert_eq!(out.status.code(), Some(0), "{reply}");
        reply["digest"].as_str().expect("digest").to_owned()
    }
}

fn json(out: &Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// The entry for `digest` is `arch/DIGEST`, with its `sha256:` prefix as
/// hallpass names it.
fn entry(case: &Case, digest: &str) -> PathBuf {
    case.path("arch").join(digest)
}

/// Assert the reply is an `archive-corrupt` error that exits 1 and records
/// nothing, and that it names the message `needle`.
fn assert_corrupt(out: &Output, needle: &str) {
    let reply = json(out);
    assert_eq!(out.status.code(), Some(1), "{reply}");
    assert_eq!(reply["result"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], "archive-corrupt", "{reply}");
    assert_eq!(reply["error"]["recording"], "not-recorded", "{reply}");
    let message = reply["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains(needle), "{message}");
}

#[test]
fn an_edited_archived_entry_is_archive_corrupt() {
    let case = Case::new();
    let digest = case.archive();
    let file = entry(&case, &digest);
    // The archived bytes change: the digest no longer matches.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("writable");
    fs::write(&file, PASS.replace("requests = 5", "requests = 500")).expect("edit");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).expect("read only");

    let retrieved = case.run(&["retrieve", "arch", &digest]);
    assert_corrupt(&retrieved, "does not match its digest");

    let archived = case.run(&["archive", "p.toml", "arch"]);
    assert_corrupt(&archived, "does not match its digest");
}

#[test]
fn a_damaged_signature_record_is_archive_corrupt() {
    let case = Case::new();
    let digest = case.archive();
    // No signature was made, so the record is written by hand, damaged.
    case.write(
        &format!("arch/{digest}.approval"),
        "not a signature record\n",
    );

    let archived = case.run(&["archive", "p.toml", "arch"]);
    assert_corrupt(&archived, "is damaged");
}
