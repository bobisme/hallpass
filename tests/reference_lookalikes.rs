//! Caller references that look alike (bn-s33): a new reference is ASCII
//! only, and a ledger that holds a look-alike reference still reads, shows
//! it escaped where it is a disguising character, finds it and reconciles it.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use hallpass::Digest;
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const PASS: &str = "format = 1
id = \"look-1\"
name = \"Look-alikes\"
[approval]
owner = \"Owner\"
reference = \"Email\"
operator = \"Operator\"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false
[[destination]]
label = \"web\"
address = \"192.0.2.10\"
protocol = \"tcp\"
ports = 443
[ceilings]
calls = 100
";

/// Each look-alike of the ASCII reference `unit-e`.
const LOOKALIKES: [(&str, &str); 4] = [
    ("precomposed e with acute", "unit-\u{e9}"),
    ("e with a combining acute", "unit-e\u{301}"),
    ("Cyrillic e", "unit-\u{435}"),
    ("U+2010 hyphen", "unit\u{2010}e"),
];

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let earlier = SystemTime::now() - Duration::from_secs(10);
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(earlier))
            .expect("date the file back");
        path.to_str().expect("utf8").to_owned()
    }

    fn run(&self, state: &str, format: &str, args: &[&str]) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env("XDG_STATE_HOME", self.path(state))
            .args(["--format", format])
            .args(args)
            .output()
            .expect("run");
        (
            out.status.code().expect("exit"),
            String::from_utf8(out.stdout).expect("utf8"),
        )
    }

    /// Adopt as the README does: preview, then record with its token.
    fn adopt_reviewed(&self, pass: &str, reason: &str) -> (i32, Value) {
        let (_, preview) = self.json(&["adopt", pass, "--preview"]);
        let token = preview["token"].as_str().expect("token").to_owned();
        self.json(&["adopt", pass, "--reason", reason, "--token", &token])
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let (code, out) = self.run("state", "json", args);
        let value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
        (code, value)
    }
}

#[test]
fn a_new_reference_with_a_non_ascii_character_is_refused() {
    let case = Case::new();
    let pass = case.file("p.toml", PASS);
    for (class, text) in LOOKALIKES {
        let (code, value) = case.json(&[
            "spend",
            &pass,
            "calls",
            "--caller-ref",
            text,
            "--require-new-ref",
        ]);
        assert_eq!(code, 1, "{class}: {value}");
        assert_eq!(value["error"]["code"], "usage", "{class}: {value}");
        let message = value["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("non-ASCII character U+"),
            "{class}: {message}"
        );
        assert!(
            message.contains("nothing was recorded"),
            "{class}: {message}"
        );
    }
    assert!(!PathBuf::from(format!("{pass}.ledger")).exists());
    let (code, value) = case.json(&["spend", &pass, "calls", "--caller-ref", "unit-e"]);
    assert_eq!(code, 0, "{value}");
}

#[test]
fn a_reference_list_with_a_look_alike_is_refused() {
    let case = Case::new();
    let pass = case.file("p.toml", PASS);
    assert_eq!(case.json(&["spend", &pass, "calls"]).0, 0);
    fs::rename(format!("{pass}.ledger"), case.path("lost.ledger")).expect("lose");
    assert_eq!(case.adopt_reviewed(&pass, "lost").0, 0);
    for (class, text) in LOOKALIKES {
        let list = case.file(
            "refs.json",
            &json!({"version": 1, "pass_id": "look-1", "references": ["unit-e", text]}).to_string(),
        );
        let (code, value) = case.json(&[
            "reconcile-references",
            &pass,
            "--adoption",
            "1",
            "--references",
            &list,
            "--reason",
            "from the run log",
        ]);
        assert_eq!(code, 1, "{class}: {value}");
        let message = value["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("non-ASCII character U+"),
            "{class}: {message}"
        );
    }
}

/// Rewrite the ledger so that each `unit-<i>` holds the look-alike `i`, and
/// each `prev` hash follows, as an older hallpass would have written it.
fn rewrite_ledger(pass: &str) {
    let path = format!("{pass}.ledger");
    let text = fs::read_to_string(&path).expect("read");
    let old: Vec<&str> = text.lines().collect();
    let mut new: Vec<String> = Vec::new();
    for (index, line) in old.iter().enumerate() {
        let mut line = (*line).to_owned();
        for (i, (_, text)) in LOOKALIKES.iter().enumerate() {
            line = line.replace(&format!("\"unit-{i}\""), &format!("\"{text}\""));
        }
        if let Some(previous) = index.checked_sub(1) {
            line = line.replace(
                &Digest::of(old[previous].as_bytes()).to_string(),
                &Digest::of(new[previous].as_bytes()).to_string(),
            );
        }
        new.push(line);
    }
    fs::write(&path, format!("{}\n", new.join("\n"))).expect("write");
}

#[test]
fn a_ledger_that_holds_look_alike_references_still_reads_finds_and_reconciles() {
    let case = Case::new();
    let pass = case.file("p.toml", PASS);
    for i in 0..LOOKALIKES.len() {
        let reference = format!("unit-{i}");
        let (code, value) = case.json(&[
            "spend",
            &pass,
            "calls",
            "--to",
            "192.0.2.10:443/tcp",
            "--record-target",
            "--caller-ref",
            &reference,
        ]);
        assert_eq!(code, 0, "{value}");
    }
    rewrite_ledger(&pass);

    let (code, out) = case.run("other", "json", &["ledger", &pass]);
    assert_eq!(code, 0, "{out}");
    let ledger: Value = serde_json::from_str(&out).expect("json");
    let mut units = Vec::new();
    for (i, (class, text)) in LOOKALIKES.iter().enumerate() {
        let entry = &ledger["entries"][i];
        assert_eq!(entry["receipt"]["caller_ref"], *text, "{class}");
        let (code, out) = case.run("other", "json", &["receipt", &pass, "--caller-ref", text]);
        assert_eq!(code, 0, "{class}: {out}");
        units.push(json!({
            "caller_ref": text,
            "digest": entry["digest"],
            "charges": [{"counter": "calls", "n": 1}],
            "targets": [{"target": "192.0.2.10:443/tcp"}],
        }));
        // A new spend cannot record it again.
        let (code, _) = case.run(
            "other",
            "json",
            &["spend", &pass, "calls", "--caller-ref", text],
        );
        assert_eq!(code, 1, "{class}");
    }
    let manifest = case.file(
        "manifest.json",
        &json!({"version": 1, "pass_id": "look-1", "units": units}).to_string(),
    );
    let (_, out) = case.run("other", "json", &["reconcile", &pass, &manifest]);
    for (class, text) in LOOKALIKES {
        assert!(out.contains(text), "{class}: {out}");
    }
}
