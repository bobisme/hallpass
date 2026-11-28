//! Which key signed an approval, and how the trusted signers file matched
//! its principal.
//!
//! bn-2xsn: a trusted signers line `*@example.org <intern key>` let the
//! intern's signature verify as owner@example.org, and no reply or record
//! named the key, so an auditor could not tell. Now `verify-approval` and
//! the audits report the key's fingerprint from ssh-keygen, the archive's
//! record keeps it (version 2), and a key that the file holds for the
//! principal only on a pattern line is a warning in `verify-approval` and a
//! `signer-matched-by-pattern` gap in the audits, unless
//! `--allow-pattern-principals` accepts it.
//!
//! Tests that sign need OpenSSH `ssh-keygen` and return early without it.
#![cfg(feature = "cli")]

mod live_spend;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use hallpass::{Digest, archive_verified_signature};
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const INTERN: &str = "intern@example.org";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";
const AUDITS: [&str; 2] = ["audit-receipts", "audit-charges"];
const NS: &str = "hallpass-approval-v1";

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
        env.write("p.toml", &pass());
        env
    }

    fn path(&self, name: &str) -> PathBuf {
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

    fn run(&self, args: &[&str], format: &str) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", format])
            .args(args)
            .output()
            .expect("run hallpass");
        (
            out.status.code().expect("exit code"),
            String::from_utf8(out.stdout).expect("utf8"),
            String::from_utf8(out.stderr).expect("utf8"),
        )
    }

    fn json(&self, args: &[&str], code: i32) -> Value {
        let (actual, out, _) = self.run(args, "json");
        assert_eq!(actual, code, "{args:?}: {out}");
        serde_json::from_str(out.trim()).expect("one JSON object")
    }

    fn text(&self, args: &[&str], code: i32) -> (String, String) {
        let (actual, out, err) = self.run(args, "text");
        assert_eq!(actual, code, "{args:?}: {out}{err}");
        (out, err)
    }

    fn keygen(&self, args: &[&str]) -> String {
        let out = Command::new("ssh-keygen")
            .args(args)
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).expect("utf8")
    }

    /// A new key `name`: its public key line and its fingerprint.
    fn key(&self, name: &str) -> (String, String) {
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-C", name, "-f", name]);
        let public = fs::read_to_string(self.path(&format!("{name}.pub"))).expect("public key");
        let public = public
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let listed = self.keygen(&["-l", "-f", &format!("{name}.pub")]);
        let fingerprint = listed.split_whitespace().nth(1).expect("fingerprint");
        (public, fingerprint.to_owned())
    }

    /// Sign the pass with `key` (a private key, or a certificate's .pub).
    fn sign(&self, key: &str) {
        let sig = self.path("p.toml.sig");
        if sig.exists() {
            fs::remove_file(&sig).expect("remove the old signature");
        }
        self.keygen(&["-q", "-Y", "sign", "-f", key, "-n", NS, "p.toml"]);
    }

    fn verify_args<'a>(principal: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        [
            &[
                "verify-approval",
                "p.toml",
                "--signature",
                "p.toml.sig",
                "--allowed-signers",
                "signers",
                "--principal",
                principal,
            ][..],
            extra,
        ]
        .concat()
    }

    fn spend(&self) {
        live_spend::spend(&self.path("p.toml"), &self.path("state"), WEB, 1, NOW);
    }

    fn record(&self, digest: &str) -> Value {
        let text =
            fs::read_to_string(self.path(&format!("arch/{digest}.approval"))).expect("record");
        serde_json::from_str(text.trim()).expect("record JSON")
    }
}

fn audit_args<'a>(command: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    [
        &[
            command,
            "p.toml",
            "arch",
            "--allowed-signers",
            "signers",
            "--principal",
            OWNER,
        ][..],
        extra,
    ]
    .concat()
}

/// The lead's repro: the intern's key is on a `*@example.org` line.
#[test]
fn a_wildcard_line_is_named_warned_about_and_keeps_the_audit_incomplete() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (intern, intern_key) = env.key("intern");
    env.write(
        "signers",
        &format!("*@example.org namespaces=\"{NS}\" {intern}\n"),
    );
    env.sign("intern");

    let reply = env.json(&Env::verify_args(OWNER, &["--archive", "arch"]), 0);
    assert_eq!(reply["result"], "verified", "{reply}");
    assert_eq!(reply["key"], intern_key.as_str());
    assert_eq!(reply["principal_match"], "pattern");
    let warning = reply["warnings"][0].as_str().expect("a warning");
    assert!(warning.contains(&intern_key), "{warning}");
    assert!(
        warning.contains("only on a line whose principals use a pattern"),
        "{warning}"
    );
    let digest = reply["digest"].as_str().expect("digest").to_owned();
    assert_eq!(reply["approval"]["key"], intern_key.as_str());
    let record = env.record(&digest);
    assert_eq!(record["version"], 2);
    assert_eq!(record["key"], intern_key.as_str());

    let (out, err) = env.text(&Env::verify_args(OWNER, &[]), 0);
    assert!(
        out.starts_with(&format!(
            "Verified signature from \"{OWNER}\" over pass review-example ({digest}), made with key {intern_key}."
        )),
        "{out}"
    );
    assert!(
        err.contains("hallpass: warning: the trusted signers file holds key"),
        "{err}"
    );

    // Accepted on purpose: no warning.
    let quiet = env.json(&Env::verify_args(OWNER, &["--allow-pattern-principals"]), 0);
    assert_eq!(quiet["warnings"], json!([]), "{quiet}");
    assert_eq!(quiet["principal_match"], "pattern");

    env.spend();
    for command in AUDITS {
        let audit = env.json(&audit_args(command, &[]), 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        let gap = &audit["gaps"]["signer-matched-by-pattern"]["digests"][0];
        assert_eq!(gap["digest"], digest.as_str(), "{audit}");
        assert_eq!(gap["principal"], OWNER);
        assert_eq!(gap["signer_key"], intern_key.as_str());
        let row = &audit["revisions"]["details"][0];
        assert_eq!(row["provenance"], "signature-verified");
        assert_eq!(row["signer_key"], intern_key.as_str());
        assert_eq!(row["principal_match"], "pattern");
        let (text, _) = env.text(&audit_args(command, &[]), 2);
        assert!(
            text.contains(&format!(
                "with the trusted signers you supplied, by key {intern_key}, only through a pattern principal"
            )),
            "{text}"
        );
        assert!(text.contains("Gap signer-matched-by-pattern 1:"), "{text}");
        assert!(!text.contains("confirmed"), "{text}");

        let allowed = env.json(&audit_args(command, &["--allow-pattern-principals"]), 0);
        assert_eq!(allowed["result"], "complete", "{command}: {allowed}");
        assert_eq!(
            allowed["revisions"]["details"][0]["signer_key"],
            intern_key.as_str()
        );
    }
}

/// A line that names the owner, beside a pattern line for the intern: the
/// owner's signature is `named`, and the intern's is still a `pattern`.
#[test]
fn a_named_line_is_named_even_beside_a_pattern_line() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (owner, owner_key) = env.key("owner");
    let (intern, _) = env.key("intern");
    env.write(
        "signers",
        &format!(
            "# team\n\"{OWNER}\" {owner}\n*@example.org,!{OWNER} {intern}\n{INTERN},bob@example.org {intern}\n"
        ),
    );
    env.sign("owner");
    let reply = env.json(&Env::verify_args(OWNER, &["--archive", "arch"]), 0);
    assert_eq!(reply["key"], owner_key.as_str(), "{reply}");
    assert_eq!(reply["principal_match"], "named");
    assert_eq!(reply["warnings"], json!([]));
    env.spend();
    for command in AUDITS {
        let audit = env.json(&audit_args(command, &[]), 0);
        assert_eq!(audit["result"], "complete", "{command}: {audit}");
        assert_eq!(
            audit["revisions"]["details"][0]["signer_key"],
            owner_key.as_str()
        );
        assert_eq!(audit["revisions"]["details"][0]["principal_match"], "named");
    }

    // A list of names without patterns names each of them.
    env.sign("intern");
    let listed = env.json(&Env::verify_args("bob@example.org", &[]), 0);
    assert_eq!(listed["principal_match"], "named", "{listed}");
    // The negation keeps the intern's key from verifying as the owner.
    let refused = env.json(&Env::verify_args(OWNER, &[]), 2);
    assert_eq!(refused["result"], "unverified", "{refused}");
    // Another example.org principal matches only the pattern.
    let pattern = env.json(&Env::verify_args("carol@example.org", &[]), 0);
    assert_eq!(pattern["principal_match"], "pattern", "{pattern}");
}

/// A certificate on a `cert-authority` line: the authority named the
/// principal in the certificate, so it is accepted without a warning.
#[test]
fn a_certificate_names_its_key_and_needs_the_principal_in_it() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (ca, _) = env.key("ca");
    let (_, owner_key) = env.key("owner");
    env.keygen(&[
        "-q",
        "-s",
        "ca",
        "-I",
        "owner-cert",
        "-n",
        OWNER,
        "owner.pub",
    ]);
    env.write(
        "signers",
        &format!("*@example.org cert-authority,namespaces=\"{NS}\" {ca}\n"),
    );
    env.sign("owner-cert.pub");
    let reply = env.json(&Env::verify_args(OWNER, &["--archive", "arch"]), 0);
    assert_eq!(reply["key"], owner_key.as_str(), "{reply}");
    assert_eq!(reply["principal_match"], "certificate");
    assert_eq!(reply["warnings"], json!([]));
    let (out, _) = env.text(&Env::verify_args(OWNER, &[]), 0);
    assert!(
        out.contains(&format!("made with certificate key {owner_key}.")),
        "{out}"
    );
    // The certificate does not name the intern.
    let other = env.json(&Env::verify_args(INTERN, &[]), 2);
    assert_eq!(other["result"], "unverified", "{other}");
    env.spend();
    for command in AUDITS {
        let audit = env.json(&audit_args(command, &[]), 0);
        assert_eq!(audit["result"], "complete", "{command}: {audit}");
        assert_eq!(
            audit["revisions"]["details"][0]["principal_match"],
            "certificate"
        );
    }
}

#[test]
fn signer_key_requires_that_key() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (owner, owner_key) = env.key("owner");
    let (_, other_key) = env.key("other");
    env.write("signers", &format!("{OWNER} {owner}\n"));
    env.sign("owner");
    let reply = env.json(&Env::verify_args(OWNER, &["--signer-key", &owner_key]), 0);
    assert_eq!(reply["key"], owner_key.as_str(), "{reply}");

    let wrong = env.json(
        &Env::verify_args(OWNER, &["--signer-key", &other_key, "--archive", "arch"]),
        2,
    );
    assert_eq!(wrong["result"], "unverified", "{wrong}");
    assert_eq!(wrong["reason"], "signer-key-mismatch");
    assert_eq!(wrong["key"], owner_key.as_str());
    // Nothing was archived.
    assert_eq!(fs::read_dir(env.path("arch")).expect("archive").count(), 0);
    let (out, _) = env.text(&Env::verify_args(OWNER, &["--signer-key", &other_key]), 2);
    assert!(
        out.contains(&format!("(it was made with key {owner_key})")),
        "{out}"
    );

    let (code, _, err) = env.run(&Env::verify_args(OWNER, &["--signer-key", "owner"]), "text");
    assert_eq!(code, 1);
    assert!(
        err.contains("--signer-key is \"owner\", not a key fingerprint"),
        "{err}"
    );
}

/// A version 1 record, which an older hallpass wrote, still reads: its key
/// is unknown, and the audit reports the key from its own verification.
/// A record whose key is not the key that made the signature is rejected.
#[test]
fn older_records_read_and_a_forged_key_is_rejected() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (owner, owner_key) = env.key("owner");
    let (_, other_key) = env.key("other");
    env.write("signers", &format!("{OWNER} {owner}\n"));
    env.sign("owner");
    let bytes = fs::read(env.path("p.toml")).expect("pass");
    let digest = hallpass::archive_pass_bytes(&bytes, &env.path("arch")).expect("archive");
    let signature = fs::read(env.path("p.toml.sig")).expect("signature");
    let trust = Digest::of(&fs::read(env.path("signers")).expect("signers"));
    archive_verified_signature(&env.path("arch"), digest, &signature, OWNER, trust)
        .expect("an older record");
    let digest = digest.to_string();
    assert_eq!(env.record(&digest)["version"], 1);
    assert_eq!(env.record(&digest).get("key"), None);

    // verify-approval keeps the older record of the same signature, and
    // says nothing about it.
    let again = env.json(&Env::verify_args(OWNER, &["--archive", "arch"]), 0);
    assert_eq!(again["key"], owner_key.as_str(), "{again}");
    assert_eq!(again["approval"]["key"], Value::Null);
    assert_eq!(again["warnings"], json!([]));

    env.spend();
    let audit = env.json(&audit_args("audit-receipts", &[]), 0);
    assert_eq!(audit["result"], "complete", "{audit}");
    let row = &audit["revisions"]["details"][0];
    assert_eq!(row["approval"]["key"], Value::Null);
    assert_eq!(row["signer_key"], owner_key.as_str());
    let (text, _) = env.text(&["audit-receipts", "p.toml", "arch"], 2);
    assert!(text.contains("recorded with trusted signers"), "{text}");
    assert!(text.contains("and an unknown key"), "{text}");

    // Rewrite the record to name another key.
    let path = env.path(&format!("arch/{digest}.approval"));
    let mut record = env.record(&digest);
    record["version"] = json!(2);
    record["key"] = json!(other_key);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("writable");
    fs::write(&path, format!("{record}\n")).expect("forge");
    let forged = env.json(&audit_args("audit-receipts", &[]), 2);
    assert_eq!(
        forged["revisions"]["details"][0]["reason"], "recorded-key-mismatch",
        "{forged}"
    );
    let (text, _) = env.text(&audit_args("audit-receipts", &[]), 2);
    assert!(text.contains("its record names another key"), "{text}");

    // A version 2 record without a key, or a version 1 record with one, is damaged.
    for (version, key) in [(json!(2), Value::Null), (json!(1), json!(owner_key))] {
        record["version"] = version;
        match key {
            Value::Null => {
                record.as_object_mut().expect("object").remove("key");
            }
            key => record["key"] = key,
        }
        fs::write(&path, format!("{record}\n")).expect("damage");
        let damaged = env.json(&["audit-receipts", "p.toml", "arch"], 1);
        assert_eq!(damaged["error"]["code"], "archive-corrupt", "{damaged}");
    }
}
