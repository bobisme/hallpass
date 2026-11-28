//! The audits verify archived signatures again with the auditor's own trusted
//! signers file instead of trusting the signature records (bn-2ld).
//!
//! A record is a file anyone who can write the archive can write. Copying
//! another revision's `.sig` and writing a record with the digest changed made
//! an unsigned revision audit `complete`. With `--allowed-signers` the audits
//! run `ssh-keygen -Y verify` again; without it they never present a record as
//! verified, and are never `complete`.
//!
//! Tests that sign need OpenSSH `ssh-keygen` and return early without it.
#![cfg(feature = "cli")]

mod live_spend;

use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use hallpass::evidence::{self, AsOf, Recheck, Reverify, SignatureToCheck};
use hallpass::{Digest, Error, StateDir, archive_verified_signature};
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";

fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

/// The lead's unsigned revision: one more comment line.
fn extra() -> String {
    format!("{}# extra\n", pass())
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
    /// `PATH` for hallpass, when a test replaces ssh-keygen.
    path: Option<PathBuf>,
}

impl Env {
    fn new() -> Self {
        let env = Self {
            dir: tempfile::tempdir().expect("tempdir"),
            path: None,
        };
        let archive = env.path("arch");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
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

    fn run(&self, args: &[&str], format: &str) -> (i32, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        command
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", format])
            .args(args);
        if let Some(path) = &self.path {
            command.env("PATH", path);
        }
        let out = command.output().expect("run hallpass");
        (
            out.status.code().expect("exit code"),
            String::from_utf8(out.stdout).expect("utf8"),
        )
    }

    fn json(&self, args: &[&str], code: i32) -> Value {
        let (actual, out) = self.run(args, "json");
        assert_eq!(actual, code, "{args:?}: {out}");
        serde_json::from_str(out.trim()).expect("one JSON object")
    }

    fn text(&self, args: &[&str], code: i32) -> String {
        let (actual, out) = self.run(args, "text");
        assert_eq!(actual, code, "{args:?}: {out}");
        out
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

    /// A key, trusted for `principal` in the file `trust`.
    fn owner(&self, key: &str, principal: &str, trust: &str) {
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", key]);
        self.trust(key, principal, trust);
    }

    /// Trust the existing key `key` for `principal` in the file `trust`.
    fn trust(&self, key: &str, principal: &str, trust: &str) {
        let public = fs::read_to_string(self.path(&format!("{key}.pub"))).expect("public key");
        self.write(trust, &format!("{principal} {public}"));
    }

    /// Sign `file` as `key`, and record the signature with `verify-approval
    /// --archive`. Returns the digest.
    fn sign_and_record(&self, key: &str, file: &str) -> String {
        self.keygen(&[
            "-q",
            "-Y",
            "sign",
            "-f",
            key,
            "-n",
            "hallpass-approval-v1",
            file,
        ]);
        let signature = format!("{file}.sig");
        let reply = self.json(
            &[
                "verify-approval",
                file,
                "--signature",
                &signature,
                "--allowed-signers",
                "trust",
                "--principal",
                OWNER,
                "--archive",
                "arch",
            ],
            0,
        );
        // The archive holds a record; verify-approval verified it, but the
        // archive's provenance says only that a record is there.
        assert_eq!(reply["provenance"], "signature-recorded", "{reply}");
        fs::remove_file(self.path(&signature)).expect("remove the signature");
        text_of(&reply["digest"]).to_owned()
    }

    /// Debit one request to `WEB` at `NOW`, recording the target, without
    /// the test clock, so that an audit can be `complete` (bn-2mm). Returns
    /// the ledger sequence.
    fn spend(&self) -> u64 {
        live_spend::spend(&self.path("p.toml"), &self.path("state"), WEB, 1, NOW)
    }

    fn archive_file(&self, digest: &str, suffix: &str) -> PathBuf {
        self.path(&format!("arch/{digest}{suffix}"))
    }

    /// A replacement `ssh-keygen` in a directory of its own, used as `PATH`.
    fn shim(&mut self, script: &str) {
        let bin = self.path("bin");
        fs::create_dir_all(&bin).expect("bin");
        let shim = bin.join("ssh-keygen");
        fs::write(&shim, script).expect("shim");
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).expect("executable");
        self.path = Some(bin);
    }
}

fn text_of(value: &Value) -> &str {
    value.as_str().expect("string")
}

/// The text with the phrases that say a signature was NOT verified removed.
/// What is left must not say "verified" at all.
fn affirmative(text: &str) -> String {
    text.replace("signature-not-reverified", "")
        .replace("(not re-verified)", "")
        .replace("without a verified signature", "")
        .replace("no verified signature approved", "")
        .replace("approval-unverified", "")
}

/// The lead's repro (bn-2ld): the owner signs D1; an unsigned D2 is archived
/// and spent under; then D1's signature is copied to D2 with a record whose
/// digest is changed. No key is needed.
fn forged(env: &Env) -> (String, String) {
    env.owner("owner", OWNER, "trust");
    env.write("p.toml", &pass());
    let signed = env.sign_and_record("owner", "p.toml");
    assert_eq!(env.spend(), 1);
    env.write("p.toml", &extra());
    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    assert_eq!(archived["provenance"], "unsigned");
    let unsigned = text_of(&archived["digest"]).to_owned();
    assert_eq!(env.spend(), 2);
    let before = env.json(&["audit-charges", "p.toml", "arch"], 2);
    assert_eq!(
        before["gaps"]["approval-unverified"]["digests"][0]["digest"],
        unsigned.as_str(),
        "{before}"
    );

    let record = fs::read_to_string(env.archive_file(&signed, ".approval")).expect("record");
    let copied = fs::read(env.archive_file(&signed, ".sig")).expect("signature");
    let sig = env.archive_file(&unsigned, ".sig");
    fs::write(&sig, copied).expect("copy the signature");
    fs::set_permissions(&sig, fs::Permissions::from_mode(0o600)).expect("private");
    env.write(
        &format!("arch/{unsigned}.approval"),
        &record.replace(&signed, &unsigned),
    );
    (signed, unsigned)
}

#[test]
fn without_allowed_signers_a_forged_record_never_reads_as_verified() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (_, forged_digest) = forged(&env);

    // The record is reported as a record, and the audit is not complete.
    for command in ["audit-receipts", "audit-charges"] {
        let audit = env.json(&[command, "p.toml", "arch"], 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        assert_eq!(
            audit["signatures"],
            json!({"reverified": false, "allowed_signers": null, "principals": [], "as_of": null})
        );
        assert!(
            !audit.to_string().contains("signature-verified"),
            "{command}: {audit}"
        );
        let rows = &audit["revisions"]["details"];
        assert_eq!(rows[1]["digest"], forged_digest.as_str());
        assert_eq!(rows[1]["provenance"], "signature-recorded", "{command}");
        assert_eq!(rows[1]["reason"], Value::Null);
        assert_eq!(audit["revisions"]["unverified"], 2);
        let gap = &audit["gaps"]["signature-not-reverified"];
        assert_eq!(gap["sequences"], json!([1, 2]), "{command}: {audit}");
        assert_eq!(gap["digests"][1]["digest"], forged_digest.as_str());
        assert!(audit["gaps"].get("approval-unverified").is_none());

        let text = env.text(&[command, "p.toml", "arch"], 2);
        assert!(text.contains(" audit incomplete."), "{text}");
        assert!(!text.contains("confirmed"), "{text}");
        assert!(!affirmative(&text).contains("verified"), "{text}");
        assert!(
            text.contains(&format!(
                "  {forged_digest} sequences 2 to 2, 1 line(s): signature record present (not re-verified) for principal \"{OWNER}\""
            )),
            "{text}"
        );
        assert!(
            text.contains("Gap signature-not-reverified 2: ")
                && text.contains("run the audit with --allowed-signers"),
            "{text}"
        );
    }
}

#[test]
fn with_allowed_signers_a_forged_record_fails_reverification_and_names_the_digest() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (signed, forged_digest) = forged(&env);

    // ssh-keygen rejects the copied signature over the other revision's bytes,
    // and the audit names the digest and the reason.
    let trust = Digest::of(&fs::read(env.path("trust")).expect("trust")).to_string();
    let with = ["--allowed-signers", "trust", "--principal", OWNER];
    for command in ["audit-receipts", "audit-charges"] {
        let args = [&[command, "p.toml", "arch"][..], &with[..]].concat();
        let audit = env.json(&args, 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        assert_eq!(
            audit["signatures"],
            json!({"reverified": true, "allowed_signers": trust, "principals": [OWNER], "as_of": "first-use"})
        );
        assert_eq!(
            audit["gaps"]["signature-rejected"]["digests"],
            json!([{"digest": forged_digest, "count": 1, "sequences": [2], "truncated": false, "reason": "bytes-do-not-match"}]),
            "{command}: {audit}"
        );
        assert!(audit["gaps"].get("signature-not-reverified").is_none());
        let rows = &audit["revisions"]["details"];
        assert_eq!(
            (&rows[0]["digest"], &rows[0]["provenance"]),
            (&json!(signed), &json!("signature-verified"))
        );
        assert_eq!(rows[1]["provenance"], "signature-rejected");
        assert_eq!(rows[1]["reason"], "bytes-do-not-match");
        assert_eq!(audit["revisions"]["unverified"], 1);

        let text = env.text(&args, 2);
        assert!(text.contains(" audit incomplete."), "{text}");
        assert!(
            text.contains(&format!(
                "  {forged_digest} 1 line(s). Sequences [2]. Reason bytes-do-not-match: the recorded signature does not match these archived bytes"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  {forged_digest} sequences 2 to 2, 1 line(s): recorded signature failed re-verification for principal \"{OWNER}\" as of {NOW} (bytes-do-not-match)"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  {signed} sequences 1 to 1, 1 line(s): signature re-verified for principal \"{OWNER}\" as of {NOW} with"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "Recorded signatures checked with ssh-keygen against trusted signers {trust}, as of each revision's first use, for principal \"{OWNER}\"."
            )),
            "{text}"
        );
    }
    let text = env.text(
        &[&["audit-receipts", "p.toml", "arch"][..], &with[..]].concat(),
        2,
    );
    let line = |prefix: &str| {
        text.lines()
            .find(|l| l.trim_start().starts_with(prefix))
            .unwrap_or_else(|| panic!("no line {prefix:?}: {text}"))
            .to_owned()
    };
    assert!(
        line("#1 target 1").ends_with("recorded label web confirmed"),
        "{text}"
    );
    assert!(
        line("#2 target 1").ends_with(
            "recorded label web matches the archived revision, whose recorded signature failed re-verification"
        ),
        "{text}"
    );
}

#[test]
fn moving_a_rejected_record_aside_lets_the_owner_record_a_real_signature() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (_, forged_digest) = forged(&env);
    let audit = [
        "audit-charges",
        "p.toml",
        "arch",
        "--allowed-signers",
        "trust",
        "--principal",
        OWNER,
    ];
    assert_eq!(env.json(&audit, 2)["result"], "incomplete");
    // A record is never replaced: a genuine signature is not stored while the
    // forged record is there, and the audit still rejects the forged one.
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
    let kept = env.json(
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
        0,
    );
    assert_eq!(kept["provenance"], "signature-recorded", "{kept}");
    assert!(
        text_of(&kept["warnings"][0]).contains("it was kept"),
        "{kept}"
    );
    fs::remove_file(env.path("p.toml.sig")).expect("remove the signature");
    assert_eq!(
        env.json(&audit, 2)["revisions"]["details"][1]["reason"],
        "bytes-do-not-match"
    );
    let aside = env.path("aside");
    fs::create_dir(&aside).expect("aside");
    for suffix in [".sig", ".approval"] {
        fs::rename(
            env.archive_file(&forged_digest, suffix),
            aside.join(format!("forged{suffix}")),
        )
        .expect("move aside");
    }
    assert_eq!(env.sign_and_record("owner", "p.toml"), forged_digest);
    let audit = env.json(&audit, 0);
    assert_eq!(audit["result"], "complete", "{audit}");
    assert_eq!(
        audit["revisions"]["details"][1]["provenance"],
        "signature-verified"
    );
}

#[test]
fn a_genuinely_signed_engagement_reverifies_clean() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.owner("owner", OWNER, "trust");
    env.write("p.toml", &pass());
    let first = env.sign_and_record("owner", "p.toml");
    env.spend();
    env.spend();
    env.write("p.toml", &extra());
    let second = env.sign_and_record("owner", "p.toml");
    env.spend();

    let pinned = ["--allowed-signers", "trust", "--principal", OWNER];
    for command in ["audit-receipts", "audit-charges"] {
        let all = [&[command, "p.toml", "arch"][..], &pinned[..]].concat();
        let audit = env.json(&all, 0);
        assert_eq!(audit["result"], "complete", "{command}: {audit}");
        assert_eq!(audit["gaps"], json!({}), "{command}");
        assert_eq!(audit["signatures"]["reverified"], true);
        assert_eq!(audit["signatures"]["principals"], json!([OWNER]));
        assert_eq!(audit["signatures"]["as_of"], "first-use");
        let rows = &audit["revisions"]["details"];
        assert_eq!(rows[0]["digest"], first.as_str());
        assert_eq!(rows[1]["digest"], second.as_str());
        for row in rows.as_array().expect("rows") {
            assert_eq!(row["provenance"], "signature-verified", "{audit}");
            assert_eq!(row["reason"], Value::Null);
            assert_eq!(row["verified_for"], OWNER);
            assert_eq!(row["first_time"], NOW);
            assert_eq!(row["verify_time"], NOW);
        }
        assert_eq!(audit["revisions"]["unverified"], 0);
        let text = env.text(&all, 0);
        assert!(text.contains(" audit complete."), "{text}");
        assert!(
            text.contains("Revisions used 2, 0 without a verified signature"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                ", as of each revision's first use, for principal \"{OWNER}\"."
            )),
            "{text}"
        );
    }
    let text = env.text(
        &[&["audit-receipts", "p.toml", "arch"][..], &pinned[..]].concat(),
        0,
    );
    assert_eq!(text.matches(" confirmed\n").count(), 3, "{text}");

    // The same genuine archive without --allowed-signers is not complete:
    // nothing in it shows who wrote the records.
    let audit = env.json(&["audit-charges", "p.toml", "arch"], 2);
    assert_eq!(audit["result"], "incomplete");
    assert_eq!(audit["gaps"].as_object().map(serde_json::Map::len), Some(1));
    assert_eq!(
        audit["gaps"]["signature-not-reverified"]["sequences"],
        json!([1, 2, 3])
    );
}

#[test]
fn a_wrong_trust_file_or_principal_fails_reverification() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.owner("owner", OWNER, "trust");
    env.write("p.toml", &pass());
    let digest = env.sign_and_record("owner", "p.toml");
    env.spend();
    env.owner("stranger", OWNER, "stranger-trust");
    env.trust("owner", "deputy@example.org", "deputy-trust");

    for (args, reason) in [
        (vec!["--allowed-signers", "stranger-trust"], "untrusted-key"),
        (vec!["--allowed-signers", "deputy-trust"], "wrong-principal"),
        (
            vec![
                "--allowed-signers",
                "trust",
                "--principal",
                "deputy@example.org",
            ],
            "wrong-principal",
        ),
    ] {
        for command in ["audit-receipts", "audit-charges"] {
            let all = [&[command, "p.toml", "arch"][..], &args[..]].concat();
            let audit = env.json(&all, 2);
            assert_eq!(audit["result"], "incomplete", "{all:?}: {audit}");
            let gap = &audit["gaps"]["signature-rejected"]["digests"][0];
            assert_eq!(gap["digest"], digest.as_str(), "{all:?}: {audit}");
            assert_eq!(gap["reason"], reason, "{all:?}: {audit}");
            let row = &audit["revisions"]["details"][0];
            assert_eq!(row["provenance"], "signature-rejected");
            assert_eq!(row["reason"], reason);
            let text = env.text(&all, 2);
            assert!(text.contains(&format!("Reason {reason}: ")), "{text}");
            assert!(!text.contains("confirmed"), "{text}");
        }
    }

    // A record whose signature file is not an SSH signature at all.
    env.write("q.toml", &format!("{}# other\n", pass()));
    let archived = env.json(&["archive", "q.toml", "arch"], 0);
    let other: Digest = text_of(&archived["digest"]).parse().expect("digest");
    archive_verified_signature(
        &env.path("arch"),
        other,
        b"signature",
        OWNER,
        Digest::of(b"t"),
    )
    .expect("record");
    env.write("p.toml", &format!("{}# other\n", pass()));
    env.spend();
    let audit = env.json(
        &[
            "audit-charges",
            "p.toml",
            "arch",
            "--allowed-signers",
            "trust",
        ],
        2,
    );
    assert_eq!(
        audit["revisions"]["details"][1]["reason"], "malformed-signature",
        "{audit}"
    );
}

#[test]
fn reverification_needs_a_usable_ssh_keygen_and_a_readable_trust_file() {
    let mut env = Env::new();
    env.write("p.toml", &pass());
    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    let digest: Digest = text_of(&archived["digest"]).parse().expect("digest");
    archive_verified_signature(
        &env.path("arch"),
        digest,
        b"signature",
        OWNER,
        Digest::of(b"t"),
    )
    .expect("record");
    env.spend();
    env.write("trust", &format!("{OWNER} ssh-ed25519 AAAA\n"));

    // A missing or blank input is an error.
    for args in [
        vec!["--allowed-signers", "missing"],
        vec!["--allowed-signers", "trust", "--principal", " "],
        vec!["--principal", OWNER],
    ] {
        for command in ["audit-receipts", "audit-charges"] {
            let all = [&[command, "p.toml", "arch"][..], &args[..]].concat();
            let reply = env.json(&all, 1);
            assert_eq!(reply["result"], "error", "{all:?}: {reply}");
        }
    }

    // No ssh-keygen on PATH: an error, not a pass and not a gap.
    let empty = env.path("empty");
    fs::create_dir(&empty).expect("empty");
    env.path = Some(empty);
    for command in ["audit-receipts", "audit-charges"] {
        let reply = env.json(
            &[command, "p.toml", "arch", "--allowed-signers", "trust"],
            1,
        );
        assert!(
            text_of(&reply["error"]["message"]).contains("cannot run OpenSSH ssh-keygen"),
            "{reply}"
        );
        // Without --allowed-signers nothing runs ssh-keygen.
        let audit = env.json(&[command, "p.toml", "arch"], 2);
        assert_eq!(audit["result"], "incomplete");
    }

    // An ssh-keygen without SSH signature support prints its usage.
    env.shim(
        "#!/bin/sh\necho 'unknown option -- Y' >&2\necho 'usage: ssh-keygen [-q] [-a rounds]' >&2\nexit 1\n",
    );
    for command in ["audit-receipts", "audit-charges"] {
        let reply = env.json(
            &[command, "p.toml", "arch", "--allowed-signers", "trust"],
            1,
        );
        assert!(
            text_of(&reply["error"]["message"]).contains("did not accept `-Y verify`"),
            "{reply}"
        );
    }
    // verify-approval shares the verifier: an unusable one is an error there
    // too, not an `untrusted-key` refusal.
    env.write("p.toml.sig", "not a signature\n");
    let reply = env.json(
        &[
            "verify-approval",
            "p.toml",
            "--signature",
            "p.toml.sig",
            "--allowed-signers",
            "trust",
            "--principal",
            OWNER,
        ],
        1,
    );
    assert!(
        text_of(&reply["error"]["message"]).contains("did not accept `-Y verify`"),
        "{reply}"
    );
}

#[test]
fn a_trust_file_that_changes_during_reverification_does_not_change_the_result() {
    if !have_ssh_keygen() {
        return;
    }
    let mut env = Env::new();
    env.owner("owner", OWNER, "trust");
    env.write("p.toml", &pass());
    env.sign_and_record("owner", "p.toml");
    env.spend();
    let trust = Digest::of(&fs::read(env.path("trust")).expect("trust")).to_string();
    let real = Command::new("sh")
        .args(["-c", "command -v ssh-keygen"])
        .output()
        .expect("find ssh-keygen");
    let real = String::from_utf8(real.stdout).expect("path");
    // The file given trusts no key by the time ssh-keygen runs. ssh-keygen
    // reads a copy of the bytes the audit read first (bn-3c4).
    env.shim(&format!(
        "#!/bin/sh\nprintf '# trusts no key\\n' > '{}'\nexec '{}' \"$@\"\n",
        env.path("trust").display(),
        real.trim()
    ));
    let audit = env.json(
        &[
            "audit-charges",
            "p.toml",
            "arch",
            "--allowed-signers",
            "trust",
            "--principal",
            OWNER,
        ],
        0,
    );
    assert_eq!(audit["result"], "complete", "{audit}");
    assert_eq!(audit["signatures"]["allowed_signers"], trust.as_str());
    assert_eq!(
        fs::read(env.path("trust")).expect("trust"),
        b"# trusts no key\n"
    );
}

/// The library side, without ssh-keygen: the verifier is a closure.
struct Library {
    env: Env,
    digests: Vec<Digest>,
}

impl Library {
    /// Two archived revisions with signature records (not real signatures),
    /// and three lines: two under the first, one under the second.
    fn new() -> Self {
        let env = Env::new();
        let mut digests = Vec::new();
        for (text, lines) in [(pass(), 2), (extra(), 1)] {
            env.write("p.toml", &text);
            let archived = env.json(&["archive", "p.toml", "arch"], 0);
            let digest: Digest = text_of(&archived["digest"]).parse().expect("digest");
            archive_verified_signature(
                &env.path("arch"),
                digest,
                format!("signature {}", digests.len()).as_bytes(),
                OWNER,
                Digest::of(b"t"),
            )
            .expect("record");
            digests.push(digest);
            for _ in 0..lines {
                env.spend();
            }
        }
        Self { env, digests }
    }

    fn charges(&self, reverify: Option<Reverify<'_>>) -> Result<evidence::ChargeAudit, Error> {
        let loaded = hallpass::load(&self.env.path("p.toml")).expect("pass");
        evidence::audit_charges_with(
            &loaded,
            &StateDir::new(self.env.path("state")),
            &self.env.path("arch"),
            reverify,
        )
    }

    fn receipts(&self) -> evidence::ReceiptAudit {
        let loaded = hallpass::load(&self.env.path("p.toml")).expect("pass");
        evidence::audit_receipts(
            &loaded,
            &StateDir::new(self.env.path("state")),
            &self.env.path("arch"),
        )
        .expect("audit")
    }
}

#[test]
fn each_digest_is_verified_once_for_the_principal_required() {
    let lib = Library::new();
    let seen = RefCell::new(Vec::new());
    for required in [&[][..], &["deputy@example.org"][..]] {
        seen.borrow_mut().clear();
        let mut check = |s: &SignatureToCheck<'_>| {
            assert_eq!(Digest::of(s.bytes), s.digest);
            assert_eq!(Digest::of(s.signature), s.approval.signature);
            seen.borrow_mut().push((s.digest, s.principal.to_owned()));
            Ok(Recheck::Verified)
        };
        let audit = lib
            .charges(Some(Reverify {
                allowed_signers: Digest::of(b"auditor"),
                principals: required,
                as_of: AsOf::FirstUse,
                allow_pattern_principals: false,
                check: &mut check,
            }))
            .expect("audit");
        // Without a principal named, a signature that verifies is not
        // enough: its record chose the principal.
        let (result, gaps) = if required.is_empty() {
            ("incomplete", vec!["signer-not-pinned"])
        } else {
            ("complete", vec![])
        };
        assert_eq!(audit.result, result);
        assert_eq!(audit.gaps.keys().copied().collect::<Vec<_>>(), gaps);
        assert!(audit.signatures.reverified);
        assert_eq!(
            audit.signatures.allowed_signers,
            Some(Digest::of(b"auditor").to_string())
        );
        let principal = required.first().copied().unwrap_or(OWNER).to_owned();
        assert_eq!(
            *seen.borrow(),
            vec![
                (lib.digests[0], principal.clone()),
                (lib.digests[1], principal)
            ]
        );
    }
}

#[test]
fn a_rejection_is_a_gap_and_a_verifier_error_ends_the_audit() {
    let lib = Library::new();
    let second = lib.digests[1];
    let mut check = |s: &SignatureToCheck<'_>| {
        Ok(if s.digest == second {
            Recheck::Rejected("untrusted-key")
        } else {
            Recheck::Verified
        })
    };
    let audit = lib
        .charges(Some(Reverify {
            allowed_signers: Digest::of(b"auditor"),
            principals: &[OWNER],
            as_of: AsOf::FirstUse,
            allow_pattern_principals: false,
            check: &mut check,
        }))
        .expect("audit");
    assert_eq!(audit.result, "incomplete");
    let gap = &audit.gaps["signature-rejected"];
    assert_eq!(gap.sequences, vec![3]);
    assert_eq!(gap.digests[0].reason, Some("untrusted-key"));
    assert_eq!(audit.revisions.unverified, 1);
    assert_eq!(audit.revisions.details[1].provenance, "signature-rejected");

    let mut failing = |_: &SignatureToCheck<'_>| -> Result<Recheck, Error> {
        Err(Error::Usage("no verifier".into()))
    };
    let error = lib
        .charges(Some(Reverify {
            allowed_signers: Digest::of(b"auditor"),
            principals: &[OWNER],
            as_of: AsOf::FirstUse,
            allow_pattern_principals: false,
            check: &mut failing,
        }))
        .expect_err("a verifier error is never a pass");
    assert!(error.to_string().contains("no verifier"), "{error}");
}

#[test]
fn a_signature_replaced_while_it_is_verified_does_not_change_the_result() {
    // The verifier gets the signature the audit read with the record, not
    // the file (bn-3c4). A later change to the file is not what it verifies,
    // and not an error of this audit either.
    let lib = Library::new();
    let mut swap = |s: &SignatureToCheck<'_>| {
        let path = lib.env.archive_file(&s.digest.to_string(), ".sig");
        fs::remove_file(&path).expect("remove");
        fs::write(&path, b"another signature").expect("swap");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
        assert_eq!(Digest::of(s.signature), s.approval.signature);
        Ok(Recheck::Verified)
    };
    let audit = lib
        .charges(Some(Reverify {
            allowed_signers: Digest::of(b"auditor"),
            principals: &[OWNER],
            as_of: AsOf::FirstUse,
            allow_pattern_principals: false,
            check: &mut swap,
        }))
        .expect("audit");
    assert_eq!(audit.result, "complete");
    // The next audit reads the replaced files, and refuses them.
    let error = lib.charges(None).expect_err("damaged");
    assert!(error.to_string().contains("damaged"), "{error}");
}

#[test]
fn reading_records_alone_is_never_complete() {
    let lib = Library::new();
    let charges = lib.charges(None).expect("audit");
    assert_eq!(charges.result, "incomplete");
    assert!(!charges.signatures.reverified);
    assert_eq!(
        charges.gaps["signature-not-reverified"].sequences,
        vec![1, 2, 3]
    );
    let receipts = lib.receipts();
    assert_eq!(receipts.result, "incomplete");
    assert_eq!(receipts.corroborated.count, 3);
    for row in &receipts.corroborated.details {
        assert_eq!(row.provenance, "signature-recorded");
    }
    for row in &receipts.revisions.details {
        assert_eq!(row.provenance, "signature-recorded");
        assert!(row.approval.is_some());
    }
}

#[test]
fn the_archive_keeps_calling_a_record_a_record() {
    let env = Env::new();
    env.write("p.toml", &pass());
    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    let digest: Digest = text_of(&archived["digest"]).parse().expect("digest");
    archive_verified_signature(
        &env.path("arch"),
        digest,
        b"signature",
        OWNER,
        Digest::of(b"t"),
    )
    .expect("record");
    let again = env.json(&["archive", "p.toml", "arch"], 0);
    assert_eq!(again["provenance"], "signature-recorded");
    let text = env.text(&["archive", "p.toml", "arch"], 0);
    assert!(!text.contains("verified"), "{text}");
    assert!(
        text.contains(&format!(
            "its signature record for principal \"{OWNER}\" is kept"
        )),
        "{text}"
    );
    assert!(env.archive_file(&digest.to_string(), ".sig").exists());
}
