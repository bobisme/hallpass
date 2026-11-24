//! The audits tell revisions an owner signed from revisions stored without a
//! signature (bn-da6), name the revision of every revision gap, and say what a
//! spend without a recorded target leaves out (bn-5zp).
//!
//! Tests that sign need OpenSSH `ssh-keygen` and return early without it.
#![cfg(feature = "cli")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hallpass::{
    ArchivedSignature, Digest, Provenance, SpendRequest, StateDir, archive_pass_bytes,
    archive_provenance, archive_verified_signature, evidence, spend_in, time::macros::datetime,
};
use serde_json::{Value, json};

const NOW: &str = "2026-11-20T09:00:00Z";
const OWNER: &str = "owner@example.org";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";
const EXTRA: &str = "192.0.2.99:443/tcp";
const TRUST: &str = "--allowed-signers";

fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

/// The evaluator's unapproved revision: one more destination.
fn widened() -> String {
    format!(
        "{}\n[[destination]]\nlabel = \"extra\"\naddress = \"192.0.2.99\"\nprotocol = \"tcp\"\nports = 443\n",
        pass()
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
        env
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, text: &str) {
        let path = self.path(name);
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
    }

    fn run(&self, args: &[&str], format: &str) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", NOW)
            .env_remove("FORMAT")
            .env_remove("HALLPASS_FORMAT")
            .args(["--format", format])
            .args(args)
            .output()
            .expect("run hallpass");
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

    /// A key for `principal`, trusted in the file `trust`.
    fn owner(&self, key: &str, principal: &str, trust: &str) {
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", key]);
        let public = fs::read_to_string(self.path(&format!("{key}.pub"))).expect("public key");
        fs::write(self.path(trust), format!("{principal} {public}")).expect("trust");
    }

    fn sign(&self, key: &str, file: &str) {
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
    }

    fn verify(&self, file: &str, trust: &str, principal: &str) -> Value {
        let signature = format!("{file}.sig");
        self.json(
            &[
                "verify-approval",
                file,
                "--signature",
                &signature,
                "--allowed-signers",
                trust,
                "--principal",
                principal,
                "--archive",
                "arch",
            ],
            0,
        )
    }

    fn spend(&self, n: &str, to: &str) -> Value {
        self.json(
            &[
                "spend",
                "p.toml",
                "--charge",
                &format!("requests={n}"),
                "--to",
                to,
                "--record-target",
            ],
            0,
        )
    }

    fn archived(&self, digest: &str, suffix: &str) -> Vec<u8> {
        fs::read(self.path(&format!("arch/{digest}{suffix}"))).expect("archive file")
    }
}

fn text_of(value: &Value) -> &str {
    value.as_str().expect("string")
}

/// The evaluator's demo: the owner signs, the operator archives an unsigned
/// revision with `archive`, spends under it and restores the signed bytes.
fn evaluator_scenario(env: &Env) -> (String, String) {
    env.owner("owner", OWNER, "trust");
    env.write("p.toml", &pass());
    env.sign("owner", "p.toml");
    let verified = env.verify("p.toml", "trust", OWNER);
    assert_eq!(verified["provenance"], "signature-recorded", "{verified}");
    assert_eq!(verified["approval"]["principal"], OWNER);
    let signed = text_of(&verified["digest"]).to_owned();
    assert_eq!(env.spend("1", WEB)["seq"], 1);

    env.write("p.toml", &widened());
    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    assert_eq!(archived["provenance"], "unsigned", "{archived}");
    assert!(archived["approval"].is_null());
    let unsigned = text_of(&archived["digest"]).to_owned();
    assert_eq!(env.spend("5", EXTRA)["seq"], 2);

    env.write("p.toml", &pass());
    // Archiving signed bytes again keeps their signature record.
    let again = env.json(&["archive", "p.toml", "arch"], 0);
    assert_eq!(again["digest"], signed.as_str());
    assert_eq!(again["provenance"], "signature-recorded", "{again}");
    assert_eq!(again["approval"]["principal"], OWNER);
    (signed, unsigned)
}

#[test]
fn the_evaluator_scenario_names_the_unapproved_revision_and_is_not_complete() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (signed, unsigned) = evaluator_scenario(&env);

    // The auditor verifies the recorded signatures again with their own
    // trusted signers file (bn-2ld).
    let receipts = env.json(&["audit-receipts", "p.toml", "arch", TRUST, "trust"], 2);
    assert_eq!(receipts["result"], "incomplete", "{receipts}");
    assert_eq!(receipts["mismatches"]["count"], 0);
    let gap = &receipts["gaps"]["approval-unverified"];
    assert_eq!(gap["count"], 1, "{receipts}");
    assert_eq!(gap["sequences"], json!([2]));
    assert_eq!(
        gap["digests"],
        json!([{"digest": unsigned, "count": 1, "sequences": [2], "truncated": false}])
    );
    let endpoints = &receipts["corroborated"]["details"];
    assert_eq!(endpoints[0]["provenance"], "signature-verified");
    assert_eq!(endpoints[1]["provenance"], "unsigned");
    assert_eq!(endpoints[1]["label"], "extra");
    let revisions = &receipts["revisions"];
    assert_eq!(revisions["count"], 2);
    assert_eq!(revisions["unverified"], 1);
    let rows = &revisions["details"];
    assert_eq!(rows[0]["digest"], signed.as_str());
    assert_eq!(rows[0]["provenance"], "signature-verified");
    assert_eq!(rows[0]["approval"]["principal"], OWNER);
    assert_eq!(rows[0]["approval"]["namespace"], "hallpass-approval-v1");
    assert_eq!(
        rows[0]["approval"]["allowed_signers"],
        Digest::of(&fs::read(env.path("trust")).expect("trust")).to_string()
    );
    assert_eq!(
        rows[0]["approval"]["signature"],
        Digest::of(&fs::read(env.path("p.toml.sig")).expect("sig")).to_string()
    );
    assert_eq!(
        (&rows[1]["digest"], &rows[1]["provenance"]),
        (&json!(unsigned), &json!("unsigned"))
    );
    assert_eq!(
        (&rows[1]["first_seq"], &rows[1]["last_seq"]),
        (&json!(2), &json!(2))
    );
    assert!(rows[1]["approval"].is_null());

    let text = env.text(&["audit-receipts", "p.toml", "arch", TRUST, "trust"], 2);
    assert!(text.starts_with("Receipt audit incomplete."), "{text}");
    assert!(!text.contains("audit complete"), "{text}");
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
    let second = line("#2 target 1");
    assert!(!second.contains("confirmed"), "{text}");
    assert!(
        second.ends_with("matches the archived revision, which no verified signature approved"),
        "{text}"
    );
    assert!(text.contains("Gap approval-unverified 1: "), "{text}");
    assert!(
        text.contains(&format!("  {unsigned} 1 line(s). Sequences [2]")),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "  {unsigned} sequences 2 to 2, 1 line(s): archived with no signature record"
        )),
        "{text}"
    );

    let charges = env.json(&["audit-charges", "p.toml", "arch", TRUST, "trust"], 2);
    assert_eq!(charges["result"], "incomplete", "{charges}");
    assert_eq!(charges["checked_debits"], 2);
    assert_eq!(
        charges["gaps"]["approval-unverified"]["digests"][0]["digest"],
        unsigned.as_str()
    );
    assert_eq!(charges["revisions"], receipts["revisions"]);
    let text = env.text(&["audit-charges", "p.toml", "arch", TRUST, "trust"], 2);
    assert!(text.starts_with("Charge audit incomplete."), "{text}");
    assert!(!text.contains("audit complete"), "{text}");
}

#[test]
fn signing_the_revision_later_upgrades_it_and_a_signed_engagement_audits_clean() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (signed, unsigned) = evaluator_scenario(&env);
    // The owner approves the wider revision after all.
    env.write("wider.toml", &widened());
    env.sign("owner", "wider.toml");
    assert_eq!(
        env.verify("wider.toml", "trust", OWNER)["digest"],
        unsigned.as_str()
    );

    let receipts = env.json(&["audit-receipts", "p.toml", "arch", TRUST, "trust"], 0);
    assert_eq!(receipts["result"], "complete", "{receipts}");
    assert_eq!(receipts["gaps"], json!({}));
    assert_eq!(receipts["revisions"]["unverified"], 0);
    let text = env.text(&["audit-receipts", "p.toml", "arch", TRUST, "trust"], 0);
    assert!(text.starts_with("Receipt audit complete."), "{text}");
    assert_eq!(text.matches(" confirmed\n").count(), 2, "{text}");
    assert!(
        text.contains("Revisions used 2, 0 without a verified signature"),
        "{text}"
    );
    let charges = env.json(&["audit-charges", "p.toml", "arch", TRUST, "trust"], 0);
    assert_eq!(charges["result"], "complete", "{charges}");
    let text = env.text(&["audit-charges", "p.toml", "arch", TRUST, "trust"], 0);
    assert!(text.starts_with("Charge audit complete."), "{text}");
    assert!(text.contains("Gaps none"), "{text}");

    // An auditor can also check each kept signature by hand with their own
    // trust file, as docs/EVIDENCE.md shows.
    for digest in [&signed, &unsigned] {
        let bytes = fs::File::open(env.path(&format!("arch/{digest}"))).expect("bytes");
        let status = Command::new("ssh-keygen")
            .current_dir(env.dir.path())
            .args(["-Y", "verify", "-n", "hallpass-approval-v1", "-I", OWNER])
            .args(["-f", "trust", "-s"])
            .arg(format!("arch/{digest}.sig"))
            .stdin(bytes)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("ssh-keygen");
        assert!(status.success(), "{digest}");
    }
}

#[test]
fn a_signature_record_is_never_replaced_or_downgraded() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.owner("owner", OWNER, "trust");
    env.owner("deputy", "deputy@example.org", "deputy-trust");
    env.write("p.toml", &pass());
    env.sign("owner", "p.toml");
    let first = env.verify("p.toml", "trust", OWNER);
    let digest = text_of(&first["digest"]).to_owned();
    assert_eq!(first["warnings"], json!([]));
    let kept = (
        env.archived(&digest, ".approval"),
        env.archived(&digest, ".sig"),
    );
    assert_eq!(kept.1, fs::read(env.path("p.toml.sig")).expect("sig"));

    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    assert_eq!(archived["provenance"], "signature-recorded");
    let text = env.text(&["archive", "p.toml", "arch"], 0);
    assert!(
        text.contains("its signature record for principal \"owner@example.org\" is kept"),
        "{text}"
    );

    // A second, different verified signature over the same bytes is not stored.
    env.write("copy.toml", &pass());
    env.sign("deputy", "copy.toml");
    let second = env.verify("copy.toml", "deputy-trust", "deputy@example.org");
    assert_eq!(second["digest"], digest.as_str());
    assert_eq!(second["approval"]["principal"], OWNER, "{second}");
    assert!(
        text_of(&second["warnings"][0]).contains("it was kept"),
        "{second}"
    );
    // The same verification again changes nothing and warns of nothing.
    assert_eq!(env.verify("p.toml", "trust", OWNER)["warnings"], json!([]));
    assert_eq!(
        (
            env.archived(&digest, ".approval"),
            env.archived(&digest, ".sig")
        ),
        kept
    );
}

#[test]
fn verify_approval_records_nothing_when_its_inputs_change_during_verification() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    env.owner("owner", OWNER, "trust");
    env.write("p.toml", &pass());
    env.sign("owner", "p.toml");
    let real = Command::new("sh")
        .args(["-c", "command -v ssh-keygen"])
        .output()
        .expect("find ssh-keygen");
    let real = String::from_utf8(real.stdout).expect("path");
    let bin = env.path("bin");
    fs::create_dir(&bin).expect("bin");
    let shim = bin.join("ssh-keygen");
    fs::write(
        &shim,
        "#!/bin/sh\nprintf '# edited\\n' >> \"$HALLPASS_TEST_TRUST\"\nexec \"$HALLPASS_TEST_REAL\" \"$@\"\n",
    )
    .expect("shim");
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).expect("executable");
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .current_dir(env.dir.path())
        .env("HOME", env.dir.path())
        .env("PATH", &bin)
        .env("HALLPASS_TEST_TRUST", env.path("trust"))
        .env("HALLPASS_TEST_REAL", real.trim())
        .args([
            "--json",
            "verify-approval",
            "p.toml",
            "--signature",
            "p.toml.sig",
        ])
        .args([
            "--allowed-signers",
            "trust",
            "--principal",
            OWNER,
            "--archive",
            "arch",
        ])
        .output()
        .expect("verify");
    let reply: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(out.status.code(), Some(1), "{reply}");
    assert!(
        text_of(&reply["error"]["message"]).contains("changed while it was verified"),
        "{reply}"
    );
    assert_eq!(fs::read_dir(env.path("arch")).expect("archive").count(), 0);
}

#[test]
fn an_archive_without_records_reads_as_unsigned() {
    // Older versions wrote only the bytes, as `archive` still does.
    let env = Env::new();
    env.write("p.toml", &pass());
    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    assert_eq!(archived["provenance"], "unsigned");
    let text = env.text(&["archive", "p.toml", "arch"], 0);
    assert!(
        text.contains("without a signature record (verify-approval --archive records one)"),
        "{text}"
    );
    env.spend("1", WEB);
    let audit = env.json(&["audit-receipts", "p.toml", "arch"], 2);
    assert_eq!(audit["result"], "incomplete");
    assert_eq!(audit["corroborated"]["count"], 1);
    assert_eq!(
        audit["gaps"]["approval-unverified"]["sequences"],
        json!([1])
    );
    assert_eq!(audit["revisions"]["details"][0]["provenance"], "unsigned");
    assert_eq!(
        env.json(&["audit-charges", "p.toml", "arch"], 2)["result"],
        "incomplete"
    );
}

#[test]
fn signature_records_are_kept_once_and_checked_like_the_bytes() {
    let env = Env::new();
    let archive = env.path("arch");
    let bytes = pass();
    let digest = Digest::of(bytes.as_bytes());
    let trust = Digest::of(b"trusted signers");
    let record = |signature: &[u8], principal: &str| {
        archive_verified_signature(&archive, digest, signature, principal, trust)
    };
    assert_eq!(
        archive_provenance(&archive, digest).expect("lookup"),
        Provenance::Missing
    );
    assert!(record(b"signature", OWNER).is_err(), "bytes come first");
    archive_pass_bytes(bytes.as_bytes(), &archive).expect("archive");
    assert_eq!(
        archive_provenance(&archive, digest).expect("lookup"),
        Provenance::Unsigned
    );
    let ArchivedSignature::Recorded(approval) = record(b"signature", OWNER).expect("record") else {
        panic!("not recorded");
    };
    assert_eq!(approval.signature, Digest::of(b"signature"));
    assert_eq!(
        archive_provenance(&archive, digest).expect("lookup"),
        Provenance::SignatureRecorded(approval.clone())
    );
    assert_eq!(
        record(b"signature", OWNER).expect("again"),
        ArchivedSignature::Recorded(approval.clone())
    );
    assert_eq!(
        record(b"other signature", "deputy@example.org").expect("second"),
        ArchivedSignature::KeptEarlier(approval.clone())
    );
    assert!(record(b"signature", "two\nlines").is_err());

    let sig = env.path(&format!("arch/{digest}.sig"));
    let rec = env.path(&format!("arch/{digest}.approval"));
    let line = fs::read(&rec).expect("record");
    let damage = |path: &Path, content: &[u8], mode: u32| {
        fs::remove_file(path).expect("remove");
        fs::write(path, content).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
    };
    // A record that the audit cannot read is an error, never "unsigned". An
    // intact one is a record, not a verified signature (bn-2ld): without
    // --allowed-signers the audit is incomplete.
    let audit = |code| {
        env.write("p.toml", &bytes);
        env.json(&["audit-charges", "p.toml", "arch"], code)
    };
    env.write("p.toml", &bytes);
    env.spend("1", WEB);
    let intact = audit(2);
    assert_eq!(intact["result"], "incomplete");
    assert_eq!(
        intact["revisions"]["details"][0]["provenance"],
        "signature-recorded"
    );
    assert_eq!(
        intact["gaps"]["signature-not-reverified"]["sequences"],
        json!([1])
    );
    damage(&sig, b"another signature", 0o600);
    assert!(archive_provenance(&archive, digest).is_err());
    assert!(text_of(&audit(1)["error"]["message"]).contains("damaged"));
    damage(&sig, b"signature", 0o600);
    damage(&rec, &line, 0o644);
    assert_eq!(audit(1)["error"]["code"], "insecure-permissions");
    let extended = String::from_utf8(line.clone())
        .expect("utf8")
        .replace("{\"version\"", "{\"extra\":1,\"version\"");
    damage(&rec, extended.as_bytes(), 0o600);
    assert!(archive_provenance(&archive, digest).is_err());
    fs::remove_file(&rec).expect("remove");
    env.write("elsewhere", std::str::from_utf8(&line).expect("utf8"));
    symlink(env.path("elsewhere"), &rec).expect("link");
    assert!(archive_provenance(&archive, digest).is_err());
    damage(&rec, &line, 0o600);
    assert_eq!(audit(2)["result"], "incomplete");

    // An interrupted run can leave a signature without a record. The same
    // signature completes it; another one is refused, and nothing is replaced.
    fs::remove_file(&rec).expect("interrupted");
    assert_eq!(
        archive_provenance(&archive, digest).expect("lookup"),
        Provenance::Unsigned
    );
    assert!(record(b"other signature", OWNER).is_err());
    assert_eq!(fs::read(&sig).expect("kept"), b"signature");
    assert_eq!(
        record(b"signature", OWNER).expect("complete"),
        ArchivedSignature::Recorded(approval)
    );
}

#[test]
fn a_plain_spend_keeps_no_target_and_the_gap_says_how_to_keep_one() {
    let env = Env::new();
    env.write("p.toml", &pass());
    let archived = env.json(&["archive", "p.toml", "arch"], 0);
    let digest = text_of(&archived["digest"]).parse().expect("digest");
    archive_verified_signature(
        &env.path("arch"),
        digest,
        b"signature",
        OWNER,
        Digest::of(b"t"),
    )
    .expect("record");
    // The default is unchanged: a plain spend --to keeps no target.
    let plain = env.json(&["spend", "p.toml", "requests", "--to", WEB], 0);
    assert!(plain["receipt"].is_null(), "{plain}");
    let audit = env.json(&["audit-receipts", "p.toml", "arch"], 2);
    assert_eq!(audit["result"], "incomplete");
    assert_eq!(audit["gaps"]["targets-unrecorded"]["sequences"], json!([1]));
    assert!(audit["gaps"].get("legacy-spend").is_none(), "{audit}");
    assert_eq!(audit["gaps"]["targets-unrecorded"]["digests"], json!([]));
    let text = env.text(&["audit-receipts", "p.toml", "arch"], 2);
    assert!(
        text.contains(
            "Gap targets-unrecorded 1: the line keeps no target; spend with --to and --record-target to keep endpoint evidence. Sequences [1]"
        ),
        "{text}"
    );
    // With --record-target the same spend is evidence the audit replays.
    let kept = env.spend("1", WEB);
    assert_eq!(kept["receipt"]["targets"][0]["label"], "web");
    let audit = env.json(&["audit-receipts", "p.toml", "arch"], 2);
    assert_eq!(audit["corroborated"]["count"], 1);
    assert_eq!(audit["gaps"]["targets-unrecorded"]["sequences"], json!([1]));
}

#[test]
fn archive_missing_gaps_name_each_digest_with_its_sequences() {
    let env = Env::new();
    let first = pass();
    let second = format!("{first}# reviewed again\n");
    env.write("p.toml", &first);
    env.spend("1", WEB);
    env.spend("1", WEB);
    env.write("p.toml", &second);
    env.spend("1", WEB);
    env.write("p.toml", &first);
    env.spend("1", WEB);
    let a = Digest::of(first.as_bytes()).to_string();
    let b = Digest::of(second.as_bytes()).to_string();
    let expected = json!([
        {"digest": a, "count": 3, "sequences": [1, 2, 4], "truncated": false},
        {"digest": b, "count": 1, "sequences": [3], "truncated": false},
    ]);
    for command in ["audit-receipts", "audit-charges"] {
        let audit = env.json(&[command, "p.toml", "arch"], 2);
        let gap = &audit["gaps"]["archive-missing"];
        assert_eq!(gap["count"], 4, "{command}: {audit}");
        assert_eq!(gap["digests"], expected, "{command}");
        assert_eq!(gap["digests_truncated"], false);
        assert_eq!(audit["gaps"]["approval-unverified"]["digests"], expected);
        let rows = &audit["revisions"]["details"];
        assert_eq!(
            rows[0],
            json!({"digest": a, "first_seq": 1, "last_seq": 4, "lines": 3, "provenance": "missing", "approval": null, "reason": null}),
            "{command}"
        );
        assert_eq!(rows[1]["provenance"], "missing");
        let text = env.text(&[command, "p.toml", "arch"], 2);
        assert!(
            text.contains("Gap archive-missing 4: the revision is not in the archive"),
            "{text}"
        );
        assert!(
            text.contains(&format!("  {a} 3 line(s). Sequences [1, 2, 4]\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("  {b} 1 line(s). Sequences [3]\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  {a} sequences 1 to 4, 3 line(s): not in the archive"
            )),
            "{text}"
        );
    }
}

#[test]
fn revision_lists_stop_at_the_detail_limit_but_count_everything() {
    let env = Env::new();
    let file = env.path("p.toml");
    let state = StateDir::new(env.path("state"));
    let now = datetime!(2026-11-20 09:00 UTC);
    let limit = evidence::DETAIL_LIMIT;
    for i in 0..=limit {
        env.write("p.toml", &format!("{}# revision {i}\n", pass()));
        let outcome =
            spend_in(&file, &SpendRequest::new("requests", 1), now, &state).expect("spend");
        assert!(outcome.refusal.is_none());
    }
    let loaded = hallpass::load(&file).expect("pass");
    let audit = evidence::audit_charges(&loaded, &state, &env.path("arch")).expect("audit");
    assert_eq!(audit.result, "incomplete");
    let gap = &audit.gaps["archive-missing"];
    assert_eq!(gap.count, limit as u64 + 1);
    assert_eq!(gap.digests.len(), limit);
    assert!(gap.digests_truncated);
    assert_eq!(audit.revisions.count, limit as u64 + 1);
    assert_eq!(audit.revisions.unverified, limit as u64 + 1);
    assert_eq!(audit.revisions.details.len(), limit);
    assert!(audit.revisions.truncated);
}
