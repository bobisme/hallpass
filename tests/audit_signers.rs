//! Whose signature completes an audit, and as of when it is verified.
//!
//! bn-1zq: the trusted signers file decides whose keys count, and
//! `--principal` decides who must have approved. Without it, each signature
//! was verified for the principal its record names, which whoever writes the
//! archive picks. So a consultant who widened the pass and signed it with
//! their own trusted key got a `complete` audit. Now an audit is `complete`
//! only when every revision verifies for a principal the auditor named.
//!
//! bn-1vr: the audits verified every signature as of now, so a past audit
//! broke once the owner's key expired, and said `untrusted-key`. Now they
//! verify each signature as of the time its revision was first used, and a
//! key outside its window is `key-not-valid-at-time`.
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
use hallpass::time::{OffsetDateTime, macros::datetime};
use hallpass::{Digest, Error, StateDir, archive_verified_signature};
use serde_json::{Value, json};

/// When the first revision is first used.
const NOW: &str = "2026-11-20T09:00:00Z";
/// When the second revision is first used.
const LATER: &str = "2026-11-20T12:00:00Z";
const OWNER: &str = "owner@example.org";
const SAM: &str = "sam@example.com";
const WEB: &str = "192.0.2.10:443/tcp@app.example.com";
const SSH: &str = "192.0.2.10:22/tcp@app.example.com";

fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

/// The consultant's widening: port 22 as well.
fn widened() -> String {
    pass().replace("ports = 443\n", "ports = [22, 443]\n")
}

fn have_ssh_keygen() -> bool {
    Command::new("ssh-keygen")
        .arg("-?")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn text_of(value: &Value) -> &str {
    value.as_str().expect("string")
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

    fn run(&self, args: &[&str], format: &str, clock: &str) -> (i32, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        command
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path())
            .env("XDG_STATE_HOME", self.path("state"))
            .env("HALLPASS_UNSAFE_TEST_CLOCK", clock)
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
        let (actual, out) = self.run(args, "json", NOW);
        assert_eq!(actual, code, "{args:?}: {out}");
        serde_json::from_str(out.trim()).expect("one JSON object")
    }

    fn text(&self, args: &[&str], code: i32) -> String {
        let (actual, out) = self.run(args, "text", NOW);
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

    fn key(&self, name: &str) -> String {
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", name]);
        fs::read_to_string(self.path(&format!("{name}.pub")))
            .expect("public key")
            .trim()
            .to_owned()
    }

    /// Sign `file` as `key`, and record the signature for `principal` with
    /// `verify-approval --archive`, verifying against `trust`. Returns the
    /// digest.
    fn sign_and_record(&self, key: &str, file: &str, principal: &str, trust: &str) -> String {
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
                trust,
                "--principal",
                principal,
                "--archive",
                "arch",
            ],
            0,
        );
        fs::remove_file(self.path(&signature)).expect("remove the signature");
        text_of(&reply["digest"]).to_owned()
    }

    /// Debit one request to `to` at `clock`, recording the target, without
    /// the test clock, so that an audit can be `complete` (bn-2mm).
    fn spend(&self, to: &str, clock: &str) {
        live_spend::spend(&self.path("p.toml"), &self.path("state"), to, 1, clock);
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

const AUDITS: [&str; 2] = ["audit-receipts", "audit-charges"];

fn audit_args<'a>(command: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    [&[command, "p.toml", "arch"][..], extra].concat()
}

/// The lead's repro (bn-1zq): the signers file trusts the owner and the
/// consultant. The owner signs revision A; the consultant widens it to B
/// (port 22), signs B with their own key and records it. Both are spent
/// under. Returns the two digests.
fn consultant_widening(env: &Env) -> (String, String) {
    let owner = env.key("owner");
    let sam = env.key("sam");
    env.write("org_signers", &format!("{OWNER} {owner}\n{SAM} {sam}\n"));
    env.write("p.toml", &pass());
    let a = env.sign_and_record("owner", "p.toml", OWNER, "org_signers");
    env.spend(WEB, NOW);
    env.write("p.toml", &widened());
    let b = env.sign_and_record("sam", "p.toml", SAM, "org_signers");
    env.spend(SSH, LATER);
    (a, b)
}

#[test]
fn the_gate_without_a_principal_is_never_complete() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let (a, b) = consultant_widening(&env);
    let trust = Digest::of(&fs::read(env.path("org_signers")).expect("trust")).to_string();

    // Both signatures verify, each for the principal its record names. That
    // shows whose key signed, not that the owner approved: not complete.
    for command in AUDITS {
        let args = audit_args(command, &["--allowed-signers", "org_signers"]);
        let audit = env.json(&args, 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        assert_eq!(
            audit["signatures"],
            json!({"reverified": true, "allowed_signers": trust, "principals": [], "as_of": "first-use"})
        );
        assert_eq!(
            audit["gaps"]
                .as_object()
                .map(|g| g.keys().cloned().collect::<Vec<_>>()),
            Some(vec!["signer-not-pinned".to_owned()]),
            "{command}: {audit}"
        );
        assert_eq!(
            audit["gaps"]["signer-not-pinned"]["digests"],
            json!([
                {"digest": a, "count": 1, "sequences": [1], "truncated": false, "principal": OWNER},
                {"digest": b, "count": 1, "sequences": [2], "truncated": false, "principal": SAM},
            ]),
            "{command}"
        );
        let rows = &audit["revisions"]["details"];
        for (row, principal, first) in [(&rows[0], OWNER, NOW), (&rows[1], SAM, LATER)] {
            assert_eq!(row["provenance"], "signature-verified", "{audit}");
            assert_eq!(row["verified_for"], principal);
            assert_eq!(row["first_time"], first);
            assert_eq!(row["verify_time"], first);
        }

        let text = env.text(&args, 2);
        assert!(text.contains(" audit incomplete."), "{text}");
        assert!(!text.contains("confirmed"), "{text}");
        assert!(
            text.contains("Gap signer-not-pinned 2: ")
                && text.contains("so name the owner with --principal"),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  {b} 1 line(s). Sequences [2]. Verified for principal \"{SAM}\""
            )),
            "{text}"
        );
        assert!(
            text.contains(", as of each revision's first use, each for the principal its record names, as no --principal named the owner."),
            "{text}"
        );
    }

    // Naming the owner: the consultant's revision does not verify for them.
    for command in AUDITS {
        let args = audit_args(
            command,
            &["--allowed-signers", "org_signers", "--principal", OWNER],
        );
        let audit = env.json(&args, 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        assert_eq!(audit["signatures"]["principals"], json!([OWNER]));
        assert!(audit["gaps"].get("signer-not-pinned").is_none(), "{audit}");
        assert_eq!(
            audit["gaps"]["signature-rejected"]["digests"],
            json!([{"digest": b, "count": 1, "sequences": [2], "truncated": false, "reason": "wrong-principal"}]),
            "{command}: {audit}"
        );
        let rows = &audit["revisions"]["details"];
        assert_eq!(rows[0]["provenance"], "signature-verified");
        assert_eq!(rows[0]["verified_for"], OWNER);
        assert_eq!(rows[1]["provenance"], "signature-rejected");
        assert_eq!(rows[1]["verified_for"], Value::Null);
        assert_eq!(rows[1]["verify_time"], LATER);
    }
    let text = env.text(
        &audit_args(
            "audit-receipts",
            &["--allowed-signers", "org_signers", "--principal", OWNER],
        ),
        2,
    );
    assert!(text.contains("#1 target 1 at 2026-11-20T09:00:00Z 192.0.2.10:443/tcp name app.example.com: recorded label web confirmed"), "{text}");
    assert!(
        text.contains(&format!(
            "  {b} sequences 2 to 2, 1 line(s): recorded signature failed re-verification for principal \"{OWNER}\" as of {LATER} (wrong-principal)"
        )),
        "{text}"
    );
}

#[test]
fn an_owner_with_several_principals_names_each_one() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    // The owner signs from two keys, each trusted for one of their principals.
    let home = "owner@example.net";
    let first = env.key("first");
    let second = env.key("second");
    env.write("trust", &format!("{OWNER} {first}\n{home} {second}\n"));
    env.write("p.toml", &pass());
    let a = env.sign_and_record("first", "p.toml", OWNER, "trust");
    env.spend(WEB, NOW);
    env.write("p.toml", &widened());
    let b = env.sign_and_record("second", "p.toml", home, "trust");
    env.spend(SSH, LATER);

    for command in AUDITS {
        // A repeated name counts once.
        let both = audit_args(
            command,
            &[
                "--allowed-signers",
                "trust",
                "--principal",
                OWNER,
                "--principal",
                home,
                "--principal",
                OWNER,
            ],
        );
        let audit = env.json(&both, 0);
        assert_eq!(audit["result"], "complete", "{command}: {audit}");
        assert_eq!(audit["gaps"], json!({}));
        assert_eq!(audit["signatures"]["principals"], json!([OWNER, home]));
        let rows = &audit["revisions"]["details"];
        assert_eq!(
            (&rows[0]["digest"], &rows[0]["verified_for"]),
            (&json!(a), &json!(OWNER))
        );
        assert_eq!(
            (&rows[1]["digest"], &rows[1]["verified_for"]),
            (&json!(b), &json!(home))
        );
        let text = env.text(&both, 0);
        assert!(
            text.contains(&format!(
                ", each for any of principals \"{OWNER}\", \"{home}\"."
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "  {b} sequences 2 to 2, 1 line(s): signature re-verified for principal \"{home}\" as of {LATER} with the trusted signers you supplied"
            )),
            "{text}"
        );

        // One of them alone does not cover the other's revision.
        let one = audit_args(
            command,
            &["--allowed-signers", "trust", "--principal", OWNER],
        );
        let audit = env.json(&one, 2);
        assert_eq!(audit["result"], "incomplete");
        assert_eq!(
            audit["gaps"]["signature-rejected"]["digests"][0]["digest"],
            b.as_str()
        );
        assert_eq!(
            audit["revisions"]["details"][1]["reason"],
            "wrong-principal"
        );
    }
}

/// The owner's key, trusted in `trust` for recording, and with `window` in
/// `limited`. One revision, first used at `NOW`.
fn signed_with_window(env: &Env, window: &str) -> String {
    let owner = env.key("owner");
    env.write("trust", &format!("{OWNER} {owner}\n"));
    env.write("limited", &format!("{OWNER} {window} {owner}\n"));
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
            "--archive",
            "arch",
        ],
        0,
    );
    env.spend(WEB, NOW);
    text_of(&reply["digest"]).to_owned()
}

#[test]
fn a_key_that_expired_after_first_use_still_approves_what_it_signed() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    // Valid until after the first use, and expired by now (the test clock
    // only dates the ledger; ssh-keygen's own clock is real).
    let digest = signed_with_window(&env, "valid-before=\"20261121Z\"");
    let pinned = ["--allowed-signers", "limited", "--principal", OWNER];

    for command in AUDITS {
        let args = audit_args(command, &pinned);
        let audit = env.json(&args, 0);
        assert_eq!(audit["result"], "complete", "{command}: {audit}");
        assert_eq!(audit["signatures"]["as_of"], "first-use");
        let row = &audit["revisions"]["details"][0];
        assert_eq!(row["digest"], digest.as_str());
        assert_eq!(row["first_time"], NOW);
        assert_eq!(row["verify_time"], NOW);
        let text = env.text(&args, 0);
        assert!(
            text.contains(&format!(
                "signature re-verified for principal \"{OWNER}\" as of {NOW} with the trusted signers you supplied"
            )),
            "{text}"
        );

        // As of now, the key has expired: it is named as such.
        let now = audit_args(
            command,
            &[&pinned[..], &["--signatures-as-of", "now"]].concat(),
        );
        let audit = env.json(&now, 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        let as_of = text_of(&audit["signatures"]["as_of"]).to_owned();
        assert!(as_of.as_str() > "2026-11-21", "{as_of}");
        let row = &audit["revisions"]["details"][0];
        assert_eq!(row["reason"], "key-not-valid-at-time", "{audit}");
        assert_eq!(row["verify_time"], as_of.as_str());
        let text = env.text(&now, 2);
        assert!(text.contains("Reason key-not-valid-at-time: "), "{text}");
        assert!(!text.contains("untrusted-key"), "{text}");
        assert!(text.contains(", as of 20"), "{text}");
    }

    // verify-approval checks as of now, and --at checks history.
    let verify = |extra: &[&str], code| {
        let args = [
            &[
                "verify-approval",
                "p.toml",
                "--signature",
                "p.toml.sig",
                "--allowed-signers",
                "limited",
                "--principal",
                OWNER,
            ][..],
            extra,
        ]
        .concat();
        (env.json(&args, code), env.text(&args, code))
    };
    let (reply, text) = verify(&[], 2);
    assert_eq!(reply["reason"], "key-not-valid-at-time", "{reply}");
    assert_eq!(reply["verify_time"], Value::Null);
    assert!(
        text.contains("valid-after or valid-before window"),
        "{text}"
    );
    let (reply, text) = verify(&["--at", NOW], 0);
    assert_eq!(reply["result"], "verified", "{reply}");
    assert_eq!(reply["verify_time"], NOW);
    assert_eq!(reply["digest"], digest.as_str());
    assert!(
        text.starts_with(&format!(
            "Verified signature from \"{OWNER}\" as of {NOW} over pass"
        )),
        "{text}"
    );
    let (reply, _) = verify(&["--at", "yesterday"], 1);
    assert_eq!(reply["error"]["code"], "usage", "{reply}");
    assert!(
        text_of(&reply["error"]["message"])
            .contains("--at is \"yesterday\", not an RFC 3339 timestamp"),
        "{reply}"
    );
}

#[test]
fn a_key_not_yet_valid_at_first_use_does_not_approve() {
    if !have_ssh_keygen() {
        return;
    }
    let env = Env::new();
    let digest = signed_with_window(&env, "valid-after=\"20261121Z\"");
    for command in AUDITS {
        let args = audit_args(
            command,
            &["--allowed-signers", "limited", "--principal", OWNER],
        );
        let audit = env.json(&args, 2);
        assert_eq!(audit["result"], "incomplete", "{command}: {audit}");
        assert_eq!(
            audit["gaps"]["signature-rejected"]["digests"],
            json!([{"digest": digest, "count": 1, "sequences": [1], "truncated": false, "reason": "key-not-valid-at-time"}]),
            "{command}: {audit}"
        );
        let text = env.text(&args, 2);
        assert!(
            text.contains(&format!(
                "recorded signature failed re-verification for principal \"{OWNER}\" as of {NOW} (key-not-valid-at-time): the key is in the trusted signers file you supplied for the principal checked, but its valid-after or valid-before window"
            )),
            "{text}"
        );

        // The key is valid now, so an audit as of now accepts it.
        let now = audit_args(
            command,
            &[
                "--allowed-signers",
                "limited",
                "--principal",
                OWNER,
                "--signatures-as-of",
                "now",
            ],
        );
        assert_eq!(env.json(&now, 0)["result"], "complete");

        // Outside its window and for another principal: the principal is
        // what is wrong, and the key is never called untrusted.
        let other = audit_args(
            command,
            &[
                "--allowed-signers",
                "limited",
                "--principal",
                "deputy@example.org",
            ],
        );
        let audit = env.json(&other, 2);
        assert_eq!(
            audit["revisions"]["details"][0]["reason"], "wrong-principal",
            "{audit}"
        );
    }
}

#[test]
fn the_time_options_are_checked() {
    let env = Env::new();
    env.write("p.toml", &pass());
    env.write("trust", &format!("{OWNER} ssh-ed25519 AAAA\n"));
    for command in AUDITS {
        for extra in [
            &["--signatures-as-of", "now"][..],
            &[
                "--allowed-signers",
                "trust",
                "--signatures-as-of",
                "yesterday",
            ][..],
        ] {
            let reply = env.json(&audit_args(command, extra), 1);
            assert_eq!(reply["error"]["code"], "usage", "{extra:?}: {reply}");
        }
    }
}

#[test]
fn an_ssh_keygen_without_verify_time_is_an_error() {
    if !have_ssh_keygen() {
        return;
    }
    let mut env = Env::new();
    signed_with_window(&env, "valid-before=\"20991231Z\"");
    let real = Command::new("sh")
        .args(["-c", "command -v ssh-keygen"])
        .output()
        .expect("find ssh-keygen");
    let real = String::from_utf8(real.stdout).expect("path");
    // As an older ssh-keygen does, it refuses the option it does not know.
    env.shim(&format!(
        "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    -Overify-time=*) echo \"Invalid option \\\"${{arg#-O}}\\\"\" >&2; exit 255 ;;\n  esac\ndone\nexec '{}' \"$@\"\n",
        real.trim()
    ));
    for command in AUDITS {
        let reply = env.json(
            &audit_args(
                command,
                &["--allowed-signers", "trust", "--principal", OWNER],
            ),
            1,
        );
        assert!(
            text_of(&reply["error"]["message"]).contains("did not accept `-O verify-time`"),
            "{reply}"
        );
    }
    let verify = |extra: &[&str], code| {
        let args = [
            &[
                "verify-approval",
                "p.toml",
                "--signature",
                "p.toml.sig",
                "--allowed-signers",
                "trust",
                "--principal",
                OWNER,
            ][..],
            extra,
        ]
        .concat();
        env.json(&args, code)
    };
    // Without --at, verify-approval passes no time and still works.
    assert_eq!(verify(&[], 0)["result"], "verified");
    let reply = verify(&["--at", NOW], 1);
    assert!(
        text_of(&reply["error"]["message"]).contains("did not accept `-O verify-time`"),
        "{reply}"
    );
}

/// The library side, without ssh-keygen: two archived revisions with
/// signature records naming `OWNER` (not real signatures), first used at
/// 09:00 and 12:00.
struct Library {
    env: Env,
    digests: Vec<Digest>,
}

impl Library {
    fn new() -> Self {
        let env = Env::new();
        let mut digests = Vec::new();
        for (text, clock) in [(pass(), NOW), (widened(), LATER)] {
            env.write("p.toml", &text);
            let digest =
                hallpass::archive_pass(&env.path("p.toml"), &env.path("arch")).expect("archive");
            archive_verified_signature(
                &env.path("arch"),
                digest,
                format!("signature {}", digests.len()).as_bytes(),
                OWNER,
                Digest::of(b"t"),
            )
            .expect("record");
            digests.push(digest);
            env.spend(if clock == NOW { WEB } else { SSH }, clock);
        }
        Self { env, digests }
    }

    fn audits(
        &self,
        principals: &[&str],
        as_of: AsOf,
        check: &mut dyn FnMut(&SignatureToCheck<'_>) -> Result<Recheck, Error>,
    ) -> (evidence::ChargeAudit, evidence::ReceiptAudit) {
        let loaded = hallpass::load(&self.env.path("p.toml")).expect("pass");
        let state = StateDir::new(self.env.path("state"));
        let archive = self.env.path("arch");
        let charges = evidence::audit_charges_with(
            &loaded,
            &state,
            &archive,
            Some(Reverify {
                allowed_signers: Digest::of(b"auditor"),
                principals,
                as_of,
                allow_pattern_principals: false,
                check: &mut *check,
            }),
        )
        .expect("charges");
        let receipts = evidence::audit_receipts_with(
            &loaded,
            &state,
            &archive,
            Some(Reverify {
                allowed_signers: Digest::of(b"auditor"),
                principals,
                as_of,
                allow_pattern_principals: false,
                check,
            }),
        )
        .expect("receipts");
        (charges, receipts)
    }
}

/// One call of the verifier: the revision (0 or 1), the principal and the
/// time.
type Call = (usize, String, OffsetDateTime);

impl Library {
    /// Both audits with a verifier that accepts only `accept` for the first
    /// revision, and OWNER for the second. Records name OWNER, and a
    /// rejection for OWNER says `key-not-valid-at-time`. Returns the calls of
    /// the charge audit too.
    fn run(
        &self,
        principals: &[&str],
        accept: &str,
        as_of: AsOf,
    ) -> (evidence::ChargeAudit, evidence::ReceiptAudit, Vec<Call>) {
        let calls = RefCell::new(Vec::new());
        let mut check = |s: &SignatureToCheck<'_>| {
            let i = self
                .digests
                .iter()
                .position(|d| *d == s.digest)
                .expect("digest");
            calls
                .borrow_mut()
                .push((i, s.principal.to_owned(), s.as_of));
            let wanted = if i == 0 { accept } else { OWNER };
            Ok(if s.principal == wanted {
                Recheck::Verified
            } else if s.principal == OWNER {
                Recheck::Rejected("key-not-valid-at-time")
            } else {
                Recheck::Rejected("wrong-principal")
            })
        };
        let (charges, receipts) = self.audits(principals, as_of, &mut check);
        let mut calls = calls.into_inner();
        // The receipt audit makes the same calls again.
        let half = calls.len() / 2;
        assert_eq!(calls[..half], calls[half..]);
        calls.truncate(half);
        (charges, receipts, calls)
    }
}

#[test]
fn the_library_tries_the_named_principals_as_of_first_use() {
    let lib = Library::new();
    let first = [
        datetime!(2026-11-20 09:00 UTC),
        datetime!(2026-11-20 12:00 UTC),
    ];
    let deputy = "deputy@example.org";

    // The record's principal first when it is named, then the others in
    // order, until one verifies.
    let (charges, receipts, calls) = lib.run(&[deputy, OWNER], deputy, AsOf::FirstUse);
    let principals: Vec<(usize, &str)> = calls.iter().map(|(i, p, _)| (*i, p.as_str())).collect();
    assert_eq!(principals, [(0, OWNER), (0, deputy), (1, OWNER)]);
    for (i, _, as_of) in &calls {
        assert_eq!(*as_of, first[*i]);
    }
    for (result, revisions, signatures) in [
        (charges.result, &charges.revisions, &charges.signatures),
        (receipts.result, &receipts.revisions, &receipts.signatures),
    ] {
        assert_eq!(result, "complete");
        assert_eq!(revisions.details[0].verified_for.as_deref(), Some(deputy));
        assert_eq!(revisions.details[1].verified_for.as_deref(), Some(OWNER));
        assert_eq!(revisions.details[1].first_time, LATER);
        assert_eq!(revisions.details[1].verify_time.as_deref(), Some(LATER));
        assert_eq!(signatures.principals, [deputy, OWNER]);
        assert_eq!(signatures.as_of.as_deref(), Some("first-use"));
    }

    // None verifies: the reason is the first try's, the record's principal.
    let (charges, _, _) = lib.run(&[deputy, OWNER], "nobody", AsOf::FirstUse);
    assert_eq!(
        charges.revisions.details[0].reason,
        Some("key-not-valid-at-time")
    );
    // The record's principal is not named: the named ones, in order.
    let (charges, _, calls) = lib.run(
        &["b@example.org", "a@example.org"],
        "nobody",
        AsOf::FirstUse,
    );
    let principals: Vec<(usize, &str)> = calls.iter().map(|(i, p, _)| (*i, p.as_str())).collect();
    assert_eq!(
        principals,
        [
            (0, "b@example.org"),
            (0, "a@example.org"),
            (1, "b@example.org"),
            (1, "a@example.org")
        ]
    );
    assert_eq!(charges.revisions.details[0].reason, Some("wrong-principal"));
    assert_eq!(charges.gaps["signature-rejected"].count, 2);
}

#[test]
fn the_library_without_a_principal_matches_the_command_line() {
    let lib = Library::new();
    // No principal named: the record's, and a signer-not-pinned gap.
    let (charges, receipts, calls) = lib.run(&[], OWNER, AsOf::FirstUse);
    assert_eq!(calls.len(), 2);
    for gaps in [&charges.gaps, &receipts.gaps] {
        assert_eq!(
            gaps.keys().copied().collect::<Vec<_>>(),
            ["signer-not-pinned"]
        );
        let gap = &gaps["signer-not-pinned"];
        assert_eq!(gap.sequences, [1, 2]);
        assert_eq!(gap.digests[0].principal.as_deref(), Some(OWNER));
    }
    assert_eq!(charges.result, "incomplete");
    assert_eq!(receipts.result, "incomplete");
    assert_eq!(charges.signatures.principals, Vec::<String>::new());
    assert_eq!(charges.revisions.unverified, 0);

    // One instant for all.
    let at: OffsetDateTime = datetime!(2026-11-24 10:00 UTC);
    let (charges, _, calls) = lib.run(&[OWNER], OWNER, AsOf::Instant(at));
    assert!(calls.iter().all(|(_, _, as_of)| *as_of == at), "{calls:?}");
    assert_eq!(
        charges.signatures.as_of.as_deref(),
        Some("2026-11-24T10:00:00Z")
    );
    assert_eq!(
        charges.revisions.details[0].verify_time.as_deref(),
        Some("2026-11-24T10:00:00Z")
    );
    assert_eq!(charges.revisions.details[0].first_time, NOW);
}
