//! The audits verify signatures after they release the ledger lock, over the
//! bytes they read under it (bn-3c4).
//!
//! Before, `Reverify::check` (ssh-keygen) ran under the shared ledger lock, so
//! every spend waited for one ssh-keygen per digest. And ssh-keygen read the
//! signature and the trusted signers file by path, so a file swapped out and
//! back between the audit's reads was not noticed, and the signature verified
//! could differ from the one the record names.
//!
//! The command-line tests need OpenSSH `ssh-keygen` and return early without it.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hallpass::evidence::{self, Recheck, Reverify, SignatureToCheck};
use hallpass::time::{OffsetDateTime, macros::datetime};
use hallpass::{Digest, Error, SpendRequest, StateDir, archive_verified_signature, spend_in};

const OWNER: &str = "owner@example.org";

fn pass() -> String {
    format!(
        "{}[ceilings]\nrequests = 100\n",
        include_str!("../docs/review-approval.toml")
    )
}

fn now() -> OffsetDateTime {
    datetime!(2026-11-20 09:00 UTC)
}

/// Two archived revisions with signature records (not real signatures), and
/// three lines: two under the first, one under the second.
struct Fixture {
    dir: tempfile::TempDir,
    digests: Vec<Digest>,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().expect("tempdir"),
            digests: Vec::new(),
        };
        let archive = fixture.path("arch");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
        let mut digests = Vec::new();
        for (text, lines) in [(pass(), 2), (format!("{}# extra\n", pass()), 1)] {
            fixture.write("p.toml", &text);
            let digest =
                hallpass::archive_pass(&fixture.path("p.toml"), &archive).expect("archive");
            archive_verified_signature(
                &archive,
                digest,
                format!("signature {}", digests.len()).as_bytes(),
                OWNER,
                Digest::of(b"t"),
            )
            .expect("record");
            digests.push(digest);
            for _ in 0..lines {
                fixture.spend(None).expect("spend");
            }
        }
        Self { digests, ..fixture }
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
        fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(SystemTime::now() - Duration::from_secs(60)))
            .expect("date the file back");
    }

    fn state(&self) -> StateDir {
        StateDir::new(self.path("state"))
    }

    fn spend(&self, lock_timeout: Option<Duration>) -> Result<(), Error> {
        let mut request = SpendRequest::new("requests", 1);
        request.lock_timeout = lock_timeout;
        let outcome = spend_in(&self.path("p.toml"), &request, now(), &self.state())?;
        assert!(outcome.refusal.is_none(), "{outcome:?}");
        Ok(())
    }

    fn signature(&self, digest: Digest) -> PathBuf {
        self.path(&format!("arch/{digest}.sig"))
    }

    /// `audit-charges` or `audit-receipts` as JSON, so that the two compare
    /// the same way.
    fn audit(&self, charges: bool, reverify: Reverify<'_>) -> Result<serde_json::Value, Error> {
        let loaded = hallpass::load(&self.path("p.toml")).expect("pass");
        let (state, archive) = (self.state(), self.path("arch"));
        Ok(if charges {
            serde_json::to_value(evidence::audit_charges_with(
                &loaded,
                &state,
                &archive,
                Some(reverify),
            )?)
        } else {
            serde_json::to_value(evidence::audit_receipts_with(
                &loaded,
                &state,
                &archive,
                Some(reverify),
            )?)
        }
        .expect("json"))
    }
}

/// A `Reverify` with `check`, for a trusted signers file that is not read.
fn reverify(
    check: &mut dyn FnMut(&SignatureToCheck<'_>) -> Result<Recheck, Error>,
) -> Reverify<'_> {
    Reverify {
        allowed_signers: Digest::of(b"auditor"),
        principal: None,
        check,
    }
}

/// Replace a private archive file, as someone who can write the archive could.
fn replace(path: &Path, bytes: &[u8]) {
    fs::remove_file(path).expect("remove");
    fs::write(path, bytes).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private");
}

#[test]
fn the_ledger_lock_is_free_while_the_verifier_runs() {
    let fixture = Fixture::new();
    // The second audit also reads the two lines the first one's verifier
    // spent.
    for (charges, later) in [(true, 1), (false, 3)] {
        let mut checked = Vec::new();
        // A writer on the same pass needs the exclusive ledger lock. Under the
        // audit's shared lock it would wait, and give up after two seconds.
        let mut check = |s: &SignatureToCheck<'_>| {
            fixture.spend(Some(Duration::from_secs(2)))?;
            checked.push(s.digest);
            Ok(Recheck::Verified)
        };
        let audit = fixture
            .audit(charges, reverify(&mut check))
            .expect("the spends inside the verifier got the lock");
        assert_eq!(checked, fixture.digests, "once per digest");
        // The audit reports the lines it read under the lock, not the spends
        // the verifier made after it.
        assert_eq!(audit["revisions"]["details"][0]["lines"], 2, "{audit}");
        assert_eq!(audit["revisions"]["details"][1]["lines"], later, "{audit}");
        assert_eq!(audit["revisions"]["unverified"], 0, "{audit}");
    }
    let view = hallpass::read_ledger(
        &hallpass::load(&fixture.path("p.toml")).expect("pass"),
        &fixture.state(),
    )
    .expect("ledger");
    assert_eq!(view.entries.len(), 3 + 2 + 2);
}

#[test]
fn the_signature_verified_is_the_one_read_even_if_swapped_out_and_back() {
    let fixture = Fixture::new();
    let read: Vec<Vec<u8>> = fixture
        .digests
        .iter()
        .map(|d| fs::read(fixture.signature(*d)).expect("signature"))
        .collect();
    // A verifier that accepts only the signature the record names.
    let verdict = |s: &SignatureToCheck<'_>| {
        if Digest::of(s.signature) == s.approval.signature {
            Recheck::Verified
        } else {
            Recheck::Rejected("bytes-do-not-match")
        }
    };
    for charges in [true, false] {
        let mut plain = |s: &SignatureToCheck<'_>| Ok(verdict(s));
        let before = fixture.audit(charges, reverify(&mut plain)).expect("audit");

        // While the verifier runs, the .sig on disk is another signature; it
        // is put back before the audit could read it again.
        let mut seen = Vec::new();
        let mut swapping = |s: &SignatureToCheck<'_>| {
            let path = fixture.signature(s.digest);
            let kept = fs::read(&path).expect("signature");
            replace(&path, b"another signature");
            seen.push(s.signature.to_vec());
            let result = verdict(s);
            replace(&path, &kept);
            Ok(result)
        };
        let after = fixture
            .audit(charges, reverify(&mut swapping))
            .expect("audit");
        assert_eq!(seen, read, "the verifier got the signatures the audit read");
        assert_eq!(after, before);
        assert_eq!(after["revisions"]["unverified"], 0, "{after}");
    }
}

#[cfg(feature = "cli")]
mod cli {
    //! The ssh-keygen verifier of the command line, through a shim that
    //! records what ssh-keygen is given and changes the files meanwhile.
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use hallpass::Digest;
    use serde_json::Value;

    use super::{OWNER, pass};

    const WEB: &str = "192.0.2.10:443/tcp@app.example.com";

    struct Env {
        dir: tempfile::TempDir,
    }

    impl Env {
        fn new() -> Self {
            let env = Self {
                dir: tempfile::tempdir().expect("tempdir"),
            };
            for name in ["arch", "tmp", "log", "bin"] {
                fs::create_dir(env.path(name)).expect("directory");
                fs::set_permissions(env.path(name), fs::Permissions::from_mode(0o700))
                    .expect("private");
            }
            env
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        fn write(&self, name: &str, text: &str) {
            let path = self.path(name);
            fs::write(&path, text).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
            let earlier = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
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

        /// Run hallpass with `TMPDIR` inside the test directory and, with
        /// `shim`, the shim first on `PATH`.
        fn json(&self, args: &[&str], code: i32, shim: bool) -> Value {
            let mut command = Command::new(env!("CARGO_BIN_EXE_hallpass"));
            command
                .current_dir(self.dir.path())
                .env("HOME", self.dir.path())
                .env("XDG_STATE_HOME", self.path("state"))
                .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
                .env("TMPDIR", self.path("tmp"))
                .env_remove("FORMAT")
                .env_remove("HALLPASS_FORMAT")
                .args(["--format", "json"])
                .args(args);
            if shim {
                let path = std::env::var_os("PATH").unwrap_or_default();
                let mut dirs = vec![self.path("bin")];
                dirs.extend(std::env::split_paths(&path));
                command
                    .env("PATH", std::env::join_paths(dirs).expect("PATH"))
                    .env("SHIM_LOG", self.path("log"))
                    .env("SHIM_REAL", real_ssh_keygen())
                    .env("SHIM_HALLPASS", env!("CARGO_BIN_EXE_hallpass"));
            }
            let out = command.output().expect("run hallpass");
            let text = String::from_utf8(out.stdout).expect("utf8");
            assert_eq!(out.status.code(), Some(code), "{args:?}: {text}");
            serde_json::from_str(text.trim()).expect("one JSON object")
        }

        fn spend(&self) {
            let reply = self.json(
                &[
                    "spend",
                    "p.toml",
                    "--charge",
                    "requests=1",
                    "--to",
                    WEB,
                    "--record-target",
                ],
                0,
                false,
            );
            assert_eq!(reply["result"], "allowed", "{reply}");
        }

        /// A signed, recorded revision and two spends under it. Returns the
        /// digest.
        fn signed(&self) -> Digest {
            self.keygen(&["-q", "-t", "ed25519", "-N", "", "-f", "owner"]);
            let public = fs::read_to_string(self.path("owner.pub")).expect("public key");
            self.write("trust", &format!("{OWNER} {public}"));
            self.write("p.toml", &pass());
            self.keygen(&[
                "-q",
                "-Y",
                "sign",
                "-f",
                "owner",
                "-n",
                "hallpass-approval-v1",
                "p.toml",
            ]);
            let reply = self.json(
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
                false,
            );
            self.spend();
            self.spend();
            reply["digest"]
                .as_str()
                .expect("digest")
                .parse()
                .expect("digest")
        }

        fn shim(&self, script: &str) {
            let shim = self.path("bin/ssh-keygen");
            fs::write(&shim, script).expect("shim");
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o700)).expect("executable");
        }

        fn log(&self, name: &str) -> Vec<u8> {
            fs::read(self.path("log").join(name)).expect("shim log")
        }
    }

    fn have_ssh_keygen() -> bool {
        Command::new("ssh-keygen")
            .arg("-?")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    fn real_ssh_keygen() -> String {
        let out = Command::new("sh")
            .args(["-c", "command -v ssh-keygen"])
            .output()
            .expect("find ssh-keygen");
        String::from_utf8(out.stdout)
            .expect("path")
            .trim()
            .to_owned()
    }

    /// The start of a shim: `$trust` and `$signature` are the files given to
    /// ssh-keygen. It records them and the directory that holds them.
    const FIND_INPUTS: &str = r#"#!/bin/sh
prev=
for arg in "$@"; do
  case "$prev" in
    -f) trust="$arg" ;;
    -s) signature="$arg" ;;
  esac
  prev="$arg"
done
dir=$(dirname "$trust")
printf '%s\n' "$dir" > "$SHIM_LOG/dir"
ls -ld "$dir" > "$SHIM_LOG/mode"
cat "$trust" > "$SHIM_LOG/trust"
cat "$signature" > "$SHIM_LOG/signature"
"#;

    #[test]
    fn ssh_keygen_verifies_private_copies_of_the_bytes_the_audit_read() {
        if !have_ssh_keygen() {
            return;
        }
        let env = Env::new();
        let digest = env.signed();
        let trust = fs::read(env.path("trust")).expect("trust");
        let sig = env.path(&format!("arch/{digest}.sig"));
        let signature = fs::read(&sig).expect("signature");
        // While ssh-keygen runs, the archived signature is not a signature and
        // the trust file trusts no key. Both are put back afterwards.
        env.shim(&format!(
            "{FIND_INPUTS}cp '{sig}' \"$SHIM_LOG/kept-sig\"
cp trust \"$SHIM_LOG/kept-trust\"
printf 'not a signature\\n' > '{sig}'
printf '# trusts no key\\n' > trust
\"$SHIM_REAL\" \"$@\"
status=$?
cat \"$SHIM_LOG/kept-sig\" > '{sig}'
cat \"$SHIM_LOG/kept-trust\" > trust
exit $status
",
            sig = sig.display()
        ));
        for command in ["audit-receipts", "audit-charges"] {
            let audit = env.json(
                &[command, "p.toml", "arch", "--allowed-signers", "trust"],
                0,
                true,
            );
            assert_eq!(audit["result"], "complete", "{command}: {audit}");
            assert_eq!(
                audit["revisions"]["details"][0]["provenance"],
                "signature-verified"
            );
            assert_eq!(
                audit["signatures"]["allowed_signers"],
                Digest::of(&trust).to_string()
            );
            // ssh-keygen got copies of exactly the bytes the audit read, in a
            // private directory under TMPDIR, removed afterwards.
            assert_eq!(env.log("trust"), trust, "{command}");
            assert_eq!(env.log("signature"), signature, "{command}");
            let dir = String::from_utf8(env.log("dir")).expect("utf8");
            let dir = Path::new(dir.trim());
            assert_eq!(dir.parent(), Some(env.path("tmp").as_path()), "{dir:?}");
            let mode = String::from_utf8(env.log("mode")).expect("utf8");
            assert!(mode.starts_with("drwx------"), "{mode}");
            assert!(!dir.exists(), "{dir:?} was not removed");
            assert_eq!(fs::read_dir(env.path("tmp")).expect("tmp").count(), 0);
            assert_eq!(fs::read(&sig).expect("signature"), signature);
        }

        // verify-approval verifies copies too, and records what it verified.
        let reply = env.json(
            &[
                "verify-approval",
                "p.toml",
                "--signature",
                &format!("arch/{digest}.sig"),
                "--allowed-signers",
                "trust",
                "--principal",
                OWNER,
            ],
            0,
            true,
        );
        assert_eq!(reply["result"], "verified", "{reply}");
        assert_eq!(env.log("trust"), trust);
        assert_eq!(env.log("signature"), signature);
    }

    #[test]
    fn a_spend_does_not_wait_for_ssh_keygen() {
        if !have_ssh_keygen() {
            return;
        }
        let env = Env::new();
        env.signed();
        // The shim spends on the same pass while the audit waits for it.
        env.shim(&format!(
            "{FIND_INPUTS}\"$SHIM_HALLPASS\" --format json spend p.toml --charge requests=1 --to '{WEB}' --record-target --lock-timeout-ms 2000 > \"$SHIM_LOG/spend\" 2>&1
printf '%s\\n' $? >> \"$SHIM_LOG/spends\"
exec \"$SHIM_REAL\" \"$@\"
"
        ));
        for (command, lines) in [("audit-receipts", 2), ("audit-charges", 3)] {
            let audit = env.json(
                &[command, "p.toml", "arch", "--allowed-signers", "trust"],
                0,
                true,
            );
            assert_eq!(audit["result"], "complete", "{command}: {audit}");
            let spend = String::from_utf8(env.log("spend")).expect("utf8");
            assert!(spend.contains("\"result\":\"allowed\""), "{spend}");
            // The audit counts the lines it read before the spend.
            assert_eq!(audit["revisions"]["details"][0]["lines"], lines);
        }
        assert_eq!(env.log("spends"), b"0\n0\n");
    }
}
