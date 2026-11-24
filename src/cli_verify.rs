//! Verify a detached approval signature using the installed OpenSSH verifier,
//! for `verify-approval` and for the audits' `--allowed-signers`.
use std::cell::Cell;
use std::collections::hash_map::RandomState;
use std::fs::{DirBuilder, OpenOptions};
use std::hash::{BuildHasher as _, Hasher as _};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{OK, Output, REFUSED, error_output, quoted, safe};
use hallpass::evidence::{Recheck, Reverify, SignatureToCheck};
use hallpass::{APPROVAL_NAMESPACE as NAMESPACE, ArchivedSignature, Digest, Error};
use serde_json::json;

/// The largest trusted signers file `verify-approval --archive` and the
/// audits digest.
const MAX_TRUST_BYTES: u64 = 16 * 1024 * 1024;

fn input_path(path: &Path) -> Result<PathBuf, Error> {
    // An absolute name also keeps a literal "-" from acquiring stdin semantics.
    let full = std::path::absolute(path).map_err(|e| Error::Io {
        path: path.into(),
        message: e.to_string(),
    })?;
    let meta = std::fs::metadata(&full).map_err(|e| Error::Io {
        path: full.clone(),
        message: e.to_string(),
    })?;
    if !meta.is_file() {
        return Err(Error::Usage(format!(
            "expected a regular signature or trust file at {}",
            full.display()
        )));
    }
    Ok(full)
}

/// The bytes of a signature or trust file, read once.
fn read_input(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let full = input_path(path)?;
    let io = |e: &io::Error| Error::Io {
        path: full.clone(),
        message: e.to_string(),
    };
    let mut bytes = Vec::new();
    std::fs::File::open(&full)
        .map_err(|e| io(&e))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io(&e))?;
    if bytes.len() as u64 > limit {
        return Err(Error::TooLarge { path: full, limit });
    }
    Ok(bytes)
}

/// The signature and trust file, read once. The verifier gets copies of
/// these bytes, so what `--archive` records is exactly what it verified, even
/// if a file changes on disk meanwhile.
struct Inputs {
    signature: Vec<u8>,
    trust: Vec<u8>,
}

impl Inputs {
    fn read(signature: &Path, trust: &Path) -> Result<Self, Error> {
        Ok(Self {
            signature: read_input(signature, hallpass::MAX_SIGNATURE_BYTES)?,
            trust: read_input(trust, MAX_TRUST_BYTES)?,
        })
    }

    fn verify(&self, bytes: &[u8], principal: &str) -> Result<Result<(), Why>, Error> {
        Verifier::new(&self.trust)?.verify(bytes, &self.signature, principal)
    }
}

/// Retain the verified bytes and the signature that verified over them.
fn retain(
    bytes: &[u8],
    inputs: &Inputs,
    principal: &str,
    directory: &Path,
) -> Result<(Digest, ArchivedSignature), Error> {
    let digest = hallpass::archive_pass_bytes(bytes, directory)?;
    let record = hallpass::archive_verified_signature(
        directory,
        digest,
        &inputs.signature,
        principal,
        Digest::of(&inputs.trust),
    )?;
    Ok((digest, record))
}

/// A private (0700) temporary directory for the verifier's input files,
/// removed when dropped. Each file in it is written from bytes hallpass has
/// already read, so ssh-keygen reads exactly those bytes, whatever happens
/// to the original files meanwhile.
struct Scratch {
    dir: PathBuf,
    files: Cell<u64>,
}

impl Scratch {
    fn new() -> Result<Self, Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir();
        let failed = |path: &Path, e: &io::Error| Error::Io {
            path: path.to_owned(),
            message: format!(
                "cannot create a private temporary directory for the signature verifier ({e}); set TMPDIR to a directory this user can write"
            ),
        };
        // An absolute name also keeps a TMPDIR that starts with "-" from
        // reading as an option to ssh-keygen.
        let base = std::path::absolute(&base).map_err(|e| failed(&base, &e))?;
        for _ in 0..100 {
            // A random part keeps another user from taking every name in
            // advance in a shared TMPDIR, which would stop verification.
            let random = RandomState::new().build_hasher().finish();
            let dir = base.join(format!(
                "hallpass-verify-{}-{}-{random:016x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            // A new directory only: one left by another process is skipped.
            match DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    return Ok(Self {
                        dir,
                        files: Cell::new(0),
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(failed(&dir, &e)),
            }
        }
        Err(failed(
            &base,
            &io::Error::from(io::ErrorKind::AlreadyExists),
        ))
    }

    /// A new private file in the directory, holding `bytes`.
    fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, Error> {
        let n = self.files.get();
        self.files.set(n + 1);
        let path = self.dir.join(format!("{name}-{n}"));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(bytes))
            .map_err(|e| Error::Io {
                path: path.clone(),
                message: format!("writing the signature verifier's input: {e}"),
            })?;
        Ok(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `ssh-keygen -Y verify` with a trusted signers file given as bytes.
struct Verifier {
    scratch: Scratch,
    trust: PathBuf,
}

impl Verifier {
    fn new(trust: &[u8]) -> Result<Self, Error> {
        let scratch = Scratch::new()?;
        let trust = scratch.write("allowed_signers", trust)?;
        Ok(Self { scratch, trust })
    }

    /// Verify `signature` over `bytes` for `principal`. ssh-keygen reads
    /// `bytes` on its standard input and a copy of `signature` from the
    /// private directory.
    fn verify(
        &self,
        bytes: &[u8],
        signature: &[u8],
        principal: &str,
    ) -> Result<Result<(), Why>, Error> {
        let signature = self.scratch.write("signature", signature)?;
        let verdict = verified(bytes, &signature, &self.trust, principal);
        let _ = std::fs::remove_file(&signature);
        verdict
    }
}

/// Why a signature did not verify, as far as ssh-keygen's output shows.
#[derive(Clone, Copy)]
enum Why {
    Namespace,
    Tampered,
    Malformed,
    UntrustedKey,
    WrongPrincipal,
    Unknown,
}

impl Why {
    const ALL: [Self; 6] = [
        Self::Namespace,
        Self::Tampered,
        Self::Malformed,
        Self::UntrustedKey,
        Self::WrongPrincipal,
        Self::Unknown,
    ];

    const fn code(self) -> &'static str {
        match self {
            Self::Namespace => "wrong-namespace",
            Self::Tampered => "bytes-do-not-match",
            Self::Malformed => "malformed-signature",
            Self::UntrustedKey => "untrusted-key",
            Self::WrongPrincipal => "wrong-principal",
            Self::Unknown => "unknown",
        }
    }

    const fn advice(self) -> &'static str {
        match self {
            Self::Namespace => {
                "the signature was made for a different namespace; sign again with `ssh-keygen -Y sign -n hallpass-approval-v1`"
            }
            Self::Tampered => {
                "the signature does not match these exact bytes: the pass file was changed after signing, or another file was signed; sign the exact file again, or restore the signed bytes"
            }
            Self::Malformed => {
                "the signature file could not be read as an SSH signature; check that --signature names the .sig file that ssh-keygen wrote"
            }
            Self::UntrustedKey => {
                "the signing key is not in the trusted signers file; ask the owner for their public key through a channel you trust and add a `principal key` line, or use the right trust file"
            }
            Self::WrongPrincipal => {
                "the key is trusted, but for a different principal than the one expected; check the principal name against the trusted signers file"
            }
            Self::Unknown => {
                "check the signed bytes, signature namespace, expected principal and trusted signers"
            }
        }
    }

    /// The advice for a signature that an audit verified again, from the
    /// archive, with the auditor's trusted signers file.
    const fn audit_advice(self) -> &'static str {
        match self {
            Self::Namespace => {
                "the recorded signature was made for another namespace than hallpass-approval-v1, so it does not approve a pass"
            }
            Self::Tampered => {
                "the recorded signature does not match these archived bytes, for example because it was copied from another revision"
            }
            Self::Malformed => "the archived .sig file could not be read as an SSH signature",
            Self::UntrustedKey => {
                "the key that made the recorded signature is not in the trusted signers file you supplied; check that it is the right file"
            }
            Self::WrongPrincipal => {
                "the key is in the trusted signers file you supplied, but not for the principal checked (--principal, else the one the record names)"
            }
            Self::Unknown => {
                "check the archived bytes, the archived signature and the trusted signers file you supplied"
            }
        }
    }
}

/// What a `reason` code of a signature an audit verified again means, and
/// what to do about it.
pub fn audit_advice(code: &str) -> &'static str {
    Why::ALL
        .into_iter()
        .find(|why| why.code() == code)
        .unwrap_or(Why::Unknown)
        .audit_advice()
}

/// The audits' `--allowed-signers` and `--principal`.
#[derive(clap::Args)]
pub struct SignatureArgs {
    /// Your own trusted OpenSSH allowed-signers file. The audit runs `ssh-keygen -Y verify` again for every recorded signature with it. Without it, no revision is signature-verified and the audit is never complete.
    #[arg(long)]
    allowed_signers: Option<PathBuf>,
    /// Require every recorded signature to verify for this principal, instead of the principal its record names.
    #[arg(long, requires = "allowed_signers")]
    principal: Option<String>,
}

impl SignatureArgs {
    /// Run `audit`, verifying every recorded signature again when
    /// `--allowed-signers` was given. The trusted signers file is read once
    /// here: the verifier gets a copy of those bytes, and the audit reports
    /// their digest.
    pub fn reverifying<T>(
        &self,
        audit: impl FnOnce(Option<Reverify<'_>>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let Some(trust) = &self.allowed_signers else {
            return audit(None);
        };
        let principal = self.principal.as_deref();
        if principal.is_some_and(|p| p.trim().is_empty() || p.chars().any(char::is_control)) {
            return Err(Error::Usage(
                "provide a nonblank single-line signer principal".into(),
            ));
        }
        let trust = read_input(trust, MAX_TRUST_BYTES)?;
        // Made at the first recorded signature, so that an audit with none
        // needs no temporary directory.
        let mut verifier: Option<Verifier> = None;
        let mut check = |signed: &SignatureToCheck<'_>| {
            let verifier = match &mut verifier {
                Some(verifier) => verifier,
                None => verifier.insert(Verifier::new(&trust)?),
            };
            let verdict = verifier.verify(signed.bytes, signed.signature, signed.principal)?;
            Ok(verdict.map_or_else(|why| Recheck::Rejected(why.code()), |()| Recheck::Verified))
        };
        audit(Some(Reverify {
            allowed_signers: Digest::of(&trust),
            principal,
            check: &mut check,
        }))
    }
}

/// Look at ssh-keygen's complaint, and when it says nothing useful, ask
/// `find-principals` whether the key is trusted at all. The result code does
/// not depend on this: the caller has already seen the failure.
fn classify(stderr: &str, signature: &Path, trust: &Path, principal: &str) -> Why {
    if stderr.contains("namespace does not match") {
        return Why::Namespace;
    }
    if stderr.contains("incorrect signature") {
        return Why::Tampered;
    }
    if stderr.contains("Couldn't parse signature")
        || stderr.contains("sshsig_armor")
        || stderr.contains("missing header")
    {
        return Why::Malformed;
    }
    let found = Command::new("ssh-keygen")
        .args(["-Y", "find-principals", "-f"])
        .arg(trust)
        .arg("-s")
        .arg(signature)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match found {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.lines().any(|l| l.trim() == principal) {
                Why::Unknown
            } else {
                Why::WrongPrincipal
            }
        }
        Ok(out) if out.status.code().is_some() => Why::UntrustedKey,
        _ => Why::Unknown,
    }
}

/// Run ssh-keygen over `bytes`, with the signature and trusted signers files
/// that a [`Verifier`] wrote.
fn verified(
    bytes: &[u8],
    signature: &Path,
    trust: &Path,
    principal: &str,
) -> Result<Result<(), Why>, Error> {
    if principal.trim().is_empty() || principal.chars().any(char::is_control) {
        return Err(Error::Usage(
            "provide a nonblank single-line signer principal".into(),
        ));
    }
    let mut verifier = Command::new("ssh-keygen");
    verifier
        .args(["-Y", "verify", "-n", NAMESPACE, "-I", principal])
        .arg("-f")
        .arg(trust)
        .arg("-s")
        .arg(signature)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = verifier.spawn().map_err(|e| Error::Io {
        path: "ssh-keygen".into(),
        message: format!("cannot run OpenSSH ssh-keygen ({e}). Install OpenSSH with SSH signature support and check PATH"),
    })?;
    let write = child
        .stdin
        .take()
        .expect("requested piped stdin")
        .write_all(bytes);
    // Keep the first 16 KiB for the reason, and drain the rest so that
    // ssh-keygen never blocks on a full pipe while we wait for it.
    let stderr = child.stderr.take().map_or_else(String::new, |mut pipe| {
        let mut raw = Vec::new();
        let _ = (&mut pipe).take(16 * 1024).read_to_end(&mut raw);
        let _ = io::copy(&mut pipe, &mut io::sink());
        String::from_utf8_lossy(&raw).into_owned()
    });
    let status = child.wait().map_err(|e| Error::Io {
        path: "ssh-keygen".into(),
        message: e.to_string(),
    })?;
    if let Err(e) = write
        && (status.success() || e.kind() != io::ErrorKind::BrokenPipe)
    {
        return Err(Error::Io {
            path: "ssh-keygen".into(),
            message: format!("writing approval to verifier: {e}"),
        });
    }
    if status.code().is_none() {
        return Err(Error::Io {
            path: "ssh-keygen".into(),
            message: format!("signature verifier terminated: {status}"),
        });
    }
    // An ssh-keygen without SSH signature support rejects `-Y` and prints its
    // usage. That is an unusable verifier, not an unverified signature.
    if !status.success()
        && (stderr.contains("usage: ssh-keygen") || stderr.contains("unknown option"))
    {
        return Err(Error::Io {
            path: "ssh-keygen".into(),
            message: "ssh-keygen did not accept `-Y verify` and printed its usage. Install OpenSSH with SSH signature support and check PATH".into(),
        });
    }
    if status.success() {
        Ok(Ok(()))
    } else {
        Ok(Err(classify(&stderr, signature, trust, principal)))
    }
}

pub fn verify_approval(
    path: &Path,
    signature: &Path,
    trust: &Path,
    principal: &str,
    archive: Option<&Path>,
) -> Output {
    let (loaded, bytes) = match hallpass::load_with_bytes(path) {
        Ok(value) => value,
        Err(e) => return error_output("verify-approval", Some(path), &e),
    };
    // Read the inputs once: ssh-keygen verifies copies of these bytes, and
    // --archive records them.
    let inputs = match Inputs::read(signature, trust) {
        Ok(inputs) => inputs,
        Err(e) => return error_output("verify-approval", Some(path), &e),
    };
    match inputs.verify(&bytes, principal) {
        Ok(Ok(())) => {
            let (digest, record) = match archive {
                Some(directory) => match retain(&bytes, &inputs, principal, directory) {
                    Ok((digest, record)) => (digest, Some(record)),
                    Err(e) => return error_output("verify-approval", Some(path), &e),
                },
                None => (loaded.digest, None),
            };
            let mut warnings = Vec::new();
            if let Some(ArchivedSignature::KeptEarlier(kept)) = &record {
                warnings.push(format!(
                    "the archive already held a different signature record for these bytes (principal {}); it was kept, and this signature was not stored",
                    quoted(&kept.principal)
                ));
            }
            let approval = record.as_ref().map(ArchivedSignature::approval);
            Output {
                code: OK,
                text: format!(
                    "Verified signature from {} over pass {} ({}).{} Supply this digest for the live policy check.\n",
                    quoted(principal),
                    loaded.pass.id,
                    digest,
                    archive.map_or(String::new(), |dir| format!(
                        " Retained the exact bytes and a signature record in {}.",
                        safe(&dir.display().to_string())
                    ))
                ),
                json: json!({"command":"verify-approval","result":"verified","principal":principal,"pass_id":loaded.pass.id,"digest":digest.to_string(),"namespace":NAMESPACE,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string()),"provenance":approval.map(|_| "signature-recorded"),"approval":approval,"warnings":warnings}),
            }
        }
        Ok(Err(why)) => Output {
            code: REFUSED,
            text: format!(
                "Unverified signature for {}: {}.\n",
                quoted(principal),
                why.advice()
            ),
            json: json!({"command":"verify-approval","result":"unverified","reason":why.code(),"next_step":why.advice(),"expected_principal":principal,"namespace":NAMESPACE,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string()),"provenance":null,"approval":null}),
        },
        Err(e) => error_output("verify-approval", Some(path), &e),
    }
}
