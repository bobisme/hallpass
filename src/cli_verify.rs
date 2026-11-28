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
use hallpass::evidence::{AsOf, Recheck, Reverify, SignatureToCheck};
use hallpass::time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use hallpass::{APPROVAL_NAMESPACE as NAMESPACE, ArchivedSignature, Digest, Error};
use serde_json::json;

/// The largest trusted signers file `verify-approval --archive` and the
/// audits digest.
const MAX_TRUST_BYTES: u64 = 16 * 1024 * 1024;

/// The bytes of a signature or trust file, read once. It is opened as a pass
/// is: never through a link, only a regular file, without blocking on a FIFO.
/// A trusted signers file must also pass the pass file's owner and mode rule.
fn read_input(path: &Path, limit: u64, trusted: bool) -> Result<Vec<u8>, Error> {
    // An absolute name also keeps a literal "-" from acquiring stdin semantics.
    let full = std::path::absolute(path).map_err(|e| Error::Io {
        path: path.into(),
        message: e.to_string(),
    })?;
    let io = |e: &io::Error| Error::Io {
        path: full.clone(),
        message: e.to_string(),
    };
    let mut bytes = Vec::new();
    let file = if trusted {
        hallpass::open_trusted_signers(&full)?
    } else {
        hallpass::open_input(&full)?
    };
    file.take(limit + 1)
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
            signature: read_input(signature, hallpass::MAX_SIGNATURE_BYTES, false)?,
            trust: read_input(trust, MAX_TRUST_BYTES, true)?,
        })
    }

    fn verify(
        &self,
        bytes: &[u8],
        principal: &str,
        at: Option<OffsetDateTime>,
    ) -> Result<Result<(), Why>, Error> {
        Verifier::new(&self.trust)?.verify(bytes, &self.signature, principal, at)
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
            .and_then(|mut file| hallpass_write(&mut file, bytes))
            .map_err(|e| Error::Io {
                path: path.clone(),
                message: format!("writing the signature verifier's input: {e}"),
            })?;
        Ok(path)
    }
}

/// Write `bytes` to a new empty scratch file, refusing first when they would
/// pass the file size limit (`ulimit -f`), whose `SIGXFSZ` would otherwise
/// end hallpass with no reply.
fn hallpass_write(file: &mut std::fs::File, bytes: &[u8]) -> io::Result<()> {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Fsize).current;
    if let Some(limit) = limit
        && u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit
    {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!(
                "{} bytes are past this process's file size limit of {limit} bytes (RLIMIT_FSIZE, `ulimit -f`)",
                bytes.len()
            ),
        ));
    }
    file.write_all(bytes)
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

    /// Verify `signature` over `bytes` for `principal`, as of `at` or else
    /// now. ssh-keygen reads `bytes` on its standard input and a copy of
    /// `signature` from the private directory.
    fn verify(
        &self,
        bytes: &[u8],
        signature: &[u8],
        principal: &str,
        at: Option<OffsetDateTime>,
    ) -> Result<Result<(), Why>, Error> {
        let signature = self.scratch.write("signature", signature)?;
        let verdict = verified(bytes, &signature, &self.trust, principal, at);
        let _ = std::fs::remove_file(&signature);
        verdict
    }
}

/// ssh-keygen's `-Overify-time` for `at`: UTC, to the second.
fn verify_time_option(at: OffsetDateTime) -> Result<String, Error> {
    let utc = at
        .checked_to_offset(UtcOffset::UTC)
        .filter(|utc| (1..=9999).contains(&utc.year()))
        .ok_or_else(|| {
            Error::Usage(format!(
                "cannot verify a signature as of {}: ssh-keygen takes a time in the years 0001 to 9999; supply a time in that range",
                hallpass::stamp(at)
            ))
        })?;
    Ok(format!(
        "-Overify-time={:04}{:02}{:02}{:02}{:02}{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    ))
}

/// Why a signature did not verify, as far as ssh-keygen's output shows.
#[derive(Clone, Copy)]
enum Why {
    Namespace,
    Tampered,
    Malformed,
    UntrustedKey,
    WrongPrincipal,
    NotValidAtTime,
    KeyNotForNamespace,
    Unknown,
}

impl Why {
    const ALL: [Self; 8] = [
        Self::Namespace,
        Self::Tampered,
        Self::Malformed,
        Self::UntrustedKey,
        Self::WrongPrincipal,
        Self::NotValidAtTime,
        Self::KeyNotForNamespace,
        Self::Unknown,
    ];

    const fn code(self) -> &'static str {
        match self {
            Self::Namespace => "wrong-namespace",
            Self::Tampered => "bytes-do-not-match",
            Self::Malformed => "malformed-signature",
            Self::UntrustedKey => "untrusted-key",
            Self::WrongPrincipal => "wrong-principal",
            Self::NotValidAtTime => "key-not-valid-at-time",
            Self::KeyNotForNamespace => "key-not-permitted-for-namespace",
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
            Self::NotValidAtTime => {
                "the key is trusted for this principal, but its valid-after or valid-before window in the trusted signers file does not include the verification time; check the window, or for an approval used in the past, verify with --at the time it was first used"
            }
            Self::KeyNotForNamespace => {
                "the key is trusted for this principal, but its line in the trusted signers file has a namespaces= option without hallpass-approval-v1; add hallpass-approval-v1 to that option if this key may approve passes"
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
                "the key is in the trusted signers file you supplied, but not for the principal checked (--principal, else the one the record names); if the record names the wrong principal, move DIGEST.sig and DIGEST.approval aside (a record is never replaced) and run verify-approval --archive again"
            }
            Self::NotValidAtTime => {
                "the key is in the trusted signers file you supplied for the principal checked, but its valid-after or valid-before window there does not include the time the signature was verified as of (verify_time); check the window, and keep a retired key's line with valid-before set, so that the revisions it signed before still verify"
            }
            Self::KeyNotForNamespace => {
                "the key is in the trusted signers file you supplied for the principal checked, but its namespaces= option there does not include hallpass-approval-v1, so it may not approve a pass; add hallpass-approval-v1 to that option if this key may approve passes"
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

/// The audits' `--allowed-signers`, `--principal` and `--signatures-as-of`.
#[derive(clap::Args)]
pub struct SignatureArgs {
    /// Your own trusted OpenSSH allowed-signers file: it decides whose keys count. The audit runs `ssh-keygen -Y verify` again for every recorded signature with it. Without it, no revision is signature-verified and the audit is never complete.
    #[arg(long)]
    allowed_signers: Option<PathBuf>,
    /// The owner's principal: it decides who must have approved. Every recorded signature must verify for it. Repeat it for an owner with several principals; a signature then verifies for any of them. Without it, each signature is verified for the principal its record names, and the audit is never complete.
    #[arg(long, requires = "allowed_signers", value_name = "PRINCIPAL")]
    principal: Vec<String>,
    /// Verify each signature as of `first-use` (the default: the time of the first ledger line decided under its revision) or `now`.
    #[arg(long, requires = "allowed_signers", value_enum, value_name = "WHEN")]
    signatures_as_of: Option<SignaturesAsOf>,
}

/// The values of `--signatures-as-of`.
#[derive(Clone, Copy, clap::ValueEnum)]
enum SignaturesAsOf {
    FirstUse,
    Now,
}

/// A principal that ssh-keygen can take: nonblank, on one line.
fn check_principal(principal: &str) -> Result<(), Error> {
    if principal.trim().is_empty() || principal.chars().any(char::is_control) {
        return Err(Error::Usage(
            "provide a nonblank single-line signer principal".into(),
        ));
    }
    Ok(())
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
        for principal in &self.principal {
            check_principal(principal)?;
        }
        let principals: Vec<&str> = self.principal.iter().map(String::as_str).collect();
        let as_of = match self.signatures_as_of {
            None | Some(SignaturesAsOf::FirstUse) => AsOf::FirstUse,
            // The real clock, to the second as ssh-keygen takes it: the
            // audits do not take the test clock.
            Some(SignaturesAsOf::Now) => {
                let now = OffsetDateTime::now_utc();
                AsOf::Instant(now.replace_nanosecond(0).unwrap_or(now))
            }
        };
        let trust = read_input(trust, MAX_TRUST_BYTES, true)?;
        // Made at the first recorded signature, so that an audit with none
        // needs no temporary directory.
        let mut verifier: Option<Verifier> = None;
        let mut check = |signed: &SignatureToCheck<'_>| {
            let verifier = match &mut verifier {
                Some(verifier) => verifier,
                None => verifier.insert(Verifier::new(&trust)?),
            };
            let verdict = verifier.verify(
                signed.bytes,
                signed.signature,
                signed.principal,
                Some(signed.as_of),
            )?;
            Ok(verdict.map_or_else(|why| Recheck::Rejected(why.code()), |()| Recheck::Verified))
        };
        audit(Some(Reverify {
            allowed_signers: Digest::of(&trust),
            principals: &principals,
            as_of,
            check: &mut check,
        }))
    }
}

/// Whether ssh-keygen said that a key matched but was not valid at the
/// verification time: outside its `valid-after`/`valid-before` window, or a
/// certificate outside its validity.
fn outside_window(stderr: &str) -> bool {
    ["key has expired", "key is not yet valid"]
        .iter()
        .any(|m| stderr.contains(m))
        || (stderr.contains("Certificate invalid")
            && (stderr.contains("expired") || stderr.contains("not yet valid")))
}

/// Look at ssh-keygen's complaint, and when it says nothing useful, ask
/// `find-principals`, as of the same time, whether the key is trusted at
/// all. The result code does not depend on this: the caller has already seen
/// the failure.
fn classify(
    stderr: &str,
    signature: &Path,
    trust: &Path,
    principal: &str,
    at: Option<&str>,
) -> Why {
    if stderr.contains("namespace does not match") {
        return Why::Namespace;
    }
    // The trust file's `namespaces=` option leaves out hallpass's namespace
    // for the only line that has this key and principal.
    if stderr.contains("not permitted for use in signature namespace") {
        return Why::KeyNotForNamespace;
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
    // ssh-keygen names the window only for a line that has both this key
    // and this principal.
    if outside_window(stderr) {
        return Why::NotValidAtTime;
    }
    let Ok(mut found) = ssh_keygen() else {
        return Why::Unknown;
    };
    let found = found
        .args(["-Y", "find-principals", "-f"])
        .arg(trust)
        .arg("-s")
        .arg(signature)
        .args(at)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
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
        // The key is in the file, but only for other principals, and not
        // valid at this time for them either: the principal is still wrong.
        Ok(out) if out.status.code().is_some() => {
            if outside_window(&String::from_utf8_lossy(&out.stderr)) {
                Why::WrongPrincipal
            } else {
                Why::UntrustedKey
            }
        }
        _ => Why::Unknown,
    }
}

/// The environment variable that names the `ssh-keygen` to run.
const SSH_KEYGEN_VARIABLE: &str = "HALLPASS_SSH_KEYGEN";

/// The `ssh-keygen` that verifies signatures: the absolute path in
/// `HALLPASS_SSH_KEYGEN` when it is set, else `ssh-keygen` on PATH. Whoever
/// controls hallpass's environment controls its verifier either way; the
/// variable lets a caller pin it without trusting every PATH directory.
fn ssh_keygen() -> Result<Command, Error> {
    let Some(pinned) = std::env::var_os(SSH_KEYGEN_VARIABLE) else {
        return Ok(Command::new("ssh-keygen"));
    };
    let pinned = PathBuf::from(pinned);
    if !pinned.is_absolute() {
        return Err(Error::Usage(format!(
            "{SSH_KEYGEN_VARIABLE} is {}, not an absolute path; set it to the absolute path of OpenSSH ssh-keygen, such as /usr/bin/ssh-keygen, or unset it to use ssh-keygen on PATH",
            quoted(&pinned.to_string_lossy())
        )));
    }
    Ok(Command::new(pinned))
}

/// The verifier's name for messages, and what to check when it fails.
fn verifier_name() -> (PathBuf, String) {
    std::env::var_os(SSH_KEYGEN_VARIABLE).map_or_else(
        || {
            (
                "ssh-keygen".into(),
                "check PATH, or set HALLPASS_SSH_KEYGEN to its absolute path".to_owned(),
            )
        },
        |pinned| {
            (
                PathBuf::from(pinned),
                format!("check {SSH_KEYGEN_VARIABLE}"),
            )
        },
    )
}

/// Run ssh-keygen over `bytes`, with the signature and trusted signers files
/// that a [`Verifier`] wrote.
fn verified(
    bytes: &[u8],
    signature: &Path,
    trust: &Path,
    principal: &str,
    at: Option<OffsetDateTime>,
) -> Result<Result<(), Why>, Error> {
    check_principal(principal)?;
    let at = at.map(verify_time_option).transpose()?;
    let mut verifier = ssh_keygen()?;
    let (program, check) = verifier_name();
    verifier
        .args(["-Y", "verify", "-n", NAMESPACE, "-I", principal])
        .arg("-f")
        .arg(trust)
        .arg("-s")
        .arg(signature)
        .args(&at)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = verifier.spawn().map_err(|e| Error::Io {
        path: program.clone(),
        message: format!("cannot run OpenSSH ssh-keygen ({e}). Install OpenSSH with SSH signature support and {check}"),
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
        path: program.clone(),
        message: e.to_string(),
    })?;
    if let Err(e) = write
        && (status.success() || e.kind() != io::ErrorKind::BrokenPipe)
    {
        return Err(Error::Io {
            path: program,
            message: format!("writing approval to verifier: {e}"),
        });
    }
    if status.code().is_none() {
        return Err(Error::Io {
            path: program,
            message: format!("signature verifier terminated: {status}"),
        });
    }
    // An older ssh-keygen does not know the time option, and names it. A
    // time it cannot take is an unusable verifier, not an unverified
    // signature.
    if !status.success() && at.is_some() && stderr.contains("verify-time") {
        return Err(Error::Io {
            path: program,
            message: format!(
                "ssh-keygen did not accept `-O verify-time`, so it cannot verify a signature as of a given time. Install an OpenSSH whose ssh-keygen supports `-O verify-time` and {check}"
            ),
        });
    }
    // An ssh-keygen without SSH signature support rejects `-Y` and prints its
    // usage. That is an unusable verifier, not an unverified signature.
    if !status.success()
        && (stderr.contains("usage: ssh-keygen") || stderr.contains("unknown option"))
    {
        return Err(Error::Io {
            path: program,
            message: format!(
                "ssh-keygen did not accept `-Y verify` and printed its usage. Install OpenSSH with SSH signature support and {check}"
            ),
        });
    }
    if status.success() {
        Ok(Ok(()))
    } else {
        Ok(Err(classify(
            &stderr,
            signature,
            trust,
            principal,
            at.as_deref(),
        )))
    }
}

/// `verify-approval --at`: an RFC 3339 instant with an offset.
fn parse_at(at: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(at, &Rfc3339).map_err(|_| {
        Error::Usage(format!(
            "--at is {}, not an RFC 3339 timestamp with an offset; supply one such as 2026-11-20T09:00:00Z, or leave --at out to verify as of now",
            quoted(at)
        ))
    })
}

pub fn verify_approval(
    path: &Path,
    signature: &Path,
    trust: &Path,
    principal: &str,
    archive: Option<&Path>,
    at: Option<&str>,
) -> Output {
    let at = match at.map(parse_at).transpose() {
        Ok(at) => at,
        Err(e) => return error_output("verify-approval", Some(path), &e),
    };
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
    // Null: as of now, by ssh-keygen's own clock.
    let verify_time = at.map(hallpass::rfc3339);
    let as_of = at.map_or_else(String::new, |at| format!(" as of {}", hallpass::stamp(at)));
    match inputs.verify(&bytes, principal, at) {
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
            // Only a kept record of ANOTHER principal fails: a re-signing by the
            // same principal leaves the archive naming the right one.
            let kept = match &record {
                Some(ArchivedSignature::KeptEarlier(kept)) if kept.principal != principal => {
                    Some(kept.principal.clone())
                }
                _ => None,
            };
            let earlier = matches!(&record, Some(ArchivedSignature::KeptEarlier(_)));
            let retained = match (&kept, archive) {
                (Some(other), Some(dir)) => {
                    let base = format!("{}/{digest}", dir.display());
                    format!(
                        " NOT stored: the archive in {} keeps the record of {}. To record this signature, move {} and {} aside, then run verify-approval --archive again.",
                        safe(&dir.display().to_string()),
                        quoted(other),
                        safe(&format!("{base}.sig")),
                        safe(&format!("{base}.approval"))
                    )
                }
                (None, Some(dir)) if earlier => format!(
                    " Retained the exact bytes in {}; the archive keeps an earlier signature record of {} for them.",
                    safe(&dir.display().to_string()),
                    quoted(principal)
                ),
                (None, Some(dir)) => format!(
                    " Retained the exact bytes and a signature record in {}.",
                    safe(&dir.display().to_string())
                ),
                _ => String::new(),
            };
            let provenance = match (&kept, approval) {
                (Some(_), _) => Some("signature-not-stored"),
                (None, Some(_)) => Some("signature-recorded"),
                (None, None) => None,
            };
            Output {
                // A signature the archive did not keep must fail a step that archives approvals.
                code: if kept.is_some() { REFUSED } else { OK },
                text: format!(
                    "Verified signature from {}{as_of} over pass {} ({}).{retained} Supply this digest for the live policy check.\n",
                    quoted(principal),
                    loaded.pass.id,
                    digest,
                ),
                json: json!({"command":"verify-approval","result":"verified","principal":principal,"pass_id":loaded.pass.id,"digest":digest.to_string(),"namespace":NAMESPACE,"verify_time":verify_time,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string()),"provenance":provenance,"approval":approval,"warnings":warnings}),
            }
        }
        Ok(Err(why)) => Output {
            code: REFUSED,
            text: format!(
                "Unverified signature for {}{as_of}: {}.\n",
                quoted(principal),
                why.advice()
            ),
            json: json!({"command":"verify-approval","result":"unverified","reason":why.code(),"next_step":why.advice(),"expected_principal":principal,"namespace":NAMESPACE,"verify_time":verify_time,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string()),"provenance":null,"approval":null}),
        },
        Err(e) => error_output("verify-approval", Some(path), &e),
    }
}
