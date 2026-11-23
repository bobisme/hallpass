//! Verify a detached approval signature using the installed OpenSSH verifier.
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{OK, Output, REFUSED, error_output, safe};
use hallpass::{APPROVAL_NAMESPACE as NAMESPACE, ArchivedSignature, Digest, Error};
use serde_json::json;

/// The largest trusted signers file `verify-approval --archive` digests.
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

/// The bytes of a signature or trust file, read once through the same path
/// that the verifier is given.
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

/// The signature and trust file as they were before and after verification.
/// A change in between means the record could name bytes ssh-keygen never saw.
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
}

/// Retain the verified bytes and the signature that verified over them.
fn retain(
    bytes: &[u8],
    before: &Inputs,
    signature: &Path,
    trust: &Path,
    principal: &str,
    directory: &Path,
) -> Result<(Digest, ArchivedSignature), Error> {
    let after = Inputs::read(signature, trust)?;
    if after.signature != before.signature || after.trust != before.trust {
        return Err(Error::Usage(
            "the signature or trusted signers file changed while it was verified; nothing was recorded for it. Run verify-approval again".into(),
        ));
    }
    let digest = hallpass::archive_pass_bytes(bytes, directory)?;
    let record = hallpass::archive_verified_signature(
        directory,
        digest,
        &before.signature,
        principal,
        Digest::of(&before.trust),
    )?;
    Ok((digest, record))
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
    let Ok(trust) = input_path(trust) else {
        return Why::Unknown;
    };
    let Ok(signature) = input_path(signature) else {
        return Why::Unknown;
    };
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
        .arg(input_path(trust)?)
        .arg("-s")
        .arg(input_path(signature)?)
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
    // With --archive, read the inputs before ssh-keygen does, to record them.
    let before = match archive.map(|_| Inputs::read(signature, trust)).transpose() {
        Ok(inputs) => inputs,
        Err(e) => return error_output("verify-approval", Some(path), &e),
    };
    match verified(&bytes, signature, trust, principal) {
        Ok(Ok(())) => {
            let (digest, record) = match (archive, &before) {
                (Some(directory), Some(before)) => {
                    match retain(&bytes, before, signature, trust, principal, directory) {
                        Ok((digest, record)) => (digest, Some(record)),
                        Err(e) => return error_output("verify-approval", Some(path), &e),
                    }
                }
                _ => (loaded.digest, None),
            };
            let mut warnings = Vec::new();
            if let Some(ArchivedSignature::KeptEarlier(kept)) = &record {
                warnings.push(format!(
                    "the archive already held a different verified signature record for these bytes (principal {:?}); it was kept, and this signature was not stored",
                    kept.principal
                ));
            }
            let approval = record.as_ref().map(ArchivedSignature::approval);
            Output {
                code: OK,
                text: format!(
                    "Verified signature from {} over pass {} ({}).{} Supply this digest for the live policy check.\n",
                    safe(principal),
                    loaded.pass.id,
                    digest,
                    archive.map_or(String::new(), |dir| format!(
                        " Retained the exact bytes and a signature record in {}.",
                        safe(&dir.display().to_string())
                    ))
                ),
                json: json!({"command":"verify-approval","result":"verified","principal":principal,"pass_id":loaded.pass.id,"digest":digest.to_string(),"namespace":NAMESPACE,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string()),"provenance":approval.map(|_| "signature-verified"),"approval":approval,"warnings":warnings}),
            }
        }
        Ok(Err(why)) => Output {
            code: REFUSED,
            text: format!(
                "Unverified signature for {}: {}.\n",
                safe(principal),
                why.advice()
            ),
            json: json!({"command":"verify-approval","result":"unverified","reason":why.code(),"next_step":why.advice(),"expected_principal":principal,"namespace":NAMESPACE,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string()),"provenance":null,"approval":null}),
        },
        Err(e) => error_output("verify-approval", Some(path), &e),
    }
}
