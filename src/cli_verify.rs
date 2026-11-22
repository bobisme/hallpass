//! Verify a detached approval signature using the installed OpenSSH verifier.
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{OK, Output, REFUSED, error_output, safe};
use hallpass::Error;
use serde_json::json;

const NAMESPACE: &str = "hallpass-approval-v1";

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

fn verified(bytes: &[u8], signature: &Path, trust: &Path, principal: &str) -> Result<bool, Error> {
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
        .stderr(Stdio::null());
    let mut child = verifier.spawn().map_err(|e| Error::Io {
        path: "ssh-keygen".into(),
        message: format!("cannot run OpenSSH ssh-keygen ({e}). Install OpenSSH with SSH signature support and check PATH"),
    })?;
    let write = child
        .stdin
        .take()
        .expect("requested piped stdin")
        .write_all(bytes);
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
    Ok(status.success())
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
    match verified(&bytes, signature, trust, principal) {
        Ok(true) => {
            let digest = if let Some(directory) = archive {
                match hallpass::archive_pass_bytes(&bytes, directory) {
                    Ok(digest) => digest,
                    Err(e) => return error_output("verify-approval", Some(path), &e),
                }
            } else {
                loaded.digest
            };
            Output {
                code: OK,
                text: format!(
                    "Verified signature from {} over pass {} ({}).{} Supply this digest for the live policy check.\n",
                    safe(principal),
                    loaded.pass.id,
                    digest,
                    archive.map_or(String::new(), |dir| format!(
                        " Retained exact bytes in {}.",
                        safe(&dir.display().to_string())
                    ))
                ),
                json: json!({"command":"verify-approval","result":"verified","principal":principal,"pass_id":loaded.pass.id,"digest":digest.to_string(),"namespace":NAMESPACE,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string())}),
            }
        }
        Ok(false) => Output {
            code: REFUSED,
            text: format!(
                "Unverified signature for {}. Check the signed bytes, signature namespace, expected principal and trusted signers.\n",
                safe(principal)
            ),
            json: json!({"command":"verify-approval","result":"unverified","expected_principal":principal,"namespace":NAMESPACE,"file":path.display().to_string(),"archive":archive.map(|dir|dir.display().to_string())}),
        },
        Err(e) => error_output("verify-approval", Some(path), &e),
    }
}
