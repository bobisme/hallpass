//! Explicit retention and retrieval of the exact approved pass bytes, and of
//! the owner signatures that `verify-approval --archive` verified over them.
//!
//! An archive directory holds, per pass digest `D`:
//!
//! - `D`: the exact pass bytes (`archive` and `verify-approval --archive`);
//! - `D.sig`: the detached signature that verified over them, and
//!   `D.approval`: a one-line JSON record of that verification (only
//!   `verify-approval --archive` writes these two).
//!
//! Every file is created once and never replaced, so a later `archive` of the
//! same bytes cannot remove or downgrade a signature record.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize, Serializer};

use crate::error::Error;
use crate::files::{Digest, MAX_PASS_BYTES, open_no_follow, read_pass_bytes};
use crate::pass::Pass;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// The SSH signature namespace of an owner's approval of a pass.
pub const APPROVAL_NAMESPACE: &str = "hallpass-approval-v1";

/// The largest detached signature or signature record the archive keeps.
pub const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;

const RECORD_VERSION: u32 = 1;

fn directory(dir: &Path) -> Result<fs::File, Error> {
    let meta = fs::symlink_metadata(dir).map_err(|e| Error::io(dir, &e))?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(Error::Usage(format!(
            "archive {} must be a real directory",
            dir.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Insecure {
            path: dir.to_path_buf(),
            mode: meta.mode() & 0o7777,
            who: "other users can read or change archived approvals",
            fix: "700",
            advice: "check that nothing in this directory was changed by someone else",
        });
    }
    let file = fs::File::open(dir).map_err(|e| Error::io(dir, &e))?;
    let opened = file.metadata().map_err(|e| Error::io(dir, &e))?;
    if opened.dev() != meta.dev() || opened.ino() != meta.ino() || opened.mode() & 0o077 != 0 {
        return Err(Error::Usage(
            "archive directory changed or is insecure".into(),
        ));
    }
    Ok(file)
}

/// Check that `dir` is an existing real, private archive directory, with the
/// same checks `retrieve` and `archive` make.
///
/// # Errors
/// If the path is missing, is not a directory, or is not private.
pub fn check_directory(dir: &Path) -> Result<(), Error> {
    directory(dir).map(drop)
}

fn destination(dir: &Path, digest: Digest) -> PathBuf {
    dir.join(digest.to_string())
}

/// Where the archive keeps the detached signature of `digest` (`DIGEST.sig`).
fn signature_path(dir: &Path, digest: Digest) -> PathBuf {
    dir.join(format!("{digest}.sig"))
}

fn record_path(dir: &Path, digest: Digest) -> PathBuf {
    dir.join(format!("{digest}.approval"))
}

fn present(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(path, &e)),
    }
}

/// Read a private regular archive file of at most `limit` bytes, without
/// following a link.
fn read_private(path: &Path, limit: u64, advice: &'static str) -> Result<Vec<u8>, Error> {
    let file = open_no_follow(path, OpenOptions::new().read(true))?;
    let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Insecure {
            path: path.to_path_buf(),
            mode: meta.mode() & 0o7777,
            who: "other users can read or change archived approvals",
            fix: "600",
            advice,
        });
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(path, &e))?;
    if bytes.len() as u64 > limit {
        return Err(Error::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(bytes)
}

/// Archive one validated byte snapshot in an existing private directory.
/// Existing entries are accepted only when their exact bytes agree.
///
/// # Errors
/// If the pass or directory is unusable, or a conflicting file exists.
pub fn archive_pass(pass: &Path, dir: &Path) -> Result<Digest, Error> {
    let bytes = read_pass_bytes(pass)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Usage("pass is not UTF-8".into()))?;
    Pass::parse(text).map_err(|problems| Error::Invalid {
        path: pass.to_path_buf(),
        problems,
    })?;
    publish_bytes(&bytes, dir)
}

/// Archive an already loaded pass snapshot in an existing private directory.
/// The bytes are validated again so callers cannot retain malformed pass data.
///
/// # Errors
///
/// If the bytes do not parse as a pass, the directory is insecure or
/// unavailable, or an existing content-addressed entry conflicts.
pub fn archive_pass_bytes(bytes: &[u8], dir: &Path) -> Result<Digest, Error> {
    if bytes.len() as u64 > MAX_PASS_BYTES {
        return Err(Error::TooLarge {
            path: "<bytes>".into(),
            limit: MAX_PASS_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Usage("pass is not UTF-8".into()))?;
    Pass::parse(text).map_err(|problems| Error::Invalid {
        path: "<bytes>".into(),
        problems,
    })?;
    publish_bytes(bytes, dir)
}

fn publish_bytes(bytes: &[u8], dir: &Path) -> Result<Digest, Error> {
    let digest = Digest::of(bytes);
    if publish(dir, &destination(dir, digest), bytes, || {
        retrieve_pass(dir, digest)
    })? {
        Ok(digest)
    } else {
        Err(Error::Usage(
            "archive entry conflicts with this snapshot".into(),
        ))
    }
}

/// Create `target` with exactly `bytes`, once. Returns false, and leaves the
/// file alone, when it already holds other bytes (as `existing` reads them).
fn publish(
    dir: &Path,
    target: &Path,
    bytes: &[u8],
    existing: impl FnOnce() -> Result<Vec<u8>, Error>,
) -> Result<bool, Error> {
    let directory_file = directory(dir)?;
    let temp = dir.join(format!(
        ".hallpass-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| Error::io(&temp, &e))?;
    let result = (|| {
        file.write_all(bytes).map_err(|e| Error::io(&temp, &e))?;
        file.sync_all().map_err(|e| Error::io(&temp, &e))?;
        match fs::hard_link(&temp, target) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(existing()? == bytes),
            Err(e) => Err(Error::io(target, &e)),
        }
    })();
    let _ = fs::remove_file(&temp);
    let same = result?;
    if same {
        directory_file.sync_all().map_err(|e| Error::io(dir, &e))?;
    }
    Ok(same)
}

/// Return archived bytes only after checking their full digest and file mode.
///
/// # Errors
/// If the entry is missing, insecure, damaged, or unreadable.
pub fn retrieve_pass(dir: &Path, digest: Digest) -> Result<Vec<u8>, Error> {
    let _directory_file = directory(dir)?;
    let path = destination(dir, digest);
    let bytes = read_private(
        &path,
        MAX_PASS_BYTES,
        "check that its content is the approved pass it was archived from",
    )?;
    if Digest::of(&bytes) != digest {
        return Err(Error::Usage(format!(
            "archive entry {} does not match its digest",
            path.display()
        )));
    }
    Ok(bytes)
}

fn digest_text<S: Serializer>(digest: &Digest, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(digest)
}

/// What `verify-approval --archive` recorded when an owner's detached SSH
/// signature verified over archived pass bytes.
///
/// The record says that the installed `ssh-keygen -Y verify` accepted
/// `signature` over those bytes for `principal`, under `namespace`, with the
/// trusted signers file whose digest is `allowed_signers`. Reading it does not
/// verify the signature again: anyone who can write the archive can write a
/// record. To check it independently, verify `DIGEST.sig` over the archived
/// bytes with a trusted signers file of your own, as the audits do with
/// `--allowed-signers` (see [`crate::evidence::Reverify`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignedApproval {
    /// The signer identity that was expected and verified.
    pub principal: String,
    /// The signature namespace, always [`APPROVAL_NAMESPACE`].
    pub namespace: String,
    /// The digest of the trusted signers file the signature verified against.
    #[serde(serialize_with = "digest_text")]
    pub allowed_signers: Digest,
    /// The digest of the detached signature, kept as `DIGEST.sig`.
    #[serde(serialize_with = "digest_text")]
    pub signature: Digest,
}

/// The on-disk form of [`SignedApproval`], one JSON line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    version: u32,
    digest: String,
    namespace: String,
    principal: String,
    allowed_signers: String,
    signature: String,
}

/// How the archived bytes of one pass digest got there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// The archive holds no bytes for this digest.
    Missing,
    /// The bytes are archived without a signature record: `archive` stored
    /// them, or `verify-approval --archive` stopped before it recorded the
    /// signature.
    Unsigned,
    /// The bytes are archived with a signature record and the signature it
    /// names, as `verify-approval --archive` keeps them after the signature
    /// verified. Reading the record does not verify the signature again.
    SignatureRecorded(SignedApproval),
}

impl Provenance {
    /// `missing`, `unsigned` or `signature-recorded`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unsigned => "unsigned",
            Self::SignatureRecorded(_) => "signature-recorded",
        }
    }

    /// The signature record, for [`Provenance::SignatureRecorded`].
    #[must_use]
    pub const fn approval(&self) -> Option<&SignedApproval> {
        match self {
            Self::SignatureRecorded(approval) => Some(approval),
            Self::Missing | Self::Unsigned => None,
        }
    }
}

fn valid_principal(principal: &str) -> bool {
    !principal.trim().is_empty() && !principal.chars().any(char::is_control)
}

fn damaged_record(path: &Path, why: &str) -> Error {
    Error::Usage(format!(
        "signature record {} is damaged ({why}); restore it from a copy, or remove it and its .sig and run verify-approval --archive again",
        path.display()
    ))
}

/// How the archived bytes of `digest` were retained, after checking the bytes
/// against their digest and any signature record against its signature file.
///
/// # Errors
/// If the directory, the bytes, the record or the signature file is unusable,
/// insecure or damaged.
pub fn archive_provenance(dir: &Path, digest: Digest) -> Result<Provenance, Error> {
    Ok(match read_revision(dir, digest)? {
        None => Provenance::Missing,
        Some(ArchivedRevision { signed: None, .. }) => Provenance::Unsigned,
        Some(ArchivedRevision {
            signed: Some((approval, _)),
            ..
        }) => Provenance::SignatureRecorded(approval),
    })
}

/// One archived revision, as one read of the archive found it.
pub struct ArchivedRevision {
    /// The exact bytes, checked against their digest.
    pub bytes: Vec<u8>,
    /// The signature record and the bytes of the `.sig` file beside it,
    /// checked against the record's `signature` digest. None without a record.
    pub signed: Option<(SignedApproval, Vec<u8>)>,
}

/// Read the archived revision `digest` once: its bytes, and its signature
/// record with the signature the record names. None when the archive does
/// not hold the bytes. The audits verify these bytes again, not the files.
///
/// # Errors
/// As [`archive_provenance`].
pub fn read_revision(dir: &Path, digest: Digest) -> Result<Option<ArchivedRevision>, Error> {
    let _directory_file = directory(dir)?;
    if !present(&destination(dir, digest))? {
        return Ok(None);
    }
    let bytes = retrieve_pass(dir, digest)?;
    let path = record_path(dir, digest);
    if !present(&path)? {
        return Ok(Some(ArchivedRevision {
            bytes,
            signed: None,
        }));
    }
    let advice = "check that verify-approval wrote this signature record";
    let raw = read_private(&path, MAX_SIGNATURE_BYTES, advice)?;
    let record: RecordFile =
        serde_json::from_slice(&raw).map_err(|e| damaged_record(&path, &e.to_string()))?;
    let digest_field = |text: &str, name: &str| {
        text.parse::<Digest>()
            .map_err(|_| damaged_record(&path, &format!("`{name}` is not a digest")))
    };
    if record.version != RECORD_VERSION {
        return Err(damaged_record(
            &path,
            &format!("unknown version {}", record.version),
        ));
    }
    if digest_field(&record.digest, "digest")? != digest {
        return Err(damaged_record(&path, "it names another digest"));
    }
    if record.namespace != APPROVAL_NAMESPACE {
        return Err(damaged_record(&path, "unknown namespace"));
    }
    if !valid_principal(&record.principal) {
        return Err(damaged_record(&path, "blank or multi-line principal"));
    }
    let approval = SignedApproval {
        allowed_signers: digest_field(&record.allowed_signers, "allowed_signers")?,
        signature: digest_field(&record.signature, "signature")?,
        principal: record.principal,
        namespace: record.namespace,
    };
    let signature = read_private(&signature_path(dir, digest), MAX_SIGNATURE_BYTES, advice)?;
    if Digest::of(&signature) != approval.signature {
        return Err(damaged_record(
            &path,
            "the .sig file beside it is not the signature it records",
        ));
    }
    Ok(Some(ArchivedRevision {
        bytes,
        signed: Some((approval, signature)),
    }))
}

/// What [`archive_verified_signature`] left in the archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchivedSignature {
    /// This verification is recorded (now, or by an identical earlier run).
    Recorded(SignedApproval),
    /// An earlier, different signature record for the same bytes was kept
    /// unchanged, and this one was not stored. The bytes keep that record.
    KeptEarlier(SignedApproval),
}

impl ArchivedSignature {
    /// The record now in the archive.
    #[must_use]
    pub const fn approval(&self) -> &SignedApproval {
        match self {
            Self::Recorded(approval) | Self::KeptEarlier(approval) => approval,
        }
    }
}

/// Record that `signature` verified over the archived bytes of `digest` for
/// `principal`, with the trusted signers file whose digest is
/// `allowed_signers`. The bytes must already be archived.
///
/// This function does not verify anything: call it only after the signature
/// verified over exactly those bytes, as `verify-approval --archive` does. A
/// record is never replaced, so the first verified signature of a digest stays.
///
/// # Errors
/// If the bytes are not archived, an input is unusable, the archive is
/// insecure or damaged, or an earlier run left a different signature without
/// a record.
pub fn archive_verified_signature(
    dir: &Path,
    digest: Digest,
    signature: &[u8],
    principal: &str,
    allowed_signers: Digest,
) -> Result<ArchivedSignature, Error> {
    if !valid_principal(principal) {
        return Err(Error::Usage(
            "provide a nonblank single-line signer principal".into(),
        ));
    }
    if signature.len() as u64 > MAX_SIGNATURE_BYTES {
        return Err(Error::TooLarge {
            path: "<signature>".into(),
            limit: MAX_SIGNATURE_BYTES,
        });
    }
    let approval = SignedApproval {
        principal: principal.to_owned(),
        namespace: APPROVAL_NAMESPACE.to_owned(),
        allowed_signers,
        signature: Digest::of(signature),
    };
    let kept = |existing: SignedApproval| {
        if existing == approval {
            ArchivedSignature::Recorded(existing)
        } else {
            ArchivedSignature::KeptEarlier(existing)
        }
    };
    match archive_provenance(dir, digest)? {
        Provenance::Missing => {
            return Err(Error::Usage(format!(
                "archive the bytes of {digest} before recording their signature"
            )));
        }
        Provenance::SignatureRecorded(existing) => return Ok(kept(existing)),
        Provenance::Unsigned => (),
    }
    let advice = "check that verify-approval wrote this signature";
    let sig = signature_path(dir, digest);
    if !publish(dir, &sig, signature, || {
        read_private(&sig, MAX_SIGNATURE_BYTES, advice)
    })? {
        return Err(Error::Usage(format!(
            "{} holds another signature without a record: an earlier verification stopped before it finished. Check that file, remove it, then run verify-approval --archive again",
            sig.display()
        )));
    }
    let mut line = serde_json::to_vec(&RecordFile {
        version: RECORD_VERSION,
        digest: digest.to_string(),
        namespace: approval.namespace.clone(),
        principal: approval.principal.clone(),
        allowed_signers: approval.allowed_signers.to_string(),
        signature: approval.signature.to_string(),
    })
    .map_err(|e| Error::Usage(format!("cannot encode the signature record: {e}")))?;
    line.push(b'\n');
    if line.len() as u64 > MAX_SIGNATURE_BYTES {
        return Err(Error::TooLarge {
            path: "<signature record>".into(),
            limit: MAX_SIGNATURE_BYTES,
        });
    }
    let path = record_path(dir, digest);
    if publish(dir, &path, &line, || {
        read_private(&path, MAX_SIGNATURE_BYTES, advice)
    })? {
        return Ok(ArchivedSignature::Recorded(approval));
    }
    // Another run recorded the same signature with another principal or trust
    // file first. Keep its record.
    match archive_provenance(dir, digest)? {
        Provenance::SignatureRecorded(existing) => Ok(kept(existing)),
        Provenance::Missing | Provenance::Unsigned => Err(damaged_record(&path, "unreadable")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::tests::GOOD;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn exact_revisions_and_conflicts() {
        let temp = tempfile::tempdir().expect("directory");
        let archive = temp.path().join("archive");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("mode");
        let pass = temp.path().join("pass");
        fs::write(&pass, GOOD).expect("pass");
        let a = archive_pass(&pass, &archive).expect("archive");
        assert_eq!(archive_pass(&pass, &archive).expect("repeat"), a);
        fs::write(&pass, format!("{GOOD}\n# edited comment\n")).expect("edit");
        let b = archive_pass(&pass, &archive).expect("archive edited");
        assert_ne!(a, b);
        assert_eq!(
            retrieve_pass(&archive, a).expect("original"),
            GOOD.as_bytes()
        );
        fs::write(destination(&archive, b), b"damaged").expect("damage");
        assert!(retrieve_pass(&archive, b).is_err());
        assert!(archive_pass(&pass, &archive).is_err());
    }
    #[test]
    fn concurrent_creators_and_private_path_checks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().expect("directory");
        let archive = temp.path().join("archive");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("mode");
        let pass = temp.path().join("pass");
        fs::write(&pass, GOOD).expect("pass");
        let (first, second) = std::thread::scope(|scope| {
            let a = scope.spawn(|| archive_pass(&pass, &archive));
            let b = scope.spawn(|| archive_pass(&pass, &archive));
            (a.join().expect("thread"), b.join().expect("thread"))
        });
        let digest = first.expect("first");
        assert_eq!(second.expect("second"), digest);
        assert_eq!(
            retrieve_pass(&archive, digest).expect("retrieve"),
            GOOD.as_bytes()
        );
        let link = temp.path().join("archive-link");
        symlink(&archive, &link).expect("link");
        assert!(archive_pass(&pass, &link).is_err());
        assert!(retrieve_pass(&link, digest).is_err());
        fs::remove_file(destination(&archive, digest)).expect("remove");
        symlink(&pass, destination(&archive, digest)).expect("link");
        assert!(archive_pass(&pass, &archive).is_err());
        assert!(retrieve_pass(&archive, digest).is_err());
        fs::remove_file(destination(&archive, digest)).expect("remove");
        fs::write(destination(&archive, digest), b"conflict").expect("conflict");
        fs::set_permissions(
            destination(&archive, digest),
            fs::Permissions::from_mode(0o600),
        )
        .expect("mode");
        assert!(archive_pass(&pass, &archive).is_err());
        assert_eq!(
            fs::read(destination(&archive, digest)).expect("conflict"),
            b"conflict"
        );
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(archive_pass(&pass, &archive).is_err());
    }

    #[test]
    fn concurrent_input_replacement_yields_one_valid_snapshot_or_error() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let temp = tempfile::tempdir().expect("directory");
        let archive = temp.path().join("archive");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("mode");
        let pass = temp.path().join("pass");
        fs::write(&pass, GOOD).expect("pass");
        let alternate = format!("{GOOD}\n# alternate\n");
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let staged = temp.path().join("staged");
                while !stop.load(Ordering::Relaxed) {
                    fs::write(&staged, &alternate).expect("stage");
                    fs::rename(&staged, &pass).expect("replace");
                    fs::write(&staged, GOOD).expect("stage");
                    fs::rename(&staged, &pass).expect("replace");
                }
            });
            for _ in 0..50 {
                if let Ok(digest) = archive_pass(&pass, &archive) {
                    let bytes = retrieve_pass(&archive, digest).expect("retrieve");
                    assert!(bytes == GOOD.as_bytes() || bytes == alternate.as_bytes());
                    assert_eq!(Digest::of(&bytes), digest);
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
    }
}
