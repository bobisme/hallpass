//! Explicit retention and retrieval of the exact approved pass bytes.
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::files::{Digest, MAX_PASS_BYTES, open_no_follow, read_pass_bytes};
use crate::pass::Pass;

static NEXT: AtomicU64 = AtomicU64::new(0);

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

fn destination(dir: &Path, digest: Digest) -> PathBuf {
    dir.join(digest.to_string())
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
    let directory_file = directory(dir)?;
    let digest = Digest::of(bytes);
    let target = destination(dir, digest);
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
        match fs::hard_link(&temp, &target) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if retrieve_pass(dir, digest)? == bytes {
                    Ok(())
                } else {
                    Err(Error::Usage(
                        "archive entry conflicts with this snapshot".into(),
                    ))
                }
            }
            Err(e) => Err(Error::io(&target, &e)),
        }
    })();
    let _ = fs::remove_file(&temp);
    result?;
    directory_file.sync_all().map_err(|e| Error::io(dir, &e))?;
    Ok(digest)
}

/// Return archived bytes only after checking their full digest and file mode.
///
/// # Errors
/// If the entry is missing, insecure, damaged, or unreadable.
pub fn retrieve_pass(dir: &Path, digest: Digest) -> Result<Vec<u8>, Error> {
    let _directory_file = directory(dir)?;
    let path = destination(dir, digest);
    let file = open_no_follow(&path, OpenOptions::new().read(true))?;
    let meta = file.metadata().map_err(|e| Error::io(&path, &e))?;
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Insecure {
            path,
            mode: meta.mode() & 0o7777,
            who: "other users can read or change archived approvals",
            fix: "600",
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_PASS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(&path, &e))?;
    if bytes.len() as u64 > MAX_PASS_BYTES {
        return Err(Error::TooLarge {
            path,
            limit: MAX_PASS_BYTES,
        });
    }
    if Digest::of(&bytes) != digest {
        return Err(Error::Usage(format!(
            "archive entry {} does not match its digest",
            path.display()
        )));
    }
    Ok(bytes)
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
