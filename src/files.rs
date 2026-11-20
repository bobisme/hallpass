//! Reading the pass file without following links, and its digest.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use crate::error::Error;
use crate::pass::Pass;

/// One monotonic budget for the witness and ledger writer locks.
#[derive(Clone, Copy, Default)]
pub struct WriterWait(Option<(std::time::Instant, std::time::Duration)>);

impl WriterWait {
    pub(crate) fn new(limit: Option<std::time::Duration>) -> Self {
        Self(limit.map(|limit| (std::time::Instant::now(), limit)))
    }

    pub(crate) fn exclusive(
        self,
        file: &File,
        path: &Path,
        io_error: impl FnOnce(&std::io::Error) -> Error,
    ) -> Result<(), Error> {
        use std::fs::TryLockError;
        let Some((start, limit)) = self.0 else {
            return file.lock().map_err(|e| io_error(&e));
        };
        loop {
            if !limit.is_zero() && start.elapsed() >= limit {
                break;
            }
            match file.try_lock() {
                Ok(()) => return Ok(()),
                Err(TryLockError::Error(e)) => return Err(io_error(&e)),
                Err(TryLockError::WouldBlock) => {}
            }
            let left = limit.saturating_sub(start.elapsed());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(std::time::Duration::from_millis(5)));
        }
        Err(Error::LockTimeout {
            path: path.to_owned(),
        })
    }
}

/// The largest pass file hallpass reads (1 MiB).
pub const MAX_PASS_BYTES: u64 = 1 << 20;

/// The SHA-256 of the exact bytes of a pass file, written `sha256:<hex>`.
///
/// Any edit changes it, comments included, so a consumer that records it
/// knows exactly which file a run was held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Digest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || format!("`{s}` is not a digest; write sha256: and 64 lower-case hex digits");
        let hex = s.strip_prefix("sha256:").ok_or_else(bad)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
        }
        Ok(Self(out))
    }
}

/// A pass read from disk, with the digest of the bytes it was parsed from.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LoadedPass {
    /// The validated pass.
    pub pass: Pass,
    /// The digest of the file's bytes.
    pub digest: Digest,
    /// The path it was read from.
    pub path: PathBuf,
}

/// Open `path` with `options` only if it is a regular file and not a
/// symbolic link. The file opened is checked to be the one inspected, so a
/// link swapped in between is refused too.
pub fn open_no_follow(path: &Path, options: &OpenOptions) -> Result<File, Error> {
    let before = fs::symlink_metadata(path).map_err(|e| Error::io(path, &e))?;
    if before.file_type().is_symlink() {
        return Err(Error::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !before.file_type().is_file() {
        return Err(Error::NotRegular {
            path: path.to_path_buf(),
        });
    }
    let file = options.open(path).map_err(|e| Error::io(path, &e))?;
    let after = file.metadata().map_err(|e| Error::io(path, &e))?;
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(Error::Symlink {
            path: path.to_path_buf(),
        });
    }
    Ok(file)
}

pub fn writable_directory(path: &Path) -> Result<(), Error> {
    use rustix::fs::{Access, AtFlags, CWD, accessat};
    if !path.is_dir() {
        return Err(Error::io(
            path,
            &std::io::Error::other("expected a directory"),
        ));
    }
    accessat(
        CWD,
        path,
        Access::WRITE_OK | Access::EXEC_OK,
        AtFlags::EACCESS,
    )
    .map_err(|e| Error::io(path, &std::io::Error::from(e)))
}

fn check_pass_owner_mode(path: &Path, owner: u32, effective: u32, mode: u32) -> Result<(), Error> {
    if owner != effective && owner != 0 {
        return Err(Error::UntrustedOwner {
            path: path.to_owned(),
            owner,
            effective,
        });
    }
    if mode & 0o022 != 0 {
        return Err(Error::Insecure {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
            who: "other users can change the approval",
            fix: "600",
        });
    }
    Ok(())
}

/// Read a pass file: not a link, a regular file, not writable by others,
/// at most [`MAX_PASS_BYTES`].
pub fn read_pass_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    let file = open_no_follow(path, OpenOptions::new().read(true))?;
    let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
    check_pass_owner_mode(
        path,
        meta.uid(),
        rustix::process::geteuid().as_raw(),
        meta.mode(),
    )?;
    let mut bytes = Vec::new();
    file.take(MAX_PASS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(path, &e))?;
    if bytes.len() as u64 > MAX_PASS_BYTES {
        return Err(Error::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_PASS_BYTES,
        });
    }
    Ok(bytes)
}

/// Read, validate and digest the pass at `path`.
///
/// # Errors
///
/// [`Error::Symlink`], [`Error::NotRegular`], [`Error::Insecure`] (group or
/// other may write it), [`Error::TooLarge`], [`Error::Io`], and
/// [`Error::Invalid`] with every problem found.
pub fn load(path: &Path) -> Result<LoadedPass, Error> {
    let bytes = read_pass_bytes(path)?;
    let digest = Digest::of(&bytes);
    let text = String::from_utf8(bytes).map_err(|_| Error::Invalid {
        path: path.to_path_buf(),
        problems: vec![crate::pass::Problem {
            field: "(file)".to_owned(),
            message: "the file is not UTF-8 text; save it as UTF-8".to_owned(),
        }],
    })?;
    let pass = Pass::parse(&text).map_err(|problems| Error::Invalid {
        path: path.to_path_buf(),
        problems,
    })?;
    Ok(LoadedPass {
        pass,
        digest,
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trip() {
        let d = Digest::of(b"abc");
        assert_eq!(
            d.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(d.to_string().parse::<Digest>(), Ok(d));
        assert!("sha256:BA7816".parse::<Digest>().is_err());
        assert!("md5:00".parse::<Digest>().is_err());
    }
}

#[cfg(test)]
mod ownership {
    use super::*;
    #[test]
    fn owner_and_mode_are_independent_requirements() {
        let p = Path::new("example");
        for owner in [0, 1001] {
            for mode in [0o600, 0o644] {
                assert!(check_pass_owner_mode(p, owner, 1001, mode).is_ok());
            }
            for mode in [0o620, 0o602] {
                assert!(matches!(
                    check_pass_owner_mode(p, owner, 1001, mode),
                    Err(Error::Insecure { .. })
                ));
            }
        }
        assert!(matches!(
            check_pass_owner_mode(p, 1002, 1001, 0o644),
            Err(Error::UntrustedOwner { .. })
        ));
    }
}
