//! Reading the pass file without following links, and its digest.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use crate::error::Error;
use crate::pass::Pass;

/// How long a spend waits for a writer lock before it reports the wait.
pub const LOCK_WAIT_NOTICE_AFTER: Duration = Duration::from_secs(2);

/// A report that a writer lock has been busy for a while. The library never
/// prints; a caller that wants to tell its user sets
/// [`crate::SpendRequest::on_lock_wait`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockWait {
    /// The lock file being waited for.
    pub path: PathBuf,
    /// The process holding the lock, when it could be found (Linux, from
    /// `/proc/locks`; the id is as seen from this process's namespace).
    pub holder_pid: Option<u32>,
}

/// The holder of the `flock` on `file`, from `/proc/locks`. None when it is
/// not Linux, the table cannot be read, or no entry matches.
fn lock_holder(file: &File) -> Option<u32> {
    let meta = file.metadata().ok()?;
    let (major, minor) = (
        (meta.dev() >> 8) & 0xfff | (meta.dev() >> 32) & !0xfff,
        (meta.dev() & 0xff) | ((meta.dev() >> 12) & !0xff),
    );
    let dev = format!("{major:02x}:{minor:02x}");
    let table = fs::read_to_string("/proc/locks").ok()?;
    table.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let kind = fields.nth(1)?;
        let pid = fields.nth(2)?;
        let id = fields.next()?;
        let (found_dev, rest) = id.split_once(':')?;
        let (found_minor, inode) = rest.split_once(':')?;
        let same = kind == "FLOCK"
            && format!("{found_dev}:{found_minor}") == dev
            && inode.parse::<u64>().ok() == Some(meta.ino());
        if same { pid.parse().ok() } else { None }
    })
}

/// One monotonic budget for the witness and ledger writer locks.
#[derive(Clone, Copy, Default)]
pub struct WriterWait {
    limit: Option<(std::time::Instant, Duration)>,
    notify: Option<fn(&LockWait)>,
}

impl WriterWait {
    pub(crate) fn new(limit: Option<Duration>) -> Self {
        Self {
            limit: limit.map(|limit| (std::time::Instant::now(), limit)),
            notify: None,
        }
    }

    pub(crate) const fn notifying(mut self, notify: Option<fn(&LockWait)>) -> Self {
        self.notify = notify;
        self
    }

    fn poll_interval(left: Duration) -> Duration {
        // Leave time for another attempt even when the entire budget is below 5 ms.
        // The floor avoids polling repeatedly at sub-microsecond intervals.
        (left / 4)
            .clamp(Duration::from_micros(50), Duration::from_millis(5))
            .min(left)
    }

    pub(crate) fn exclusive(
        self,
        file: &File,
        path: &Path,
        io_error: impl FnOnce(&std::io::Error) -> Error,
    ) -> Result<(), Error> {
        use std::fs::TryLockError;
        if self.limit.is_none() && self.notify.is_none() {
            return file.lock().map_err(|e| io_error(&e));
        }
        let began = std::time::Instant::now();
        let mut told = false;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(()),
                Err(TryLockError::Error(e)) => return Err(io_error(&e)),
                Err(TryLockError::WouldBlock) => {}
            }
            if let Some(notify) = self.notify
                && !told
                && began.elapsed() >= LOCK_WAIT_NOTICE_AFTER
            {
                told = true;
                notify(&LockWait {
                    path: path.to_owned(),
                    holder_pid: lock_holder(file),
                });
            }
            let Some((start, limit)) = self.limit else {
                // No budget: poll gently, so the notice can fire.
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            let left = limit.saturating_sub(start.elapsed());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(Self::poll_interval(left));
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

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The length of a digest's text form: `sha256:` and 64 hex digits.
const DIGEST_TEXT_LEN: usize = 7 + 64;

impl Digest {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// The text form, as [`fmt::Display`] writes it, without allocating.
    fn text(&self) -> [u8; DIGEST_TEXT_LEN] {
        let mut out = [0u8; DIGEST_TEXT_LEN];
        out[..7].copy_from_slice(b"sha256:");
        for (pair, byte) in out[7..].as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
            *pair = [
                HEX_DIGITS[usize::from(byte >> 4)],
                HEX_DIGITS[usize::from(byte & 0x0f)],
            ];
        }
        out
    }

    /// Whether `text` is exactly this digest's text form (`sha256:` and 64
    /// lower-case hex digits). The ledger chain compares every `prev` field
    /// this way, without formatting a new string per line.
    pub(crate) fn is_written_as(&self, text: &str) -> bool {
        text.as_bytes() == self.text()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.text();
        f.write_str(std::str::from_utf8(&text).map_err(|_| fmt::Error)?)
    }
}

/// The value of each lower-case hex digit, and 0xff for every other byte.
static HEX_VALUES: [u8; 256] = {
    let mut table = [0xff; 256];
    let mut value: u8 = 0;
    while value < 16 {
        table[HEX_DIGITS[value as usize] as usize] = value;
        value += 1;
    }
    table
};

impl FromStr for Digest {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || format!("`{s}` is not a digest; write sha256: and 64 lower-case hex digits");
        let hex = s.strip_prefix("sha256:").ok_or_else(bad)?.as_bytes();
        if hex.len() != 64 {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        // Any byte that is not a lower-case hex digit sets the high bits.
        let mut seen = 0u8;
        for (byte, [high, low]) in out.iter_mut().zip(hex.as_chunks::<2>().0) {
            let (high, low) = (
                HEX_VALUES[usize::from(*high)],
                HEX_VALUES[usize::from(*low)],
            );
            seen |= high | low;
            *byte = (high << 4) | (low & 0x0f);
        }
        if seen > 0x0f {
            return Err(bad());
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
            advice: "check that its content is what the owner approved",
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
    load_with_bytes(path).map(|(loaded, _)| loaded)
}

/// Read one validated snapshot, retaining the exact bytes used for its digest.
///
/// # Errors
/// Returns the same validation and file errors as [`load`].
pub fn load_with_bytes(path: &Path) -> Result<(LoadedPass, Vec<u8>), Error> {
    let bytes = read_pass_bytes(path)?;
    let digest = Digest::of(&bytes);
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Invalid {
        path: path.to_path_buf(),
        problems: vec![crate::pass::Problem {
            field: "(file)".to_owned(),
            message: "the file is not UTF-8 text; save it as UTF-8".to_owned(),
        }],
    })?;
    let pass = Pass::parse(text).map_err(|problems| Error::Invalid {
        path: path.to_path_buf(),
        problems,
    })?;
    Ok((
        LoadedPass {
            pass,
            digest,
            path: path.to_path_buf(),
        },
        bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_writer_deadlines_leave_time_for_more_probes() {
        let short = Duration::from_millis(4);
        let first = WriterWait::poll_interval(short);
        assert!(first > Duration::ZERO && first < short);
        let remaining = short.checked_sub(first).expect("within deadline");
        let second = WriterWait::poll_interval(remaining);
        assert!(second > Duration::ZERO && second < remaining);
        assert_eq!(
            WriterWait::poll_interval(Duration::from_secs(1)),
            Duration::from_millis(5)
        );
        // Honor even the smallest residual budget, without a zero-length sleep.
        assert_eq!(
            WriterWait::poll_interval(Duration::from_nanos(1)),
            Duration::from_nanos(1)
        );
    }

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

    #[test]
    fn digest_text_is_exactly_lower_case_hex() {
        use std::fmt::Write as _;
        for input in [&b""[..], b"abc", b"\xff\x00", &[0xab; 1000]] {
            let d = Digest::of(input);
            let text = d.to_string();
            // The text as the earlier `Display` wrote it, a byte at a time.
            let mut expected = "sha256:".to_owned();
            for byte in d.0 {
                write!(expected, "{byte:02x}").expect("write");
            }
            assert_eq!(text, expected);
            assert!(d.is_written_as(&text));
            assert_eq!(text.parse::<Digest>(), Ok(d));
            for other in [
                text.to_uppercase(),
                text.replace("sha256:", "SHA256:"),
                format!("{text}0"),
                text[..text.len() - 1].to_owned(),
                format!("{}g", &text[..text.len() - 1]),
                Digest::of(b"other").to_string(),
            ] {
                assert!(!d.is_written_as(&other), "{other}");
                assert_ne!(other.parse::<Digest>(), Ok(d), "{other}");
            }
        }
        for bad in ["g", "G", "A", "/", ":", "`", " "] {
            let text = format!("sha256:{bad}{}", "0".repeat(63));
            assert!(text.parse::<Digest>().is_err(), "{text}");
        }
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
