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
        let Some((start, limit)) = self.limit else {
            // No budget: take the blocking lock, so the kernel queues and
            // wakes waiters instead of pollers racing. A notice, when wanted,
            // comes from a timer thread that stands down once the lock is held.
            let Some(notify) = self.notify else {
                return file.lock().map_err(|e| io_error(&e));
            };
            return std::thread::scope(|scope| {
                let (done, timer) = std::sync::mpsc::channel::<()>();
                scope.spawn(move || {
                    // Only a timeout means the lock is still busy; a message
                    // or a closed channel means the lock was taken.
                    if timer.recv_timeout(LOCK_WAIT_NOTICE_AFTER)
                        == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    {
                        notify(&LockWait {
                            path: path.to_owned(),
                            holder_pid: lock_holder(file),
                        });
                    }
                });
                let result = file.lock().map_err(|e| io_error(&e));
                drop(done);
                result
            });
        };
        // A bounded wait polls: a blocked `flock` cannot be cancelled, so a
        // helper could not give up at the limit without possibly taking the
        // lock afterwards. Pollers are not queued, so this path is not fair
        // under heavy contention; see DESIGN.md "Cost per call".
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

/// A warning about a shared pass directory.
///
/// It fires when the directory that holds the pass (and so its ledger and
/// lock file) lets other users create, rename or delete entries in it. The
/// file-mode checks cannot see this: a user who can write the directory can
/// `rename` a file over the pass, the ledger or the lock without writing to
/// them. A directory with the sticky bit (like `/tmp`) restricts that to the
/// owner of the entry, so it raises no warning. Group write counts, as it does
/// for the pass file, whatever the group's members are.
///
/// `None` when the directory is not shared, cannot be inspected, or is
/// sticky.
#[must_use]
pub fn shared_directory_warning(pass: &Path) -> Option<String> {
    let dir = match pass.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mode = fs::metadata(dir).ok()?.mode();
    shared_directory_mode_warning(dir, mode)
}

/// Refuse to append when any user can rename or delete files in the
/// directory that holds the pass: no write bit for others without the sticky
/// bit. Another user could put the operator's own older revision of the pass
/// over the current one, which the owner and mode checks accept.
pub fn refuse_world_writable_directory(pass: &Path) -> Result<(), Error> {
    let dir = match pass.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let Ok(meta) = fs::metadata(dir) else {
        return Ok(());
    };
    let mode = meta.mode();
    if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        return Err(Error::SharedDirectory {
            path: dir.to_path_buf(),
            mode: mode & 0o7777,
        });
    }
    Ok(())
}

fn shared_directory_mode_warning(dir: &Path, mode: u32) -> Option<String> {
    if mode & 0o022 == 0 || mode & 0o1000 != 0 {
        return None;
    }
    let who = if mode & 0o002 != 0 {
        "any user"
    } else {
        "users in its group"
    };
    Some(format!(
        "the directory {} (mode {:04o}) holds the pass, its ledger and its lock file, and {who} can rename or delete them there without the sticky bit, which the file-mode checks do not see; run `chmod go-w {}`",
        dir.display(),
        mode & 0o7777,
        dir.display()
    ))
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
            advice: "check that its content is what the owner approved. If you saved it with `hallpass retrieve DIR DIGEST > FILE` under a umask that leaves group write, write it with `hallpass retrieve DIR DIGEST --output FILE` instead, which creates the file with mode 0600",
        });
    }
    Ok(())
}

/// How long a pass file must have gone unchanged before hallpass uses what
/// it read. A save that truncates the file and then writes it in pieces
/// leaves a prefix on disk between two writes, and a prefix that ends at a
/// line boundary can be a valid pass that grants more than the whole file
/// (its last `names` line missing, say). Editors and tools save a file in
/// one burst: the pauses between their writes are normally microseconds,
/// and the longest pause Linux imposes on a writer for dirty-page
/// throttling is 200 ms. A file modified less than this long ago is read
/// again once this long has passed, and refused unless nothing changed.
#[cfg(not(test))]
const PASS_SETTLE: Duration = Duration::from_millis(250);

/// The library's own unit tests rewrite passes hundreds of times and read
/// each one at once, so they use a shorter period. The binary, the library
/// as other crates build it, and every test under `tests/` use 250 ms.
#[cfg(test)]
const PASS_SETTLE: Duration = Duration::from_millis(20);

/// Added to a modification time with no fraction of a second: such a
/// filesystem may keep whole seconds (one second, or two on FAT), so the
/// write may have been up to this much later than the time it shows.
const COARSE_TIMESTAMP: Duration = Duration::from_secs(2);

/// What `fstat` says about a pass file: any write changes the size or the
/// modification time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    size: u64,
    modified: (i64, i64),
}

impl Stamp {
    fn of(file: &File, path: &Path) -> Result<Self, Error> {
        let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
        Ok(Self {
            size: meta.size(),
            modified: (meta.mtime(), meta.mtime_nsec()),
        })
    }

    /// How much longer to wait, at `now`, before the file has gone
    /// [`PASS_SETTLE`] without a change. A modification time in the future
    /// (a clock set differently) waits the whole period.
    fn unsettled_for(&self, now: std::time::SystemTime) -> Duration {
        let (seconds, nanos) = self.modified;
        let period = if nanos == 0 {
            PASS_SETTLE + COARSE_TIMESTAMP
        } else {
            PASS_SETTLE
        };
        let period = period.as_nanos().cast_signed();
        let last = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
        let now = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos().cast_signed());
        let left = (last + period - now).clamp(0, period);
        Duration::from_nanos(u64::try_from(left).unwrap_or(u64::MAX))
    }
}

/// The whole file from its start, at most [`MAX_PASS_BYTES`].
fn read_from_start(file: &File, path: &Path) -> Result<Vec<u8>, Error> {
    use std::io::{Seek, SeekFrom};
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| Error::io(path, &e))?;
    let mut bytes = Vec::new();
    reader
        .take(MAX_PASS_BYTES + 1)
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

fn file_problem(path: &Path, message: &str) -> Error {
    Error::Invalid {
        path: path.to_path_buf(),
        problems: vec![crate::pass::Problem {
            field: "(file)".to_owned(),
            message: message.to_owned(),
        }],
    }
}

/// The problem reported when a pass file changed while it was read.
pub const CHANGED_WHILE_READ: &str = "the file changed while hallpass was reading it, so what was read may be part of a save still in progress. Run the command again once the save has finished. To replace a pass, write the new version to a file in the same directory, `chmod 600` it, and `mv` it over this one";

/// The problem reported when a pass file does not end with a newline.
const NO_FINAL_NEWLINE: &str = "the file does not end with a newline, so its last line may have been cut short by a save in progress. If the last line is complete, end it with a newline";

/// The bytes of an open pass file, once they are known not to be part of a
/// save in progress: read, then `fstat`; if the file was modified within
/// [`PASS_SETTLE`], `pause` until that long after the modification, read
/// and `fstat` again, and require the same bytes, size and modification
/// time. A read that does not hold still is refused, and so is a file whose
/// last line has no newline. Both reads use the open file, so a pass
/// replaced by `mv` meanwhile is read as it was when it was opened.
fn settled_bytes(
    file: &File,
    path: &Path,
    now: impl FnOnce() -> std::time::SystemTime,
    pause: impl FnOnce(Duration),
) -> Result<Vec<u8>, Error> {
    let bytes = read_from_start(file, path)?;
    let first = Stamp::of(file, path)?;
    let wait = first.unsettled_for(now());
    if !wait.is_zero() || first.size != bytes.len() as u64 {
        pause(wait);
        let again = read_from_start(file, path)?;
        if again != bytes || Stamp::of(file, path)? != first || first.size != bytes.len() as u64 {
            return Err(file_problem(path, CHANGED_WHILE_READ));
        }
    }
    if bytes.last().is_some_and(|&last| last != b'\n') {
        return Err(file_problem(path, NO_FINAL_NEWLINE));
    }
    Ok(bytes)
}

/// Read a pass file: not a link, a regular file, not writable by others,
/// at most [`MAX_PASS_BYTES`], not changed while it was read, and ending
/// with a newline. This is the only read of a pass file: the bytes it
/// returns are both the ones parsed and the ones digested.
pub fn read_pass_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    let file = open_no_follow(path, OpenOptions::new().read(true))?;
    let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
    check_pass_owner_mode(
        path,
        meta.uid(),
        rustix::process::geteuid().as_raw(),
        meta.mode(),
    )?;
    settled_bytes(&file, path, std::time::SystemTime::now, std::thread::sleep)
}

/// Read, validate and digest the pass at `path`.
///
/// A file modified in the last 0.25 s may be part of a save in progress, so
/// it is read again 0.25 s after the modification and must not have changed:
/// the call can wait that long (2.25 s when the modification time has no
/// fraction of a second).
///
/// # Errors
///
/// [`Error::Symlink`], [`Error::NotRegular`], [`Error::Insecure`] (group or
/// other may write it), [`Error::TooLarge`], [`Error::Io`], and
/// [`Error::Invalid`] with every problem found, or with one `(file)`
/// problem when the file changed while it was read or its last line has no
/// newline.
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

#[cfg(test)]
mod settle {
    use super::*;
    use std::io::Write as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// The pass the evaluator rewrote: its last line restricts the shared
    /// address to one name.
    fn named_pass() -> String {
        format!(
            "{}\n[[destination]]\nlabel = \"shop-cdn\"\naddress = \"203.0.113.10\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"shop.example.com\"]\n",
            crate::pass::tests::GOOD
        )
    }

    fn written(text: &str) -> (tempfile::TempDir, PathBuf, File) {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("pass.toml");
        fs::write(&path, text).expect("write");
        let file = File::open(&path).expect("open");
        (dir, path, file)
    }

    fn modified(file: &File) -> SystemTime {
        file.metadata()
            .and_then(|meta| meta.modified())
            .expect("modification time")
    }

    fn refusal(result: Result<Vec<u8>, Error>) -> String {
        match result {
            Err(Error::Invalid { problems, .. }) if problems.len() == 1 => {
                assert_eq!(problems[0].field, "(file)");
                problems[0].message.clone()
            }
            other => panic!("expected one file problem, got {other:?}"),
        }
    }

    #[test]
    fn only_a_recent_modification_waits_and_only_for_the_rest_of_the_period() {
        let at = |seconds, nanos| UNIX_EPOCH + Duration::new(seconds, nanos);
        let stamp = Stamp {
            size: 0,
            modified: (1_000, 250_000_000),
        };
        let written = at(1_000, 250_000_000);
        assert_eq!(stamp.unsettled_for(written), PASS_SETTLE);
        assert_eq!(
            stamp.unsettled_for(written + PASS_SETTLE / 4),
            PASS_SETTLE * 3 / 4
        );
        assert_eq!(stamp.unsettled_for(written + PASS_SETTLE), Duration::ZERO);
        assert_eq!(stamp.unsettled_for(at(2_000, 0)), Duration::ZERO);
        // A modification time ahead of the clock waits the whole period, no more.
        assert_eq!(stamp.unsettled_for(at(900, 0)), PASS_SETTLE);
        assert_eq!(stamp.unsettled_for(UNIX_EPOCH), PASS_SETTLE);
        // Whole seconds: the write may have been up to two seconds later.
        let coarse = Stamp {
            size: 0,
            modified: (1_000, 0),
        };
        let longest = PASS_SETTLE + COARSE_TIMESTAMP;
        assert_eq!(coarse.unsettled_for(at(1_000, 0)), longest);
        assert_eq!(
            coarse.unsettled_for(at(1_001, 0)),
            longest.saturating_sub(Duration::from_secs(1))
        );
        assert_eq!(coarse.unsettled_for(at(1_000, 0) + longest), Duration::ZERO);
    }

    #[test]
    fn a_settled_file_is_read_once() {
        let text = named_pass();
        let (_dir, path, file) = written(&text);
        let later = modified(&file) + PASS_SETTLE + COARSE_TIMESTAMP;
        let bytes = settled_bytes(&file, &path, || later, |_| panic!("no pause")).expect("settled");
        assert_eq!(bytes, text.as_bytes());
    }

    #[test]
    fn a_fresh_file_is_read_again_once_the_period_has_passed() {
        let text = named_pass();
        let (_dir, path, file) = written(&text);
        let soon = modified(&file) + PASS_SETTLE / 4;
        let mut paused = None;
        let bytes =
            settled_bytes(&file, &path, || soon, |wait| paused = Some(wait)).expect("unchanged");
        assert_eq!(paused, Some(PASS_SETTLE * 3 / 4));
        assert_eq!(bytes, text.as_bytes());
    }

    #[test]
    fn a_valid_prefix_whose_last_line_arrives_during_the_pause_is_refused() {
        let text = named_pass();
        let (prefix, last) = text
            .trim_end()
            .rsplit_once('\n')
            .map(|(prefix, last)| (format!("{prefix}\n"), format!("{last}\n")))
            .expect("lines");
        assert!(last.starts_with("names = "), "{last}");
        // The prefix alone is a valid pass: what a torn read would see.
        crate::pass::Pass::parse(&prefix).expect("a valid prefix");
        let (_dir, path, file) = written(&prefix);
        let now = modified(&file);
        let result = settled_bytes(
            &file,
            &path,
            || now,
            |_| {
                let mut writer = OpenOptions::new().append(true).open(&path).expect("open");
                writer
                    .write_all(last.as_bytes())
                    .expect("the rest of the save");
            },
        );
        assert_eq!(refusal(result), CHANGED_WHILE_READ);
    }

    #[test]
    fn the_same_bytes_saved_again_during_the_pause_are_refused() {
        let text = named_pass();
        let (_dir, path, file) = written(&text);
        let now = modified(&file);
        let result = settled_bytes(
            &file,
            &path,
            || now,
            |_| {
                let writer = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .expect("open");
                (&writer).write_all(text.as_bytes()).expect("save");
                writer
                    .set_modified(now + Duration::from_millis(1))
                    .expect("a later time");
            },
        );
        assert_eq!(refusal(result), CHANGED_WHILE_READ);
    }

    #[test]
    fn a_pass_replaced_by_mv_during_the_pause_is_read_as_it_was_opened() {
        let text = named_pass();
        let (dir, path, file) = written(&text);
        let now = modified(&file);
        let bytes = settled_bytes(
            &file,
            &path,
            || now,
            |_| {
                let staged = dir.path().join("pass.toml.new");
                fs::write(&staged, "format = 1\n").expect("stage");
                fs::rename(&staged, &path).expect("mv");
            },
        )
        .expect("the opened file did not change");
        assert_eq!(bytes, text.as_bytes());
    }

    #[test]
    fn a_last_line_without_a_newline_is_refused() {
        for text in [
            "format = 1",
            "ports = 44",
            "format = 1\r",
            "format = 1\n# end",
        ] {
            let (_dir, path, file) = written(text);
            let later = modified(&file) + PASS_SETTLE + COARSE_TIMESTAMP;
            let result = settled_bytes(&file, &path, || later, |_| panic!("no pause"));
            assert_eq!(refusal(result), NO_FINAL_NEWLINE, "{text:?}");
        }
        for text in ["format = 1\n", "format = 1\r\n", ""] {
            let (_dir, path, file) = written(text);
            let later = modified(&file) + PASS_SETTLE + COARSE_TIMESTAMP;
            let bytes = settled_bytes(&file, &path, || later, |_| panic!("no pause"))
                .expect("ends with a newline or is empty");
            assert_eq!(bytes, text.as_bytes());
        }
    }
}
