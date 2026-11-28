//! Reading the pass file without following links, and its digest.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use crate::error::Error;
use crate::pass::Pass;

/// How long a command waits for a lock before it reports the wait.
pub const LOCK_WAIT_NOTICE_AFTER: Duration = Duration::from_secs(2);

/// A report that a ledger or witness lock has been busy for a while.
///
/// The library never prints; a caller that wants to tell its user sets
/// [`crate::SpendRequest::on_lock_wait`], or passes a function to
/// [`with_lock_wait`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockWait {
    /// The lock file being waited for.
    pub path: PathBuf,
    /// The process holding the lock, when it could be found (Linux, from
    /// `/proc/locks`; the id is as seen from this process's namespace).
    pub holder_pid: Option<u32>,
    /// True for a shared lock, taken to read the ledger; false for an
    /// exclusive lock, taken to write the ledger or the witness.
    pub shared: bool,
    /// How long the wait has left before it gives up with `lock-timeout`,
    /// when a limit was set; none when it waits without end.
    pub give_up_in: Option<std::time::Duration>,
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

/// The lock wait that [`with_lock_wait`] set on this thread: what is left of
/// its budget, and who hears about a long wait.
#[derive(Clone, Copy)]
struct Scope {
    left: Option<Duration>,
    notify: Option<fn(&LockWait)>,
}

thread_local! {
    static SCOPE: std::cell::Cell<Option<Scope>> = const { std::cell::Cell::new(None) };
}

/// Run `f` with a bound on how long it waits for ledger and witness locks.
///
/// A read ([`crate::read_ledger`], [`crate::permits_in`], an audit, a
/// checkpoint, a preview) takes a shared lock on the ledger, and waits while
/// a spend, an adoption or another process holds it exclusively. The read
/// functions have no request to carry a limit, so it is set around the call:
///
/// ```no_run
/// use std::time::Duration;
/// # let path = std::path::Path::new("engagement.pass.toml");
/// # let state = hallpass::StateDir::from_env();
/// let view = hallpass::with_lock_wait(Some(Duration::from_secs(5)), None, || {
///     hallpass::read_summary(&hallpass::load(path)?, &state)
/// })?;
/// # Ok::<(), hallpass::Error>(())
/// ```
///
/// `lock_timeout` means what [`crate::SpendRequest::lock_timeout`] means:
/// the most time, in total, that the calls in `f` wait for every lock they
/// take. Zero tries each lock once, and `None` waits without limit. A wait
/// that reaches the limit fails with [`Error::LockTimeout`]. Time spent
/// reading is not counted, only time spent waiting. `on_lock_wait` is called
/// once for each lock that stays busy for about two seconds, from the waiting
/// thread or a helper thread.
///
/// The bound holds on this thread only, for the duration of `f`; the scope
/// before it is restored afterwards, even if `f` panics. A
/// [`crate::SpendRequest`] whose own `lock_timeout` or `on_lock_wait` is set
/// uses that field instead of this one.
pub fn with_lock_wait<T>(
    lock_timeout: Option<Duration>,
    on_lock_wait: Option<fn(&LockWait)>,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<Scope>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SCOPE.set(self.0);
        }
    }
    let _restore = Restore(SCOPE.replace(Some(Scope {
        left: lock_timeout,
        notify: on_lock_wait,
    })));
    f()
}

/// Run `f` with a request's own limit and notice, each one that is not set
/// taken from the current [`with_lock_wait`] scope.
pub fn with_requested_wait<T>(
    lock_timeout: Option<Duration>,
    on_lock_wait: Option<fn(&LockWait)>,
    f: impl FnOnce() -> T,
) -> T {
    if lock_timeout.is_none() && on_lock_wait.is_none() {
        return f();
    }
    let scope = SCOPE.get();
    with_lock_wait(
        lock_timeout.or_else(|| scope.and_then(|s| s.left)),
        on_lock_wait.or_else(|| scope.and_then(|s| s.notify)),
        f,
    )
}

/// Take away `waited` from what is left of the current scope's budget.
fn charge_scope(waited: Duration) {
    if let Some(mut scope) = SCOPE.get() {
        scope.left = scope.left.map(|left| left.saturating_sub(waited));
        SCOPE.set(Some(scope));
    }
}

/// Take a shared lock on the ledger `file`, waiting as the current
/// [`with_lock_wait`] scope allows.
pub fn lock_shared(file: &File, path: &Path) -> Result<(), Error> {
    LockBudget::requested(None, None).shared(file, path, |e| Error::io(path, e))
}

/// One monotonic budget for the locks a call takes: the witness and ledger
/// writer locks of a spend, or the shared ledger lock of a read.
#[derive(Clone, Copy, Default)]
pub struct LockBudget {
    limit: Option<(std::time::Instant, Duration)>,
    notify: Option<fn(&LockWait)>,
    /// True when the limit is the scope's, so the time waited is taken from it.
    scoped: bool,
}

impl LockBudget {
    pub(crate) fn new(limit: Option<Duration>) -> Self {
        Self {
            limit: limit.map(|limit| (std::time::Instant::now(), limit)),
            notify: None,
            scoped: false,
        }
    }

    pub(crate) const fn notifying(mut self, notify: Option<fn(&LockWait)>) -> Self {
        self.notify = notify;
        self
    }

    /// A request's own limit and notice; each one that is not set comes from
    /// the current [`with_lock_wait`] scope, or is none.
    pub(crate) fn requested(limit: Option<Duration>, notify: Option<fn(&LockWait)>) -> Self {
        let scope = SCOPE.get();
        let mut budget = Self::new(limit.or_else(|| scope.and_then(|s| s.left)))
            .notifying(notify.or_else(|| scope.and_then(|s| s.notify)));
        budget.scoped = limit.is_none();
        budget
    }

    fn poll_interval(left: Duration) -> Duration {
        // Leave time for another attempt even when the entire budget is below 5 ms.
        // The floor avoids polling repeatedly at sub-microsecond intervals.
        (left / 4)
            .clamp(Duration::from_micros(50), Duration::from_millis(5))
            .min(left)
    }

    /// Take the exclusive lock on `file`.
    pub(crate) fn exclusive(
        self,
        file: &File,
        path: &Path,
        io_error: impl FnOnce(&std::io::Error) -> Error,
    ) -> Result<(), Error> {
        self.acquire(file, path, false, io_error)
    }

    /// Take a shared lock on `file`.
    pub(crate) fn shared(
        self,
        file: &File,
        path: &Path,
        io_error: impl FnOnce(&std::io::Error) -> Error,
    ) -> Result<(), Error> {
        self.acquire(file, path, true, io_error)
    }

    fn acquire(
        self,
        file: &File,
        path: &Path,
        shared: bool,
        io_error: impl FnOnce(&std::io::Error) -> Error,
    ) -> Result<(), Error> {
        let began = std::time::Instant::now();
        let result = self.wait(file, path, shared, io_error);
        if self.scoped {
            charge_scope(began.elapsed());
        }
        result
    }

    fn wait(
        self,
        file: &File,
        path: &Path,
        shared: bool,
        io_error: impl FnOnce(&std::io::Error) -> Error,
    ) -> Result<(), Error> {
        use std::fs::TryLockError;
        let lock = || {
            if shared {
                file.lock_shared()
            } else {
                file.lock()
            }
        };
        let report = || LockWait {
            path: path.to_owned(),
            holder_pid: lock_holder(file),
            shared,
            give_up_in: self
                .limit
                .map(|(start, limit)| limit.saturating_sub(start.elapsed())),
        };
        let Some((start, limit)) = self.limit else {
            // No budget: take the blocking lock, so the kernel queues and
            // wakes waiters instead of pollers racing. A notice, when wanted,
            // comes from a timer thread that stands down once the lock is held.
            let Some(notify) = self.notify else {
                return lock().map_err(|e| io_error(&e));
            };
            return std::thread::scope(|scope| {
                let (done, timer) = std::sync::mpsc::channel::<()>();
                scope.spawn(move || {
                    // Only a timeout means the lock is still busy; a message
                    // or a closed channel means the lock was taken.
                    if timer.recv_timeout(LOCK_WAIT_NOTICE_AFTER)
                        == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    {
                        notify(&report());
                    }
                });
                let result = lock().map_err(|e| io_error(&e));
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
            let attempt = if shared {
                file.try_lock_shared()
            } else {
                file.try_lock()
            };
            match attempt {
                Ok(()) => return Ok(()),
                Err(TryLockError::Error(e)) => return Err(io_error(&e)),
                Err(TryLockError::WouldBlock) => {}
            }
            if let Some(notify) = self.notify
                && !told
                && began.elapsed() >= LOCK_WAIT_NOTICE_AFTER
            {
                told = true;
                notify(&report());
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
    /// Which file was read, to tell a pass rewritten in place from one
    /// replaced by a rename.
    pub(crate) file: FileId,
    /// What `fstat` said when the bytes were read, to let a later read of
    /// the same unchanged file skip the settle wait (see [`load_after`]).
    pub(crate) mark: Stamp,
}

/// The identity of an open file: its device, inode and, where the file
/// system records one, its birth time. A file replaced by a rename has a new
/// identity; a file rewritten in place keeps its own. The birth time tells a
/// new file that reuses a freed inode number from the old one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub born_ns: Option<u64>,
}

impl FileId {
    fn of(meta: &fs::Metadata) -> Self {
        let born_ns = meta
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| u64::try_from(d.as_nanos()).ok());
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            born_ns,
        }
    }
}

/// Open `path` with `options` only if it is a regular file and not a
/// symbolic link. The file opened is checked to be the one inspected, so a
/// link swapped in between is refused too.
///
/// The open itself neither follows a link nor blocks: a FIFO or a device
/// swapped in after the check is opened without waiting for a writer, then
/// refused as [`Error::NotRegular`].
pub fn open_no_follow(path: &Path, options: &OpenOptions) -> Result<File, Error> {
    use rustix::fs::OFlags;
    use std::os::unix::fs::OpenOptionsExt as _;
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
    let mut options = options.clone();
    options.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits().cast_signed());
    let file = options.open(path).map_err(|e| {
        if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
            Error::Symlink {
                path: path.to_path_buf(),
            }
        } else {
            Error::io(path, &e)
        }
    })?;
    let after = file.metadata().map_err(|e| Error::io(path, &e))?;
    if !after.file_type().is_file() {
        return Err(Error::NotRegular {
            path: path.to_path_buf(),
        });
    }
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return Err(Error::Symlink {
            path: path.to_path_buf(),
        });
    }
    // Reads and writes of a regular file do not block anyway; clear the
    // flag so that the descriptor is the one a plain open gives.
    let flags = rustix::fs::fcntl_getfl(&file).map_err(|e| Error::io(path, &e.into()))?;
    rustix::fs::fcntl_setfl(&file, flags - OFlags::NONBLOCK)
        .map_err(|e| Error::io(path, &e.into()))?;
    Ok(file)
}

/// Write `bytes` at the end of `file` (a file opened to append, or a new
/// empty one), but refuse first, writing nothing, when that would take the
/// file past the soft file size limit (`RLIMIT_FSIZE`, `ulimit -f`).
///
/// The kernel answers a write past that limit with `SIGXFSZ`, whose default
/// action ends the process at once: no reply, no rollback, and a line cut
/// short. Safe Rust cannot ignore the signal, so hallpass checks the limit
/// before each write instead. The refusal is an `EFBIG`-style error
/// ([`io::ErrorKind::FileTooLarge`]), the error the write itself gives when
/// the signal is ignored, so each caller handles it as it handles a full
/// disk.
pub fn write_within_size_limit(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    let len = file.metadata()?.len();
    check_size_limit(len, bytes.len())?;
    file.write_all(bytes)
}

/// Refuse a write to standard output or error that would pass the file size limit.
///
/// Only a regular file has the limit. Past it the kernel kills the process
/// with SIGXFSZ, and the crate cannot ignore that signal without `unsafe`.
///
/// # Errors
/// Returns `FileTooLarge` when the write would pass the limit.
pub fn check_stream_write<Fd: std::os::fd::AsFd>(fd: Fd, bytes: &[u8]) -> io::Result<()> {
    use rustix::fs::{FileType, OFlags, SeekFrom};
    let Ok(info) = rustix::fs::fstat(&fd) else {
        return Ok(());
    };
    if FileType::from_raw_mode(info.st_mode) != FileType::RegularFile {
        return Ok(());
    }
    let append = rustix::fs::fcntl_getfl(&fd).is_ok_and(|f| f.contains(OFlags::APPEND));
    let start = if append {
        u64::try_from(info.st_size).unwrap_or(0)
    } else {
        rustix::fs::seek(&fd, SeekFrom::Current(0)).unwrap_or(0)
    };
    check_size_limit(start, bytes.len())
}

/// Refuse writing `adding` bytes to a file of `len` bytes when the file
/// would end past the soft file size limit; see [`write_within_size_limit`].
fn check_size_limit(len: u64, adding: usize) -> io::Result<()> {
    let end = len.saturating_add(u64::try_from(adding).unwrap_or(u64::MAX));
    match size_limit() {
        Some(limit) if end > limit => Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!(
                "writing {adding} bytes would make the file {end} bytes long, past this process's file size limit of {limit} bytes (RLIMIT_FSIZE, `ulimit -f`)"
            ),
        )),
        _ => Ok(()),
    }
}

/// The soft file size limit, or `None` when there is none.
fn size_limit() -> Option<u64> {
    #[cfg(test)]
    if let Some(limit) = size_limit_fault::LIMIT.get() {
        return Some(limit);
    }
    rustix::process::getrlimit(rustix::process::Resource::Fsize).current
}

/// A file size limit the unit tests set for this thread only, since a real
/// `setrlimit` would apply to every test thread at once.
#[cfg(test)]
pub mod size_limit_fault {
    use std::cell::Cell;

    thread_local! {
        pub static LIMIT: Cell<Option<u64>> = const { Cell::new(None) };
    }
}

/// Open an input file for reading as hallpass opens a pass.
///
/// It is never opened through a symbolic link, only a regular file is
/// opened, and a FIFO or a device does not block the open. A case suite, a
/// checkpoint, a signature or a trusted signers file is opened this way.
///
/// # Errors
///
/// [`Error::Symlink`], [`Error::NotRegular`] or [`Error::Io`].
pub fn open_input(path: &Path) -> Result<File, Error> {
    open_no_follow(path, OpenOptions::new().read(true))
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
/// directory that holds the pass.
///
/// That is a write bit for others without the sticky
/// bit. Another user could put the operator's own older revision of the pass
/// over the current one, which the owner and mode checks accept.
///
/// # Errors
/// [`Error::SharedDirectory`].
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

/// How far ahead of the clock a modification time may be before hallpass
/// warns about it (a coarse timestamp can run ahead by this much, and
/// clocks differ a little).
const FUTURE_TOLERANCE: Duration = Duration::from_secs(2);

/// What `fstat` says about a pass file: any write changes the size or the
/// modification time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
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

    /// Whether the modification time is later than `now`.
    fn in_future(&self, now: std::time::SystemTime) -> bool {
        let (seconds, nanos) = self.modified;
        let last = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
        let now = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos().cast_signed());
        last > now
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
#[cfg(test)]
fn settled_bytes(
    file: &File,
    path: &Path,
    now: impl FnOnce() -> std::time::SystemTime,
    pause: impl FnOnce(Duration),
) -> Result<Vec<u8>, Error> {
    settled_read(file, path, now, pause, None).map(|(bytes, _)| bytes)
}

/// [`settled_bytes`], and the `fstat` the bytes were settled against.
///
/// `prior` is an earlier read of the same file that was settled: its stamp
/// and digest. A modification time in the future gives no moment to settle
/// from, so every read of such a file waits [`PASS_SETTLE`]. When this read
/// finds the same file with the same stamp and the same bytes as `prior`,
/// and that stamp is in the future, nothing has been written since `prior`
/// was settled (a write sets the modification time to now, which differs),
/// and the wait is skipped. Any difference falls back to the full wait.
fn settled_read(
    file: &File,
    path: &Path,
    now: impl FnOnce() -> std::time::SystemTime,
    pause: impl FnOnce(Duration),
    prior: Option<(Stamp, &Digest)>,
) -> Result<(Vec<u8>, Stamp), Error> {
    let bytes = read_from_start(file, path)?;
    let first = Stamp::of(file, path)?;
    let now = now();
    let held = prior.is_some_and(|(stamp, digest)| {
        stamp == first && first.in_future(now) && *digest == Digest::of(&bytes)
    });
    let wait = if held {
        Duration::ZERO
    } else {
        first.unsettled_for(now)
    };
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
    Ok((bytes, first))
}

/// The warning for a pass whose modification time is in the future, or
/// `None`. Every read of such a file waits the whole settle period, because
/// there is no moment to count it from.
#[must_use]
pub fn future_mtime_warning(pass: &Path) -> Option<String> {
    let modified = fs::metadata(pass).ok()?.modified().ok()?;
    let ahead = modified.duration_since(std::time::SystemTime::now()).ok()?;
    if ahead <= FUTURE_TOLERANCE {
        return None;
    }
    let shown = time::OffsetDateTime::from(modified)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "an unreadable time".to_owned());
    Some(format!(
        "the pass file {} has a modification time of {shown}, which is in the future, so every call waits {} ms for it to settle. Fix the clock that is wrong, or run `touch` on the file.",
        crate::witness::quote_path(pass),
        PASS_SETTLE.as_millis()
    ))
}

/// Read a pass file: not a link, a regular file, not writable by others,
/// at most [`MAX_PASS_BYTES`], not changed while it was read, and ending
/// with a newline. This is the only read of a pass file: the bytes it
/// returns are both the ones parsed and the ones digested.
pub fn read_pass_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    read_pass_file(path, None).map(|(bytes, _, _)| bytes)
}

/// [`read_pass_bytes`], and the identity of the file the bytes came from.
fn read_pass_file(
    path: &Path,
    prior: Option<&LoadedPass>,
) -> Result<(Vec<u8>, FileId, Stamp), Error> {
    let file = open_no_follow(path, OpenOptions::new().read(true))?;
    let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
    check_pass_owner_mode(
        path,
        meta.uid(),
        rustix::process::geteuid().as_raw(),
        meta.mode(),
    )?;
    let id = FileId::of(&meta);
    let prior = prior.filter(|p| p.file == id).map(|p| (p.mark, &p.digest));
    let (bytes, stamp) = settled_read(
        &file,
        path,
        std::time::SystemTime::now,
        std::thread::sleep,
        prior,
    )?;
    Ok((bytes, id, stamp))
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
    load_inner(path, None)
}

/// Read the pass again, under a lock, after `earlier` was read and settled
/// outside it. The result is a full read and is validated again; the only
/// difference from [`load`] is that a file whose modification time is in
/// the future and which is unchanged since `earlier` is not waited for a
/// second time (see `settled_read`).
pub fn load_after(path: &Path, earlier: &LoadedPass) -> Result<LoadedPass, Error> {
    load_inner(path, Some(earlier)).map(|(loaded, _)| loaded)
}

fn load_inner(path: &Path, prior: Option<&LoadedPass>) -> Result<(LoadedPass, Vec<u8>), Error> {
    let (bytes, file, mark) = read_pass_file(path, prior)?;
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
            file,
            mark,
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
        let first = LockBudget::poll_interval(short);
        assert!(first > Duration::ZERO && first < short);
        let remaining = short.checked_sub(first).expect("within deadline");
        let second = LockBudget::poll_interval(remaining);
        assert!(second > Duration::ZERO && second < remaining);
        assert_eq!(
            LockBudget::poll_interval(Duration::from_secs(1)),
            Duration::from_millis(5)
        );
        // Honor even the smallest residual budget, without a zero-length sleep.
        assert_eq!(
            LockBudget::poll_interval(Duration::from_nanos(1)),
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

#[cfg(test)]
mod future_settle {
    use super::*;
    use std::time::SystemTime;

    fn future_file() -> (tempfile::TempDir, PathBuf, File) {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("pass.toml");
        fs::write(&path, "a = 1\n").expect("write");
        let file = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open");
        file.set_modified(SystemTime::now() + Duration::from_secs(3600))
            .expect("date ahead");
        (dir, path, file)
    }

    #[test]
    fn a_file_unchanged_since_a_settled_read_in_the_future_is_not_waited_for_again() {
        let (_dir, path, file) = future_file();
        let mut waits = Vec::new();
        let (bytes, stamp) = settled_read(&file, &path, SystemTime::now, |w| waits.push(w), None)
            .expect("first read");
        assert_eq!(waits, [PASS_SETTLE], "the first read waits the period");
        let digest = Digest::of(&bytes);
        let (again, _) = settled_read(
            &file,
            &path,
            SystemTime::now,
            |_| panic!("no second wait"),
            Some((stamp, &digest)),
        )
        .expect("second read");
        assert_eq!(again, bytes);
    }

    #[test]
    fn a_changed_file_is_waited_for_again_even_when_dated_in_the_future() {
        let (_dir, path, file) = future_file();
        let (bytes, stamp) =
            settled_read(&file, &path, SystemTime::now, |_| (), None).expect("first read");
        let digest = Digest::of(&bytes);
        // New bytes with the same size and the same time, as a writer that
        // restores the time would leave them: the digest differs.
        fs::write(&path, "a = 2\n").expect("rewrite");
        file.set_modified(
            SystemTime::UNIX_EPOCH + Duration::new(stamp.modified.0.cast_unsigned(), 0),
        )
        .expect("restore time");
        let mut waited = false;
        let result = settled_read(
            &file,
            &path,
            SystemTime::now,
            |_| waited = true,
            Some((stamp, &digest)),
        );
        assert!(waited, "a changed file gets the full settle");
        drop(result);
        // A stamp that differs also gets the full settle.
        let (bytes, stamp) =
            settled_read(&file, &path, SystemTime::now, |_| (), None).expect("read");
        let digest = Digest::of(&bytes);
        file.set_modified(SystemTime::now() + Duration::from_secs(7200))
            .expect("date moved");
        let mut waited = false;
        let _ = settled_read(
            &file,
            &path,
            SystemTime::now,
            |_| waited = true,
            Some((stamp, &digest)),
        );
        assert!(waited);
    }

    #[test]
    fn a_file_dated_in_the_past_is_never_held() {
        let (_dir, path, file) = future_file();
        file.set_modified(SystemTime::now() - Duration::from_secs(5))
            .expect("date back");
        let mut waits = 0;
        let (bytes, stamp) =
            settled_read(&file, &path, SystemTime::now, |_| waits += 1, None).expect("read");
        assert_eq!(waits, 0, "an old file needs no wait");
        // Held only for a time in the future: an old file is read twice
        // when it differs, and this one differs from nothing, so no wait.
        let digest = Digest::of(&bytes);
        let mut waited = false;
        settled_read(
            &file,
            &path,
            || SystemTime::now() + Duration::from_secs(10_000),
            |_| waited = true,
            Some((stamp, &digest)),
        )
        .expect("read again");
        assert!(!waited, "a settled old file is still not waited for");
    }

    #[test]
    fn the_warning_names_the_time_and_the_remedy() {
        let (_dir, path, _file) = future_file();
        let text = future_mtime_warning(&path).expect("warns");
        assert!(text.contains("modification time of"), "{text}");
        assert!(text.contains("which is in the future"), "{text}");
        assert!(text.contains("`touch`"), "{text}");
        let (_dir, path, file) = future_file();
        file.set_modified(SystemTime::now()).expect("now");
        assert_eq!(future_mtime_warning(&path), None);
    }
}
