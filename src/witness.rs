//! The witness: a small record of each ledger's tail, kept outside the pass
//! directory, so that a lost, replaced or rewound ledger is noticed.
//!
//! The ledger beside the pass detects damage inside the file (its hash
//! chain), but not the loss of the whole file, a ledger swapped for an older
//! copy, or an edited last line (nothing follows it to check its hash). The
//! witness closes those gaps for accidents: after every recorded spend,
//! hallpass writes the ledger's last sequence number, the hash of its last
//! line, the totals and where the ledger was, to
//! `$XDG_STATE_HOME/hallpass/<pass id>.witness` (default
//! `~/.local/state/hallpass/`). The next command checks that the ledger still
//! contains exactly that line at that position.
//!
//! The operator owns both files, so a determined operator can still delete
//! the witness too. The witness catches accidents and casual edits, not a
//! deliberate cheat.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// A path as one quoted value in a message, escaped once.
fn quote_path(path: impl AsRef<Path>) -> String {
    crate::display_quoted(&path.as_ref().display().to_string())
}
use crate::files::{Digest, open_no_follow};
use crate::pass::{MAX_CEILING, is_counter_name};

/// The witness format version.
const WITNESS_VERSION: u32 = 1;
/// The largest witness file hallpass reads.
// Version 1 originally read only 64 KiB, but accepted appends could write
// a larger witness. This limit leaves room for that last valid batch and
// accommodates many revisions of a pass's counter set.
const MAX_WITNESS_BYTES: usize = 1024 * 1024;

/// Where hallpass keeps its witnesses: `$XDG_STATE_HOME/hallpass`, or
/// `$HOME/.local/state/hallpass` when `XDG_STATE_HOME` is unset, empty or
/// not absolute.
///
/// A `StateDir` that could not be determined still exists as a value; every
/// use of it then reports why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDir {
    path: Result<PathBuf, String>,
}

impl StateDir {
    /// The given directory (the `hallpass` directory itself, not its parent).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Ok(path.into()),
        }
    }

    /// The state directory named by the environment (`XDG_STATE_HOME`, else
    /// `HOME`).
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            path: resolve(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME")),
        }
    }

    /// A warning when `XDG_STATE_HOME` is set but not absolute, so the XDG
    /// rules make hallpass ignore it. It names the value and the directory
    /// used instead; a witness kept there is a different one from any kept
    /// under the ignored value.
    #[must_use]
    pub fn ignored_env_warning() -> Option<String> {
        let xdg = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty())?;
        if Path::new(&xdg).is_absolute() {
            return None;
        }
        let shown = crate::display_quoted(&xdg.to_string_lossy());
        let instead = resolve(None, std::env::var_os("HOME")).map_or_else(
            |_| "and HOME is not absolute either, so there is no state directory".to_owned(),
            |dir| format!("using {} instead", quote_path(&dir)),
        );
        Some(format!(
            "XDG_STATE_HOME is set to the relative path {shown}, which is ignored (the XDG rules need an absolute path); {instead}. Witnesses kept under another directory are not seen there, so a lost or rewound ledger is not noticed until one is recorded; set XDG_STATE_HOME to an absolute path or unset it"
        ))
    }

    /// The directory, or why there is none.
    ///
    /// # Errors
    ///
    /// Neither variable names an absolute directory.
    pub fn path(&self) -> Result<&Path, &str> {
        self.path.as_deref().map_err(String::as_str)
    }

    /// The witness file for a pass id.
    ///
    /// # Errors
    ///
    /// As [`StateDir::path`].
    pub fn witness_path(&self, pass_id: &str) -> Result<PathBuf, &str> {
        Ok(self.path()?.join(format!("{pass_id}.witness")))
    }

    fn unavailable(&self, pass_id: &str, detail: String) -> Error {
        Error::WitnessUnavailable {
            pass_id: pass_id.to_owned(),
            dir: self.path().ok().map(Path::to_path_buf),
            detail,
        }
    }

    /// The directory, created (mode 0700) if missing, and checked: not a
    /// link, a directory, private to its owner.
    fn ensure(&self, pass_id: &str) -> Result<&Path, Error> {
        let dir = self
            .path()
            .map_err(|e| self.unavailable(pass_id, e.to_owned()))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| {
                self.unavailable(
                    pass_id,
                    format!("the state directory cannot be created ({e})"),
                )
            })?;
        self.check_dir(pass_id, dir)?;
        Ok(dir)
    }

    fn check_dir(&self, pass_id: &str, dir: &Path) -> Result<(), Error> {
        let meta = fs::symlink_metadata(dir).map_err(|e| {
            self.unavailable(pass_id, format!("the state directory cannot be read ({e})"))
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(self.unavailable(
                pass_id,
                "the state directory is a symbolic link or not a directory".to_owned(),
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(self.unavailable(
                pass_id,
                format!(
                    "the state directory has mode {:04o}, so other users can read or change the witnesses; run `chmod 700 {}`",
                    meta.mode() & 0o7777,
                    quote_path(dir)
                ),
            ));
        }
        Ok(())
    }

    /// Inspect writability without creating the state directory, probe, or lock.
    pub(crate) fn preview_write_access(&self, pass_id: &str) -> Result<(), Error> {
        let dir = self
            .path()
            .map_err(|s| self.unavailable(pass_id, s.into()))?;
        let mut ancestor = dir;
        loop {
            match fs::metadata(ancestor) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    ancestor = ancestor
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."));
                }
                Err(e) => return Err(self.unavailable(pass_id, e.to_string())),
            }
        }
        crate::files::writable_directory(ancestor)
            .map_err(|e| self.unavailable(pass_id, e.to_string()))?;
        let lock = dir.join(format!("{pass_id}.lock"));
        match fs::symlink_metadata(&lock) {
            Ok(_) => {
                open_no_follow(&lock, OpenOptions::new().write(true))
                    .map_err(|e| self.unavailable(pass_id, e.to_string()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(self.unavailable(pass_id, e.to_string())),
        }
        Ok(())
    }

    /// Take the exclusive lock that serializes every writer of the witness
    /// for `pass_id` (held until the returned file is dropped). Creates the
    /// directory and the lock file as needed.
    pub(crate) fn lock(
        &self,
        pass_id: &str,
        wait: crate::files::LockBudget,
    ) -> Result<File, Error> {
        let dir = self.ensure(pass_id)?;
        let path = dir.join(format!("{pass_id}.lock"));
        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                open_no_follow(&path, OpenOptions::new().write(true))
                    .map_err(|e| self.unavailable(pass_id, e.to_string()))?
            }
            Err(e) => {
                return Err(self.unavailable(
                    pass_id,
                    format!("{} cannot be created ({e})", quote_path(&path)),
                ));
            }
        };
        wait.exclusive(&file, &path, |e| {
            self.unavailable(
                pass_id,
                format!("{} cannot be locked ({e})", quote_path(&path)),
            )
        })?;
        // The witness is written after the ledger; find out now, before
        // anything is recorded, whether it can be.
        let probe = dir.join(format!(
            ".{pass_id}.probe.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
            .and_then(|_| fs::remove_file(&probe))
            .map_err(|e| {
                self.unavailable(
                    pass_id,
                    format!(
                        "the state directory {} is not writable ({e})",
                        quote_path(dir)
                    ),
                )
            })?;
        Ok(file)
    }

    /// Read the witness for `pass_id`: `None` when there is none (no
    /// directory, or no file).
    pub(crate) fn read(&self, pass_id: &str) -> Result<Option<Witnessed>, Error> {
        let dir = self
            .path()
            .map_err(|e| self.unavailable(pass_id, e.to_owned()))?;
        match fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => self.check_dir(pass_id, dir)?,
        }
        let path = dir.join(format!("{pass_id}.witness"));
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(self.unavailable(
                    pass_id,
                    format!("{} cannot be read ({e})", quote_path(&path)),
                ));
            }
            Ok(_) => {}
        }
        let file = open_no_follow(&path, OpenOptions::new().read(true))
            .map_err(|e| self.unavailable(pass_id, e.to_string()))?;
        let meta = file
            .metadata()
            .map_err(|e| self.unavailable(pass_id, e.to_string()))?;
        if meta.mode() & 0o077 != 0 {
            return Err(self.unavailable(
                pass_id,
                format!(
                    "{} has mode {:04o}; run `chmod 600` on it",
                    quote_path(&path),
                    meta.mode() & 0o7777
                ),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_WITNESS_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| self.unavailable(pass_id, format!("{} ({e})", quote_path(&path))))?;
        self.check_size(pass_id, bytes.len())?;
        let damaged = || {
            self.unavailable(
                pass_id,
                format!(
                    "{} is damaged (not a hallpass witness for this pass id); move it aside and run `hallpass adopt` to record a new one",
                    quote_path(&path)
                ),
            )
        };
        let record: WitnessFile = serde_json::from_slice(&bytes).map_err(|_| damaged())?;
        if record.hallpass_witness != WITNESS_VERSION || record.pass_id != pass_id {
            return Err(damaged());
        }
        let tail = record.tail.parse::<Digest>().map_err(|_| damaged())?;
        if !valid_totals(&record.totals) {
            return Err(damaged());
        }
        Ok(Some(Witnessed {
            ledger: record.ledger,
            seq: record.seq,
            tail,
            totals: record.totals,
            updated: record.updated,
        }))
    }

    fn check_size(&self, pass_id: &str, len: usize) -> Result<(), Error> {
        if len <= MAX_WITNESS_BYTES {
            return Ok(());
        }
        Err(self.unavailable(pass_id, format!(
            "the witness exceeds the {MAX_WITNESS_BYTES}-byte size limit. Preserve the ledger and witness and ask the approval owner to issue a new pass ID with ceilings that account for the existing spends"
        )))
    }

    /// Serialize and check the final witness before appending its ledger record.
    pub(crate) fn prepare(
        &self,
        pass_id: &str,
        witness: &Witnessed,
    ) -> Result<PreparedWitness, Error> {
        let mut text = serde_json::to_string(&WitnessFile {
            hallpass_witness: WITNESS_VERSION,
            pass_id: pass_id.to_owned(),
            ledger: witness.ledger.clone(),
            seq: witness.seq,
            tail: witness.tail.to_string(),
            totals: witness.totals.clone(),
            updated: witness.updated.clone(),
        })
        .map_err(|e| self.unavailable(pass_id, e.to_string()))?;
        text.push('\n');
        self.check_size(pass_id, text.len())?;
        Ok(PreparedWitness(text))
    }

    /// Prepare and replace a witness for already verified ledger evidence.
    pub(crate) fn write(&self, pass_id: &str, witness: &Witnessed) -> Result<(), Error> {
        self.publish(pass_id, &self.prepare(pass_id, witness)?)
    }

    /// Replace the witness by syncing a temporary file and renaming it.
    /// The caller holds the witness lock.
    pub(crate) fn publish(&self, pass_id: &str, witness: &PreparedWitness) -> Result<(), Error> {
        let dir = self.ensure(pass_id)?;
        let path = dir.join(format!("{pass_id}.witness"));
        let temp = dir.join(format!(
            ".{pass_id}.witness.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(witness.0.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temp, &path)?;
            File::open(dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|e| {
            self.unavailable(
                pass_id,
                format!("{} cannot be written ({e})", quote_path(&path)),
            )
        })
    }
}

/// A fully serialized witness that fits the reader's size limit.
pub struct PreparedWitness(String);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Pick the state directory from the two variables (XDG Base Directory
/// rules: a relative `XDG_STATE_HOME` is ignored).
fn resolve(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf, String> {
    let absolute = |v: Option<OsString>| {
        v.filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(base) = absolute(xdg) {
        return Ok(base.join("hallpass"));
    }
    if let Some(home) = absolute(home) {
        return Ok(home.join(".local").join("state").join("hallpass"));
    }
    Err("there is no state directory: neither XDG_STATE_HOME nor HOME is set to an absolute path; set one of them".to_owned())
}

pub fn valid_totals(totals: &BTreeMap<String, u64>) -> bool {
    totals
        .iter()
        .all(|(name, n)| is_counter_name(name) && *n <= MAX_CEILING)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessFile {
    hallpass_witness: u32,
    pass_id: String,
    ledger: String,
    seq: u64,
    tail: String,
    totals: BTreeMap<String, u64>,
    updated: String,
}

/// What the witness recorded about a ledger the last time hallpass wrote
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Witnessed {
    /// Where the ledger was (absolute path, informational).
    pub ledger: String,
    /// The sequence number of its last line (0: only the header).
    pub seq: u64,
    /// The hash of its last line.
    pub tail: Digest,
    /// The total recorded per counter.
    pub totals: BTreeMap<String, u64>,
    /// When it was written (UTC, `YYYY-MM-DDTHH:MM:SSZ`).
    pub updated: String,
}

/// The totals in words: `calls 4, requests 30`, or `nothing`.
#[must_use]
pub fn totals_text(totals: &BTreeMap<String, u64>) -> String {
    let parts: Vec<String> = totals
        .iter()
        .filter(|(_, n)| **n > 0)
        .map(|(name, n)| format!("{name} {n}"))
        .collect();
    if parts.is_empty() {
        "nothing".to_owned()
    } else {
        parts.join(", ")
    }
}

/// The path a ledger is recorded under in the witness: its directory
/// resolved (links and `..` removed) plus its file name.
pub fn ledger_identity(path: &Path) -> String {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let resolved = fs::canonicalize(parent)
        .map(|dir| dir.join(path.file_name().unwrap_or_default()))
        .or_else(|_| std::path::absolute(path))
        .unwrap_or_else(|_| path.to_path_buf());
    resolved.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_like_xdg() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            resolve(os("/x/state"), os("/home/u")),
            Ok(PathBuf::from("/x/state/hallpass"))
        );
        assert_eq!(
            resolve(os("relative"), os("/home/u")),
            Ok(PathBuf::from("/home/u/.local/state/hallpass"))
        );
        assert_eq!(
            resolve(os(""), os("/home/u")),
            Ok(PathBuf::from("/home/u/.local/state/hallpass"))
        );
        assert!(resolve(None, None).is_err());
        assert!(resolve(os("rel"), os("also-rel")).is_err());
        let none = StateDir {
            path: resolve(None, None),
        };
        assert!(matches!(
            none.lock("x", crate::files::LockBudget::default()),
            Err(Error::WitnessUnavailable { .. })
        ));
        assert!(matches!(
            none.read("x"),
            Err(Error::WitnessUnavailable { .. })
        ));
    }

    #[test]
    fn writes_private_files_and_reads_them_back() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = StateDir::new(tmp.path().join("a").join("hallpass"));
        assert_eq!(state.read("p1").expect("read"), None);
        let lock = state
            .lock("p1", crate::files::LockBudget::default())
            .expect("lock");
        let dir = state.path().expect("dir");
        assert_eq!(
            fs::metadata(dir).expect("dir").permissions().mode() & 0o777,
            0o700
        );
        let w = Witnessed {
            ledger: "/x/p.ledger".to_owned(),
            seq: 3,
            tail: Digest::of(b"line"),
            totals: BTreeMap::from([("calls".to_owned(), 3)]),
            updated: "2026-11-20T09:00:00Z".to_owned(),
        };
        state.write("p1", &w).expect("write");
        drop(lock);
        let file = state.witness_path("p1").expect("path");
        assert_eq!(
            fs::metadata(&file).expect("file").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(state.read("p1").expect("read"), Some(w));
        // Another pass id's witness is not this one's.
        fs::copy(&file, dir.join("p2.witness")).expect("copy");
        assert!(matches!(
            state.read("p2"),
            Err(Error::WitnessUnavailable { .. })
        ));
        fs::write(&file, "{}").expect("damage");
        assert!(matches!(
            state.read("p1"),
            Err(Error::WitnessUnavailable { .. })
        ));
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            state.lock("p1", crate::files::LockBudget::default()),
            Err(Error::WitnessUnavailable { .. })
        ));
    }
}
