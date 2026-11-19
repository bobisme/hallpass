//! The ledger: spends recorded across processes, so a ceiling holds for the
//! whole engagement and not only for one command.
//!
//! The ledger is `<pass file>.ledger`, beside the pass, mode 0600. It is
//! JSON Lines: a header line naming the pass id, then one line per spend.
//! Every entry carries its sequence number and the SHA-256 of the line
//! before it, so a damaged, reordered or cut line is detected. A ledger that
//! cannot be read exactly fails closed: nothing more can be spent.
//!
//! [`spend`] takes an exclusive lock on the ledger, re-reads the pass from
//! disk (so a revocation or an edited window takes effect at once), counts
//! the recorded spends, and appends the new one only if it fits.
//!
//! Recorded spends count against the counter of the same name whatever the
//! digest of the pass was when they were made: an edit that raises a total
//! takes effect, and no edit resets the count.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::decision::{Refusal, RefusalCode, stamp};
use crate::error::Error;
use crate::files::{Digest, LoadedPass, load, open_no_follow};
use crate::pass::{MAX_CEILING, is_counter_name};

/// The ledger format version.
const LEDGER_VERSION: u32 = 1;
/// The longest note a spend may carry, in characters.
pub const MAX_NOTE: usize = 500;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    hallpass_ledger: u32,
    pass_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    seq: u64,
    time: String,
    counter: String,
    n: u64,
    digest: String,
    note: Option<String>,
    prev: String,
}

/// What the ledger has recorded so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tally {
    /// Total recorded per counter name (every digest of the pass counts).
    pub spent: BTreeMap<String, u64>,
    /// The number of spend entries.
    pub entries: u64,
}

impl Tally {
    /// The amount recorded for `counter`.
    #[must_use]
    pub fn spent(&self, counter: &str) -> u64 {
        self.spent.get(counter).copied().unwrap_or(0)
    }
}

/// A spend to record.
#[derive(Clone, Debug)]
pub struct SpendRequest<'a> {
    /// The counter name (one of the pass's ceilings).
    pub counter: &'a str,
    /// The amount, at least 1.
    pub amount: u64,
    /// An optional free-text note recorded with the entry.
    pub note: Option<&'a str>,
    /// Refuse unless the pass on disk still has this digest.
    pub expect_digest: Option<Digest>,
    /// Refuse unless the window stays open at least this long.
    pub needed: Duration,
}

/// The result of a spend that was decided (recorded or refused).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendOutcome {
    /// `None` when recorded; the refusal otherwise. Nothing is recorded on a
    /// refusal.
    pub refusal: Option<Refusal>,
    /// The counter.
    pub counter: String,
    /// The amount asked for.
    pub amount: u64,
    /// The counter's total in the pass, if the pass defines it.
    pub total: Option<u64>,
    /// The amount recorded for the counter, including this spend if it was
    /// recorded.
    pub spent: u64,
    /// The sequence number of the new entry, when recorded.
    pub seq: Option<u64>,
    /// The digest of the pass the decision was made against.
    pub digest: Digest,
    /// The pass id.
    pub pass_id: String,
}

impl SpendOutcome {
    /// What remains of the total after this decision.
    #[must_use]
    pub fn remaining(&self) -> Option<u64> {
        self.total.map(|t| t.saturating_sub(self.spent))
    }
}

/// The ledger path for a pass: the pass file name with `.ledger` added.
#[must_use]
pub fn ledger_path(pass_path: &Path) -> PathBuf {
    let mut name = pass_path.file_name().unwrap_or_default().to_os_string();
    name.push(".ledger");
    pass_path.with_file_name(name)
}

fn line_hash(line: &[u8]) -> String {
    Digest::of(line).to_string()
}

/// Check a note: printable, at most [`MAX_NOTE`] characters.
fn check_note(note: &str) -> Result<(), String> {
    if note.chars().any(char::is_control) {
        return Err(
            "the note contains a control character (such as a newline); write one plain line"
                .to_owned(),
        );
    }
    if note.chars().count() > MAX_NOTE {
        return Err(format!(
            "the note is longer than {MAX_NOTE} characters; shorten it"
        ));
    }
    Ok(())
}

/// Parse the whole ledger. Any doubt is an error, never an empty count.
fn parse_ledger(path: &Path, bytes: &[u8], pass_id: &str) -> Result<(Tally, String, u64), Error> {
    let corrupt = |line: usize, detail: &str| Error::LedgerCorrupt {
        path: path.to_path_buf(),
        line,
        detail: detail.to_owned(),
    };
    if bytes.is_empty() {
        return Err(corrupt(
            1,
            "the file is empty, but a ledger always starts with a header line (was it truncated?)",
        ));
    }
    if bytes.last() != Some(&b'\n') {
        let line = bytes.split(|b| *b == b'\n').count();
        return Err(corrupt(line, "the last line is cut short (no line end)"));
    }
    let mut lines = bytes[..bytes.len() - 1].split(|b| *b == b'\n');
    let first = lines.next().unwrap_or_default();
    let header: Header = serde_json::from_slice(first)
        .map_err(|_| corrupt(1, "the header line is not a hallpass ledger header"))?;
    if header.hallpass_ledger != LEDGER_VERSION {
        return Err(corrupt(
            1,
            "the ledger version is not one this hallpass reads",
        ));
    }
    if header.pass_id != pass_id {
        return Err(Error::LedgerForeign {
            path: path.to_path_buf(),
            ledger_id: header.pass_id,
            pass_id: pass_id.to_owned(),
        });
    }
    let mut tally = Tally::default();
    let mut prev = line_hash(first);
    let mut seq = 0u64;
    for (i, line) in lines.enumerate() {
        let number = i + 2;
        let entry: Entry = serde_json::from_slice(line)
            .map_err(|_| corrupt(number, "the line is not a complete ledger entry"))?;
        if entry.seq != seq + 1 {
            return Err(corrupt(
                number,
                "the sequence number is out of order (a line is missing or was moved)",
            ));
        }
        if entry.prev != prev {
            return Err(corrupt(
                number,
                "the line does not follow the one before it (a line was changed, removed or moved)",
            ));
        }
        if !is_counter_name(&entry.counter) || entry.n == 0 || entry.n > MAX_CEILING {
            return Err(corrupt(number, "the counter name or amount is not valid"));
        }
        if entry.digest.parse::<Digest>().is_err()
            || OffsetDateTime::parse(&entry.time, &Rfc3339).is_err()
            || entry
                .note
                .as_deref()
                .is_some_and(|n| check_note(n).is_err())
        {
            return Err(corrupt(number, "the time, digest or note is not valid"));
        }
        let total = tally.spent.entry(entry.counter).or_insert(0);
        *total = total
            .checked_add(entry.n)
            .filter(|t| *t <= MAX_CEILING)
            .ok_or_else(|| corrupt(number, "the recorded amounts add up beyond any ceiling"))?;
        tally.entries += 1;
        seq = entry.seq;
        prev = line_hash(line);
    }
    Ok((tally, prev, seq))
}

fn check_private(path: &Path, file: &fs::File) -> Result<(), Error> {
    let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Insecure {
            path: path.to_path_buf(),
            mode: meta.mode() & 0o7777,
            who: "other users can read or change the ledger",
            fix: "600",
        });
    }
    Ok(())
}

/// Read what the ledger beside `loaded` has recorded. A missing ledger
/// means nothing was spent. Takes a shared lock, so it never sees half of a
/// spend.
///
/// # Errors
///
/// A ledger that is a link, not private, damaged, or for another pass id.
pub fn tally(loaded: &LoadedPass) -> Result<Tally, Error> {
    let path = ledger_path(&loaded.path);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Tally::default()),
        Err(e) => return Err(Error::io(&path, &e)),
        Ok(_) => {}
    }
    let mut file = open_no_follow(&path, OpenOptions::new().read(true))?;
    check_private(&path, &file)?;
    file.lock_shared().map_err(|e| Error::io(&path, &e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::io(&path, &e))?;
    let (tally, _, _) = parse_ledger(&path, &bytes, &loaded.pass.id)?;
    Ok(tally)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create the ledger with its header if it does not exist. The file appears
/// complete or not at all (written aside, then hard-linked into place), so
/// an empty ledger is always damage.
fn create_ledger(path: &Path, pass_id: &str) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(path, &e)),
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let unique = format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let temp = path.with_file_name(unique);
    let header = serde_json::to_string(&Header {
        hallpass_ledger: LEDGER_VERSION,
        pass_id: pass_id.to_owned(),
    })
    .map_err(|e| Error::Usage(e.to_string()))?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(header.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        match fs::hard_link(&temp, path) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
            _ => Ok(()),
        }
    })();
    let _ = fs::remove_file(&temp);
    result.map_err(|e| Error::io(path, &e))?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && let Ok(dir) = fs::File::open(dir)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// The policy part of a spend: `Some(refusal)` when it may not be recorded.
fn decide(
    loaded: &LoadedPass,
    request: &SpendRequest<'_>,
    total: Option<u64>,
    spent: u64,
    now: OffsetDateTime,
) -> Option<Refusal> {
    let refuse = |code, message: String| Refusal {
        code,
        message: format!("{message}. Nothing was recorded"),
    };
    if let Some(expected) = request.expect_digest
        && expected != loaded.digest
    {
        return Some(refuse(
            RefusalCode::PassChanged,
            format!(
                "the pass has changed since this run started (expected {expected}, now {}); stop, review the pass, and start again under the new one",
                loaded.digest
            ),
        ));
    }
    if let Err(refusal) = loaded.pass.check_window(now, request.needed) {
        return Some(refuse(refusal.code, refusal.message));
    }
    let Some(total) = total else {
        let known: Vec<&str> = loaded.pass.ceilings.keys().map(String::as_str).collect();
        return Some(refuse(
            RefusalCode::UnknownCounter,
            format!(
                "`{}` is not a ceiling of this pass (it has: {}); only what the owner put a ceiling on can be spent",
                request.counter,
                if known.is_empty() {
                    "none".to_owned()
                } else {
                    known.join(", ")
                }
            ),
        ));
    };
    (spent.saturating_add(request.amount) > total).then(|| {
        refuse(
            RefusalCode::CeilingReached,
            format!(
                "spending {} {} would exceed the ceiling: {spent} of {total} already spent, {} left; stop, or ask the owner to raise the ceiling in writing",
                request.amount,
                request.counter,
                total.saturating_sub(spent)
            ),
        )
    })
}

/// Atomically check and record a spend against the pass at `pass_path`.
///
/// Under an exclusive lock on the ledger it re-reads the pass, checks the
/// expected digest, the window and revocation at `now`, and the remaining
/// total, then appends the entry (and syncs it to disk) or refuses and
/// records nothing. Two processes spending at once never together exceed
/// the total.
///
/// # Errors
///
/// Anything that prevents a sure decision: an unreadable or invalid pass, a
/// damaged or foreign ledger, a malformed request, a failed write. Nothing
/// is recorded.
pub fn spend(
    pass_path: &Path,
    request: &SpendRequest<'_>,
    now: OffsetDateTime,
) -> Result<SpendOutcome, Error> {
    if request.amount == 0 || request.amount > MAX_CEILING {
        return Err(Error::Usage(format!(
            "the amount must be a whole number from 1 to {MAX_CEILING}; nothing was recorded"
        )));
    }
    if let Some(note) = request.note {
        check_note(note).map_err(|m| Error::Usage(format!("{m}; nothing was recorded")))?;
    }
    let first = load(pass_path)?;
    let path = ledger_path(pass_path);
    create_ledger(&path, &first.pass.id)?;
    let mut file = open_no_follow(&path, OpenOptions::new().read(true).append(true))?;
    check_private(&path, &file)?;
    file.lock().map_err(|e| Error::io(&path, &e))?;

    // Everything below holds the lock. The pass is read again: what counts
    // is the pass as it is now, not as it was a moment ago.
    let loaded = load(pass_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::io(&path, &e))?;
    let (tally, prev, seq) = parse_ledger(&path, &bytes, &loaded.pass.id)?;
    let total = loaded.pass.ceilings.get(request.counter).copied();
    let spent = tally.spent(request.counter);
    let mut outcome = SpendOutcome {
        refusal: None,
        counter: request.counter.to_owned(),
        amount: request.amount,
        total,
        spent,
        seq: None,
        digest: loaded.digest,
        pass_id: loaded.pass.id.clone(),
    };
    if let Some(refusal) = decide(&loaded, request, total, spent, now) {
        outcome.refusal = Some(refusal);
        return Ok(outcome);
    }
    let entry = Entry {
        seq: seq + 1,
        time: now
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .unwrap_or_else(|_| stamp(now)),
        counter: request.counter.to_owned(),
        n: request.amount,
        digest: loaded.digest.to_string(),
        note: request.note.map(str::to_owned),
        prev,
    };
    let mut line = serde_json::to_string(&entry).map_err(|e| Error::Usage(e.to_string()))?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_data())
        .map_err(|e| Error::Io {
            path: path.clone(),
            message: format!(
                "the spend could not be written ({e}); treat it as NOT permitted and check the ledger before continuing"
            ),
        })?;
    outcome.spent = spent + request.amount;
    outcome.seq = Some(entry.seq);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::tests::GOOD;
    use std::os::unix::fs::PermissionsExt;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pass.toml");
        fs::write(&path, GOOD).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        (dir, path)
    }

    fn request(counter: &str, amount: u64) -> SpendRequest<'_> {
        SpendRequest {
            counter,
            amount,
            note: None,
            expect_digest: None,
            needed: Duration::ZERO,
        }
    }

    #[test]
    fn spends_up_to_the_ceiling() {
        let (_dir, path) = setup();
        for i in 1..=6 {
            let out = spend(&path, &request("calls", 1), NOW).expect("spend");
            assert_eq!(out.refusal, None);
            assert_eq!(out.spent, i);
            assert_eq!(out.seq, Some(i));
        }
        let out = spend(&path, &request("calls", 1), NOW).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::CeilingReached)
        );
        assert_eq!(out.spent, 6);
        let meta = fs::metadata(ledger_path(&path)).expect("ledger");
        assert_eq!(meta.mode() & 0o777, 0o600);
        let loaded = load(&path).expect("load");
        assert_eq!(tally(&loaded).expect("tally").spent("calls"), 6);
    }

    #[test]
    fn edits_keep_the_count() {
        let (_dir, path) = setup();
        for _ in 0..6 {
            spend(&path, &request("calls", 1), NOW).expect("spend");
        }
        fs::write(&path, GOOD.replace("calls = 6", "calls = 8\n# raised")).expect("edit");
        let out = spend(&path, &request("calls", 2), NOW).expect("spend");
        assert_eq!(out.refusal, None);
        assert_eq!(out.spent, 8);
        fs::write(&path, GOOD.replace("calls = 6", "calls = 4")).expect("edit");
        let out = spend(&path, &request("calls", 1), NOW).expect("spend");
        assert_eq!(out.remaining(), Some(0));
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::CeilingReached)
        );
        fs::write(&path, GOOD.replace("acme-2026-11", "other")).expect("edit");
        assert!(matches!(
            spend(&path, &request("calls", 1), NOW),
            Err(Error::LedgerForeign { .. })
        ));
    }

    #[test]
    fn refusals_record_nothing() {
        let (_dir, path) = setup();
        let out = spend(&path, &request("bogus", 1), NOW).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::UnknownCounter)
        );
        let late =
            spend(&path, &request("calls", 1), datetime!(2026-12-01 00:00 UTC)).expect("spend");
        assert_eq!(late.refusal.map(|r| r.code), Some(RefusalCode::Expired));
        let mut changed = request("calls", 1);
        changed.expect_digest = Some(Digest::of(b"something else"));
        let out = spend(&path, &changed, NOW).expect("spend");
        assert_eq!(out.refusal.map(|r| r.code), Some(RefusalCode::PassChanged));
        let loaded = load(&path).expect("load");
        assert_eq!(tally(&loaded).expect("tally").entries, 0);
        assert!(matches!(
            spend(&path, &request("calls", 0), NOW),
            Err(Error::Usage(_))
        ));
        let mut noted = request("calls", 1);
        noted.note = Some("two\nlines");
        assert!(matches!(spend(&path, &noted, NOW), Err(Error::Usage(_))));
    }

    #[test]
    fn damaged_ledgers_fail_closed() {
        let (_dir, path) = setup();
        let mut noted = request("calls", 1);
        noted.note = Some("first call");
        spend(&path, &noted, NOW).expect("spend");
        spend(&path, &request("calls", 1), NOW).expect("spend");
        let ledger = ledger_path(&path);
        let good = fs::read(&ledger).expect("read");
        let damage = |bytes: &[u8]| {
            fs::write(&ledger, bytes).expect("write");
            match spend(&path, &request("calls", 1), NOW) {
                Err(Error::LedgerCorrupt { line, .. }) => line,
                other => panic!("not refused as corrupt: {other:?}"),
            }
        };
        assert_eq!(damage(&good[..good.len() - 5]), 3);
        assert_eq!(damage(b""), 1);
        let text = String::from_utf8(good.clone()).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            damage(format!("{}\n{}\n", lines[0], lines[2]).as_bytes()),
            2
        );
        assert_eq!(damage(text.replace("\"n\":1", "\"n\":0").as_bytes()), 2);
        assert_eq!(
            damage(text.replace("first call", "first cal").as_bytes()),
            3
        );
        assert_eq!(damage(format!("{text}{{}}\n").as_bytes()), 4);
        fs::write(&ledger, &good).expect("restore");
        assert!(
            spend(&path, &request("calls", 1), NOW)
                .expect("spend")
                .refusal
                .is_none()
        );
    }

    #[test]
    fn threads_never_overspend() {
        let (_dir, path) = setup();
        #[allow(clippy::needless_collect)] // all threads must start before any join
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    spend(&path, &request("calls", 1), NOW)
                        .expect("spend")
                        .refusal
                        .is_none()
                })
            })
            .collect();
        let recorded = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(recorded, 6);
        let loaded = load(&path).expect("load");
        assert_eq!(tally(&loaded).expect("tally").spent("calls"), 6);
    }

    #[test]
    fn links_and_modes_refused() {
        let (dir, path) = setup();
        spend(&path, &request("calls", 1), NOW).expect("spend");
        let ledger = ledger_path(&path);
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            spend(&path, &request("calls", 1), NOW),
            Err(Error::Insecure { .. })
        ));
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = dir.path().join("link.pass.toml");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(matches!(
            spend(&link, &request("calls", 1), NOW),
            Err(Error::Symlink { .. })
        ));
        let other = dir.path().join("other.pass.toml");
        fs::copy(&path, &other).expect("copy");
        std::os::unix::fs::symlink(&ledger, ledger_path(&other)).expect("symlink");
        assert!(matches!(
            spend(&other, &request("calls", 1), NOW),
            Err(Error::Symlink { .. })
        ));
    }
}
