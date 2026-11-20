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
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::decision::{Refusal, RefusalCode, in_utc, stamp};
use crate::error::{Error, MissingLedger};
use crate::files::{Digest, LoadedPass, load, open_no_follow};
use crate::pass::{MAX_CEILING, is_counter_name};
use crate::witness::{StateDir, Witnessed, ledger_identity, totals_text, valid_totals};

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
    /// Refuse unless the window stays open at least this long: the longest
    /// the work this spend pays for may take. Zero means "right now"; a
    /// negative duration is a usage error.
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
    /// Things the operator should know about the ledger and its witness, in
    /// words (for example that a witness was recorded for a ledger that had
    /// none).
    pub warnings: Vec<String>,
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

/// Characters a note may not contain when it is written, beyond control
/// characters: the Unicode line and paragraph separators (some viewers break
/// lines at them) and the bidirectional formatting controls (they reorder how
/// the text around them is displayed, so a note could disguise itself).
const fn is_disguising(c: char) -> bool {
    matches!(
        c,
        '\u{2028}'
            | '\u{2029}'
            | '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// `text` made safe to print on a terminal as part of one line.
///
/// Control characters, line separators and bidirectional controls are
/// written as `\u{…}`, and a backslash as `\\`, so the escaping cannot be
/// forged either. Other text is unchanged.
#[must_use]
pub fn display_safe(text: &str) -> std::borrow::Cow<'_, str> {
    let unsafe_char = |c: char| c == '\\' || c.is_control() || is_disguising(c);
    if !text.chars().any(unsafe_char) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if unsafe_char(c) {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Check a note before it is recorded: one plain line, at most
/// [`MAX_NOTE`] characters, without control characters, line separators or
/// bidirectional controls.
fn check_new_note(note: &str) -> Result<(), String> {
    if note.chars().any(is_disguising) {
        return Err(
            "the note contains a line separator or a bidirectional text control, which can make it display as something else; write one plain line"
                .to_owned(),
        );
    }
    check_note(note)
}

/// Check a recorded note: printable, at most [`MAX_NOTE`] characters. This is
/// the rule hallpass 0.1 wrote notes under, so older ledgers stay readable;
/// new notes must also pass [`check_new_note`].
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

/// One recorded spend, as read back from the ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LedgerEntry {
    /// The sequence number, from 1.
    pub seq: u64,
    /// When the spend was recorded (the caller's clock at the time).
    pub time: OffsetDateTime,
    /// The counter.
    pub counter: String,
    /// The amount.
    pub amount: u64,
    /// The digest of the pass the spend was decided against.
    pub digest: Digest,
    /// The note, if one was given. Operator-supplied text: escape it before
    /// showing it on a terminal.
    pub note: Option<String>,
}

/// An adoption recorded in the ledger: the operator acknowledged a ledger
/// that was lost, changed outside hallpass, or had no witness, and gave a
/// reason. It sits in the hash chain like a spend.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Adoption {
    /// The sequence number (shared with spends).
    pub seq: u64,
    /// When it was recorded.
    pub time: OffsetDateTime,
    /// Why, in the operator's words. Escape it before showing it on a
    /// terminal.
    pub reason: String,
    /// The digest of the pass at the time.
    pub digest: Digest,
    /// Amounts the witness had recorded that this ledger did not hold, per
    /// counter. They count as spent, so an adoption never lowers a count.
    pub carried: BTreeMap<String, u64>,
    /// What the witness recorded before the adoption, if there was one.
    pub previous: Option<Witnessed>,
}

/// Which situation an adoption resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdoptCase {
    /// There was no ledger, but the witness recorded spends.
    LedgerMissing,
    /// The ledger did not contain the line the witness recorded.
    LedgerChanged,
    /// The ledger had no witness (for example a pass brought from another
    /// machine).
    NoWitness,
}

impl AdoptCase {
    /// The stable spelling used in JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LedgerMissing => "ledger-missing",
            Self::LedgerChanged => "ledger-changed",
            Self::NoWitness => "no-witness",
        }
    }
}

/// How the ledger compares with its witness, when the comparison does not
/// fail closed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WitnessStatus {
    /// No ledger, and no witness of any spend: nothing was recorded.
    Fresh,
    /// The ledger ends with exactly the line the witness recorded.
    Matches,
    /// The ledger holds the line the witness recorded, followed by `added`
    /// more lines: a spend that stopped between writing the ledger and the
    /// witness, or one made by a hallpass that keeps no witness. Lines are
    /// only ever added, so the count cannot have gone down; they are
    /// counted.
    Extended {
        /// Lines after the witnessed one.
        added: u64,
    },
    /// There is a ledger but no witness for this pass id: a pass brought
    /// from another machine, user or state directory, or a ledger from
    /// before witnesses existed.
    Missing,
    /// The witness could not be read, so nothing was compared.
    NotChecked {
        /// Why.
        reason: String,
    },
}

impl WitnessStatus {
    /// The stable spelling used in JSON output.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Matches => "matches",
            Self::Extended { .. } => "extended",
            Self::Missing => "missing",
            Self::NotChecked { .. } => "not-checked",
        }
    }
}

/// The whole ledger of a pass, read and verified, and compared with its
/// witness.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LedgerView {
    /// The ledger file.
    pub path: PathBuf,
    /// False when there is no ledger yet (nothing was spent).
    pub exists: bool,
    /// Every spend, in order.
    pub entries: Vec<LedgerEntry>,
    /// Every adoption, in order.
    pub adoptions: Vec<Adoption>,
    /// The totals (spends and carried amounts).
    pub tally: Tally,
    /// How the ledger compares with its witness.
    pub witness: WitnessStatus,
    /// Where the witness last saw this ledger, when that was another path
    /// (the pass was moved, or copied with its ledger).
    pub moved_from: Option<String>,
    /// Things the operator should know, in words (no ledger witness yet, a
    /// moved ledger, a witness that could not be read).
    pub warnings: Vec<String>,
}

/// A ledger parsed and verified.
struct Parsed {
    tally: Tally,
    entries: Vec<LedgerEntry>,
    adoptions: Vec<Adoption>,
    /// The hash of every line; index 0 is the header, index `n` the line
    /// with sequence number `n`.
    hashes: Vec<Digest>,
    /// The last sequence number (0 when there are only the header).
    seq: u64,
}

impl Parsed {
    fn tail(&self) -> Digest {
        self.hashes
            .last()
            .copied()
            .unwrap_or_else(|| Digest::of(b""))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Line {
    Spend(Entry),
    Adopt(AdoptLine),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptLine {
    seq: u64,
    time: String,
    event: String,
    reason: String,
    digest: String,
    carried: BTreeMap<String, u64>,
    witness: Option<WitnessLine>,
    prev: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessLine {
    ledger: String,
    seq: u64,
    tail: String,
    totals: BTreeMap<String, u64>,
    updated: String,
}

/// Add `n` to `counter` in `totals`, refusing a sum beyond any ceiling.
fn add(totals: &mut BTreeMap<String, u64>, counter: &str, n: u64) -> Option<()> {
    let total = totals.entry(counter.to_owned()).or_insert(0);
    *total = total.checked_add(n).filter(|t| *t <= MAX_CEILING)?;
    Some(())
}

/// Parse the whole ledger. Any doubt is an error, never an empty count.
fn parse_ledger(path: &Path, bytes: &[u8], pass_id: &str) -> Result<Parsed, Error> {
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
            "the ledger version is not one this hallpass reads (if a newer hallpass wrote it, use that one)",
        ));
    }
    if header.pass_id != pass_id {
        return Err(Error::LedgerForeign {
            path: path.to_path_buf(),
            ledger_id: header.pass_id,
            pass_id: pass_id.to_owned(),
        });
    }
    let mut parsed = Parsed {
        tally: Tally::default(),
        entries: Vec::new(),
        adoptions: Vec::new(),
        hashes: vec![Digest::of(first)],
        seq: 0,
    };
    for (i, line) in lines.enumerate() {
        let number = i + 2;
        let record: Line = serde_json::from_slice(line)
            .map_err(|_| corrupt(number, "the line is not a complete ledger entry"))?;
        let (seq, prev) = match &record {
            Line::Spend(e) => (e.seq, &e.prev),
            Line::Adopt(a) => (a.seq, &a.prev),
        };
        if seq != parsed.seq + 1 {
            return Err(corrupt(
                number,
                "the sequence number is out of order (a line is missing or was moved)",
            ));
        }
        if *prev != parsed.tail().to_string() {
            return Err(corrupt(
                number,
                "the line does not follow the one before it (a line was changed, removed or moved)",
            ));
        }
        match record {
            Line::Spend(entry) => {
                parse_spend(&mut parsed, entry).map_err(|detail| corrupt(number, detail))?;
            }
            Line::Adopt(adopt) => {
                parse_adopt(&mut parsed, adopt).map_err(|detail| corrupt(number, detail))?;
            }
        }
        parsed.seq = seq;
        parsed.hashes.push(Digest::of(line));
    }
    Ok(parsed)
}

fn parse_spend(parsed: &mut Parsed, entry: Entry) -> Result<(), &'static str> {
    if !is_counter_name(&entry.counter) || entry.n == 0 || entry.n > MAX_CEILING {
        return Err("the counter name or amount is not valid");
    }
    let (Ok(digest), Ok(time)) = (
        entry.digest.parse::<Digest>(),
        OffsetDateTime::parse(&entry.time, &Rfc3339),
    ) else {
        return Err("the time, digest or note is not valid");
    };
    if entry
        .note
        .as_deref()
        .is_some_and(|n| check_note(n).is_err())
    {
        return Err("the time, digest or note is not valid");
    }
    add(&mut parsed.tally.spent, &entry.counter, entry.n)
        .ok_or("the recorded amounts add up beyond any ceiling")?;
    parsed.tally.entries += 1;
    parsed.entries.push(LedgerEntry {
        seq: entry.seq,
        time,
        counter: entry.counter,
        amount: entry.n,
        digest,
        note: entry.note,
    });
    Ok(())
}

fn parse_adopt(parsed: &mut Parsed, line: AdoptLine) -> Result<(), &'static str> {
    let bad = "the adoption record is not valid";
    let (Ok(digest), Ok(time)) = (
        line.digest.parse::<Digest>(),
        OffsetDateTime::parse(&line.time, &Rfc3339),
    ) else {
        return Err(bad);
    };
    if line.event != "adopt"
        || check_reason(&line.reason).is_err()
        || !valid_totals(&line.carried)
        || line.carried.values().any(|n| *n == 0)
    {
        return Err(bad);
    }
    let previous = match line.witness {
        None => None,
        Some(w) => {
            let tail = w.tail.parse::<Digest>().map_err(|_| bad)?;
            if !valid_totals(&w.totals) || w.ledger.len() > 4096 || w.updated.len() > 64 {
                return Err(bad);
            }
            Some(Witnessed {
                ledger: w.ledger,
                seq: w.seq,
                tail,
                totals: w.totals,
                updated: w.updated,
            })
        }
    };
    for (counter, n) in &line.carried {
        add(&mut parsed.tally.spent, counter, *n)
            .ok_or("the recorded amounts add up beyond any ceiling")?;
    }
    parsed.adoptions.push(Adoption {
        seq: line.seq,
        time,
        reason: line.reason,
        digest,
        carried: line.carried,
        previous,
    });
    Ok(())
}

/// Check an adoption reason: required, and a note in every other way.
fn check_reason(reason: &str) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("the reason is empty; say why the ledger is being adopted".to_owned());
    }
    check_new_note(reason).map_err(|m| m.replace("the note", "the reason"))
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
/// This reads the ledger only and does not consult the witness, so it
/// cannot tell a lost ledger from an unused one: [`read_ledger`] does.
///
/// # Errors
///
/// A ledger that is a link, not private, damaged, or for another pass id.
pub fn tally(loaded: &LoadedPass) -> Result<Tally, Error> {
    Ok(read_shared(loaded)?
        .0
        .map_or_else(Tally::default, |p| p.tally))
}

/// Read and verify the whole ledger beside `loaded` under a shared lock:
/// `None` when there is no ledger. The lock is held as long as the returned
/// file is.
fn read_shared(loaded: &LoadedPass) -> Result<(Option<Parsed>, Option<fs::File>), Error> {
    let path = ledger_path(&loaded.path);
    if !exists(&path)? {
        return Ok((None, None));
    }
    let mut file = open_no_follow(&path, OpenOptions::new().read(true))?;
    check_private(&path, &file)?;
    file.lock_shared().map_err(|e| Error::io(&path, &e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::io(&path, &e))?;
    Ok((
        Some(parse_ledger(&path, &bytes, &loaded.pass.id)?),
        Some(file),
    ))
}

/// Whether anything (even a dangling link) is at `path`.
fn exists(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(path, &e)),
    }
}

/// Compare the ledger (or its absence) with the witness. The errors are the
/// cases that fail closed; the second value is where the witness last saw
/// the ledger, when that was another path.
fn compare(
    pass_path: &Path,
    ledger: &Path,
    parsed: Option<&Parsed>,
    witness: Option<&Witnessed>,
    state: &StateDir,
    pass_id: &str,
) -> Result<(WitnessStatus, Option<String>), Error> {
    let witness_file = state.witness_path(pass_id).unwrap_or_default();
    match (parsed, witness) {
        (None, None) => Ok((WitnessStatus::Fresh, None)),
        (None, Some(w)) if w.seq == 0 => Ok((WitnessStatus::Fresh, None)),
        (None, Some(w)) => Err(Error::LedgerMissing(Box::new(MissingLedger {
            path: ledger.to_path_buf(),
            pass: pass_path.to_path_buf(),
            pass_id: pass_id.to_owned(),
            witness: witness_file,
            seq: w.seq,
            last_seen: w.ledger.clone(),
            totals: w.totals.clone(),
            updated: w.updated.clone(),
        }))),
        (Some(_), None) => Ok((WitnessStatus::Missing, None)),
        (Some(p), Some(w)) => {
            let here = ledger_identity(ledger);
            let moved = (w.ledger != here).then(|| w.ledger.clone());
            let witnessed = usize::try_from(w.seq)
                .ok()
                .and_then(|i| p.hashes.get(i))
                .is_some_and(|h| *h == w.tail);
            if witnessed {
                let added = p.seq - w.seq;
                let status = if added == 0 {
                    WitnessStatus::Matches
                } else {
                    WitnessStatus::Extended { added }
                };
                return Ok((status, moved));
            }
            let mut detail = if w.seq > p.seq {
                format!(
                    "the witness recorded {} line(s) after the header (spent: {}) on {}, but this ledger has only {}: lines were removed, or this is an older copy",
                    w.seq,
                    totals_text(&w.totals),
                    w.updated,
                    p.seq
                )
            } else {
                format!(
                    "entry {} is not the line hallpass wrote there on {}: it was edited, or this is a different ledger for the same pass id",
                    w.seq, w.updated
                )
            };
            if let Some(other) = &moved {
                if Path::new(other).exists() {
                    let _ = write!(
                        detail,
                        "; another ledger for pass `{pass_id}` exists at {other}: if two pass files share this id, give one of them its own id"
                    );
                } else {
                    let _ = write!(detail, "; the witness last saw the ledger at {other}");
                }
            }
            Err(Error::LedgerChanged {
                path: ledger.to_path_buf(),
                pass: pass_path.to_path_buf(),
                witness: witness_file,
                detail,
            })
        }
    }
}

/// Warnings for a comparison that did not fail. `writing` is true when the
/// caller is about to record (or has recorded) a new witness.
fn warnings(
    status: &WitnessStatus,
    moved: Option<&String>,
    pass_id: &str,
    writing: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    match status {
        WitnessStatus::Missing if writing => out.push(format!(
            "there was no witness for pass `{pass_id}` (a pass brought from another machine, user or state directory?); one is recorded now, so from here on a lost or rewound ledger is noticed"
        )),
        WitnessStatus::Missing => out.push(format!(
            "there is no witness for pass `{pass_id}` (a pass brought from another machine, user or state directory?); the next spend records one, and until then a lost or rewound ledger would not be noticed"
        )),
        WitnessStatus::Extended { added } => out.push(format!(
            "the ledger has {added} line(s) after the last one the witness recorded (a spend that stopped before updating the witness, or a hallpass that keeps none); they are counted"
        )),
        WitnessStatus::NotChecked { reason } => {
            out.push(format!("the ledger was not checked against its witness: {reason}"));
        }
        WitnessStatus::Fresh | WitnessStatus::Matches => {}
    }
    if let Some(from) = moved {
        out.push(format!(
            "the witness last saw this ledger at {from}; it was moved or copied. Spend from one copy only: the other will then be refused as changed"
        ));
    }
    out
}

/// Read and verify every entry of the ledger beside `loaded`, and compare
/// it with its witness in `state`.
///
/// The chain is verified under a shared lock, so it never sees half of a
/// spend. A missing ledger with no witness of any spend is returned with
/// `exists: false` and no entries.
///
/// Read-only: it never writes the ledger or the witness. A witness that
/// cannot be read is reported in `witness` and `warnings`, not as an error.
///
/// # Errors
///
/// As [`tally`] (a ledger that is a link, not private, damaged, or for
/// another pass id), plus [`Error::LedgerMissing`] when the ledger is gone
/// but the witness recorded spends, and [`Error::LedgerChanged`] when the
/// ledger does not hold the line the witness recorded.
pub fn read_ledger(loaded: &LoadedPass, state: &StateDir) -> Result<LedgerView, Error> {
    let path = ledger_path(&loaded.path);
    let id = &loaded.pass.id;
    let (parsed, _lock) = read_shared(loaded)?;
    let (witness, moved) = match state.read(id) {
        Err(e) => (
            WitnessStatus::NotChecked {
                reason: e.to_string(),
            },
            None,
        ),
        Ok(w) => compare(&loaded.path, &path, parsed.as_ref(), w.as_ref(), state, id)?,
    };
    let warnings = warnings(&witness, moved.as_ref(), id, false);
    let exists = parsed.is_some();
    let parsed = parsed.unwrap_or_else(|| Parsed {
        tally: Tally::default(),
        entries: Vec::new(),
        adoptions: Vec::new(),
        hashes: Vec::new(),
        seq: 0,
    });
    Ok(LedgerView {
        path,
        exists,
        entries: parsed.entries,
        adoptions: parsed.adoptions,
        tally: parsed.tally,
        witness,
        moved_from: moved,
        warnings,
    })
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create the ledger with its header if it does not exist. The file appears
/// complete or not at all (written aside, then hard-linked into place), so
/// an empty ledger is always damage.
fn create_ledger(path: &Path, pass_id: &str) -> Result<(), Error> {
    if exists(path)? {
        return Ok(());
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
                "`{}` is not a ceiling of this pass (it has: {}); only what the owner put a ceiling on can be spent: use one of those names, or ask the owner to add this ceiling to the pass in writing",
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

/// A ledger opened for writing under both locks.
struct Locked {
    /// The witness lock (held until dropped).
    _witness_lock: fs::File,
    /// The ledger, locked exclusively.
    file: fs::File,
    path: PathBuf,
    /// The pass as read under the locks.
    loaded: LoadedPass,
    /// The witness as read under the lock.
    witness: Option<Witnessed>,
    /// The ledger as read under the locks.
    parsed: Parsed,
    /// True when this call created the ledger.
    created: bool,
}

/// Take the witness lock for the pass id, then the ledger lock, and read
/// both. Lock order is always witness, then ledger, for every writer, so
/// writers cannot deadlock; readers take only the ledger lock (shared) and
/// read the witness, which is replaced atomically.
///
/// For a spend (`adopting` false), a missing ledger whose witness recorded
/// spends is [`Error::LedgerMissing`] and nothing is created; otherwise a
/// missing ledger is created. For an adoption, a missing ledger is created
/// only when the witness recorded spends (that is what is adopted).
fn lock_for_writing(pass_path: &Path, state: &StateDir, adopting: bool) -> Result<Locked, Error> {
    let id = load(pass_path)?.pass.id;
    let witness_lock = state.lock(&id)?;
    let witness = state.read(&id)?;
    let path = ledger_path(pass_path);
    let created = !exists(&path)?;
    if created {
        if !adopting {
            compare(pass_path, &path, None, witness.as_ref(), state, &id)?;
        } else if witness.as_ref().is_none_or(|w| w.seq == 0) {
            return Err(Error::Usage(
                "there is no ledger and no witness of any spend for this pass: nothing to adopt. Nothing was recorded".to_owned(),
            ));
        }
        create_ledger(&path, &id)?;
    }
    let mut file = open_no_follow(&path, OpenOptions::new().read(true).append(true))?;
    check_private(&path, &file)?;
    file.lock().map_err(|e| Error::io(&path, &e))?;

    // Everything below holds both locks. The pass is read again: what counts
    // is the pass as it is now, not as it was a moment ago.
    let loaded = load(pass_path)?;
    if loaded.pass.id != id {
        return Err(Error::Usage(format!(
            "the pass id changed from `{id}` to `{}` while waiting for the ledger; nothing was recorded. Run the command again",
            loaded.pass.id
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::io(&path, &e))?;
    let parsed = parse_ledger(&path, &bytes, &id)?;
    Ok(Locked {
        _witness_lock: witness_lock,
        file,
        path,
        loaded,
        witness,
        parsed,
        created,
    })
}

fn rfc3339(now: OffsetDateTime) -> String {
    in_utc(now)
        .and_then(|utc| utc.format(&Rfc3339).ok())
        .unwrap_or_else(|| stamp(now))
}

/// Refuse a clock that cannot be written into the ledger (a UTC year
/// outside 0001 to 9999), before anything is touched.
fn check_clock(now: OffsetDateTime) -> Result<(), Error> {
    if in_utc(now).is_some() {
        return Ok(());
    }
    Err(Error::Usage(format!(
        "the clock says {}, which is outside the years 0001 to 9999 in UTC; fix the clock the caller passes. Nothing was recorded",
        stamp(now)
    )))
}

/// Append one line (without its newline) to the locked ledger and sync it.
fn append(locked: &mut Locked, line: &str, what: &str) -> Result<(), Error> {
    locked
        .file
        .write_all(format!("{line}\n").as_bytes())
        .and_then(|()| locked.file.sync_data())
        .map_err(|e| Error::Io {
            path: locked.path.clone(),
            message: format!(
                "the {what} could not be written ({e}); treat it as NOT permitted and check the ledger before continuing"
            ),
        })
}

/// Atomically check and record a spend against the pass at `pass_path`,
/// with the witness in the state directory named by the environment
/// ([`StateDir::from_env`]). See [`spend_in`].
///
/// # Errors
///
/// As [`spend_in`].
pub fn spend(
    pass_path: &Path,
    request: &SpendRequest<'_>,
    now: OffsetDateTime,
) -> Result<SpendOutcome, Error> {
    spend_in(pass_path, request, now, &StateDir::from_env())
}

/// Atomically check and record a spend against the pass at `pass_path`,
/// keeping its witness in `state`.
///
/// Under an exclusive lock on the witness and then on the ledger it re-reads
/// the pass, checks the ledger against the witness, the expected digest, the
/// window and revocation at `now`, and the remaining total, then appends the
/// entry (and syncs it to disk) and updates the witness, or refuses and
/// records nothing in the ledger. Two processes spending at once never
/// together exceed the total.
///
/// The witness is written after the ledger. A crash between the two leaves
/// the witness one line behind, which the next call accepts (the ledger
/// only grew). When the ledger had no witness, or the witness saw it at
/// another path, the witness is recorded before deciding, even if the
/// spend is then refused; [`SpendOutcome::warnings`] says so.
///
/// # Errors
///
/// Anything that prevents a sure decision: an unreadable or invalid pass, a
/// damaged or foreign ledger, a ledger that is missing or changed according
/// to the witness, a state directory that cannot be used, a malformed
/// request, a failed write. Nothing is recorded, except in
/// [`Error::WitnessNotUpdated`], where the spend was recorded but the
/// witness could not be updated afterwards.
pub fn spend_in(
    pass_path: &Path,
    request: &SpendRequest<'_>,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<SpendOutcome, Error> {
    check_clock(now)?;
    if request.needed.is_negative() {
        return Err(Error::Usage(
            "the duration the work may take is negative; pass zero for \"right now\", or how long the work may take. Nothing was recorded".to_owned(),
        ));
    }
    if request.amount == 0 || request.amount > MAX_CEILING {
        return Err(Error::Usage(format!(
            "the amount must be a whole number from 1 to {MAX_CEILING}; nothing was recorded"
        )));
    }
    if let Some(note) = request.note {
        check_new_note(note).map_err(|m| Error::Usage(format!("{m}; nothing was recorded")))?;
    }
    let mut locked = lock_for_writing(pass_path, state, false)?;
    let id = locked.loaded.pass.id.clone();
    let here = ledger_identity(&locked.path);
    let (status, moved) = compare(
        pass_path,
        &locked.path,
        Some(&locked.parsed),
        locked.witness.as_ref(),
        state,
        &id,
    )?;
    let mut warnings = warnings(&status, moved.as_ref(), &id, true);
    if locked.created && status == WitnessStatus::Missing {
        // This call started the ledger: it has no witness because it is
        // new, not because it came from somewhere else.
        warnings.clear();
    }
    if status != WitnessStatus::Matches || moved.is_some() {
        state.write(
            &id,
            &Witnessed {
                ledger: here.clone(),
                seq: locked.parsed.seq,
                tail: locked.parsed.tail(),
                totals: locked.parsed.tally.spent.clone(),
                updated: stamp(now),
            },
        )?;
    }
    let loaded = &locked.loaded;
    let total = loaded.pass.ceilings.get(request.counter).copied();
    let spent = locked.parsed.tally.spent(request.counter);
    let mut outcome = SpendOutcome {
        refusal: None,
        counter: request.counter.to_owned(),
        amount: request.amount,
        total,
        spent,
        seq: None,
        digest: loaded.digest,
        pass_id: id.clone(),
        warnings,
    };
    if let Some(refusal) = decide(loaded, request, total, spent, now) {
        outcome.refusal = Some(refusal);
        return Ok(outcome);
    }
    let entry = Entry {
        seq: locked.parsed.seq + 1,
        time: rfc3339(now),
        counter: request.counter.to_owned(),
        n: request.amount,
        digest: loaded.digest.to_string(),
        note: request.note.map(str::to_owned),
        prev: locked.parsed.tail().to_string(),
    };
    let line = serde_json::to_string(&entry).map_err(|e| Error::Usage(e.to_string()))?;
    append(&mut locked, &line, "spend")?;
    let mut totals = locked.parsed.tally.spent.clone();
    let _ = add(&mut totals, request.counter, request.amount);
    state
        .write(
            &id,
            &Witnessed {
                ledger: here,
                seq: entry.seq,
                tail: Digest::of(line.as_bytes()),
                totals,
                updated: stamp(now),
            },
        )
        .map_err(|e| Error::WitnessNotUpdated {
            path: locked.path.clone(),
            seq: entry.seq,
            detail: e.to_string(),
        })?;
    outcome.spent = spent + request.amount;
    outcome.seq = Some(entry.seq);
    Ok(outcome)
}

/// The result of an adoption.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdoptOutcome {
    /// The situation that was resolved.
    pub case: AdoptCase,
    /// The adoption as recorded in the ledger.
    pub adoption: Adoption,
    /// The ledger file.
    pub ledger: PathBuf,
    /// True when the ledger was missing and a new one was started.
    pub created: bool,
    /// The pass id.
    pub pass_id: String,
    /// The totals after the adoption (spends and carried amounts).
    pub totals: BTreeMap<String, u64>,
}

/// Acknowledge, with a reason, a ledger that hallpass would otherwise
/// refuse or warn about, and record that acknowledgment in the ledger.
///
/// - The ledger is missing but the witness recorded spends: a new ledger is
///   started, and the adoption carries the witness's totals.
/// - The ledger does not hold the line the witness recorded: the adoption
///   is appended, carrying, per counter, whatever the witness recorded
///   beyond what the ledger holds.
/// - The ledger has no witness: the adoption is appended, carrying nothing.
///
/// In each case the witness then records the new last line. An adoption
/// never lowers a count below what the witness recorded; a new budget is a
/// raised ceiling in the pass or a new pass. The window is not checked: an
/// adoption records, it permits nothing.
///
/// # Errors
///
/// [`Error::Usage`] when the reason is missing or not one plain line, or
/// when there is nothing to adopt (the ledger matches its witness, or there
/// is neither a ledger nor a witnessed spend). Otherwise as [`spend_in`]: an
/// invalid pass, a damaged or foreign ledger (repair or move it aside
/// first), an unusable state directory, a failed write.
pub fn adopt(
    pass_path: &Path,
    reason: &str,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<AdoptOutcome, Error> {
    check_clock(now)?;
    check_reason(reason).map_err(|m| Error::Usage(format!("{m}; nothing was recorded")))?;
    let mut locked = lock_for_writing(pass_path, state, true)?;
    let id = locked.loaded.pass.id.clone();
    let here = ledger_identity(&locked.path);
    let case = if locked.created {
        AdoptCase::LedgerMissing
    } else {
        match compare(
            pass_path,
            &locked.path,
            Some(&locked.parsed),
            locked.witness.as_ref(),
            state,
            &id,
        ) {
            Err(Error::LedgerChanged { .. }) => AdoptCase::LedgerChanged,
            Ok((WitnessStatus::Missing, _)) => AdoptCase::NoWitness,
            Ok(_) => {
                return Err(Error::Usage(format!(
                    "the ledger {} matches its witness: nothing to adopt. Nothing was recorded",
                    locked.path.display()
                )));
            }
            Err(e) => return Err(e),
        }
    };
    let mut carried = BTreeMap::new();
    if let Some(w) = &locked.witness {
        for (counter, n) in &w.totals {
            let have = locked.parsed.tally.spent(counter);
            if *n > have {
                carried.insert(counter.clone(), n - have);
            }
        }
    }
    let line = AdoptLine {
        seq: locked.parsed.seq + 1,
        time: rfc3339(now),
        event: "adopt".to_owned(),
        reason: reason.to_owned(),
        digest: locked.loaded.digest.to_string(),
        carried: carried.clone(),
        witness: locked.witness.as_ref().map(|w| WitnessLine {
            ledger: w.ledger.clone(),
            seq: w.seq,
            tail: w.tail.to_string(),
            totals: w.totals.clone(),
            updated: w.updated.clone(),
        }),
        prev: locked.parsed.tail().to_string(),
    };
    let text = serde_json::to_string(&line).map_err(|e| Error::Usage(e.to_string()))?;
    append(&mut locked, &text, "adoption")?;
    let mut totals = locked.parsed.tally.spent.clone();
    for (counter, n) in &carried {
        let _ = add(&mut totals, counter, *n);
    }
    state
        .write(
            &id,
            &Witnessed {
                ledger: here,
                seq: line.seq,
                tail: Digest::of(text.as_bytes()),
                totals: totals.clone(),
                updated: stamp(now),
            },
        )
        .map_err(|e| Error::WitnessUnavailable {
            pass_id: id.clone(),
            dir: state.path().ok().map(Path::to_path_buf),
            detail: format!(
                "the adoption was recorded in the ledger as entry {}, but the witness could not be updated ({e}); fix the state directory and run `hallpass adopt` again",
                line.seq
            ),
        })?;
    Ok(AdoptOutcome {
        case,
        adoption: Adoption {
            seq: line.seq,
            time: now,
            reason: reason.to_owned(),
            digest: locked.loaded.digest,
            carried,
            previous: locked.witness.clone(),
        },
        ledger: locked.path.clone(),
        created: locked.created,
        pass_id: id,
        totals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::tests::GOOD;
    use std::os::unix::fs::PermissionsExt;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

    /// A pass in a fresh directory, and a state directory of its own (never
    /// the real one).
    fn setup() -> (tempfile::TempDir, PathBuf, StateDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pass.toml");
        fs::write(&path, GOOD).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let state = StateDir::new(dir.path().join("state").join("hallpass"));
        (dir, path, state)
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
        let (_dir, path, state) = setup();
        for i in 1..=6 {
            let out = spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
            assert_eq!(out.refusal, None);
            assert_eq!(out.spent, i);
            assert_eq!(out.seq, Some(i));
        }
        let out = spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
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
    fn the_first_spend_of_a_new_pass_has_nothing_to_warn_about() {
        // A new ledger has no witness yet because it is new, not because it
        // was "brought from another machine".
        let (_dir, path, state) = setup();
        let out = ok(&path, &state, "calls", 1);
        assert_eq!(out.warnings, Vec::<String>::new());
        assert_eq!(ok(&path, &state, "calls", 1).warnings, Vec::<String>::new());
        // The same when the first spend is refused.
        let (_dir, path, state) = setup();
        let out = spend_in(&path, &request("calls", 7), NOW, &state).expect("spend");
        assert!(out.refusal.is_some());
        assert_eq!(out.warnings, Vec::<String>::new());
        assert_eq!(
            view(&path, &state).expect("read").witness,
            WitnessStatus::Matches
        );
    }

    #[test]
    fn edits_keep_the_count() {
        let (_dir, path, state) = setup();
        for _ in 0..6 {
            spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
        }
        fs::write(&path, GOOD.replace("calls = 6", "calls = 8\n# raised")).expect("edit");
        let out = spend_in(&path, &request("calls", 2), NOW, &state).expect("spend");
        assert_eq!(out.refusal, None);
        assert_eq!(out.spent, 8);
        fs::write(&path, GOOD.replace("calls = 6", "calls = 4")).expect("edit");
        let out = spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
        assert_eq!(out.remaining(), Some(0));
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::CeilingReached)
        );
        fs::write(&path, GOOD.replace("acme-2026-11", "other")).expect("edit");
        assert!(matches!(
            spend_in(&path, &request("calls", 1), NOW, &state),
            Err(Error::LedgerForeign { .. })
        ));
    }

    #[test]
    fn refusals_record_nothing() {
        let (_dir, path, state) = setup();
        let out = spend_in(&path, &request("bogus", 1), NOW, &state).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::UnknownCounter)
        );
        let late = spend_in(
            &path,
            &request("calls", 1),
            datetime!(2026-12-01 00:00 UTC),
            &state,
        )
        .expect("spend");
        assert_eq!(late.refusal.map(|r| r.code), Some(RefusalCode::Expired));
        // A negative duration is a caller's mistake, not "right now".
        let mut negative = request("calls", 1);
        negative.needed = Duration::seconds(-1);
        match spend_in(&path, &negative, NOW, &state) {
            Err(Error::Usage(message)) => assert!(message.contains("negative"), "{message}"),
            other => panic!("{other:?}"),
        }
        let out = spend_in(&path, &request("bogus", 1), NOW, &state).expect("spend");
        let message = out.refusal.expect("refused").message;
        assert!(message.contains("ask the owner"), "{message}");
        let mut changed = request("calls", 1);
        changed.expect_digest = Some(Digest::of(b"something else"));
        let out = spend_in(&path, &changed, NOW, &state).expect("spend");
        assert_eq!(out.refusal.map(|r| r.code), Some(RefusalCode::PassChanged));
        let loaded = load(&path).expect("load");
        assert_eq!(tally(&loaded).expect("tally").entries, 0);
        assert!(matches!(
            spend_in(&path, &request("calls", 0), NOW, &state),
            Err(Error::Usage(_))
        ));
        let mut noted = request("calls", 1);
        noted.note = Some("two\nlines");
        assert!(matches!(
            spend_in(&path, &noted, NOW, &state),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn damaged_ledgers_fail_closed() {
        let (_dir, path, state) = setup();
        let mut noted = request("calls", 1);
        noted.note = Some("first call");
        spend_in(&path, &noted, NOW, &state).expect("spend");
        spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
        let ledger = ledger_path(&path);
        let good = fs::read(&ledger).expect("read");
        let damage = |bytes: &[u8]| {
            fs::write(&ledger, bytes).expect("write");
            match spend_in(&path, &request("calls", 1), NOW, &state) {
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
            spend_in(&path, &request("calls", 1), NOW, &state)
                .expect("spend")
                .refusal
                .is_none()
        );
    }

    #[test]
    fn notes_that_could_disguise_themselves_are_refused() {
        let (_dir, path, state) = setup();
        for bad in [
            "a\nb",
            "a\rb",
            "tab\there",
            "esc\u{1b}[31m",
            "csi\u{9b}31m",
            "del\u{7f}",
            "line\u{2028}sep",
            "para\u{2029}sep",
            "rlo\u{202e}txt",
            "isolate\u{2066}x\u{2069}",
            "mark\u{200f}",
        ] {
            let mut noted = request("calls", 1);
            noted.note = Some(bad);
            assert!(
                matches!(spend_in(&path, &noted, NOW, &state), Err(Error::Usage(_))),
                "{bad:?}"
            );
        }
        let mut noted = request("calls", 1);
        noted.note = Some("plain note, with \"quotes\" and ünïcode");
        assert!(
            spend_in(&path, &noted, NOW, &state)
                .expect("spend")
                .refusal
                .is_none()
        );
        let long = "x".repeat(MAX_NOTE + 1);
        noted.note = Some(&long);
        assert!(matches!(
            spend_in(&path, &noted, NOW, &state),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn display_safe_escapes_everything_that_moves_the_cursor() {
        assert_eq!(display_safe("plain ünïcode"), "plain ünïcode");
        assert_eq!(display_safe("a\nb"), "a\\u{000a}b");
        assert_eq!(display_safe("\u{1b}[2J"), "\\u{001b}[2J");
        assert_eq!(display_safe("\u{9b}"), "\\u{009b}");
        assert_eq!(display_safe("x\u{202e}y"), "x\\u{202e}y");
        assert_eq!(display_safe("x\u{2028}y"), "x\\u{2028}y");
        // An escaped-looking note cannot pass for an escape.
        assert_eq!(display_safe("\\u{000a}"), "\\\\u{000a}");
    }

    proptest::proptest! {
        #[test]
        fn display_safe_is_one_plain_line(text in ".*") {
            let shown = display_safe(&text);
            proptest::prop_assert!(!shown.chars().any(|c| c.is_control() || is_disguising(c)));
        }
    }

    #[test]
    fn read_ledger_lists_entries() {
        let (dir, path, state) = setup();
        let loaded = load(&path).expect("load");
        let view = read_ledger(&loaded, &state).expect("read");
        assert!(!view.exists);
        assert_eq!(view.entries, Vec::new());
        let mut noted = request("calls", 2);
        noted.note = Some("first");
        spend_in(&path, &noted, NOW, &state).expect("spend");
        spend_in(&path, &request("requests", 5), NOW, &state).expect("spend");
        let view = read_ledger(&loaded, &state).expect("read");
        assert!(view.exists);
        assert_eq!(view.entries.len(), 2);
        let first = &view.entries[0];
        assert_eq!(
            (first.seq, first.counter.as_str(), first.amount),
            (1, "calls", 2)
        );
        assert_eq!(first.note.as_deref(), Some("first"));
        assert_eq!(first.digest, loaded.digest);
        assert_eq!(first.time, NOW);
        assert_eq!(view.entries[1].note, None);
        assert_eq!(view.tally.spent("requests"), 5);
        // A ledger written by an older hallpass may hold a line separator in
        // a note; it stays readable.
        let ledger = ledger_path(&path);
        let text = fs::read_to_string(&ledger).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        let entry = lines[1].replace("\"first\"", "\"fir\\u2028st\"");
        let second = lines[2].replace(
            &Digest::of(lines[1].as_bytes()).to_string(),
            &Digest::of(entry.as_bytes()).to_string(),
        );
        fs::write(&ledger, format!("{}\n{entry}\n{second}\n", lines[0])).expect("write");
        // This witness notices the rewrite...
        assert!(matches!(
            read_ledger(&loaded, &state),
            Err(Error::LedgerChanged { .. })
        ));
        // ...but a 0.1 ledger has no witness at all.
        let fresh = StateDir::new(dir.path().join("other-state"));
        let view = read_ledger(&loaded, &fresh).expect("read");
        assert_eq!(view.entries[0].note.as_deref(), Some("fir\u{2028}st"));
        assert_eq!(view.witness, WitnessStatus::Missing);
        assert_eq!(view.warnings.len(), 1);
    }

    #[test]
    fn threads_never_overspend() {
        let (_dir, path, state) = setup();
        #[allow(clippy::needless_collect)] // all threads must start before any join
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let path = path.clone();
                let state = state.clone();
                std::thread::spawn(move || {
                    spend_in(&path, &request("calls", 1), NOW, &state)
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
        let view = read_ledger(&loaded, &state).expect("read");
        assert_eq!(view.tally.spent("calls"), 6);
        assert_eq!(view.witness, WitnessStatus::Matches);
    }

    #[test]
    fn links_and_modes_refused() {
        let (dir, path, state) = setup();
        spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
        let ledger = ledger_path(&path);
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            spend_in(&path, &request("calls", 1), NOW, &state),
            Err(Error::Insecure { .. })
        ));
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("chmod");
        let link = dir.path().join("link.pass.toml");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(matches!(
            spend_in(&link, &request("calls", 1), NOW, &state),
            Err(Error::Symlink { .. })
        ));
        let other = dir.path().join("other.pass.toml");
        fs::copy(&path, &other).expect("copy");
        std::os::unix::fs::symlink(&ledger, ledger_path(&other)).expect("symlink");
        assert!(matches!(
            spend_in(&other, &request("calls", 1), NOW, &state),
            Err(Error::Symlink { .. })
        ));
    }

    // ---- the witness ---------------------------------------------------

    fn ok(path: &Path, state: &StateDir, counter: &str, n: u64) -> SpendOutcome {
        let out = spend_in(path, &request(counter, n), NOW, state).expect("spend");
        assert_eq!(out.refusal, None, "{out:?}");
        out
    }

    fn view(path: &Path, state: &StateDir) -> Result<LedgerView, Error> {
        read_ledger(&load(path).expect("load"), state)
    }

    #[test]
    fn a_lost_ledger_is_noticed_and_adoption_keeps_the_count() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 3);
        ok(&path, &state, "requests", 7);
        fs::remove_file(ledger_path(&path)).expect("lose the ledger");
        for result in [
            spend_in(&path, &request("calls", 1), NOW, &state).map(|_| ()),
            view(&path, &state).map(|_| ()),
        ] {
            match result {
                Err(e @ Error::LedgerMissing(_)) => {
                    let text = e.to_string();
                    assert!(text.contains("calls 3, requests 7"), "{text}");
                    assert!(text.contains("hallpass adopt"), "{text}");
                }
                other => panic!("not refused as missing: {other:?}"),
            }
        }
        assert!(!ledger_path(&path).exists(), "nothing was created");
        assert!(matches!(
            adopt(&path, "  ", NOW, &state),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            adopt(&path, "two\nlines", NOW, &state),
            Err(Error::Usage(_))
        ));
        let adopted = adopt(&path, "ledger lost in a copy", NOW, &state).expect("adopt");
        assert_eq!(adopted.case, AdoptCase::LedgerMissing);
        assert!(adopted.created);
        assert_eq!(adopted.adoption.seq, 1);
        assert_eq!(adopted.adoption.carried.get("calls"), Some(&3));
        assert_eq!(adopted.adoption.previous.as_ref().map(|w| w.seq), Some(2));
        let v = view(&path, &state).expect("read");
        assert_eq!(v.witness, WitnessStatus::Matches);
        assert_eq!((v.tally.spent("calls"), v.tally.spent("requests")), (3, 7));
        assert_eq!(v.adoptions[0].reason, "ledger lost in a copy");
        // The count goes on from 3, not from 0.
        ok(&path, &state, "calls", 3);
        let out = spend_in(&path, &request("calls", 1), NOW, &state).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::CeilingReached)
        );
        // Nothing left to adopt.
        assert!(matches!(
            adopt(&path, "again", NOW, &state),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn an_edited_last_line_is_noticed() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        let mut noted = request("calls", 2);
        noted.note = Some("last one");
        spend_in(&path, &noted, NOW, &state).expect("spend");
        let ledger = ledger_path(&path);
        let good = fs::read_to_string(&ledger).expect("read");
        // The chain cannot see this: nothing follows the last line.
        let edited = good.replace("\"n\":2", "\"n\":1");
        fs::write(&ledger, &edited).expect("edit");
        assert_eq!(
            tally(&load(&path).expect("load"))
                .expect("tally")
                .spent("calls"),
            2
        );
        for result in [
            spend_in(&path, &request("calls", 1), NOW, &state).map(|_| ()),
            view(&path, &state).map(|_| ()),
        ] {
            match result {
                Err(e @ Error::LedgerChanged { .. }) => {
                    assert!(e.to_string().contains("entry 2 is not the line"), "{e}");
                }
                other => panic!("not refused as changed: {other:?}"),
            }
        }
        fs::write(&ledger, &good).expect("restore");
        assert_eq!(
            view(&path, &state).expect("read").witness,
            WitnessStatus::Matches
        );
    }

    #[test]
    fn an_older_copy_is_noticed_and_adoption_carries_the_difference() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 2);
        let ledger = ledger_path(&path);
        let older = fs::read(&ledger).expect("read");
        ok(&path, &state, "calls", 3);
        fs::write(&ledger, &older).expect("rewind");
        match spend_in(&path, &request("calls", 1), NOW, &state) {
            Err(e @ Error::LedgerChanged { .. }) => {
                assert!(e.to_string().contains("has only 1"), "{e}");
            }
            other => panic!("{other:?}"),
        }
        let adopted = adopt(&path, "restored from backup", NOW, &state).expect("adopt");
        assert_eq!(adopted.case, AdoptCase::LedgerChanged);
        assert_eq!(adopted.adoption.carried.get("calls"), Some(&3));
        assert_eq!(adopted.totals.get("calls"), Some(&5));
        let out = ok(&path, &state, "calls", 1);
        assert_eq!(out.spent, 6);
    }

    #[test]
    fn two_passes_with_one_id_are_not_merged() {
        let (dir, path, state) = setup();
        ok(&path, &state, "calls", 2);
        let other_dir = dir.path().join("elsewhere");
        fs::create_dir(&other_dir).expect("mkdir");
        let other = other_dir.join("test.pass.toml");
        fs::copy(&path, &other).expect("copy");
        // A second pass with the same id and no ledger: refused, naming
        // where the ledger of that id was last seen.
        match spend_in(&other, &request("calls", 1), NOW, &state) {
            Err(e @ Error::LedgerMissing(_)) => {
                assert!(
                    e.to_string()
                        .contains(&ledger_identity(&ledger_path(&path)))
                );
            }
            other => panic!("{other:?}"),
        }
        // The pass moved with its ledger: accepted, with a warning.
        fs::copy(ledger_path(&path), ledger_path(&other)).expect("copy ledger");
        let out = ok(&other, &state, "calls", 1);
        assert_eq!(out.spent, 3);
        assert!(
            out.warnings[0].contains("moved or copied"),
            "{:?}",
            out.warnings
        );
        // The copy left behind is now stale and refused.
        match spend_in(&path, &request("calls", 1), NOW, &state) {
            Err(e @ Error::LedgerChanged { .. }) => {
                assert!(e.to_string().contains("another ledger for pass"), "{e}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn concurrent_spends_on_two_copies_never_both_count() {
        let (dir, path, state) = setup();
        ok(&path, &state, "requests", 1);
        let copy_dir = dir.path().join("copy");
        fs::create_dir(&copy_dir).expect("mkdir");
        let copy = copy_dir.join("test.pass.toml");
        fs::copy(&path, &copy).expect("copy");
        fs::copy(ledger_path(&path), ledger_path(&copy)).expect("copy ledger");
        #[allow(clippy::needless_collect)] // all threads must start before any join
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let target = if i % 2 == 0 {
                    path.clone()
                } else {
                    copy.clone()
                };
                let state = state.clone();
                std::thread::spawn(move || {
                    let result = spend_in(&target, &request("requests", 1), NOW, &state);
                    (target, result)
                })
            })
            .collect();
        let mut winners = std::collections::BTreeSet::new();
        let mut recorded = 0;
        for h in handles {
            let (target, result) = h.join().expect("join");
            match result {
                Ok(out) if out.refusal.is_none() => {
                    winners.insert(target);
                    recorded += 1;
                }
                Err(Error::LedgerChanged { .. }) => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(winners.len(), 1, "both copies were spent from");
        assert_eq!(recorded, 8);
        let winner = winners.first().expect("winner");
        assert_eq!(
            view(winner, &state).expect("read").tally.spent("requests"),
            9
        );
    }

    #[test]
    fn a_crash_between_ledger_and_witness_neither_locks_out_nor_loses_a_spend() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        let witness = state.witness_path("acme-2026-11").expect("path");
        let before = fs::read(&witness).expect("read");
        ok(&path, &state, "calls", 1);
        // As if the process died after syncing the ledger line and before
        // replacing the witness.
        fs::write(&witness, &before).expect("rewind witness");
        let v = view(&path, &state).expect("read");
        assert_eq!(v.witness, WitnessStatus::Extended { added: 1 });
        assert_eq!(v.tally.spent("calls"), 2, "the spend still counts");
        assert_eq!(v.warnings.len(), 1);
        let out = ok(&path, &state, "calls", 1);
        assert_eq!(out.spent, 3);
        assert_eq!(out.warnings.len(), 1);
        assert_eq!(
            view(&path, &state).expect("read").witness,
            WitnessStatus::Matches
        );
    }

    #[test]
    fn a_ledger_without_witness_is_accepted_with_a_warning() {
        let (dir, path, state) = setup();
        ok(&path, &state, "calls", 2);
        let elsewhere = StateDir::new(dir.path().join("other-machine"));
        let v = view(&path, &elsewhere).expect("read");
        assert_eq!(v.witness, WitnessStatus::Missing);
        assert!(v.warnings[0].contains("next spend records one"));
        assert!(
            !dir.path().join("other-machine").exists(),
            "reading wrote nothing"
        );
        // Refused spends record the witness too.
        let out = spend_in(&path, &request("calls", 9), NOW, &elsewhere).expect("spend");
        assert!(out.refusal.is_some());
        assert!(out.warnings[0].contains("one is recorded now"));
        assert_eq!(
            view(&path, &elsewhere).expect("read").witness,
            WitnessStatus::Matches
        );
        // An explicit adoption is possible too, and carries nothing.
        let third = StateDir::new(dir.path().join("third"));
        let adopted = adopt(&path, "brought from the lab machine", NOW, &third).expect("adopt");
        assert_eq!(adopted.case, AdoptCase::NoWitness);
        assert!(adopted.adoption.carried.is_empty());
        assert_eq!(adopted.adoption.previous, None);
        assert_eq!(view(&path, &third).expect("read").tally.spent("calls"), 2);
        // With no ledger and no witness there is nothing to adopt.
        let (_d2, fresh, s2) = setup();
        assert!(matches!(
            adopt(&fresh, "why", NOW, &s2),
            Err(Error::Usage(_))
        ));
        assert!(!ledger_path(&fresh).exists());
    }

    #[test]
    fn an_unusable_state_directory_fails_closed_for_spends_only() {
        let (dir, path, _) = setup();
        let blocker = dir.path().join("a-file");
        fs::write(&blocker, "").expect("write");
        let broken = StateDir::new(blocker.join("hallpass"));
        assert!(matches!(
            spend_in(&path, &request("calls", 1), NOW, &broken),
            Err(Error::WitnessUnavailable { .. })
        ));
        assert!(!ledger_path(&path).exists(), "nothing was recorded");
        let v = view(&path, &broken).expect("read-only commands still work");
        assert!(matches!(
            v.witness,
            WitnessStatus::Fresh | WitnessStatus::NotChecked { .. }
        ));

        let state = StateDir::new(dir.path().join("state"));
        ok(&path, &state, "calls", 1);
        let state_dir = dir.path().join("state");
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o500)).expect("chmod");
        let result = spend_in(&path, &request("calls", 1), NOW, &state);
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        match result {
            Err(e @ Error::WitnessUnavailable { .. }) => {
                assert!(e.to_string().contains("not writable"), "{e}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(view(&path, &state).expect("read").tally.entries, 1);

        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            spend_in(&path, &request("calls", 1), NOW, &state),
            Err(Error::WitnessUnavailable { .. })
        ));
        let v = view(&path, &state).expect("read");
        assert!(matches!(v.witness, WitnessStatus::NotChecked { .. }));
        assert!(v.warnings[0].contains("chmod 700"), "{:?}", v.warnings);
    }

    #[test]
    fn a_clock_outside_the_calendar_is_refused_not_a_panic() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        fs::remove_file(ledger_path(&path)).expect("lose");
        // Year 10000 in UTC: it cannot be written into the ledger.
        let edge = datetime!(9999-12-31 23:59:59 -1);
        for result in [
            adopt(&path, "lost", edge, &state).map(|_| ()),
            spend_in(&path, &request("calls", 1), edge, &state).map(|_| ()),
        ] {
            match result {
                Err(Error::Usage(message)) => {
                    assert!(message.contains("clock"), "{message}");
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(!ledger_path(&path).exists(), "nothing was recorded");
    }

    #[test]
    fn adoption_records_survive_parsing_and_damage_is_caught() {
        let (dir, path, state) = setup();
        ok(&path, &state, "calls", 2);
        fs::remove_file(ledger_path(&path)).expect("lose");
        adopt(&path, "lost", NOW, &state).expect("adopt");
        let ledger = ledger_path(&path);
        let text = fs::read_to_string(&ledger).expect("read");
        assert!(text.contains("\"event\":\"adopt\""), "{text}");
        let fresh = StateDir::new(dir.path().join("fresh"));
        for (from, to) in [
            ("\"calls\":2", "\"calls\":0"),
            ("\"event\":\"adopt\"", "\"event\":\"reset\""),
            ("\"reason\":\"lost\"", "\"reason\":\"\""),
        ] {
            fs::write(&ledger, text.replace(from, to)).expect("damage");
            assert!(
                matches!(
                    view(&path, &fresh),
                    Err(Error::LedgerCorrupt { line: 2, .. })
                ),
                "{to}"
            );
        }
    }
}
