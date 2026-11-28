//! The ledger: spends recorded across processes, so a ceiling holds for the
//! whole engagement and not only for one command.
//!
//! The ledger is `<pass file>.ledger`, beside the pass, mode 0600. It is
//! JSON Lines: a header line naming the pass id, then one line per scalar
//! event or atomic batch. Every event carries its first sequence number and
//! the SHA-256 of the line before it; a batch assigns a distinct logical
//! sequence to each unit in its one line. A damaged, reordered or cut line is
//! detected. A ledger that
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
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::address::Target;
use crate::decision::{Refusal, RefusalCode, in_utc, stamp};
use crate::error::{ElsewhereLedger, Error, MissingLedger};
use crate::files::{
    Digest, LoadedPass, LockBudget, load, lock_shared, open_no_follow, with_requested_wait,
};
use crate::name::HostName;
use crate::pass::{MAX_CEILING, is_counter_name};
use crate::request::{TargetRefusal, decide_targets};
use crate::witness::{
    Fork, StateDir, Witnessed, ledger_identity, same_totals, totals_text, valid_totals,
};
use crate::{MAX_TARGETS, NamedTarget};

mod append;
pub mod capacity;
mod clock;
mod debit;
pub mod evidence;
mod evidence_charges;
mod evidence_manifest;
mod reference;
mod repair;
pub mod scenario;
mod written;
pub use clock::with_test_clock;
pub use debit::*;
use debit::{DEBIT_BATCH_EVENT, DebitBatchLine, DebitLine, parse_debit, parse_debit_batch};
pub use reference::{
    MAX_RECONCILED_REFERENCES, MAX_REFERENCE_LIST_BYTES, ReconcileReferencesOutcome,
    ReferenceEvidence, ReferenceReconciliation, read_reference_list, reconcile_references,
};
use reference::{ReconcileLine, parse_reconcile};
mod newline;
pub use newline::{FinalNewline, preview_restore_final_newline, restore_final_newline};
pub use repair::{TornTail, drop_torn_tail, preview_drop_torn_tail};

/// The ledger format version.
const LEDGER_VERSION: u32 = 1;
/// The longest note a spend may carry, in characters.
pub const MAX_NOTE: usize = 500;
/// The read buffer for a scan of the whole ledger (fewer, larger reads).
const SCAN_BUFFER: usize = 1 << 16;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    test_clock: Option<bool>,
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

/// A spend to record, and optionally the one thing it pays for.
///
/// With [`SpendRequest::target`] set, one call answers "may I send this
/// much to this address, port and protocol now, and count it": the
/// destination is checked under the same lock, against the same reading of
/// the pass, as the window and the ceiling, and a refusal records nothing.
///
/// Build it with [`SpendRequest::new`] and set the fields you need; more
/// fields may be added.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
    /// Maximum total wait for the locks: both writer locks on a real spend,
    /// the shared ledger lock on a preview. Zero asks once per lock; None
    /// waits indefinitely, or as an enclosing [`crate::with_lock_wait`]
    /// allows. This excludes post-lock I/O.
    pub lock_timeout: Option<std::time::Duration>,
    /// Called once, from the waiting thread, when a lock has been busy for
    /// about two seconds. The library prints nothing itself. None uses the
    /// function of an enclosing [`crate::with_lock_wait`], if any.
    pub on_lock_wait: Option<fn(&crate::files::LockWait)>,
    /// What is about to be touched. When set, the spend is also refused,
    /// and nothing is recorded, unless the pass permits this target now
    /// (as [`crate::Pass::permits_named`] decides, with `name` and
    /// `needed`). A pass can require at least one target on every debit.
    pub target: Option<Target>,
    /// The host name the request will carry (see
    /// [`crate::Pass::permits_named`]). Only with `target`; a name without
    /// a target is a usage error.
    pub name: Option<&'a HostName>,
    /// Further targets of this unit, checked in the supplied order.
    pub additional_targets: &'a [NamedTarget],
}

impl<'a> SpendRequest<'a> {
    /// A spend of `amount` from `counter`: no note, no expected digest, no
    /// duration ("right now"), no target.
    #[must_use]
    pub const fn new(counter: &'a str, amount: u64) -> Self {
        Self {
            counter,
            amount,
            note: None,
            expect_digest: None,
            needed: Duration::ZERO,
            lock_timeout: None,
            on_lock_wait: None,
            target: None,
            name: None,
            additional_targets: &[],
        }
    }

    fn targets(&self) -> impl Iterator<Item = (Target, Option<&HostName>)> {
        self.target
            .into_iter()
            .map(|target| (target, self.name))
            .chain(
                self.additional_targets
                    .iter()
                    .map(|entry| (entry.target, entry.name.as_ref())),
            )
    }
}

/// The result of a spend that was decided (recorded or refused).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendOutcome {
    /// Instant used for the decision under the lock.
    pub now: OffsetDateTime,
    /// All matched labels in order when allowed.
    pub labels: Vec<String>,
    /// One-based index of a target-specific refusal.
    pub refused_target: Option<usize>,
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
    /// The label of the destination that permits [`SpendRequest::target`],
    /// when a target was given and the spend was recorded.
    pub label: Option<String>,
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

/// The Unicode format characters (general category Cf in Unicode 16.0), as
/// inclusive ranges of code points. They include the zero-width space,
/// joiners and word joiner, the soft hyphen, the byte order mark, the
/// bidirectional controls, the interlinear annotation controls and the tag
/// characters: most are invisible, and the others change how the text around
/// them is shown.
const FORMAT_CHARACTERS: [(u32, u32); 21] = [
    (0x00ad, 0x00ad),
    (0x0600, 0x0605),
    (0x061c, 0x061c),
    (0x06dd, 0x06dd),
    (0x070f, 0x070f),
    (0x0890, 0x0891),
    (0x08e2, 0x08e2),
    (0x180e, 0x180e),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x2064),
    (0x2066, 0x206f),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x1343f),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
];

/// The default-ignorable code points (`Default_Ignorable_Code_Point` in
/// `DerivedCoreProperties.txt` of Unicode 16.0), as inclusive ranges. A
/// viewer that does not support one shows nothing for it. Most are also
/// format characters; the others are the combining grapheme joiner (U+034F),
/// the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), two Khmer inherent
/// vowels (U+17B4, U+17B5), the variation selectors (U+180B to U+180F,
/// U+FE00 to U+FE0F, U+E0100 to U+E01EF) and code points reserved as
/// ignorable (U+2065, U+FFF0 to U+FFF8 and the rest of U+E0000 to U+E0FFF).
const DEFAULT_IGNORABLE: [(u32, u32); 17] = [
    (0x00ad, 0x00ad),
    (0x034f, 0x034f),
    (0x061c, 0x061c),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfff8),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

/// The space separators (general category Zs in Unicode 16.0) other than
/// the ASCII space U+0020, as inclusive ranges: the no-break space, the
/// Ogham space mark, the en, em and other fixed-width spaces, the narrow
/// no-break space, the medium mathematical space and the ideographic space.
/// Each looks like a plain space, or like nothing.
const SPACE_SEPARATORS: [(u32, u32); 6] = [
    (0x00a0, 0x00a0),
    (0x1680, 0x1680),
    (0x2000, 0x200a),
    (0x202f, 0x202f),
    (0x205f, 0x205f),
    (0x3000, 0x3000),
];

/// Whether code point `c` is in one of the inclusive ranges of `table`.
fn in_table(table: &[(u32, u32)], c: u32) -> bool {
    table
        .iter()
        .any(|&(first, last)| (first..=last).contains(&c))
}

/// Characters that can make text display as something other than its
/// characters, beyond control characters: the Unicode line and paragraph
/// separators (some viewers break lines at them), every Unicode format
/// character ([`FORMAT_CHARACTERS`]), every default-ignorable code point
/// ([`DEFAULT_IGNORABLE`]) and every space other than the ASCII space
/// ([`SPACE_SEPARATORS`]). A bidirectional control reorders the text around
/// it; a zero-width, tag or other ignorable character is invisible, and a
/// no-break or em space looks like a plain space, so text that holds one
/// looks like text that does not. New notes, reasons and caller references
/// and pass text may not contain them, and text output escapes them.
pub fn is_disguising(c: char) -> bool {
    let c = u32::from(c);
    c >= 0xa0
        && (c == 0x2028
            || c == 0x2029
            || in_table(&FORMAT_CHARACTERS, c)
            || in_table(&DEFAULT_IGNORABLE, c)
            || in_table(&SPACE_SEPARATORS, c))
}

/// The disguising characters refused before every format character was: the
/// line and paragraph separators and the bidirectional controls. Reading a
/// ledger checks a recorded caller reference or reason against this set
/// only, so a line written earlier, which may hold another format character,
/// stays readable.
const fn is_line_or_bidi_control(c: char) -> bool {
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

/// A disguising character for a message: what it is and its code point, as
/// in "a bidirectional text control (U+202E)" or "a look-alike space
/// (U+00A0)".
pub fn describe_disguising(c: char) -> String {
    let n = u32::from(c);
    let kind = match c {
        '\u{2028}' => "a line separator",
        '\u{2029}' => "a paragraph separator",
        c if is_line_or_bidi_control(c) => "a bidirectional text control",
        _ if in_table(&FORMAT_CHARACTERS, n) => "a Unicode format character",
        _ if in_table(&SPACE_SEPARATORS, n) => "a look-alike space",
        _ => "an invisible character",
    };
    format!("{kind} (U+{n:04X})")
}

/// `text` made safe to print on a terminal as part of one line.
///
/// Control characters, line and paragraph separators, Unicode format
/// characters (bidirectional controls, zero-width and tag characters, the
/// soft hyphen), the other invisible characters (variation selectors, the
/// Hangul fillers) and the spaces other than the ASCII space (the others of
/// [`is_disguising`]) are written as `\u{…}`, and a backslash as `\\`, so
/// the escaping cannot be forged either. Other text is unchanged.
#[must_use]
pub fn display_safe(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(|c| c == '\\' || needs_escape(c)) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    push_escaped(&mut out, text, false);
    std::borrow::Cow::Owned(out)
}

/// `text` as one quoted value in a line of text output, escaped once.
///
/// The value is in double quotes. A double quote inside is written as `\"`,
/// and everything else is escaped as [`display_safe`] escapes it. Each
/// character is escaped once, so the value cannot end its quotes early or
/// pass for more than one value, and undoing the escapes (`\"`, `\\` and
/// `\u{…}`) gives `text` back.
#[must_use]
pub fn display_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    push_escaped(&mut out, text, true);
    out.push('"');
    out
}

/// Whether [`display_safe`] writes `c` as `\u{…}`.
fn needs_escape(c: char) -> bool {
    c.is_control() || is_disguising(c)
}

/// Append `text` to `out` escaped once: a backslash as `\\`, with `quote` a
/// double quote as `\"`, and each character of [`needs_escape`] as `\u{…}`.
fn push_escaped(out: &mut String, text: &str, quote: bool) {
    for c in text.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if quote && c == '"' {
            out.push_str("\\\"");
        } else if needs_escape(c) {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
}

/// Whether `text` has a control character (`char::is_control`). ASCII text,
/// the usual case, is checked byte by byte without decoding characters: its
/// control characters are the bytes below 0x20 and 0x7f. Every byte is
/// checked, without stopping early, so that the loop runs on many at once.
fn has_control(text: &str) -> bool {
    if text.is_ascii() {
        text.bytes().fold(0, |found, b| {
            found | u8::from(b < 0x20) | u8::from(b == 0x7f)
        }) != 0
    } else {
        text.chars().any(char::is_control)
    }
}

/// Whether `text` has more than `max` characters. A text of at most `max`
/// bytes has at most `max` characters, so only a longer one is counted.
fn longer_than(text: &str, max: usize) -> bool {
    text.len() > max && text.chars().count() > max
}

/// Check a note before it is recorded: one plain line, at most
/// [`MAX_NOTE`] characters, without control characters or the disguising
/// characters of [`is_disguising`] (line separators, Unicode format
/// characters such as bidirectional controls and zero-width characters,
/// other invisible characters and look-alike spaces).
fn check_new_note(note: &str) -> Result<(), String> {
    if let Some(c) = note.chars().find(|c| is_disguising(*c)) {
        return Err(format!(
            "the note contains {}, which can make it display as something else; write one plain line without it",
            describe_disguising(c)
        ));
    }
    check_note(note)
}

/// Check a recorded note: printable, at most [`MAX_NOTE`] characters. This is
/// the rule hallpass 0.1 wrote notes under, so older ledgers stay readable;
/// new notes must also pass [`check_new_note`].
fn check_note(note: &str) -> Result<(), String> {
    if has_control(note) {
        return Err(
            "the note contains a control character (such as a newline); write one plain line"
                .to_owned(),
        );
    }
    if longer_than(note, MAX_NOTE) {
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
    /// True when the line was written under a test clock
    /// ([`crate::with_test_clock`]): its time is not the real time.
    pub test_clock: bool,
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
    /// True when the line was written under a test clock
    /// ([`crate::with_test_clock`]): its time is not the real time.
    pub test_clock: bool,
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
        /// Logical entries after the witnessed one.
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
    /// Tip of the verified scan, or None for a missing ledger.
    pub tip: Option<Checkpoint>,
    /// Every legacy single-counter spend, in order.
    pub entries: Vec<LedgerEntry>,
    /// Every versioned debit, in order. Shares the sequence with entries and adoptions.
    pub debits: Vec<LedgerDebit>,
    /// Every adoption, in order.
    pub adoptions: Vec<Adoption>,
    /// Every reference reconciliation, in order.
    pub reconciliations: Vec<ReferenceReconciliation>,
    /// The latest adoption that may have lost lines, and so caller
    /// references, when no reference reconciliation follows it: until one
    /// does, guarded spends are refused as `reference-inconclusive`. `None`
    /// when no adoption may have lost lines, or the latest one is reconciled.
    pub unreconciled_adoption: Option<u64>,
    /// The totals (spends and carried amounts).
    pub tally: Tally,
    /// The time of the last logical entry, if any. An entry after one written with a
    /// clock set ahead can have an earlier time: see `latest_time`.
    pub last_time: Option<OffsetDateTime>,
    /// The latest time recorded on any entry, and the sequence number of the
    /// first entry that records it. A decision clock before it was set back.
    pub latest_time: Option<(OffsetDateTime, u64)>,
    /// Number of adoption records.
    pub adoption_count: u64,
    /// The sequence number of the first entry written under a test clock
    /// ([`crate::with_test_clock`]), or None when the ledger has none. A
    /// writer refuses to mix such lines with real-clock ones.
    pub test_clock_from: Option<u64>,
    /// The first entry written at the real time, for a preview to refuse
    /// what the write would ([`clock::check_view`]).
    real_clock_from: Option<u64>,
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
    pass_id: String,
    tally: Tally,
    entries: Vec<LedgerEntry>,
    debits: Vec<LedgerDebit>,
    adoptions: Vec<Adoption>,
    reconciliations: Vec<ReferenceReconciliation>,
    /// The latest adoption that may have lost lines, if any.
    lossy_adoption: Option<u64>,
    /// The adoption that the latest reference reconciliation names, if any.
    reconciled_adoption: Option<u64>,
    /// The hash of the last physical line scanned.
    tail: Digest,
    prefix: Option<(u64, Digest)>,
    /// The totals at the requested sequence, when the scan reached it: what
    /// a witness of that sequence must record.
    prefix_spent: Option<BTreeMap<String, u64>>,
    last_time: Option<OffsetDateTime>,
    /// The latest time on any line, and the first line that records it.
    latest: Option<(OffsetDateTime, u64)>,
    adoption_count: u64,
    /// The first entry written under a test clock, if any.
    test_clock_seq: Option<u64>,
    /// The first entry written without a test clock, if any.
    real_clock_seq: Option<u64>,
    /// The first adoption that carried an amount, if any.
    carried_seq: Option<u64>,
    /// The last sequence number (0 when there are only the header).
    seq: u64,
    /// Recorded targets this scan already found valid, so that a target
    /// repeated on many lines is checked once (see `debit::KNOWN_TARGETS`).
    valid_targets: Vec<RecordedTarget>,
    /// The pass digest text this scan read last, and its value.
    last_digest: Option<(String, Digest)>,
}

impl Parsed {
    fn for_pass(self, path: &Path, id: &str) -> Result<Self, Error> {
        if self.pass_id == id {
            Ok(self)
        } else {
            Err(Error::LedgerForeign {
                path: path.to_owned(),
                ledger_id: self.pass_id,
                pass_id: id.to_owned(),
            })
        }
    }

    const fn tail(&self) -> Digest {
        self.tail
    }

    /// The witness marker for this ledger: true when it proves a rehearsal,
    /// that is every entry was written under a test clock and no adoption
    /// carried an amount (a carried amount may come from live work). With
    /// `appending`, for the ledger after a line written now is appended
    /// (an adoption that carries an amount clears it itself).
    fn rehearsal_witness(&self, appending: bool) -> bool {
        let marked = if appending {
            clock::marker() == Some(true)
        } else {
            self.seq > 0 && self.test_clock_seq.is_some()
        };
        marked && self.real_clock_seq.is_none() && self.carried_seq.is_none()
    }

    /// The latest adoption that may have lost lines, unless a reference
    /// reconciliation names it.
    fn unreconciled_adoption(&self) -> Option<u64> {
        self.lossy_adoption
            .filter(|seq| self.reconciled_adoption != Some(*seq))
    }

    /// The pass digest that a spend or debit line records as `text`. A
    /// digest's value depends only on its text, and a line usually repeats
    /// the digest of the line before, so that text is compared, not parsed
    /// again.
    fn pass_digest(&mut self, text: &str) -> Option<Digest> {
        if let Some((last, digest)) = &self.last_digest
            && last == text
        {
            return Some(*digest);
        }
        let digest = text.parse::<Digest>().ok()?;
        self.last_digest = Some((text.to_owned(), digest));
        Some(digest)
    }
}

enum Line {
    Spend(Entry),
    Debit(DebitLine),
    DebitBatch(DebitBatchLine),
    Adopt(AdoptLine),
    Reconcile(ReconcileLine),
}

/// Which record shape a ledger line has.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Spend,
    Debit,
    DebitBatch,
    Adopt,
    Reconcile,
}

impl Line {
    /// Decode one ledger line as one of the four record shapes.
    ///
    /// This accepts exactly the lines that an untagged enum of the four shapes
    /// accepts, but it does not first buffer every line into an untyped value
    /// (which cost more than hashing the line). Each shape refuses unknown
    /// fields and requires a field that the other three refuse (`counter`,
    /// `charges`, `carried`, `references`), so at most one shape decodes a
    /// line, and the order of the attempts cannot change the result. The
    /// likely shape is tried first, because a failed attempt costs more than
    /// a decode.
    ///
    /// The reference reconciliation is the newest shape. A hallpass from
    /// before it has only the other shapes, each refusing the field
    /// `references`, so it decodes no shape from such a line and stops with
    /// `ledger-corrupt` at that line: it fails closed, and never counts
    /// around the line or skips it.
    ///
    /// Every line is checked as UTF-8 once, as a whole. A line that is not
    /// UTF-8 is not JSON either, so this refuses nothing that JSON decoding
    /// accepts. A line in the exact spelling hallpass writes is then read
    /// directly ([`written`]), with the same result as `serde_json`.
    fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        if let Some(line) = written::read(text) {
            return Some(line);
        }
        let attempt = |shape: Shape| match shape {
            Shape::Spend => serde_json::from_str(text).ok().map(Self::Spend),
            Shape::Debit => serde_json::from_str(text).ok().map(Self::Debit),
            Shape::DebitBatch => serde_json::from_str(text).ok().map(Self::DebitBatch),
            Shape::Adopt => serde_json::from_str(text).ok().map(Self::Adopt),
            Shape::Reconcile => serde_json::from_str(text).ok().map(Self::Reconcile),
        };
        let first = Shape::guess(text);
        attempt(first).or_else(|| {
            [
                Shape::Spend,
                Shape::Debit,
                Shape::DebitBatch,
                Shape::Adopt,
                Shape::Reconcile,
            ]
            .into_iter()
            .filter(|shape| *shape != first)
            .find_map(attempt)
        })
    }
}

impl Shape {
    /// The shape to try first: only a guess, see [`Line::decode`].
    fn guess(text: &str) -> Self {
        if text.contains("\"charges\":") {
            Self::Debit
        } else if text.contains("\"units\":") {
            Self::DebitBatch
        } else if text.contains("\"carried\":") {
            Self::Adopt
        } else if text.contains("\"references\":") {
            Self::Reconcile
        } else {
            Self::Spend
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    test_clock: Option<bool>,
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
    /// `true` when that witness showed a rehearsal
    /// ([`Witnessed::test_clock`]) and the adoption is on the real clock;
    /// absent otherwise, so a rehearsal's own lines are as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    test_clock: Option<bool>,
}

/// Add `n` to `counter` in `totals`, refusing a sum beyond any ceiling.
fn add(totals: &mut BTreeMap<String, u64>, counter: &str, n: u64) -> Option<()> {
    // Look up before inserting: a scan adds to the same few counters on every
    // line, and an owned key would be allocated (and dropped) each time.
    if let Some(total) = totals.get_mut(counter) {
        *total = total.checked_add(n).filter(|t| *t <= MAX_CEILING)?;
        return Some(());
    }
    let total = totals.entry(counter.to_owned()).or_insert(0);
    *total = total.checked_add(n).filter(|t| *t <= MAX_CEILING)?;
    Some(())
}

/// Parse the whole ledger. Any doubt is an error, never an empty count.
fn parse_ledger(
    path: &Path,
    reader: impl BufRead,
    pass_id: &str,
    collect: bool,
    requested: Option<u64>,
) -> Result<Parsed, Error> {
    scan_ledger(path, reader, collect, requested, None, &mut |_| Ok(()))?.for_pass(path, pass_id)
}

enum VerifiedEvent {
    Spend(LedgerEntry),
    Debit(LedgerDebit),
    Adopt(Adoption),
    Reconcile(ReferenceReconciliation),
}

type Visitor<'a> = dyn FnMut(&VerifiedEvent) -> Result<(), Error> + 'a;

fn record_checkpoint(
    checkpoints: &mut Option<(&std::collections::BTreeSet<u64>, &mut BTreeMap<u64, Digest>)>,
    seq: u64,
    hash: Digest,
) {
    if let Some((wanted, found)) = checkpoints.as_mut()
        && wanted.contains(&seq)
    {
        found.insert(seq, hash);
    }
}

#[allow(clippy::too_many_lines)]
fn scan_ledger(
    path: &Path,
    reader: impl BufRead,
    collect: bool,
    requested: Option<u64>,
    mut checkpoints: Option<(&std::collections::BTreeSet<u64>, &mut BTreeMap<u64, Digest>)>,
    visit: &mut Visitor<'_>,
) -> Result<Parsed, Error> {
    // Whether the line being checked is the last in the file, for the advice.
    let at_end = std::cell::Cell::new(false);
    let corrupt = |line: usize, detail: &str| Error::LedgerCorrupt {
        path: path.to_path_buf(),
        line,
        detail: detail.to_owned(),
        last: at_end.get(),
        complete: false,
    };
    let mut reader = reader;
    let mut first = Vec::new();
    reader
        .read_until(b'\n', &mut first)
        .map_err(|e| Error::io(path, &e))?;
    at_end.set(reader.fill_buf().is_ok_and(<[u8]>::is_empty));
    if first.is_empty() {
        return Err(corrupt(
            1,
            "the file is empty, but a ledger always starts with a header line (was it truncated?)",
        ));
    }
    if first.pop() != Some(b'\n') {
        return Err(corrupt(1, crate::error::CUT_SHORT));
    }
    let header: Header = serde_json::from_slice(&first)
        .map_err(|_| corrupt(1, "the header line is not a hallpass ledger header"))?;
    if header.hallpass_ledger != LEDGER_VERSION {
        return Err(corrupt(
            1,
            "the ledger version is not one this hallpass reads (if a newer hallpass wrote it, use that one)",
        ));
    }
    let mut parsed = Parsed {
        pass_id: header.pass_id,
        tally: Tally::default(),
        entries: Vec::new(),
        debits: Vec::new(),
        adoptions: Vec::new(),
        reconciliations: Vec::new(),
        lossy_adoption: None,
        reconciled_adoption: None,
        tail: Digest::of(&first),
        prefix: (requested == Some(0)).then(|| (0, Digest::of(&first))),
        prefix_spent: (requested == Some(0)).then(BTreeMap::new),
        last_time: None,
        latest: None,
        adoption_count: 0,
        test_clock_seq: None,
        real_clock_seq: None,
        carried_seq: None,
        seq: 0,
        valid_targets: Vec::new(),
        last_digest: None,
    };
    record_checkpoint(&mut checkpoints, 0, parsed.tail);
    let mut number = 1;
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|e| Error::io(path, &e))?
            == 0
        {
            break;
        }
        number += 1;
        at_end.set(reader.fill_buf().is_ok_and(<[u8]>::is_empty));
        if line.pop() != Some(b'\n') {
            return Err(corrupt(number, crate::error::CUT_SHORT));
        }
        let record = Line::decode(&line).ok_or_else(|| {
            if let Some(detail) = unknown_event(&line).or_else(|| invalid_record(&line)) {
                // The line is whole JSON, so it was not cut short.
                return Error::LedgerCorrupt {
                    path: path.to_path_buf(),
                    line: number,
                    detail,
                    last: at_end.get(),
                    complete: true,
                };
            }
            corrupt(number, "the line is not a complete ledger entry")
        })?;
        let (seq, last_seq, prev, marker) = match &record {
            Line::Spend(e) => (e.seq, e.seq, &e.prev, e.test_clock),
            Line::Debit(e) => (e.seq, e.seq, &e.prev, e.test_clock),
            Line::DebitBatch(e) => {
                let Some(last) = e
                    .units
                    .len()
                    .checked_sub(1)
                    .and_then(|n| u64::try_from(n).ok())
                    .and_then(|n| e.seq.checked_add(n))
                else {
                    return Err(corrupt(number, "the debit batch sequence range is invalid"));
                };
                (e.seq, last, &e.prev, e.test_clock)
            }
            Line::Adopt(a) => (a.seq, a.seq, &a.prev, a.test_clock),
            Line::Reconcile(r) => (r.seq, r.seq, &r.prev, r.test_clock),
        };
        if seq != parsed.seq + 1 {
            return Err(corrupt(
                number,
                "the sequence number is out of order (a line is missing or was moved)",
            ));
        }
        if !parsed.tail().is_written_as(prev) {
            return Err(corrupt(
                number,
                &format!(
                    "line {number} does not follow line {}: one of the two was changed, or a line between them was removed or moved",
                    number - 1
                ),
            ));
        }
        let kind = if clock::read_marker(marker).map_err(|detail| corrupt(number, detail))? {
            &mut parsed.test_clock_seq
        } else {
            &mut parsed.real_clock_seq
        };
        kind.get_or_insert(seq);
        let events = match record {
            Line::Spend(entry) => parse_spend(&mut parsed, entry)
                .map(VerifiedEvent::Spend)
                .map(|event| vec![event]),
            Line::Debit(debit) => parse_debit(&mut parsed, debit)
                .map(VerifiedEvent::Debit)
                .map(|event| vec![event]),
            Line::DebitBatch(batch) => parse_debit_batch(&mut parsed, batch)
                .map(|debits| debits.into_iter().map(VerifiedEvent::Debit).collect()),
            Line::Adopt(adopt) => parse_adopt(&mut parsed, adopt)
                .map(VerifiedEvent::Adopt)
                .map(|event| vec![event]),
            Line::Reconcile(line) => parse_reconcile(&mut parsed, line)
                .map(VerifiedEvent::Reconcile)
                .map(|event| vec![event]),
        }
        .map_err(|detail| corrupt(number, detail))?;
        for event in events {
            visit(&event)?;
            if collect {
                match event {
                    VerifiedEvent::Spend(entry) => parsed.entries.push(entry),
                    VerifiedEvent::Debit(debit) => parsed.debits.push(debit),
                    VerifiedEvent::Adopt(adopt) => parsed.adoptions.push(adopt),
                    VerifiedEvent::Reconcile(r) => parsed.reconciliations.push(r),
                }
            }
        }
        parsed.seq = last_seq;
        if let Some(time) = parsed.last_time
            && parsed.latest.is_none_or(|(latest, _)| time > latest)
        {
            parsed.latest = Some((time, seq));
        }
        parsed.tail = Digest::of(&line);
        record_checkpoint(&mut checkpoints, last_seq, parsed.tail);
        if requested == Some(last_seq) {
            parsed.prefix = Some((last_seq, parsed.tail));
            parsed.prefix_spent = Some(parsed.tally.spent.clone());
        }
    }
    Ok(parsed)
}

/// The events that the line shapes of this hallpass record.
const KNOWN_EVENTS: [&str; 4] = [
    "debit",
    DEBIT_BATCH_EVENT,
    "adopt",
    reference::RECONCILE_EVENT,
];

/// For a line that no shape decodes: when it is a complete JSON object
/// whose `event` this hallpass does not know, say so. A newer hallpass may
/// have written it, and it is not a line cut short.
fn unknown_event(line: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    let event = value.get("event")?.as_str()?;
    (!KNOWN_EVENTS.contains(&event)).then(|| {
        format!(
            "the line is a complete record of an event this hallpass does not know ({}), perhaps written by a newer hallpass: read this ledger with that one",
            display_quoted(event)
        )
    })
}

/// For a line that no shape decodes but that is a complete JSON object: say
/// which record it looks like and which value is not valid, so the damage is
/// not mistaken for a line cut short.
fn invalid_record(line: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(line).ok()?;
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.as_object()?;
    let (record, error) = match Shape::guess(text) {
        Shape::Debit => ("debit", serde_json::from_str::<DebitLine>(text).err()),
        Shape::DebitBatch => (
            "debit batch",
            serde_json::from_str::<DebitBatchLine>(text).err(),
        ),
        Shape::Adopt => ("adoption", serde_json::from_str::<AdoptLine>(text).err()),
        Shape::Reconcile => (
            "reconciliation",
            serde_json::from_str::<reference::ReconcileLine>(text).err(),
        ),
        Shape::Spend => ("spend", serde_json::from_str::<Entry>(text).err()),
    };
    let error = error?;
    let full = error.to_string();
    let reason = full
        .rsplit_once(" at line ")
        .map_or(full.as_str(), |(reason, _)| reason);
    let field = text
        .get(..error.column().saturating_sub(1))
        .filter(|_| {
            error.classify() == serde_json::error::Category::Data && reason.starts_with("invalid ")
        })
        .map(key_path)
        .filter(|path| !path.is_empty());
    Some(field.map_or_else(
        || format!("the line is a complete {record} record, but it is not valid ({reason})"),
        |name| {
            format!(
                "the line is a complete {record} record, but the value of {} is not valid ({reason})",
                display_quoted(&name)
            )
        },
    ))
}

/// The object keys that enclose the end of a JSON prefix, joined by `.`, such
/// as `carried.requests` for a prefix that stops inside that value.
fn key_path(head: &str) -> String {
    let mut keys: Vec<String> = Vec::new();
    let mut depth = 0_usize;
    let mut chars = head.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                keys.truncate(depth);
            }
            '"' => {
                let mut name = String::new();
                while let Some(d) = chars.next() {
                    match d {
                        '\\' => {
                            chars.next();
                        }
                        '"' => break,
                        _ => name.push(d),
                    }
                }
                if chars.peek() == Some(&':') {
                    keys.truncate(depth.saturating_sub(1));
                    keys.push(name);
                }
            }
            _ => {}
        }
    }
    keys.join(".")
}

fn parse_spend(parsed: &mut Parsed, entry: Entry) -> Result<LedgerEntry, &'static str> {
    if !is_counter_name(&entry.counter) || entry.n == 0 || entry.n > MAX_CEILING {
        return Err("the counter name or amount is not valid");
    }
    let (Some(digest), Ok(time)) = (
        parsed.pass_digest(&entry.digest),
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
    parsed.last_time = Some(time);
    add(&mut parsed.tally.spent, &entry.counter, entry.n)
        .ok_or("the recorded amounts add up beyond any ceiling")?;
    parsed.tally.entries += 1;
    Ok(LedgerEntry {
        seq: entry.seq,
        time,
        counter: entry.counter,
        amount: entry.n,
        digest,
        note: entry.note,
        test_clock: entry.test_clock == Some(true),
    })
}

fn parse_adopt(parsed: &mut Parsed, line: AdoptLine) -> Result<Adoption, &'static str> {
    let bad = "the adoption record is not valid";
    let (Ok(digest), Ok(time)) = (
        line.digest.parse::<Digest>(),
        OffsetDateTime::parse(&line.time, &Rfc3339),
    ) else {
        return Err(bad);
    };
    if line.event != "adopt"
        || !valid_recorded_reason(&line.reason)
        || !valid_totals(&line.carried)
        || line.carried.values().any(|n| *n == 0)
    {
        return Err(bad);
    }
    let previous = match line.witness {
        None => None,
        Some(w) => {
            let tail = w.tail.parse::<Digest>().map_err(|_| bad)?;
            if !valid_totals(&w.totals)
                || w.ledger.len() > 4096
                || w.updated.len() > 64
                || w.test_clock == Some(false)
            {
                return Err(bad);
            }
            Some(Witnessed {
                ledger: w.ledger,
                seq: w.seq,
                tail,
                totals: w.totals,
                updated: w.updated,
                test_clock: w.test_clock == Some(true),
            })
        }
    };
    parsed.last_time = Some(time);
    parsed.adoption_count += 1;
    if !line.carried.is_empty() {
        parsed.carried_seq.get_or_insert(line.seq);
    }
    for (counter, n) in &line.carried {
        add(&mut parsed.tally.spent, counter, *n)
            .ok_or("the recorded amounts add up beyond any ceiling")?;
    }
    if reference::may_lose_references(
        &line.carried,
        previous.as_ref(),
        line.test_clock != Some(true),
    ) {
        parsed.lossy_adoption = Some(line.seq);
    }
    Ok(Adoption {
        seq: line.seq,
        time,
        reason: line.reason,
        digest,
        carried: line.carried,
        previous,
        test_clock: line.test_clock == Some(true),
    })
}

/// Check a new adoption reason: required, and a new note in every other way.
fn check_reason(reason: &str) -> Result<(), String> {
    if reason.trim().is_empty() {
        return Err("the reason is empty; say why the ledger is being adopted".to_owned());
    }
    check_new_note(reason).map_err(|m| m.replace("the note", "the reason"))
}

/// Check a recorded adoption or reconciliation reason: nonblank, printable,
/// at most [`MAX_NOTE`] characters, without a line separator or
/// bidirectional control. This is the rule reasons were written under
/// before every Unicode format character was refused, so a ledger written
/// earlier stays readable; a new reason must pass [`check_reason`].
fn valid_recorded_reason(reason: &str) -> bool {
    !reason.trim().is_empty()
        && !reason.chars().any(is_line_or_bidi_control)
        && check_note(reason).is_ok()
}

fn check_private(path: &Path, file: &fs::File) -> Result<(), Error> {
    let meta = file.metadata().map_err(|e| Error::io(path, &e))?;
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Insecure {
            path: path.to_path_buf(),
            mode: meta.mode() & 0o7777,
            who: "other users can read or change the ledger",
            fix: "600",
            advice: "check that no other user or process changed it, since hallpass, not the owner, wrote this ledger",
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
    Ok(read_shared(loaded, false, None)?
        .0
        .map_or_else(Tally::default, |p| p.tally))
}

/// Read and verify the whole ledger beside `loaded` under a shared lock:
/// `None` when there is no ledger. The lock is held as long as the returned
/// file is.
fn read_shared(
    loaded: &LoadedPass,
    collect: bool,
    requested: Option<u64>,
) -> Result<(Option<Parsed>, Option<fs::File>), Error> {
    let path = ledger_path(&loaded.path);
    if !exists(&path)? {
        return Ok((None, None));
    }
    let file = open_no_follow(&path, OpenOptions::new().read(true))?;
    check_private(&path, &file)?;
    lock_shared(&file, &path)?;
    let parsed = parse_ledger(
        &path,
        BufReader::new(&file),
        &loaded.pass.id,
        collect,
        requested,
    )?;
    Ok((Some(parsed), Some(file)))
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
        (None, Some(w)) => Err(missing_ledger(pass_path, ledger, w, witness_file, pass_id)),
        (Some(_), None) => Ok((WitnessStatus::Missing, None)),
        (Some(p), Some(w)) => {
            let here = ledger_identity(ledger);
            let moved = (w.ledger != here).then(|| w.ledger.clone());
            let witnessed = p.prefix == Some((w.seq, w.tail));
            if witnessed {
                // The ledger holds the witnessed line, so its verified
                // totals there are the ones hallpass recorded; a witness
                // that says otherwise was damaged after it was written.
                if let Some(spent) = &p.prefix_spent
                    && !same_totals(spent, &w.totals)
                {
                    // Remember it: once the ledger is lost, nothing else
                    // could show that these totals are wrong.
                    state.record_damage(pass_id, w, spent);
                    return Err(state.damaged(
                        pass_id,
                        &format!(
                            "it records spent: {} at sequence {}, but the verified ledger has spent: {} there",
                            totals_text(&w.totals),
                            w.seq,
                            totals_text(spent)
                        ),
                    ));
                }
                let added = p.seq - w.seq;
                let status = if added == 0 {
                    WitnessStatus::Matches
                } else {
                    WitnessStatus::Extended { added }
                };
                return Ok((status, moved));
            }
            let fork = divergence(ledger, p.seq, &state.forks(pass_id));
            let mut detail = match (w.seq > p.seq, fork) {
                (true, None) => format!(
                    "the witness recorded logical sequence {} (spent: {}) on {}, but this ledger ends at sequence {}: entries were removed, or this is an older copy",
                    w.seq,
                    totals_text(&w.totals),
                    w.updated,
                    p.seq
                ),
                (true, Some(f)) => format!(
                    "the witness recorded logical sequence {} (spent: {}) on {}, but this ledger ends at sequence {} and is a different history from sequence {}: hallpass adopted another copy of the ledger there on {}",
                    w.seq,
                    totals_text(&w.totals),
                    w.updated,
                    p.seq,
                    f.seq,
                    f.time
                ),
                (false, None) => format!(
                    "entry {} is not the line hallpass wrote there on {}: it was edited, or this is a different ledger for the same pass id",
                    w.seq, w.updated
                ),
                (false, Some(f)) => format!(
                    "entry {} is not the line hallpass wrote there on {}: this ledger is a different history from sequence {}, where hallpass adopted another copy of the ledger on {}",
                    w.seq, w.updated, f.seq, f.time
                ),
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
            // A copy of the pass and ledger spent from elsewhere: the ledger
            // the witness last saw is intact, so adopting this one would fork.
            if moved.is_some()
                && let LastSeen::Intact(live) = last_seen_ledger(ledger, w, pass_id)?
            {
                return Err(elsewhere(pass_path, ledger, w, witness_file, pass_id, live));
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

/// The adoption at which `ledger` (verified to sequence `seq`) leaves the
/// history hallpass recorded: it holds the line before the adoption, and a
/// different line where the adoption is. `None` when no noted adoption is
/// such a point, or the ledger cannot be read again. Only the words of a
/// refusal depend on this.
fn divergence(ledger: &Path, seq: u64, forks: &[Fork]) -> Option<Fork> {
    let forks: Vec<&Fork> = forks.iter().filter(|f| f.seq > 0 && f.seq <= seq).collect();
    if forks.is_empty() {
        return None;
    }
    let wanted: std::collections::BTreeSet<u64> =
        forks.iter().flat_map(|f| [f.seq - 1, f.seq]).collect();
    let mut found = BTreeMap::new();
    // The caller holds a lock on this ledger, so no writer changes it; a
    // second shared lock from this process could wait on the first.
    let file = open_no_follow(ledger, OpenOptions::new().read(true)).ok()?;
    scan_ledger(
        ledger,
        BufReader::new(&file),
        false,
        None,
        Some((&wanted, &mut found)),
        &mut |_| Ok(()),
    )
    .ok()?;
    let written = |seq: u64, hash: &str| {
        found
            .get(&seq)
            .is_some_and(|d: &Digest| d.to_string() == hash)
    };
    forks
        .into_iter()
        .find(|f| written(f.seq - 1, &f.prev) && !written(f.seq, &f.hash))
        .cloned()
}

/// The error for a pass with no ledger beside it whose witness recorded
/// lines: [`Error::LedgerElsewhere`] when the ledger is intact where the
/// witness last saw it, else [`Error::LedgerMissing`].
fn missing_ledger(
    pass_path: &Path,
    ledger: &Path,
    w: &Witnessed,
    witness_file: PathBuf,
    pass_id: &str,
) -> Error {
    match last_seen_ledger(ledger, w, pass_id) {
        Ok(LastSeen::Intact(live)) => elsewhere(pass_path, ledger, w, witness_file, pass_id, live),
        Err(e) => e,
        Ok(_) => Error::LedgerMissing(Box::new(MissingLedger {
            path: ledger.to_path_buf(),
            pass: pass_path.to_path_buf(),
            pass_id: pass_id.to_owned(),
            witness: witness_file,
            seq: w.seq,
            last_seen: w.ledger.clone(),
            totals: w.totals.clone(),
            updated: w.updated.clone(),
            // Under a test clock, an adoption carries a rehearsal's units.
            rehearsal: w.test_clock && clock::marker().is_none(),
        })),
    }
}

/// The [`Error::LedgerElsewhere`] refusal for a pass whose ledger at
/// `ledger` is missing or not the history the witness recorded, while
/// `live`, where the witness last saw the ledger, is intact.
fn elsewhere(
    pass_path: &Path,
    ledger: &Path,
    w: &Witnessed,
    witness_file: PathBuf,
    pass_id: &str,
    live: LiveLedger,
) -> Error {
    let live_pass = live
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".ledger"))
        .filter(|name| !name.is_empty())
        .map(|name| live.path.with_file_name(name))
        .filter(|pass| fs::symlink_metadata(pass).is_ok_and(|m| m.file_type().is_file()));
    Error::LedgerElsewhere(Box::new(ElsewhereLedger {
        path: ledger.to_path_buf(),
        pass: pass_path.to_path_buf(),
        pass_id: pass_id.to_owned(),
        witness: witness_file,
        seq: live.seq,
        live: live.path,
        live_pass,
        totals: live.totals,
        updated: w.updated.clone(),
        witness_seq: w.seq,
        expected_exists: exists(ledger).unwrap_or(true),
    }))
}

/// A ledger verified where the witness last saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveLedger {
    /// Its path, as the witness recorded it.
    pub path: PathBuf,
    /// Its last logical sequence number: the witnessed one or later.
    pub seq: u64,
    /// Its verified totals now.
    pub totals: BTreeMap<String, u64>,
}

/// What is at the path where the witness last saw the ledger, when that is
/// not the ledger beside this pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LastSeen {
    /// The witness last saw the ledger beside this pass, or recorded no
    /// absolute path.
    Here,
    /// Nothing is there.
    Absent,
    /// It is intact: it opens under the rules for any ledger, its whole
    /// chain verifies, it belongs to the pass id, and it holds the line the
    /// witness recorded at the witnessed sequence. It may have grown past
    /// the witness (the same test as [`WitnessStatus::Extended`]).
    Intact(LiveLedger),
    /// It verifies, but does not hold the line the witness recorded: another
    /// history, or an older copy.
    Other(PathBuf),
    /// Something is there that hallpass read and found is not this pass's
    /// intact ledger (damaged, for another pass id, not a regular file),
    /// but whose history it could not compare; the reason.
    Unchecked(PathBuf, String),
    /// Something is there that hallpass did not read (a link, not private,
    /// or not readable by this user): it may well be the intact ledger.
    Unreadable {
        /// The path.
        path: PathBuf,
        /// Why, in words.
        why: String,
        /// Its mode, when that is all that is wrong (other users have
        /// access).
        mode: Option<u32>,
    },
}

/// Whether `e`, from opening a ledger to check it, came before its bytes
/// were read: the file may still be an intact ledger.
const fn before_reading(e: &Error) -> bool {
    matches!(
        e,
        Error::Io { .. }
            | Error::Symlink { .. }
            | Error::Insecure { .. }
            | Error::UntrustedOwner { .. }
    )
}

/// The refusal of an adoption while the ledger where the witness last saw
/// it is [`LastSeen::Unreadable`].
fn unreadable_refusal(path: &Path, why: &str, mode: Option<u32>, pass_id: &str) -> Error {
    if let Some(mode) = mode {
        return Error::Insecure {
            path: path.to_path_buf(),
            mode,
            who: "other users can read or change it",
            fix: "600",
            advice: "run the command again: the witness last saw this pass's ledger there, and hallpass checks that file before it adopts, because adopting beside an intact ledger would start a second count. Nothing was recorded",
        };
    }
    Error::Io {
        path: path.to_path_buf(),
        message: format!(
            "the witness last saw the ledger of pass `{pass_id}` here, but hallpass could not read this file ({}). It may be the intact ledger, and adopting beside it would start a second count, so nothing was recorded. Put the real ledger file here in place of a link, or make it readable by this user, then run the command again. If this file is not a ledger of this pass, move it away first.",
            without_stop(why)
        ),
    }
}

fn without_stop(text: &str) -> &str {
    text.strip_suffix('.').unwrap_or(text)
}

/// Classify the ledger where the witness `w` last saw it, against `ledger`,
/// the ledger beside this pass. Read-only: it takes a shared lock on the
/// other ledger while it reads it, and writes nothing.
///
/// A ledger is trusted only when it verifies: one that merely exists is
/// [`LastSeen::Unreadable`], [`LastSeen::Unchecked`] or [`LastSeen::Other`],
/// never [`LastSeen::Intact`].
///
/// # Errors
///
/// Only [`Error::LockTimeout`]: another process holds that ledger for
/// longer than the lock-wait budget. A ledger being written is likely live,
/// so this is not "could not be checked": the caller fails closed.
pub fn last_seen_ledger(ledger: &Path, w: &Witnessed, pass_id: &str) -> Result<LastSeen, Error> {
    let seen = Path::new(&w.ledger);
    if !seen.is_absolute() || w.ledger == ledger_identity(ledger) {
        return Ok(LastSeen::Here);
    }
    match exists(seen) {
        Ok(false) => return Ok(LastSeen::Absent),
        Ok(true) => {}
        Err(e) => {
            return Ok(LastSeen::Unreadable {
                path: seen.to_path_buf(),
                why: e.to_string(),
                mode: None,
            });
        }
    }
    Ok(
        match inspect_candidate(seen, Some(w.seq)).and_then(|p| p.for_pass(seen, pass_id)) {
            Ok(parsed) if parsed.prefix == Some((w.seq, w.tail)) => LastSeen::Intact(LiveLedger {
                path: seen.to_path_buf(),
                seq: parsed.seq,
                totals: parsed.tally.spent,
            }),
            Ok(_) => LastSeen::Other(seen.to_path_buf()),
            Err(e @ Error::LockTimeout { .. }) => return Err(e),
            Err(e) if before_reading(&e) => LastSeen::Unreadable {
                path: seen.to_path_buf(),
                mode: match &e {
                    Error::Insecure { mode, .. } => Some(*mode),
                    _ => None,
                },
                why: e.to_string(),
            },
            Err(e) => LastSeen::Unchecked(seen.to_path_buf(), e.to_string()),
        },
    )
}

/// Refuse an adoption on the ledger at `ledger` (missing, or not the history
/// the witness recorded) while the ledger where the witness last saw it is
/// intact, or might be (hallpass could not read it): adopting would start a
/// second count for this id beside a live one.
fn refuse_fork(
    pass_path: &Path,
    ledger: &Path,
    witness: Option<&Witnessed>,
    state: &StateDir,
    pass_id: &str,
) -> Result<(), Error> {
    let Some(w) = witness.filter(|w| w.seq > 0) else {
        return Ok(());
    };
    match last_seen_ledger(ledger, w, pass_id)? {
        LastSeen::Intact(live) => Err(elsewhere(
            pass_path,
            ledger,
            w,
            state.witness_path(pass_id).unwrap_or_default(),
            pass_id,
            live,
        )),
        LastSeen::Unreadable { path, why, mode } => {
            Err(unreadable_refusal(&path, &why, mode, pass_id))
        }
        _ => Ok(()),
    }
}

/// The reason a witness was not checked. A witness error is reduced to its
/// detail, because callers that refuse on it wrap the detail in a full
/// witness message again; anything else is shown whole.
fn not_checked_reason(e: &Error) -> String {
    match e {
        Error::WitnessUnavailable { detail, .. } => without_stop(detail).to_owned(),
        other => other.to_string(),
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
            "there is no witness for pass `{pass_id}` (a pass brought from another machine, user or state directory?); an allowed spend records one, and so does a spend refused by the pass itself (a ceiling, a destination, the dates); a spend that --require-new-ref refuses for want of a witness, and a --dry-run preview, record none. Until one is recorded, a lost or rewound ledger would not be noticed"
        )),
        WitnessStatus::Extended { added } => out.push(format!(
            "the ledger extends the witness by {added} logical entries (a spend, debit batch, adoption or reference reconciliation stopped before updating the witness, or a hallpass that keeps none); they are counted"
        )),
        WitnessStatus::NotChecked { reason } => {
            out.push(format!("the ledger was not checked against its witness: {reason}"));
        }
        WitnessStatus::Fresh | WitnessStatus::Matches => {}
    }
    if let Some(from) = moved {
        // The old copy is refused only when this witness guards it (the
        // same state directory). A copy with a witness of its own, on
        // another machine, account or state directory, stays live.
        out.push(format!(
            "the witness last saw this ledger at {from}; it was moved or copied. Spend from one copy only. A copy that uses this same state directory will now be refused as changed. A copy on another machine, account or state directory has its own witness and is not refused: it stays live until its ledger is moved away there, after which it is refused as `ledger-missing`"
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
    read_view(loaded, state, true)
}

/// Read and verify a ledger without retaining its individual events.
///
/// # Errors
/// As [`read_ledger`].
pub fn read_summary(loaded: &LoadedPass, state: &StateDir) -> Result<LedgerView, Error> {
    read_view(loaded, state, false)
}

fn read_view(loaded: &LoadedPass, state: &StateDir, collect: bool) -> Result<LedgerView, Error> {
    visit_view(loaded, state, collect, &mut |_| Ok(()))
}

fn visit_view(
    loaded: &LoadedPass,
    state: &StateDir,
    collect: bool,
    visit: &mut Visitor<'_>,
) -> Result<LedgerView, Error> {
    let path = ledger_path(&loaded.path);
    let id = &loaded.pass.id;
    let file = if exists(&path)? {
        let file = open_no_follow(&path, OpenOptions::new().read(true))?;
        check_private(&path, &file)?;
        lock_shared(&file, &path)?;
        Some(file)
    } else {
        None
    };
    let saved_witness = state.read(id);
    let requested = saved_witness
        .as_ref()
        .ok()
        .and_then(|w| w.as_ref())
        .map(|w| w.seq);
    let parsed = file
        .as_ref()
        .map(|f| {
            let reader = BufReader::with_capacity(SCAN_BUFFER, f);
            scan_ledger(&path, reader, collect, requested, None, visit)?.for_pass(&path, id)
        })
        .transpose()?;
    let (witness, moved) = match saved_witness {
        Err(e) => (
            WitnessStatus::NotChecked {
                reason: not_checked_reason(&e),
            },
            None,
        ),
        Ok(w) => match compare(&loaded.path, &path, parsed.as_ref(), w.as_ref(), state, id) {
            // A witness that contradicts the ledger is a damaged witness:
            // answered with a warning, as one that does not parse.
            Err(e @ Error::WitnessUnavailable { .. }) => (
                WitnessStatus::NotChecked {
                    reason: not_checked_reason(&e),
                },
                None,
            ),
            other => other?,
        },
    };
    let mut warnings = warnings(&witness, moved.as_ref(), id, false);
    warnings.extend(crate::files::shared_directory_warning(&loaded.path));
    warnings.extend(crate::files::future_mtime_warning(&loaded.path));
    let exists = parsed.is_some();
    let parsed = parsed.unwrap_or_else(|| Parsed {
        pass_id: id.clone(),
        tally: Tally::default(),
        entries: Vec::new(),
        debits: Vec::new(),
        adoptions: Vec::new(),
        reconciliations: Vec::new(),
        lossy_adoption: None,
        reconciled_adoption: None,
        tail: Digest::of(b""),
        prefix: None,
        prefix_spent: None,
        last_time: None,
        latest: None,
        adoption_count: 0,
        test_clock_seq: None,
        real_clock_seq: None,
        carried_seq: None,
        seq: 0,
        valid_targets: Vec::new(),
        last_digest: None,
    });
    let unreconciled_adoption = parsed.unreconciled_adoption();
    Ok(LedgerView {
        path,
        exists,
        tip: exists.then(|| Checkpoint {
            version: 1,
            pass_id: parsed.pass_id,
            seq: parsed.seq,
            hash: parsed.tail.to_string(),
        }),
        entries: parsed.entries,
        unreconciled_adoption,
        debits: parsed.debits,
        adoptions: parsed.adoptions,
        reconciliations: parsed.reconciliations,
        tally: parsed.tally,
        last_time: parsed.last_time,
        latest_time: parsed.latest,
        adoption_count: parsed.adoption_count,
        test_clock_from: parsed.test_clock_seq,
        real_clock_from: parsed.real_clock_seq,
        witness,
        moved_from: moved,
        warnings,
    })
}

/// A retained commitment to one exact ledger line.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Checkpoint format version.
    pub version: u32,
    /// Pass identity recorded in the ledger header.
    pub pass_id: String,
    /// Sequence of the committed line; zero denotes the header.
    pub seq: u64,
    /// SHA-256 of the original line without its newline.
    pub hash: String,
}

/// Result of verifying a complete ledger against a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointStatus {
    /// The ledger ends at the committed line.
    Exact,
    /// The ledger extends the committed line.
    Extended(u64),
    /// The valid ledger differs from the commitment. Exit 2.
    Mismatch,
    /// The valid ledger is of the same pass but ends before the committed
    /// line, as an older copy does. Still a mismatch to a caller.
    Shorter,
    /// The valid ledger belongs to another pass. Still a mismatch to a caller.
    Foreign,
}

impl CheckpointStatus {
    /// The relation word shared with `compare-backups`.
    #[must_use]
    pub const fn relation(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Extended(_) => "extended",
            Self::Shorter => "shorter",
            Self::Foreign => "foreign",
            Self::Mismatch => "mismatch",
        }
    }
}

/// How the local witness relates to an exported checkpoint, observed under
/// the same lock as the export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessRelation {
    /// The witness records exactly the exported tail.
    Matches,
    /// The witness records a verified older prefix of the exported ledger.
    Lags {
        /// Sequence the witness recorded.
        witnessed: u64,
        /// Sequence of the exported checkpoint.
        exported: u64,
    },
    /// There is no witness for this pass.
    Absent,
}

/// Outcome of a checkpoint export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointExport {
    /// No ledger exists and no witness records a spend: nothing to commit to.
    Empty,
    /// A checkpoint of the verified ledger, with the observed witness relation.
    Exported(Checkpoint, WitnessRelation),
}

/// Export a checkpoint and say whether local witness corroboration exists.
///
/// # Errors
/// If the ledger or local witness is unusable or contradicts the ledger.
pub fn export_checkpoint(
    loaded: &LoadedPass,
    state: &StateDir,
) -> Result<(Checkpoint, bool), Error> {
    match export_checkpoint_observed(loaded, state)? {
        CheckpointExport::Exported(checkpoint, relation) => {
            Ok((checkpoint, relation != WitnessRelation::Absent))
        }
        CheckpointExport::Empty => Err(Error::io(
            &ledger_path(&loaded.path),
            &std::io::Error::from(std::io::ErrorKind::NotFound),
        )),
    }
}

/// Export a checkpoint and report how the witness relates to it. A pass with
/// no ledger and no witnessed spend exports [`CheckpointExport::Empty`].
///
/// # Errors
/// If the ledger or local witness is unusable or contradicts the ledger.
pub fn export_checkpoint_observed(
    loaded: &LoadedPass,
    state: &StateDir,
) -> Result<CheckpointExport, Error> {
    let path = ledger_path(&loaded.path);
    if matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        let witness = state.read(&loaded.pass.id)?;
        // A witness of recorded spends with no ledger is an error here.
        compare(
            &loaded.path,
            &path,
            None,
            witness.as_ref(),
            state,
            &loaded.pass.id,
        )?;
        return Ok(CheckpointExport::Empty);
    }
    let file = open_no_follow(&path, OpenOptions::new().read(true))?;
    check_private(&path, &file)?;
    lock_shared(&file, &path)?;
    let witness = state.read(&loaded.pass.id)?;
    let parsed = parse_ledger(
        &path,
        BufReader::new(&file),
        &loaded.pass.id,
        false,
        witness.as_ref().map(|w| w.seq),
    )?;
    compare(
        &loaded.path,
        &path,
        Some(&parsed),
        witness.as_ref(),
        state,
        &loaded.pass.id,
    )?;
    let relation = match witness.as_ref() {
        None => WitnessRelation::Absent,
        Some(w) if w.seq == parsed.seq => WitnessRelation::Matches,
        Some(w) => WitnessRelation::Lags {
            witnessed: w.seq,
            exported: parsed.seq,
        },
    };
    Ok(CheckpointExport::Exported(
        Checkpoint {
            version: 1,
            pass_id: loaded.pass.id.clone(),
            seq: parsed.seq,
            hash: parsed.tail.to_string(),
        },
        relation,
    ))
}

/// Verify every line of a ledger against an independently retained checkpoint.
/// This never reads or writes local witness state.
///
/// # Errors
/// If the checkpoint is malformed or the ledger is unavailable or corrupt.
pub fn verify_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<CheckpointStatus, Error> {
    if checkpoint.version != 1 || !crate::pass::is_identifier(&checkpoint.pass_id) {
        return Err(Error::Usage(
            "invalid checkpoint version or pass ID".to_owned(),
        ));
    }
    let hash = checkpoint.hash.parse::<Digest>().map_err(Error::Usage)?;
    let parsed = inspect_candidate(path, Some(checkpoint.seq))?;
    if parsed.pass_id != checkpoint.pass_id {
        return Ok(CheckpointStatus::Foreign);
    }
    if parsed.seq < checkpoint.seq {
        return Ok(CheckpointStatus::Shorter);
    }
    if parsed.prefix != Some((checkpoint.seq, hash)) {
        return Ok(CheckpointStatus::Mismatch);
    }
    if parsed.seq == checkpoint.seq {
        Ok(CheckpointStatus::Exact)
    } else {
        Ok(CheckpointStatus::Extended(parsed.seq - checkpoint.seq))
    }
}

/// Identity comparisons use the result only after verifying the complete suffix.
fn inspect_candidate(path: &Path, requested: Option<u64>) -> Result<Parsed, Error> {
    let file = open_no_follow(path, OpenOptions::new().read(true))?;
    check_private(path, &file)?;
    lock_shared(&file, path)?;
    scan_ledger(
        path,
        BufReader::new(&file),
        false,
        requested,
        None,
        &mut |_| Ok(()),
    )
}

fn inspect_candidate_checkpoints(
    path: &Path,
    wanted: &std::collections::BTreeSet<u64>,
) -> Result<(Parsed, BTreeMap<u64, Digest>), Error> {
    let file = open_no_follow(path, OpenOptions::new().read(true))?;
    check_private(path, &file)?;
    lock_shared(&file, path)?;
    let mut found = BTreeMap::new();
    let parsed = scan_ledger(
        path,
        BufReader::new(&file),
        false,
        None,
        Some((wanted, &mut found)),
        &mut |_| Ok(()),
    )?;
    Ok((parsed, found))
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
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| Error::ledger_create(path, &e))?;
    let result = (|| {
        crate::files::write_within_size_limit(&mut file, format!("{header}\n").as_bytes())?;
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

fn decide_spend_targets(
    loaded: &LoadedPass,
    request: &SpendRequest<'_>,
    now: OffsetDateTime,
) -> Result<Vec<String>, TargetRefusal> {
    let labels = decide_targets(
        loaded,
        request.targets(),
        request.expect_digest,
        now,
        request.needed,
    )
    .map_err(|mut refusal| {
        refusal.reason.message.push_str(". Nothing was recorded");
        refusal
    })?;
    if loaded.pass.require_target && labels.is_empty() {
        return Err(TargetRefusal {
            reason: refused_spend(
                RefusalCode::TargetRequired,
                "every debit must check at least one destination; supply a literal target".into(),
            ),
            index: None,
        });
    }
    Ok(labels)
}

/// Refuse the first charged name that is not a ceiling of the pass.
///
/// Runs before [`check_required_charges`], so a misspelt counter is named as
/// unknown rather than as a missing required counter.
fn check_known_counters<'a>(
    pass: &crate::Pass,
    counters: impl IntoIterator<Item = &'a str>,
) -> Result<(), Refusal> {
    for counter in counters {
        declared_ceiling(pass, counter)?;
    }
    Ok(())
}

/// Apply the same mandatory-charge policy after scope checks for every debit shape.
fn check_required_charges(
    pass: &crate::Pass,
    supplied: impl Fn(&str) -> bool,
) -> Result<(), Refusal> {
    if let Some(missing) = pass.required_counters.iter().find(|name| !supplied(name)) {
        return Err(refused_spend(
            RefusalCode::RequiredCounterMissing,
            format!("every debit must charge `{missing}`; include its positive cost"),
        ));
    }
    Ok(())
}

/// Check one counter against the pass and the locked ledger totals.
fn decide_ceiling(
    pass: &crate::Pass,
    counter: &str,
    amount: u64,
    spent: u64,
) -> Result<(), Refusal> {
    let total = declared_ceiling(pass, counter)?;
    if spent.checked_add(amount).is_none_or(|next| next > total) {
        return Err(refused_spend(
            RefusalCode::CeilingReached,
            format!(
                "spending {} {} would exceed the ceiling: {spent} of {total} already spent, {} left; stop, or ask the owner to raise the ceiling in writing",
                amount,
                counter,
                total.saturating_sub(spent)
            ),
        ));
    }
    Ok(())
}

fn declared_ceiling(pass: &crate::Pass, counter: &str) -> Result<u64, Refusal> {
    pass.ceilings.get(counter).copied().ok_or_else(|| {
        let known: Vec<&str> = pass.ceilings.keys().map(String::as_str).collect();
        refused_spend(
            RefusalCode::UnknownCounter,
            format!(
                "`{}` is not a ceiling of this pass (it has: {}); only what the owner put a ceiling on can be spent: use one of those names, or ask the owner to add this ceiling to the pass in writing",
                counter,
                if known.is_empty() {
                    "none".to_owned()
                } else {
                    known.join(", ")
                }
            ),
        )
    })
}

fn refused_spend(code: RefusalCode, mut message: String) -> Refusal {
    message.push_str(". Nothing was recorded");
    Refusal { code, message }
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
fn lock_for_writing(
    pass_path: &Path,
    state: &StateDir,
    adopting: bool,
    guard: Option<&str>,
    lock_timeout: Option<std::time::Duration>,
    visit: &mut Visitor<'_>,
) -> Result<Locked, Error> {
    let flags = AdoptFlags::default();
    let adopting = adopting.then_some(&flags);
    lock_for_writing_inner(pass_path, state, adopting, guard, lock_timeout, None, visit)
}

#[allow(clippy::too_many_arguments)]
fn lock_for_writing_notifying(
    pass_path: &Path,
    state: &StateDir,
    adopting: bool,
    guard: Option<&str>,
    lock_timeout: Option<std::time::Duration>,
    on_wait: Option<fn(&crate::files::LockWait)>,
    visit: &mut Visitor<'_>,
) -> Result<Locked, Error> {
    let flags = AdoptFlags::default();
    let adopting = adopting.then_some(&flags);
    lock_for_writing_inner(
        pass_path,
        state,
        adopting,
        guard,
        lock_timeout,
        on_wait,
        visit,
    )
}

/// `adopting` is `Some(flags)` for an adoption (see
/// [`adopt_guarded_rehearsal`]), `None` for every other writer.
#[allow(clippy::too_many_arguments)]
fn lock_for_writing_inner(
    pass_path: &Path,
    state: &StateDir,
    adopting: Option<&AdoptFlags>,
    guard: Option<&str>,
    lock_timeout: Option<std::time::Duration>,
    on_wait: Option<fn(&crate::files::LockWait)>,
    visit: &mut Visitor<'_>,
) -> Result<Locked, Error> {
    crate::files::refuse_world_writable_directory(pass_path)?;
    if let Some(token) = guard {
        check_token_shape(token, pass_path)?;
    }
    let earlier = load(pass_path)?;
    let id = earlier.pass.id.clone();
    let wait = LockBudget::requested(lock_timeout, on_wait);
    let witness_lock = state.lock(&id, wait)?;
    let witness = state.read(&id)?;
    if let Some(flags) = adopting {
        // Before anything is created: a refused adoption leaves no ledger.
        let raised = noted_totals(state, &id, witness.as_ref(), flags.carry_noted, pass_path)?;
        if !exists(&ledger_path(pass_path))? {
            rehearsal_totals(witness.as_ref(), flags, raised.is_some(), pass_path, &id)?;
        }
    }
    if let Some(expected) = guard {
        let flags = adopting.cloned().unwrap_or_default();
        let current = preview_adopt_rehearsal(pass_path, state, flags.carry_noted, flags.rehearsal)
            .map_err(|e| match e {
                // The preview's own refusal, so that both say the same.
                Error::LedgerElsewhere(_) | Error::LedgerClockMix { .. } => e,
                e @ (Error::WitnessUnavailable { .. } | Error::LockTimeout { .. }) => e,
                _ => stale_token(pass_path),
            })?;
        if current.token != expected {
            return Err(stale_token(pass_path));
        }
    }
    let path = ledger_path(pass_path);
    let created = !exists(&path)?;
    let mut guarded_missing_pass = None;
    if created {
        if adopting.is_some() {
            let Some(known) = witness.as_ref().filter(|w| w.seq > 0) else {
                return Err(Error::Usage(
                    "there is no ledger and no witness of any spend for this pass: nothing to adopt. Nothing was recorded".to_owned(),
                ));
            };
            // A ledger intact where the witness last saw it is not lost:
            // adopting would start a second history for this id, even
            // when that ledger has grown past the witness.
            refuse_fork(pass_path, &path, Some(known), state, &id)?;
            check_projected_witness_size(state, &id, &path, 1, &known.totals)?;
        } else {
            compare(pass_path, &path, None, witness.as_ref(), state, &id)?;
        }
        if let Some(expected) = guard {
            let snapshot = load(pass_path)?;
            if snapshot.pass.id != id
                || expected != adoption_token(&snapshot, &path, None, witness.as_ref())
            {
                return Err(stale_token(pass_path));
            }
            guarded_missing_pass = Some(snapshot);
        }
        create_ledger(&path, &id)?;
    }
    let file = open_no_follow(&path, OpenOptions::new().read(true).append(true))
        .map_err(|e| Error::ledger_append(&path, e))?;
    check_private(&path, &file)?;
    wait.exclusive(&file, &path, |e| Error::io(&path, e))?;

    // Everything below holds both locks. The pass is read again: what counts
    // is the pass as it is now, not as it was a moment ago.
    let loaded = match guarded_missing_pass {
        Some(snapshot) => snapshot,
        None => crate::files::load_after(pass_path, &earlier)?,
    };
    if loaded.pass.id != id {
        return Err(Error::Usage(format!(
            "the pass id changed from `{id}` to `{}` while waiting for the ledger; nothing was recorded. Run the command again",
            loaded.pass.id
        )));
    }
    let parsed = scan_ledger(
        &path,
        BufReader::with_capacity(SCAN_BUFFER, &file),
        false,
        witness.as_ref().map(|w| w.seq),
        None,
        visit,
    )?
    .for_pass(&path, &id)?;
    clock::check_kind(&path, &parsed)?;
    if !created
        && guard.is_some_and(|expected| {
            expected != adoption_token(&loaded, &path, Some(&parsed), witness.as_ref())
        })
    {
        return Err(stale_token(pass_path));
    }

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

/// A recorded time exactly as the ledger writes it (UTC, full precision).
#[must_use]
pub fn rfc3339(now: OffsetDateTime) -> String {
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
/// A failed write is rolled back under the lock ([`append::append_line`]).
fn append(locked: &mut Locked, line: &str, what: &str) -> Result<(), Error> {
    append::append_line(
        &mut locked.file,
        &locked.path,
        format!("{line}\n").as_bytes(),
        what,
    )
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
/// window and revocation at `now`, the destination (when the request names
/// a target), and the remaining total, then appends the
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
/// request, or a failed write. [`Error::AppendUncertain`] means the
/// append or sync failed and its outcome requires reconciliation.
/// [`Error::WitnessNotUpdated`] means the debit synced and the witness
/// update failed.
pub fn spend_in(
    pass_path: &Path,
    request: &SpendRequest<'_>,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<SpendOutcome, Error> {
    check_clock(now)?;
    spend_with_clock_in(pass_path, request, state, || now)
}

fn validate_request(request: &SpendRequest<'_>) -> Result<(), Error> {
    if request.amount == 0 || request.amount > MAX_CEILING {
        return Err(Error::Usage(format!(
            "the amount must be a whole number from 1 to {MAX_CEILING}; nothing was recorded"
        )));
    }
    validate_spend_policy(request)
}

fn validate_spend_policy(request: &SpendRequest<'_>) -> Result<(), Error> {
    if request.needed.is_negative() {
        return Err(Error::Usage(
            "the duration the work may take is negative; pass zero for \"right now\", or how long the work may take. Nothing was recorded".to_owned(),
        ));
    }
    if request.name.is_some() && request.target.is_none() {
        return Err(Error::Usage(
            "a host name was given without a target; a name is only checked together with the address, port and protocol it is sent to. Nothing was recorded".to_owned(),
        ));
    }
    if let Some(note) = request.note {
        check_new_note(note).map_err(|m| Error::Usage(format!("{m}; nothing was recorded")))?;
    }
    if !request.additional_targets.is_empty() && request.target.is_none()
        || request.additional_targets.len() >= MAX_TARGETS
    {
        return Err(Error::Usage(format!(
            "provide a first target and at most {MAX_TARGETS} targets total"
        )));
    }
    Ok(())
}

/// Sample the supplied clock after acquiring both writer locks and verifying the ledger.
///
/// # Errors
/// As for [`spend_in`]. A failed append/sync has an uncertain outcome.
pub fn spend_with_clock_in(
    pass_path: &Path,
    request: &SpendRequest<'_>,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
) -> Result<SpendOutcome, Error> {
    validate_request(request)?;
    let mut locked = lock_for_writing_notifying(
        pass_path,
        state,
        false,
        None,
        request.lock_timeout,
        request.on_lock_wait,
        &mut |_| Ok(()),
    )?;
    let id = locked.loaded.pass.id.clone();
    let (here, warnings) = prepare_witness(pass_path, &locked, state, true)?;
    let now = clock();
    check_clock(now)?;
    let mut outcome = evaluate_spend(
        &locked.loaded,
        request,
        &locked.parsed.tally,
        now,
        warnings,
        locked.parsed.latest,
    );
    if outcome.refusal.is_some() {
        return Ok(outcome);
    }
    let loaded = &locked.loaded;
    let spent = outcome.spent;
    let entry = Entry {
        seq: locked.parsed.seq + 1,
        time: rfc3339(now),
        counter: request.counter.to_owned(),
        n: request.amount,
        digest: loaded.digest.to_string(),
        note: request.note.map(str::to_owned),
        test_clock: clock::marker(),
        prev: locked.parsed.tail().to_string(),
    };
    let line = serde_json::to_string(&entry).map_err(|e| Error::Usage(e.to_string()))?;
    let mut totals = locked.parsed.tally.spent.clone();
    let _ = add(&mut totals, request.counter, request.amount);
    let prepared = state.prepare(
        &id,
        &Witnessed {
            ledger: here,
            seq: entry.seq,
            tail: Digest::of(line.as_bytes()),
            totals,
            updated: stamp(now),
            test_clock: locked.parsed.rehearsal_witness(true),
        },
    )?;
    append(&mut locked, &line, "spend")?;
    state
        .publish(&id, &prepared)
        .map_err(|e| Error::WitnessNotUpdated {
            path: locked.path.clone(),
            seq: entry.seq,
            detail: e.to_string(),
        })?;
    outcome.spent = spent + request.amount;
    outcome.seq = Some(entry.seq);
    Ok(outcome)
}

/// The warning for a decision clock before `latest`, the latest time recorded
/// in the ledger and the line that records it, when it is before.
fn clock_rollback_warning(
    now: OffsetDateTime,
    latest: Option<(OffsetDateTime, u64)>,
) -> Option<String> {
    let (time, seq) = latest.filter(|(time, _)| now < *time)?;
    let gap = time - now;
    if gap >= time::Duration::SECOND {
        return Some(format!(
            "the decision clock ({}) precedes {}, the latest time recorded in the ledger (sequence {seq}); check the system clock before continuing",
            stamp(now),
            stamp(time)
        ));
    }
    // Under a second the two stamps would read the same, so show the digits
    // that differ. A gap this small is usually a caller that sampled `now`
    // before it took the lock while another writer committed first; it is
    // not a clock that was set back.
    Some(format!(
        "the decision clock ({}) precedes {}, the latest time recorded in the ledger (sequence {seq}), by {}; if the caller took `now` before taking the ledger lock (for example several batch writers at once), sample the clock after the lock instead: use `spend_charges_batch_with_clock_in` or `spend_with_clock_in`; otherwise check the system clock before continuing",
        fine_stamp(now, gap),
        fine_stamp(time, gap),
        gap_text(gap)
    ))
}

/// `stamp` with fractional seconds, enough of them to show a gap under one
/// second: milliseconds, or microseconds or nanoseconds for a smaller gap.
fn fine_stamp(instant: OffsetDateTime, gap: time::Duration) -> String {
    let whole = stamp(instant);
    let digits = if gap >= time::Duration::MILLISECOND {
        3
    } else if gap >= time::Duration::MICROSECOND {
        6
    } else {
        9
    };
    let fraction = format!("{:09}", instant.nanosecond());
    whole.strip_suffix('Z').map_or_else(
        || whole.clone(),
        |base| format!("{base}.{}Z", &fraction[..digits]),
    )
}

fn gap_text(gap: time::Duration) -> String {
    let nanos = gap.whole_nanoseconds();
    if nanos >= 1_000_000 {
        format!("{} ms", nanos / 1_000_000)
    } else if nanos >= 1_000 {
        format!("{} us", nanos / 1_000)
    } else {
        format!("{nanos} ns")
    }
}

fn warn_clock_rollback(
    now: OffsetDateTime,
    latest: Option<(OffsetDateTime, u64)>,
    warnings: &mut Vec<String>,
) {
    warnings.extend(clock_rollback_warning(now, latest));
}

/// The most counters a left-the-pass warning names before it counts the rest.
const LEFT_COUNTERS_LISTED: usize = 4;

/// A warning when the ledger holds spend on a counter that the pass no longer
/// has, as after a rename. That spend does not count against any ceiling in
/// the pass, so a new counter starts from nothing. The warning names each such
/// counter and its spend, and each counter of the pass with no spend. Advice
/// only: an owner may drop a counter.
fn warn_left_counters(pass: &crate::Pass, tally: &Tally, warnings: &mut Vec<String>) {
    let left: Vec<(&String, u64)> = tally
        .spent
        .iter()
        .filter(|(name, spent)| **spent > 0 && !pass.ceilings.contains_key(*name))
        .map(|(name, spent)| (name, *spent))
        .collect();
    if left.is_empty() {
        return;
    }
    let list = |items: Vec<String>| {
        let more = items.len().saturating_sub(LEFT_COUNTERS_LISTED);
        let mut text = items
            .into_iter()
            .take(LEFT_COUNTERS_LISTED)
            .collect::<Vec<_>>()
            .join(", ");
        if more > 0 {
            let _ = write!(text, " and {more} more");
        }
        text
    };
    let gone = list(
        left.iter()
            .map(|(name, spent)| format!("{} ({spent} spent)", display_quoted(name)))
            .collect(),
    );
    let fresh: Vec<String> = pass
        .ceilings
        .keys()
        .filter(|name| tally.spent(name) == 0)
        .map(|name| display_quoted(name))
        .collect();
    let new_note = if fresh.is_empty() {
        String::new()
    } else {
        format!(
            "; the pass has counters with nothing spent: {}. If this is a rename, the old spend does not count against the new ceiling",
            list(fresh)
        )
    };
    warnings.push(format!(
        "the ledger has spend on counters that the pass no longer has: {gone}{new_note}. Ask the owner whether the counter was dropped on purpose, and restore its name if not"
    ));
}

fn evaluate_spend(
    loaded: &LoadedPass,
    request: &SpendRequest<'_>,
    tally: &Tally,
    now: OffsetDateTime,
    mut warnings: Vec<String>,
    latest: Option<(OffsetDateTime, u64)>,
) -> SpendOutcome {
    warn_clock_rollback(now, latest, &mut warnings);
    warn_left_counters(&loaded.pass, tally, &mut warnings);
    let total = loaded.pass.ceilings.get(request.counter).copied();
    let spent = tally.spent(request.counter);
    let mut outcome = SpendOutcome {
        now,
        labels: Vec::new(),
        refused_target: None,
        refusal: None,
        counter: request.counter.to_owned(),
        amount: request.amount,
        total,
        spent,
        seq: None,
        digest: loaded.digest,
        pass_id: loaded.pass.id.clone(),
        label: None,
        warnings,
    };
    match decide_spend_targets(loaded, request, now) {
        Ok(labels) => match check_known_counters(&loaded.pass, [request.counter])
            .and_then(|()| check_required_charges(&loaded.pass, |name| name == request.counter))
            .and_then(|()| decide_ceiling(&loaded.pass, request.counter, request.amount, spent))
        {
            Ok(()) => {
                outcome.label = labels.first().cloned();
                outcome.labels = labels;
            }
            Err(reason) => outcome.refusal = Some(reason),
        },
        Err(r) => {
            outcome.refused_target = r.index;
            outcome.refusal = Some(r.reason);
        }
    }
    outcome
}

/// Predict the policy decision from a verified read-only snapshot.
/// The returned spent and remaining values reflect the snapshot, and seq is absent.
///
/// # Errors
/// An unusable witness, invalid request/pass or ledger inconsistency.
pub fn preview_spend_in(
    path: &Path,
    request: &SpendRequest<'_>,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<SpendOutcome, Error> {
    check_clock(now)?;
    preview_spend_with_clock_in(path, request, state, || now)
}

/// Predict a spend with a clock sampled after verifying the snapshot.
///
/// # Errors
/// As [`preview_spend_in`].
pub fn preview_spend_with_clock_in(
    path: &Path,
    request: &SpendRequest<'_>,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
) -> Result<SpendOutcome, Error> {
    validate_request(request)?;
    let (loaded, mut view) =
        with_requested_wait(request.lock_timeout, request.on_lock_wait, || {
            preview_snapshot(path, state)
        })?;
    clock::check_view(&view)?;
    let now = clock();
    check_clock(now)?;
    let outcome = evaluate_spend(
        &loaded,
        request,
        &view.tally,
        now,
        std::mem::take(&mut view.warnings),
        view.latest_time,
    );
    if outcome.refusal.is_none() {
        let projected = view.tally.spent(request.counter) + request.amount;
        view.tally
            .spent
            .insert(request.counter.to_owned(), projected);
        view.check_next_witness(state, &loaded.pass.id)?;
    }
    Ok(outcome)
}

impl LedgerView {
    /// A warning when the decision clock `now` is before the latest time
    /// recorded in the ledger, naming that time and its sequence number: the
    /// clock was set back, or a line was written with a clock set ahead.
    /// Spends, previews, `permits` and `status` give it.
    #[must_use]
    pub fn clock_warning(&self, now: OffsetDateTime) -> Option<String> {
        clock_rollback_warning(now, self.latest_time)
    }

    fn check_next_witness(&self, state: &StateDir, id: &str) -> Result<(), Error> {
        check_projected_witness_size(
            state,
            id,
            &self.path,
            self.tip.as_ref().map_or(0, |tip| tip.seq) + 1,
            &self.tally.spent,
        )
    }
}

fn verified_snapshot(path: &Path, state: &StateDir) -> Result<(LoadedPass, LedgerView), Error> {
    visit_verified_snapshot(path, state, &mut |_| Ok(()))
}

fn visit_verified_snapshot(
    path: &Path,
    state: &StateDir,
    visit: &mut Visitor<'_>,
) -> Result<(LoadedPass, LedgerView), Error> {
    let loaded = load(path)?;
    let view = visit_view(&loaded, state, false, visit)?;
    if let WitnessStatus::NotChecked { reason } = view.witness {
        return Err(Error::WitnessUnavailable {
            pass_id: loaded.pass.id,
            dir: state.path().ok().map(Path::to_path_buf),
            detail: reason,
        });
    }
    Ok((loaded, view))
}

fn preview_snapshot(path: &Path, state: &StateDir) -> Result<(LoadedPass, LedgerView), Error> {
    visit_preview_snapshot(path, state, &mut |_| Ok(()))
}

fn visit_preview_snapshot(
    path: &Path,
    state: &StateDir,
    visit: &mut Visitor<'_>,
) -> Result<(LoadedPass, LedgerView), Error> {
    let (loaded, view) = visit_verified_snapshot(path, state, visit)?;
    check_preview_write_access(path, &view.path, view.exists, state, &loaded.pass.id)?;
    Ok((loaded, view))
}

fn check_preview_write_access(
    pass: &Path,
    ledger: &Path,
    exists: bool,
    state: &StateDir,
    id: &str,
) -> Result<(), Error> {
    state.preview_write_access(id)?;
    if exists {
        open_no_follow(ledger, OpenOptions::new().append(true))?;
    } else {
        crate::files::writable_directory(
            pass.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
        )?;
    }
    Ok(())
}

fn prepare_witness(
    pass_path: &Path,
    locked: &Locked,
    state: &StateDir,
    anchor_unwitnessed: bool,
) -> Result<(String, Vec<String>), Error> {
    let id = &locked.loaded.pass.id;
    let here = ledger_identity(&locked.path);
    let (status, moved) = compare(
        pass_path,
        &locked.path,
        Some(&locked.parsed),
        locked.witness.as_ref(),
        state,
        id,
    )?;
    let preserve_unanchored =
        !anchor_unwitnessed && status == WitnessStatus::Missing && locked.parsed.seq > 0;
    let mut warnings = warnings(&status, moved.as_ref(), id, !preserve_unanchored);
    if (locked.created || locked.parsed.seq == 0) && status == WitnessStatus::Missing {
        // This call started the ledger, or an earlier first spend left only
        // its header (the entry could not be written): it has no witness
        // because it holds nothing yet, not because it came from somewhere
        // else, and there is no history to lose.
        warnings.clear();
    }
    warnings.extend(crate::files::shared_directory_warning(pass_path));
    warnings.extend(crate::files::future_mtime_warning(pass_path));
    warnings.extend(state.observe_pass_file(&locked.loaded));
    if !preserve_unanchored && (status != WitnessStatus::Matches || moved.is_some()) {
        state.write(
            id,
            &Witnessed {
                ledger: here.clone(),
                seq: locked.parsed.seq,
                tail: locked.parsed.tail(),
                totals: locked.parsed.tally.spent.clone(),
                updated: locked
                    .parsed
                    .last_time
                    .map(stamp)
                    .or_else(|| locked.witness.as_ref().map(|w| w.updated.clone()))
                    .unwrap_or_else(|| stamp(OffsetDateTime::UNIX_EPOCH)),
                test_clock: locked.parsed.rehearsal_witness(false),
            },
        )?;
    }
    Ok((here, warnings))
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
    /// The counters whose carried total came from the note of a damaged
    /// witness (with `--carry-noted-totals`), and that noted total: the
    /// verified total was higher than the witness's. Empty otherwise.
    pub from_note: BTreeMap<String, u64>,
    /// When the witness proved a rehearsal ([`Witnessed::test_clock`]):
    /// whether its totals, rehearsal units, were dropped or carried.
    /// `None` when it proved none, and under a test clock without a choice
    /// (a rehearsal adopting its own units).
    pub rehearsal: Option<RehearsalTotals>,
}

/// What an adoption does with the totals of a witness that may count a
/// rehearsal.
///
/// A witness written for a ledger of test-clock lines only is marked
/// ([`Witnessed::test_clock`]). The mark is a hint: it makes an adoption on
/// the real clock refuse by default, but it never lowers a count. Only
/// [`RehearsalTotals::Drop`] lowers one, and only after the rehearsal
/// ledger it names proves the rehearsal (see [`adopt_guarded_rehearsal`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RehearsalTotals {
    /// On the real clock, refuse an adoption from a marked witness and say
    /// what the choices do; otherwise adopt as before.
    #[default]
    Refuse,
    /// Carry nothing from the witness, when the rehearsal ledger at this
    /// path, moved aside from beside the pass, proves that every unit the
    /// witness counts was a rehearsal: the rehearsal spent nothing real.
    Drop(PathBuf),
    /// Carry them: the rehearsal units count against the ceilings.
    Carry,
}

impl RehearsalTotals {
    /// The flag of `hallpass adopt` that chooses it, if any.
    #[must_use]
    pub const fn flag(&self) -> Option<&'static str> {
        match self {
            Self::Refuse => None,
            Self::Drop(_) => Some("--drop-rehearsal"),
            Self::Carry => Some("--carry-rehearsal"),
        }
    }

    const fn drops(this: Option<&Self>) -> bool {
        matches!(this, Some(Self::Drop(_)))
    }
}

/// The adoption choices: see [`adopt_guarded_rehearsal`].
#[derive(Clone, Debug, Default)]
struct AdoptFlags {
    carry_noted: bool,
    rehearsal: RehearsalTotals,
}

/// What this adoption does with the totals of `witness` as a rehearsal's,
/// or `None` when it treats them as any totals; the refusals of
/// [`adopt_guarded_rehearsal`].
fn rehearsal_totals(
    witness: Option<&Witnessed>,
    flags: &AdoptFlags,
    noted: bool,
    pass_path: &Path,
    id: &str,
) -> Result<Option<RehearsalTotals>, Error> {
    let pass = crate::witness::quote_path(pass_path);
    match &flags.rehearsal {
        RehearsalTotals::Drop(file) => {
            let Some(w) = witness.filter(|w| w.seq > 0) else {
                return Err(Error::Usage(format!(
                    "--drop-rehearsal: there is no witness of any entry for pass `{id}`, so there is nothing to drop; nothing was recorded. Run `hallpass adopt {pass} --preview` without it"
                )));
            };
            if noted {
                return Err(Error::Usage(format!(
                    "--drop-rehearsal: the witness of pass `{id}` was found damaged, so it cannot show which entries it counts; nothing was recorded. Run `hallpass adopt {pass} --preview --carry-noted-totals` without --drop-rehearsal"
                )));
            }
            prove_rehearsal(file, &ledger_path(pass_path), w, id)?;
            Ok(Some(flags.rehearsal.clone()))
        }
        RehearsalTotals::Carry => {
            if witness.is_some_and(|w| w.test_clock) {
                return Ok(Some(RehearsalTotals::Carry));
            }
            Err(Error::Usage(format!(
                "--carry-rehearsal: the witness of pass `{id}` does not show a rehearsal (hallpass marks a witness when every entry it counts was recorded under a test clock), so its totals are carried as they are; nothing was recorded. Run `hallpass adopt {pass} --preview` without it"
            )))
        }
        RehearsalTotals::Refuse => {
            let Some(w) = witness.filter(|w| w.test_clock) else {
                return Ok(None);
            };
            if w.totals.values().all(|n| *n == 0) || clock::marker().is_some() {
                return Ok(None);
            }
            Err(Error::Usage(format!(
                "the witness of pass `{id}` marks a rehearsal: it was written for a ledger whose entries, to sequence {}, were all recorded under a test clock (HALLPASS_UNSAFE_TEST_CLOCK), so its totals (spent: {}) look like rehearsal units. This adoption uses the real clock and would carry them into the live count, so nothing was recorded. If you moved the rehearsal ledger aside, run `hallpass adopt {pass} --preview --drop-rehearsal REHEARSAL_LEDGER` with that file: hallpass checks that it is the witnessed ledger and that every entry is a rehearsal, then carries nothing. To count the units against the ceilings, use --carry-rehearsal instead",
                w.seq,
                totals_text(&w.totals),
            )))
        }
    }
}

/// Check that `file`, given with `--drop-rehearsal`, proves that `w`
/// counts only a rehearsal: it is a ledger of pass `id`, opened under the
/// rules for any ledger, other than the one beside the pass (`ledger`), its
/// whole chain verifies, it ends with the line the witness recorded, every
/// entry is a test-clock line, no adoption in it carried an amount, and its
/// totals are the witness's. Any doubt refuses: the mark alone is not proof.
fn prove_rehearsal(file: &Path, ledger: &Path, w: &Witnessed, id: &str) -> Result<(), Error> {
    let refuse = |why: String| {
        Error::Usage(format!(
            "--drop-rehearsal: {} does not prove that the witness of pass `{id}` counts only a rehearsal: {why}. Nothing was recorded. Give the rehearsal ledger that was moved aside from beside the pass, unchanged; if there is none, the totals stay counted: adopt without --drop-rehearsal, or use a pass with a new id",
            crate::witness::quote_path(file)
        ))
    };
    if let (Ok(a), Ok(b)) = (fs::canonicalize(file), fs::canonicalize(ledger))
        && a == b
    {
        return Err(refuse(
            "it is the ledger beside the pass, not one moved aside".to_owned(),
        ));
    }
    let parsed = match inspect_candidate(file, Some(w.seq)).and_then(|p| p.for_pass(file, id)) {
        Ok(parsed) => parsed,
        Err(e @ Error::LockTimeout { .. }) => return Err(e),
        Err(e) => {
            return Err(refuse(format!(
                "it is not an intact ledger of this pass ({e})"
            )));
        }
    };
    if parsed.seq != w.seq || parsed.tail() != w.tail {
        let why = if parsed.prefix == Some((w.seq, w.tail)) {
            format!(
                "it holds entries after sequence {}, the last one the witness recorded",
                w.seq
            )
        } else {
            format!(
                "it does not end with the line the witness recorded (sequence {}), so it is not the witnessed ledger",
                w.seq
            )
        };
        return Err(refuse(why));
    }
    if let Some(seq) = parsed.real_clock_seq {
        return Err(refuse(format!(
            "entry {seq} was recorded at the real time, so it may be live work"
        )));
    }
    if let Some(seq) = parsed.carried_seq {
        return Err(refuse(format!(
            "the adoption at entry {seq} carried an amount, which may be live work"
        )));
    }
    if parsed.test_clock_seq.is_none() || !same_totals(&parsed.tally.spent, &w.totals) {
        return Err(refuse(format!(
            "its totals (spent: {}) are not the witness's (spent: {})",
            totals_text(&parsed.tally.spent),
            totals_text(&w.totals)
        )));
    }
    Ok(())
}

/// Read-only adoption snapshot and its guarded-apply token.
#[derive(Clone, Debug)]
pub struct AdoptPreview {
    /// The recovery situation.
    pub case: AdoptCase,
    /// Pass ID.
    pub pass_id: String,
    /// Present ledger sequence, or zero if absent.
    pub seq: u64,
    /// Present totals.
    pub present: BTreeMap<String, u64>,
    /// Additional amounts to carry from the witness.
    pub carried: BTreeMap<String, u64>,
    /// Projected totals after adoption.
    pub totals: BTreeMap<String, u64>,
    /// Witness used by the snapshot.
    pub previous: Option<Witnessed>,
    /// Opaque versioned reviewed-state token.
    pub token: String,
    /// As [`AdoptOutcome::from_note`].
    pub from_note: BTreeMap<String, u64>,
    /// A file at the other path where the witness last saw the ledger,
    /// that hallpass read and found is not this pass's intact ledger
    /// (damaged, for another id), and why: the witness may be behind it, so
    /// the carried totals may be too low. `None` otherwise (a file it could
    /// not read refuses the adoption instead).
    pub last_seen_unchecked: Option<(PathBuf, String)>,
    /// As [`AdoptOutcome::rehearsal`].
    pub rehearsal: Option<RehearsalTotals>,
}

impl AdoptPreview {
    /// Whether this adoption would accept a ledger that may lack lines, and
    /// so caller references, that hallpass had recorded. After it, every
    /// guarded spend (`--require-new-ref`) on this ledger is refused as
    /// `reference-inconclusive` until a reference reconciliation follows, as
    /// for [`Adoption::makes_references_inconclusive`].
    #[must_use]
    pub fn makes_references_inconclusive(&self) -> bool {
        reference::may_lose_references(
            &self.carried,
            self.previous.as_ref(),
            clock::marker().is_none(),
        )
    }
}

impl Adoption {
    /// Whether this adoption accepted a ledger that may lack lines, and so
    /// caller references, that hallpass had recorded: it carried an amount,
    /// or recorded a previous witness of at least one line. From it on,
    /// every guarded spend (`--require-new-ref`) on this ledger is refused
    /// as `reference-inconclusive`, until a reference reconciliation
    /// ([`crate::reconcile_references`]) names it or a later such adoption.
    #[must_use]
    pub fn makes_references_inconclusive(&self) -> bool {
        reference::may_lose_references(&self.carried, self.previous.as_ref(), !self.test_clock)
    }
}

/// The refusal when the ledger and its witness agree, for `adopt` and its
/// preview alike.
fn nothing_to_adopt(ledger: &Path) -> Error {
    Error::Usage(format!(
        "the ledger {} matches its witness, so there is nothing to adopt. Adopt only after the ledger was lost or changed, or when it has no witness; run `hallpass status` to see the current count. Nothing was recorded",
        ledger.display()
    ))
}

fn carry(present: &BTreeMap<String, u64>, witness: Option<&Witnessed>) -> BTreeMap<String, u64> {
    let mut carried = BTreeMap::new();
    if let Some(w) = witness {
        for (counter, n) in &w.totals {
            let have = present.get(counter).copied().unwrap_or(0);
            if *n > have {
                carried.insert(counter.clone(), n - have);
            }
        }
    }
    carried
}

/// The previous witness as the adoption line records it, and whether it
/// records it as a rehearsal's: only when the rehearsal ledger proved it
/// (`Drop`), on the real clock. The witness's own mark is a hint only.
fn recorded_previous(
    witness: Option<Witnessed>,
    rehearsal: Option<&RehearsalTotals>,
) -> (bool, Option<Witnessed>) {
    let proved = RehearsalTotals::drops(rehearsal) && clock::marker().is_none();
    let previous = witness.map(|mut w| {
        w.test_clock = proved;
        w
    });
    (proved, previous)
}

/// What an adoption carries over `present` from `witness` (or `raised`, the
/// witness with noted totals), and which counters the note raised: nothing
/// when it drops a rehearsal's units.
fn adoption_carry(
    present: &BTreeMap<String, u64>,
    raised: Option<&Witnessed>,
    witness: Option<&Witnessed>,
    rehearsal: Option<&RehearsalTotals>,
) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    if RehearsalTotals::drops(rehearsal) {
        return (BTreeMap::new(), BTreeMap::new());
    }
    (
        carry(present, raised.or(witness)),
        raised_counters(raised, witness),
    )
}

/// The counters `raised` (the witness with noted totals) carries above the
/// witness itself, with the noted total.
fn raised_counters(
    raised: Option<&Witnessed>,
    witness: Option<&Witnessed>,
) -> BTreeMap<String, u64> {
    let (Some(raised), Some(w)) = (raised, witness) else {
        return BTreeMap::new();
    };
    raised
        .totals
        .iter()
        .filter(|(c, n)| **n > w.totals.get(*c).copied().unwrap_or(0))
        .map(|(c, n)| (c.clone(), *n))
        .collect()
}

/// Note where an adoption replaced the history the witness recorded, so
/// that a copy of that history is later named as one.
fn note_fork(state: &StateDir, id: &str, line: &AdoptLine, text: &str, now: OffsetDateTime) {
    state.record_fork(
        id,
        Fork {
            seq: line.seq,
            hash: Digest::of(text.as_bytes()).to_string(),
            prev: line.prev.clone(),
            time: stamp(now),
        },
    );
}

/// The witness to carry totals from when a command proved this witness
/// damaged (a note in the state directory matches its bytes): refused
/// without `carry_noted`; with it, the witness with, per counter, the
/// higher of its own and the verified total noted. `None` when there is no
/// note, so the witness is used as it is.
fn noted_totals(
    state: &StateDir,
    id: &str,
    witness: Option<&Witnessed>,
    carry_noted: bool,
    pass_path: &Path,
) -> Result<Option<Witnessed>, Error> {
    let note = witness.and_then(|_| state.noted_damage(id));
    let (Some(w), Some(note)) = (witness, note) else {
        if carry_noted {
            return Err(Error::Usage(format!(
                "--carry-noted-totals: no damage is noted for the witness of pass `{id}`, so there are no noted totals to carry; nothing was recorded. Run `hallpass adopt {} --preview` without it",
                pass_path.display()
            )));
        }
        return Ok(None);
    };
    if !carry_noted {
        return Err(state.noted_as_damaged(
            id,
            &format!(
                "a command found that it records spent: {} at sequence {}, while the verified ledger had spent: {} there, and an adoption would carry those totals. Put the ledger back beside the pass, or a backup that holds sequence {}. If no copy is left, run `hallpass adopt {} --reason \"...\" --carry-noted-totals`: it carries, per counter, the higher of the two totals",
                totals_text(&note.recorded),
                note.seq,
                totals_text(&note.verified),
                note.seq,
                pass_path.display()
            ),
        ));
    }
    let mut raised = w.clone();
    for (counter, n) in &note.verified {
        let total = raised.totals.entry(counter.clone()).or_insert(0);
        *total = (*total).max(*n);
    }
    Ok(Some(raised))
}

fn adoption_token(
    loaded: &LoadedPass,
    path: &Path,
    parsed: Option<&Parsed>,
    witness: Option<&Witnessed>,
) -> String {
    let w = witness.map(|w| WitnessLine {
        ledger: w.ledger.clone(),
        seq: w.seq,
        tail: w.tail.to_string(),
        totals: w.totals.clone(),
        updated: w.updated.clone(),
        test_clock: (w.test_clock && clock::marker().is_none()).then_some(true),
    });
    let input = serde_json::json!({"version": 1, "pass_id": loaded.pass.id, "pass_digest": loaded.digest.to_string(), "ledger": ledger_identity(path), "exists": parsed.is_some(), "seq": parsed.map_or(0, |p| p.seq), "tail": parsed.map(|p| p.tail.to_string()), "witness": w });
    format!("v1:{}", Digest::of(input.to_string().as_bytes()))
}

/// Refuse an adoption token that is not shaped like one `adopt --preview`
/// prints (`v1:` and a digest), before any lock is taken.
fn check_token_shape(token: &str, pass_path: &Path) -> Result<(), Error> {
    if token
        .strip_prefix("v1:")
        .is_some_and(|d| d.parse::<Digest>().is_ok())
    {
        return Ok(());
    }
    Err(Error::Usage(format!(
        "`{token}` is not an adoption token (a token looks like v1:sha256:<64 hex digits>); nothing was recorded. Run `hallpass adopt {} --preview` and use the token it prints",
        pass_path.display()
    )))
}

/// The refusal for a well-formed token that no longer matches.
fn stale_token(pass_path: &Path) -> Error {
    Error::Usage(format!(
        "the adoption token is stale: the pass, the ledger or the witness changed since that preview; nothing was recorded. Run `hallpass adopt {} --preview` again and use the new token",
        pass_path.display()
    ))
}

/// Inspect an adoptable state without creating files or locks.
///
/// # Errors
/// If the state is not adoptable or any evidence is invalid.
pub fn preview_adopt(pass_path: &Path, state: &StateDir) -> Result<AdoptPreview, Error> {
    preview_adopt_with(pass_path, state, false)
}

/// [`preview_adopt`], and with `carry_noted` the preview of an adoption
/// that carries the totals noted for a damaged witness (see
/// [`adopt_guarded_with`]).
///
/// # Errors
/// As [`preview_adopt`]; a witness noted as damaged without `carry_noted`
/// ([`Error::WitnessUnavailable`]); `carry_noted` with no such note.
pub fn preview_adopt_with(
    pass_path: &Path,
    state: &StateDir,
    carry_noted: bool,
) -> Result<AdoptPreview, Error> {
    preview_adopt_rehearsal(pass_path, state, carry_noted, RehearsalTotals::Refuse)
}

/// [`preview_adopt_with`], and with `rehearsal` the preview of an adoption
/// that drops or carries the totals of a witness that proves a rehearsal
/// (see [`adopt_guarded_rehearsal`]).
///
/// # Errors
/// As [`preview_adopt_with`]; on the real clock, a witness that proves a
/// rehearsal with [`RehearsalTotals::Refuse`] ([`Error::Usage`]); another
/// choice when the witness proves no rehearsal ([`Error::Usage`]).
pub fn preview_adopt_rehearsal(
    pass_path: &Path,
    state: &StateDir,
    carry_noted: bool,
    rehearsal: RehearsalTotals,
) -> Result<AdoptPreview, Error> {
    let flags = AdoptFlags {
        carry_noted,
        rehearsal,
    };
    let loaded = load(pass_path)?;
    let id = &loaded.pass.id;
    let path = ledger_path(pass_path);
    let file = if exists(&path)? {
        let file = open_no_follow(&path, OpenOptions::new().read(true))?;
        check_private(&path, &file)?;
        lock_shared(&file, &path)?;
        Some(file)
    } else {
        None
    };
    let witness = state.read(id)?;
    let parsed = file
        .as_ref()
        .map(|f| {
            parse_ledger(
                &path,
                BufReader::new(f),
                id,
                false,
                witness.as_ref().map(|w| w.seq),
            )
        })
        .transpose()?;
    if let Some(parsed) = &parsed {
        clock::check_kind(&path, parsed)?;
    }
    let case = match compare(
        pass_path,
        &path,
        parsed.as_ref(),
        witness.as_ref(),
        state,
        id,
    ) {
        Err(Error::LedgerMissing(_)) => {
            refuse_fork(pass_path, &path, witness.as_ref(), state, id)?;
            AdoptCase::LedgerMissing
        }
        Err(Error::LedgerChanged { .. }) => {
            refuse_fork(pass_path, &path, witness.as_ref(), state, id)?;
            AdoptCase::LedgerChanged
        }
        Ok((WitnessStatus::Missing, _)) => AdoptCase::NoWitness,
        Ok(_) => return Err(nothing_to_adopt(&path)),
        Err(e) => return Err(e),
    };
    check_preview_write_access(pass_path, &path, parsed.is_some(), state, id)?;
    let present = parsed
        .as_ref()
        .map_or_else(BTreeMap::new, |p| p.tally.spent.clone());
    let raised = noted_totals(state, id, witness.as_ref(), carry_noted, pass_path)?;
    let rehearsal = rehearsal_totals(witness.as_ref(), &flags, raised.is_some(), pass_path, id)?;
    let (carried, from_note) = adoption_carry(
        &present,
        raised.as_ref(),
        witness.as_ref(),
        rehearsal.as_ref(),
    );
    // As the adoption line will record it: a proved rehearsal, on the
    // real clock.
    let mut totals = present.clone();
    for (counter, n) in &carried {
        let _ = add(&mut totals, counter, *n);
    }
    let seq = parsed.as_ref().map_or(0, |p| p.seq);
    check_projected_witness_size(state, id, &path, seq + 1, &totals)?;
    let token = adoption_token(&loaded, &path, parsed.as_ref(), witness.as_ref());
    let last_seen_unchecked = match (&case, &witness) {
        (AdoptCase::LedgerMissing | AdoptCase::LedgerChanged, Some(w)) => {
            match last_seen_ledger(&path, w, id)? {
                LastSeen::Unchecked(at, why) => Some((at, why)),
                _ => None,
            }
        }
        _ => None,
    };
    let (_, previous) = recorded_previous(witness, rehearsal.as_ref());
    Ok(AdoptPreview {
        case,
        pass_id: id.clone(),
        seq,
        present,
        carried,
        totals,
        previous,
        token,
        from_note,
        last_seen_unchecked,
        rehearsal,
    })
}

// The next tail hash and UTC timestamp have fixed serialized widths.
fn check_projected_witness_size(
    state: &StateDir,
    id: &str,
    path: &Path,
    next_seq: u64,
    totals: &BTreeMap<String, u64>,
) -> Result<(), Error> {
    state.prepare(
        id,
        &Witnessed {
            ledger: ledger_identity(path),
            seq: next_seq,
            tail: Digest::of(b""),
            totals: totals.clone(),
            updated: stamp(OffsetDateTime::UNIX_EPOCH),
            // The longer witness, when a write now may mark it.
            test_clock: clock::marker().is_some(),
        },
    )?;
    Ok(())
}

/// The case an adoption under `locked` resolves, or why there is none. A
/// changed ledger is refused as for a missing one (see
/// `lock_for_writing_inner`) while the ledger the witness last saw is intact
/// elsewhere.
fn locked_adopt_case(
    pass_path: &Path,
    locked: &Locked,
    state: &StateDir,
    id: &str,
) -> Result<AdoptCase, Error> {
    if locked.created {
        return Ok(AdoptCase::LedgerMissing);
    }
    let witness = locked.witness.as_ref();
    match compare(
        pass_path,
        &locked.path,
        Some(&locked.parsed),
        witness,
        state,
        id,
    ) {
        Err(Error::LedgerChanged { .. }) => {
            refuse_fork(pass_path, &locked.path, witness, state, id)?;
            Ok(AdoptCase::LedgerChanged)
        }
        Ok((WitnessStatus::Missing, _)) => Ok(AdoptCase::NoWitness),
        Ok(_) => Err(nothing_to_adopt(&locked.path)),
        Err(e) => Err(e),
    }
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
    adopt_guarded(pass_path, reason, now, state, None)
}

/// Adopt with an optional token returned by [`preview_adopt`].
///
/// # Errors
/// As [`adopt`], or a stale preview token.
pub fn adopt_guarded(
    pass_path: &Path,
    reason: &str,
    now: OffsetDateTime,
    state: &StateDir,
    token: Option<&str>,
) -> Result<AdoptOutcome, Error> {
    adopt_guarded_with(pass_path, reason, now, state, token, false)
}

/// [`adopt_guarded`], choosing what to do with a witness that a command
/// proved damaged against its ledger before the ledger was lost or replaced
/// (hallpass notes that in the state directory).
///
/// Without `carry_noted` such an adoption is refused: the witness's totals
/// are known to be wrong. With it, the adoption carries, per counter, the
/// higher of the witness's total and the verified total noted, so no count
/// is lowered. Restoring the ledger, or a backup that holds the noted
/// sequence, is better: it keeps the receipts.
///
/// # Errors
/// As [`adopt_guarded`]; a witness noted as damaged without `carry_noted`
/// ([`Error::WitnessUnavailable`]); `carry_noted` with no such note
/// ([`Error::Usage`]).
pub fn adopt_guarded_with(
    pass_path: &Path,
    reason: &str,
    now: OffsetDateTime,
    state: &StateDir,
    token: Option<&str>,
    carry_noted: bool,
) -> Result<AdoptOutcome, Error> {
    adopt_guarded_rehearsal(
        pass_path,
        reason,
        now,
        state,
        token,
        carry_noted,
        RehearsalTotals::Refuse,
    )
}

/// [`adopt_guarded_with`], choosing what to do with the totals of a witness
/// that may count a rehearsal.
///
/// A witness marked as a rehearsal's ([`Witnessed::test_clock`]) is a
/// hint. On the real clock, [`RehearsalTotals::Refuse`] refuses an
/// adoption from it: carrying rehearsal units would spend live budget on
/// work that was never sent. [`RehearsalTotals::Carry`] carries them as
/// before. [`RehearsalTotals::Drop`] carries nothing from the witness, only
/// when the file it names proves the rehearsal: a ledger of this pass,
/// other than the one beside the pass, that verifies whole, ends with the
/// line the witness recorded, holds only test-clock entries and no
/// adoption that carried an amount, and has the witness's totals. The
/// mark is not needed for `Drop`, and never enough. Under
/// [`crate::with_test_clock`], `Refuse` carries the totals as any. A
/// witness without the mark is adopted as by [`adopt_guarded_with`].
///
/// # Errors
/// As [`adopt_guarded_with`]; the refusals above, and a `Drop` file that
/// does not prove the rehearsal, naming what failed ([`Error::Usage`]);
/// `Drop` with `carry_noted` ([`Error::Usage`]: a witness found damaged
/// proves nothing).
#[allow(clippy::too_many_arguments)]
pub fn adopt_guarded_rehearsal(
    pass_path: &Path,
    reason: &str,
    now: OffsetDateTime,
    state: &StateDir,
    token: Option<&str>,
    carry_noted: bool,
    rehearsal: RehearsalTotals,
) -> Result<AdoptOutcome, Error> {
    let flags = AdoptFlags {
        carry_noted,
        rehearsal,
    };
    check_clock(now)?;
    check_reason(reason).map_err(|m| Error::Usage(format!("{m}; nothing was recorded")))?;
    let mut locked = lock_for_writing_inner(
        pass_path,
        state,
        Some(&flags),
        token,
        None,
        None,
        &mut |_| Ok(()),
    )?;
    let id = locked.loaded.pass.id.clone();
    let here = ledger_identity(&locked.path);
    let case = locked_adopt_case(pass_path, &locked, state, &id)?;
    let raised = noted_totals(state, &id, locked.witness.as_ref(), carry_noted, pass_path)?;
    let rehearsal = rehearsal_totals(
        locked.witness.as_ref(),
        &flags,
        raised.is_some(),
        pass_path,
        &id,
    )?;
    let (carried, from_note) = adoption_carry(
        &locked.parsed.tally.spent,
        raised.as_ref(),
        locked.witness.as_ref(),
        rehearsal.as_ref(),
    );
    let (proved, previous) = recorded_previous(locked.witness.clone(), rehearsal.as_ref());
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
            test_clock: proved.then_some(true),
        }),
        test_clock: clock::marker(),
        prev: locked.parsed.tail().to_string(),
    };
    let text = serde_json::to_string(&line).map_err(|e| Error::Usage(e.to_string()))?;
    let mut totals = locked.parsed.tally.spent.clone();
    for (counter, n) in &carried {
        let _ = add(&mut totals, counter, *n);
    }
    let prepared = state.prepare(
        &id,
        &Witnessed {
            ledger: here,
            seq: line.seq,
            tail: Digest::of(text.as_bytes()),
            totals: totals.clone(),
            updated: stamp(now),
            test_clock: carried.is_empty() && locked.parsed.rehearsal_witness(true),
        },
    )?;
    append(&mut locked, &text, "adoption")?;
    if case != AdoptCase::NoWitness {
        note_fork(state, &id, &line, &text, now);
    }
    state.publish(&id, &prepared)
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
            previous,
            test_clock: line.test_clock == Some(true),
        },
        ledger: locked.path.clone(),
        created: locked.created,
        pass_id: id,
        totals,
        from_note,
        rehearsal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::tests::GOOD;
    use std::os::unix::fs::PermissionsExt;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

    #[test]
    fn a_sub_second_clock_skew_shows_both_times_and_the_better_advice() {
        let latest = NOW + time::Duration::milliseconds(7);
        let warning = clock_rollback_warning(NOW, Some((latest, 4))).expect("warning");
        assert_eq!(
            warning,
            "the decision clock (2026-11-20T09:00:00.000Z) precedes 2026-11-20T09:00:00.007Z, the latest time recorded in the ledger (sequence 4), by 7 ms; if the caller took `now` before taking the ledger lock (for example several batch writers at once), sample the clock after the lock instead: use `spend_charges_batch_with_clock_in` or `spend_with_clock_in`; otherwise check the system clock before continuing"
        );
        let finer = NOW + time::Duration::microseconds(250);
        let warning = clock_rollback_warning(NOW, Some((finer, 4))).expect("warning");
        assert!(
            warning.contains("(2026-11-20T09:00:00.000000Z) precedes 2026-11-20T09:00:00.000250Z")
                && warning.contains("by 250 us"),
            "{warning}"
        );
        // A gap of a second or more keeps the plain advice.
        let hour = NOW + time::Duration::HOUR;
        let warning = clock_rollback_warning(NOW, Some((hour, 4))).expect("warning");
        assert!(warning.ends_with("(sequence 4); check the system clock before continuing"));
        assert!(clock_rollback_warning(NOW, Some((NOW, 4))).is_none());
    }

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

    #[test]
    fn live_clock_is_sampled_with_writer_locks_held() {
        let (_dir, path, state) = setup();
        let req = request("calls", 1);
        let out = spend_with_clock_in(&path, &req, &state, || {
            assert!(
                state.witness_path("acme-2026-11").expect("path").exists(),
                "preparatory witness must be synced before sampling"
            );
            let held = fs::File::open(ledger_path(&path)).expect("created");
            assert!(matches!(
                held.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            datetime!(2026-11-20 17:00 UTC)
        })
        .expect("decision");
        assert_eq!(out.refusal.expect("expired").code, RefusalCode::Expired);
        let mut boundary = req.clone();
        boundary.needed = Duration::hours(8);
        assert_eq!(
            spend_with_clock_in(&path, &boundary, &state, || NOW)
                .expect("decision")
                .refusal
                .expect("duration")
                .code,
            RefusalCode::WindowTooShort
        );
        let first = spend_with_clock_in(&path, &req, &state, || NOW).expect("spend");
        assert_eq!((first.seq, first.now), (Some(1), NOW));
        assert_eq!(
            read_ledger(&load(&path).expect("pass"), &state)
                .expect("ledger")
                .entries[0]
                .time,
            NOW
        );
    }

    #[test]
    fn preview_clock_is_sampled_after_verified_snapshot() {
        let (_dir, path, state) = setup();
        let req = request("calls", 1);
        let result = preview_spend_with_clock_in(&path, &req, &state, || {
            assert!(!ledger_path(&path).exists());
            datetime!(2026-11-20 17:00 UTC)
        })
        .expect("preview");
        assert_eq!(result.refusal.expect("expired").code, RefusalCode::Expired);
        assert!(!ledger_path(&path).exists());
    }

    #[test]
    fn rollback_warns_only_before_the_latest_entry() {
        let (_dir, path, state) = setup();
        let req = request("calls", 1);
        for (time, warn) in [
            (NOW, false),
            (NOW, false),
            (NOW - Duration::nanoseconds(1), true),
            (NOW, false),
        ] {
            let out = spend_in(&path, &req, time, &state).expect("record");
            assert!(out.seq.is_some());
            assert_eq!(
                out.warnings
                    .iter()
                    .any(|s| s.contains("the latest time recorded in the ledger")),
                warn
            );
        }
    }

    #[test]
    fn debit_survives_failure_between_append_and_witness_update() {
        let (_dir, path, state) = setup();
        let req = request("calls", 1);
        spend_in(&path, &req, NOW, &state).expect("baseline");
        let witness = state.witness_path("acme-2026-11").expect("witness");
        let saved = witness.with_extension("saved");
        let result = spend_with_clock_in(&path, &req, &state, || {
            fs::rename(&witness, &saved).expect("save witness");
            fs::create_dir(&witness).expect("make rename fail");
            NOW
        });
        assert!(matches!(
            result,
            Err(Error::WitnessNotUpdated { seq: 2, .. })
        ));
        fs::remove_dir(&witness).expect("remove fixture");
        fs::rename(&saved, &witness).expect("restore prior evidence");
        let loaded = load(&path).expect("pass");
        let view = read_ledger(&loaded, &state).expect("extended");
        assert_eq!(view.witness, WitnessStatus::Extended { added: 1 });
        assert_eq!(view.tally.spent("calls"), 2);
        assert_eq!(
            spend_in(&path, &req, NOW, &state)
                .expect("next independent spend")
                .seq,
            Some(3)
        );
        assert_eq!(
            read_ledger(&loaded, &state).expect("read").witness,
            WitnessStatus::Matches
        );
    }

    #[test]
    fn historical_counter_witness_round_trips_past_legacy_limit_and_adopts() {
        let (_dir, path, state) = setup();
        let approval = GOOD.split_once("[ceilings]").expect("ceilings").0;
        let id = load(&path).expect("pass").pass.id;
        let ledger = ledger_path(&path);
        let witness_path = state.witness_path(&id).expect("witness");
        let mut older_ledger = Vec::new();
        for revision in 0..22 {
            let mut pass = format!("{approval}[ceilings]\n");
            let names: Vec<_> = (0..crate::MAX_COUNTERS)
                .map(|counter| format!("c{:031}", revision * crate::MAX_COUNTERS + counter))
                .collect();
            for name in &names {
                writeln!(pass, "{name} = {MAX_CEILING}").expect("ceiling");
            }
            fs::write(&path, pass).expect("edited pass");
            let charges: Vec<_> = names
                .iter()
                .map(|counter| Charge {
                    counter,
                    amount: MAX_CEILING,
                })
                .collect();
            let spent = spend_charges_in(&path, &SpendChargesRequest::new(&charges), NOW, &state)
                .expect("spend across revisions");
            assert_eq!(spent.seq, Some(revision as u64 + 1));
            if revision == 0 {
                older_ledger = fs::read(&ledger).expect("initial ledger");
            }
        }
        // The unchanged version 1 encoding matches the writer from before
        // the read-limit change, including a terminal newline.
        let version_one = fs::read(&witness_path).expect("old encoding");
        assert!(version_one.len() > 64 * 1024);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&version_one).expect("JSON")["hallpass_witness"],
            1
        );
        assert_eq!(
            state
                .read(&id)
                .expect("above old cap")
                .expect("witness")
                .totals
                .len(),
            22 * crate::MAX_COUNTERS
        );
        assert_eq!(
            read_summary(&load(&path).expect("pass"), &state)
                .expect("summary")
                .witness,
            WitnessStatus::Matches
        );
        fs::write(&ledger, older_ledger).expect("restore");
        let preview = preview_adopt(&path, &state).expect("preview");
        let adopted = adopt_guarded(
            &path,
            "restored first revision",
            NOW,
            &state,
            Some(&preview.token),
        )
        .expect("adopt");
        assert_eq!(adopted.adoption.carried.len(), 21 * crate::MAX_COUNTERS);
        assert_eq!(adopted.totals, preview.totals);
        assert_eq!(
            state.read(&id).expect("read back").expect("witness").totals,
            adopted.totals
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn witness_size_refusal_leaves_accounting_records_untouched() {
        const CAP: usize = 1024 * 1024;
        const NEXT_COUNTER: &str = "abcdefghijklmnopqrstuvwxyzabcdef";
        let (_dir, path, state) = setup();
        let pass = format!("{GOOD}\n{NEXT_COUNTER} = {MAX_CEILING}\n");
        fs::write(&path, pass).expect("pass");
        let loaded = load(&path).expect("pass");
        let id = &loaded.pass.id;
        let ledger = ledger_path(&path);
        let witness_path = state.witness_path(id).expect("witness");
        let fixture_lock = state.lock(id, LockBudget::default()).expect("lock");
        let mut witness = Witnessed {
            ledger: ledger_identity(&ledger),
            seq: 1,
            tail: Digest::of(b"placeholder"),
            totals: BTreeMap::new(),
            updated: stamp(NOW),
            test_clock: false,
        };
        state.write(id, &witness).expect("empty test witness");
        let overhead = fs::read(&witness_path).expect("sample").len();
        let entry_size = format!(r#""{NEXT_COUNTER}":{MAX_CEILING},"#).len();
        for i in 0..((CAP - overhead + 1) / entry_size) {
            witness.totals.insert(format!("c{i:031}"), MAX_CEILING);
        }
        create_ledger(&ledger, id).expect("header");
        let header = fs::read_to_string(&ledger).expect("header");
        let mut record = AdoptLine {
            seq: 1,
            time: rfc3339(NOW),
            event: "adopt".to_owned(),
            reason: "simulated historical carry-forward".to_owned(),
            digest: loaded.digest.to_string(),
            carried: witness.totals.clone(),
            witness: None,
            test_clock: None,
            prev: Digest::of(header.trim_end().as_bytes()).to_string(),
        };
        let baseline = serde_json::to_string(&record).expect("ledger line");
        witness.tail = Digest::of(baseline.as_bytes());
        state
            .write(id, &witness)
            .expect("witness just below the limit");
        let witness_before = fs::read(&witness_path).expect("witness");
        drop(fixture_lock);

        let bytes = format!("{header}{baseline}\n");
        fs::write(&ledger, &bytes).expect("ledger");
        let charges = [Charge {
            counter: NEXT_COUNTER,
            amount: MAX_CEILING,
        }];
        let mut preview = SpendChargesRequest::new(&charges);
        preview.dry_run = true;
        for result in [
            preview_spend_in(
                &path,
                &SpendRequest::new(NEXT_COUNTER, MAX_CEILING),
                NOW,
                &state,
            )
            .map(|_| ()),
            spend_charges_in(&path, &preview, NOW, &state).map(|_| ()),
            spend_in(
                &path,
                &SpendRequest::new(NEXT_COUNTER, MAX_CEILING),
                NOW,
                &state,
            )
            .map(|_| ()),
            spend_charges_in(&path, &SpendChargesRequest::new(&charges), NOW, &state).map(|_| ()),
        ] {
            let error = result.expect_err("witness size refusal");
            assert!(error.to_string().contains("size limit"), "{error}");
            assert_eq!(
                fs::read(&ledger).expect("unchanged ledger"),
                bytes.as_bytes()
            );
            assert_eq!(
                fs::read(&witness_path).expect("unchanged witness"),
                witness_before
            );
        }

        record.carried.clear();
        record.carried.insert(NEXT_COUNTER.to_owned(), MAX_CEILING);
        let divergent = format!(
            "{header}{}\n",
            serde_json::to_string(&record).expect("line")
        );
        fs::write(&ledger, &divergent).expect("divergent ledger");
        let error = preview_adopt(&path, &state).expect_err("oversized adoption preview");
        assert!(error.to_string().contains("size limit"), "{error}");
        let error = adopt(&path, "reconcile divergent totals", NOW, &state)
            .expect_err("oversized adoption");
        assert!(error.to_string().contains("size limit"), "{error}");
        assert_eq!(
            fs::read(&ledger).expect("unchanged ledger"),
            divergent.as_bytes()
        );
        assert_eq!(
            fs::read(&witness_path).expect("unchanged witness"),
            witness_before
        );
    }

    fn request(counter: &str, amount: u64) -> SpendRequest<'_> {
        SpendRequest::new(counter, amount)
    }

    fn synthetic_history(count: u64) -> Vec<u8> {
        let header = r#"{"hallpass_ledger":1,"pass_id":"test"}"#;
        let mut bytes = format!("{header}\n").into_bytes();
        let mut tail = Digest::of(header.as_bytes());
        for seq in 1..=count {
            let line = serde_json::json!({"seq":seq,"time":"2026-11-20T09:00:00Z","counter":"calls","n":1,"digest":Digest::of(b"pass").to_string(),"note":null,"prev":tail.to_string()}).to_string();
            tail = Digest::of(line.as_bytes());
            bytes.extend_from_slice(line.as_bytes());
            bytes.push(b'\n');
        }
        bytes
    }

    proptest::proptest! {
        #[test]
        fn streaming_summary_matches_collected_history(count in 0u64..50) {
            let bytes = synthetic_history(count);
            let path = Path::new("synthetic");
            let full = parse_ledger(path, bytes.as_slice(), "test", true, Some(count / 2)).expect("full");
            let summary = parse_ledger(path, bytes.as_slice(), "test", false, Some(count / 2)).expect("summary");
            proptest::prop_assert_eq!(full.tally, summary.tally);
            proptest::prop_assert_eq!(full.tail, summary.tail);
            proptest::prop_assert_eq!(full.prefix, summary.prefix);
            proptest::prop_assert_eq!(summary.entries.len(), 0);
        }
    }

    #[test]
    fn summary_retains_no_per_event_storage_at_scale() {
        for count in [10_000, 100_000] {
            let bytes = synthetic_history(count);
            let summary = parse_ledger(
                Path::new("synthetic"),
                bytes.as_slice(),
                "test",
                false,
                Some(count / 2),
            )
            .expect("summary");
            assert_eq!(summary.entries.capacity(), 0);
            assert_eq!(summary.adoptions.capacity(), 0);
            assert_eq!(summary.tally.spent.len(), 1);
            let largest_line = bytes
                .split(|b| *b == b'\n')
                .map(<[u8]>::len)
                .max()
                .unwrap_or(0);
            eprintln!(
                "events={count} input_bytes={} largest_line={} old_input_plus_hash_bytes={} retained_entry_capacity={} retained_adoption_capacity={} counters={}",
                bytes.len(),
                largest_line,
                bytes.len()
                    + (usize::try_from(count).expect("bounded count") + 1)
                        * std::mem::size_of::<Digest>(),
                summary.entries.capacity(),
                summary.adoptions.capacity(),
                summary.tally.spent.len()
            );
        }
    }

    #[test]
    fn archive_checkpoint_and_recovery_walkthrough() {
        let (dir, path, state) = setup();
        let archive = dir.path().join("archive");
        fs::create_dir(&archive).expect("archive");
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).expect("private");
        let original = fs::read(&path).expect("pass");
        let digest = crate::archive_pass(&path, &archive).expect("archive pass");
        ok(&path, &state, "calls", 4);
        let ledger = ledger_path(&path);
        let older = fs::read(&ledger).expect("ledger");
        let (checkpoint, _) =
            export_checkpoint(&load(&path).expect("load"), &state).expect("checkpoint");
        fs::write(
            &path,
            format!(
                "{}\n# changed\n",
                String::from_utf8(original.clone()).expect("utf8")
            ),
        )
        .expect("edit");
        ok(&path, &state, "calls", 2);
        let witness_path = state
            .witness_path(&checkpoint.pass_id)
            .expect("witness path");
        let before = fs::read(&witness_path).expect("witness");
        assert_eq!(
            verify_checkpoint(&ledger, &checkpoint).expect("verify"),
            CheckpointStatus::Extended(1)
        );
        assert_eq!(fs::read(&witness_path).expect("witness"), before);
        assert_eq!(
            crate::retrieve_pass(&archive, digest).expect("retrieve"),
            original
        );
        fs::write(&ledger, older).expect("restore");
        let preview = preview_adopt(&path, &state).expect("preview");
        assert_eq!(preview.carried["calls"], 2);
        let outcome = adopt_guarded(&path, "restored backup", NOW, &state, Some(&preview.token))
            .expect("adopt");
        assert_eq!(outcome.totals["calls"], 6);
        assert_eq!(
            verify_checkpoint(&ledger, &checkpoint).expect("verify"),
            CheckpointStatus::Extended(1)
        );
    }

    #[test]
    fn guarded_preview_carries_and_rejects_stale_state() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 4);
        let ledger = ledger_path(&path);
        let old = fs::read(&ledger).expect("older ledger");
        ok(&path, &state, "calls", 2);
        fs::write(&ledger, old).expect("restore");
        let preview = preview_adopt(&path, &state).expect("preview");
        assert_eq!(preview.present["calls"], 4);
        assert_eq!(preview.carried["calls"], 2);
        assert_eq!(preview.totals["calls"], 6);
        let applied = adopt_guarded(
            &path,
            "restore old ledger",
            NOW,
            &state,
            Some(&preview.token),
        )
        .expect("adopt");
        assert_eq!(applied.totals, preview.totals);
        let before = fs::read(&ledger).expect("ledger");
        assert!(adopt_guarded(&path, "again", NOW, &state, Some(&preview.token)).is_err());
        assert_eq!(fs::read(&ledger).expect("ledger"), before);
    }

    #[test]
    fn concurrent_summary_reader_and_writer_agree_after_completion() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                for _ in 0..5 {
                    ok(&path, &state, "calls", 1);
                }
            });
            let reader = scope.spawn(|| {
                for _ in 0..50 {
                    let loaded = load(&path).expect("pass");
                    let summary = read_summary(&loaded, &state).expect("summary");
                    assert!(summary.tally.spent("calls") >= 1);
                }
            });
            writer.join().expect("writer");
            reader.join().expect("reader");
        });
        let loaded = load(&path).expect("pass");
        assert_eq!(
            read_summary(&loaded, &state).expect("summary").tally,
            read_ledger(&loaded, &state).expect("full").tally
        );
    }

    #[test]
    fn preview_cases_are_read_only_and_reject_bad_evidence() {
        let (dir, path, state) = setup();
        let ledger = ledger_path(&path);
        assert!(preview_adopt(&path, &state).is_err());
        assert!(!ledger.exists());
        assert!(!state.path().expect("path").exists());
        ok(&path, &state, "calls", 1);
        assert!(preview_adopt(&path, &state).is_err());
        let id = load(&path).expect("pass").pass.id;
        let witness_path = state.witness_path(&id).expect("witness");
        let earlier_witness = fs::read(&witness_path).expect("witness");
        let earlier_ledger = fs::read(&ledger).expect("ledger");
        ok(&path, &state, "calls", 1);
        let latest_witness = fs::read(&witness_path).expect("witness");
        fs::write(&witness_path, &earlier_witness).expect("rewind witness");
        assert!(
            preview_adopt(&path, &state).is_err(),
            "valid extension is not adoptable"
        );
        fs::write(&witness_path, &latest_witness).expect("restore witness");
        let fresh = StateDir::new(dir.path().join("fresh"));
        let no_witness = preview_adopt(&path, &fresh).expect("no witness");
        assert_eq!(no_witness.case, AdoptCase::NoWitness);
        assert!(!fresh.path().expect("path").exists());
        fs::write(&ledger, &earlier_ledger).expect("restore ledger");
        let changed = preview_adopt(&path, &state).expect("changed");
        assert_eq!(changed.case, AdoptCase::LedgerChanged);
        assert_eq!(changed.carried["calls"], 1);
        fs::remove_file(&ledger).expect("remove");
        let missing = preview_adopt(&path, &state).expect("missing");
        assert_eq!(missing.case, AdoptCase::LedgerMissing);
        assert!(!ledger.exists());
        fs::write(&ledger, b"corrupt\n").expect("corrupt");
        assert!(preview_adopt(&path, &state).is_err());
        fs::write(&ledger, &earlier_ledger).expect("restore");
        fs::write(&witness_path, b"broken").expect("bad witness");
        assert!(preview_adopt(&path, &state).is_err());
        assert_eq!(fs::read(&ledger).expect("ledger"), earlier_ledger);
        assert_eq!(fs::read(&witness_path).expect("witness"), b"broken");
    }

    #[test]
    fn both_modes_find_middle_damage_before_matching_tail() {
        let bytes = synthetic_history(3);
        let mut lines: Vec<Vec<u8>> = bytes
            .split_inclusive(|b| *b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        let tail = Digest::of(lines[3].strip_suffix(b"\n").expect("newline"));
        let middle = String::from_utf8(lines[1].clone())
            .expect("utf8")
            .replace("2026-11-20", "2026-11-21");
        lines[1] = middle.into_bytes();
        let corrupt = lines.concat();
        for collect in [false, true] {
            let result = parse_ledger(
                Path::new("synthetic"),
                corrupt.as_slice(),
                "test",
                collect,
                Some(3),
            );
            assert!(matches!(result, Err(Error::LedgerCorrupt { line: 3, .. })));
        }
        assert_eq!(
            tail,
            Digest::of(lines[3].strip_suffix(b"\n").expect("newline"))
        );
    }

    #[test]
    fn adoption_preview_rejects_unwritable_evidence_without_mutation() {
        let (dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        let ledger = ledger_path(&path);
        let ledger_bytes = fs::read(&ledger).expect("ledger");
        let fresh = StateDir::new(dir.path().join("fresh"));
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o400)).expect("mode");
        assert!(preview_adopt(&path, &fresh).is_err());
        assert!(!fresh.path().expect("state").exists());
        assert_eq!(fs::read(&ledger).expect("ledger"), ledger_bytes);
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("mode");
        let old = fs::read(&ledger).expect("ledger");
        ok(&path, &state, "calls", 1);
        fs::write(&ledger, &old).expect("restore");
        let witness = state.witness_path("acme-2026-11").expect("witness");
        let witness_bytes = fs::read(&witness).expect("witness");
        let state_path = state.path().expect("path");
        fs::set_permissions(state_path, fs::Permissions::from_mode(0o500)).expect("mode");
        let result = preview_adopt(&path, &state);
        fs::set_permissions(state_path, fs::Permissions::from_mode(0o700)).expect("mode");
        assert!(result.is_err());
        assert_eq!(fs::read(&ledger).expect("ledger"), old);
        assert_eq!(fs::read(&witness).expect("witness"), witness_bytes);
        fs::remove_file(&ledger).expect("remove");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).expect("mode");
        let result = preview_adopt(&path, &state);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("mode");
        assert!(result.is_err());
        assert!(!ledger.exists());
        assert_eq!(fs::read(&witness).expect("witness"), witness_bytes);
    }

    #[test]
    fn missing_ledger_guard_rejects_changed_pass_without_creation() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        let ledger = ledger_path(&path);
        fs::remove_file(&ledger).expect("remove");
        let preview = preview_adopt(&path, &state).expect("preview");
        let mut bytes = fs::read(&path).expect("pass");
        bytes.extend_from_slice(b"\n# changed\n");
        fs::write(&path, bytes).expect("edit");
        assert!(adopt_guarded(&path, "restore", NOW, &state, Some(&preview.token)).is_err());
        assert!(!ledger.exists());
    }

    #[test]
    fn checkpoint_verifies_exact_extended_and_corrupt_suffix() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        ok(&path, &state, "calls", 1);
        let loaded = load(&path).expect("pass");
        let (checkpoint, corroborated) = export_checkpoint(&loaded, &state).expect("checkpoint");
        assert!(corroborated);
        let ledger = ledger_path(&path);
        let old = fs::read(&ledger).expect("read");
        assert_eq!(
            verify_checkpoint(&ledger, &checkpoint).expect("verify"),
            CheckpointStatus::Exact
        );
        ok(&path, &state, "calls", 1);
        assert_eq!(
            verify_checkpoint(&ledger, &checkpoint).expect("verify"),
            CheckpointStatus::Extended(1)
        );
        let mut corrupt = fs::read(&ledger).expect("read");
        corrupt.pop();
        fs::write(&ledger, corrupt).expect("write");
        assert!(verify_checkpoint(&ledger, &checkpoint).is_err());
        fs::write(&ledger, &old).expect("restore");
        let mut foreign = checkpoint.clone();
        foreign.pass_id = "another-id".to_owned();
        assert_eq!(
            verify_checkpoint(&ledger, &foreign).expect("valid foreign ledger"),
            CheckpointStatus::Foreign
        );
        let mut bad_suffix = fs::read(&ledger).expect("read");
        bad_suffix.extend_from_slice(b"{broken}\n");
        fs::write(&ledger, bad_suffix).expect("damage");
        assert!(matches!(
            verify_checkpoint(&ledger, &foreign),
            Err(Error::LedgerCorrupt { line: 4, .. })
        ));
        fs::write(&ledger, old).expect("restore");
        let mut wrong = checkpoint;
        wrong.hash = Digest::of(b"different").to_string();
        assert_eq!(
            verify_checkpoint(&ledger, &wrong).expect("verify"),
            CheckpointStatus::Mismatch
        );
    }

    #[test]
    fn summary_matches_full_history_and_rejects_damage() {
        let (_dir, path, state) = setup();
        ok(&path, &state, "calls", 1);
        ok(&path, &state, "calls", 2);
        let loaded = load(&path).expect("load");
        let full = read_ledger(&loaded, &state).expect("full");
        let summary = read_summary(&loaded, &state).expect("summary");
        assert_eq!(summary.tally, full.tally);
        assert_eq!(summary.witness, full.witness);
        assert_eq!(summary.last_time, full.last_time);
        assert_eq!(summary.entries.len(), 0);
        let ledger = ledger_path(&path);
        let mut bytes = fs::read(&ledger).expect("read bytes");
        bytes.pop();
        fs::write(&ledger, bytes).expect("damage");
        assert!(read_summary(&loaded, &state).is_err());
        assert!(read_ledger(&loaded, &state).is_err());
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
    fn a_spend_with_a_target_decides_the_destination_too() {
        let (_dir, path, state) = setup();
        let to = |text: &str| -> Target { text.parse().expect("target") };
        let mut call = request("calls", 1);
        call.target = Some(to("192.0.2.10:5060/udp"));
        let out = spend_in(&path, &call, NOW, &state).expect("spend");
        assert_eq!(out.refusal, None);
        assert_eq!(out.label.as_deref(), Some("sip-edge"));
        assert_eq!((out.spent, out.seq), (1, Some(1)));
        // Without a target there is no label: only the window and the
        // ceiling were checked.
        assert_eq!(ok(&path, &state, "calls", 1).label, None);

        // Every destination refusal refuses the spend and records nothing.
        for (target, want) in [
            ("192.0.2.11:5060/udp", RefusalCode::AddressNotListed),
            ("192.0.2.10:5060/tcp", RefusalCode::PortNotListed),
            ("[::ffff:192.0.2.10]:5060/udp", RefusalCode::EmbeddedIpv4),
        ] {
            let mut call = request("calls", 1);
            call.target = Some(to(target));
            let out = spend_in(&path, &call, NOW, &state).expect("spend");
            let refusal = out.refusal.expect(target);
            assert_eq!(refusal.code, want, "{target}");
            assert!(
                refusal.message.ends_with("Nothing was recorded"),
                "{}",
                refusal.message
            );
            assert_eq!((out.spent, out.seq, out.label), (2, None, None), "{target}");
        }
        // The window is asked for the duration of the work, as in permits.
        let mut late = request("calls", 1);
        late.target = Some(to("192.0.2.10:5060/udp"));
        late.needed = Duration::minutes(10);
        let out = spend_in(&path, &late, datetime!(2026-11-20 16:55 UTC), &state).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::WindowTooShort)
        );
        // The destination is refused before the counter is looked at.
        let mut both = request("bogus", 1);
        both.target = Some(to("192.0.2.11:5060/udp"));
        let out = spend_in(&path, &both, NOW, &state).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::AddressNotListed)
        );
        // A listed target does not get past the ceiling.
        let mut big = request("calls", 5);
        big.target = Some(to("192.0.2.10:5060/udp"));
        let out = spend_in(&path, &big, NOW, &state).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::CeilingReached)
        );
        assert_eq!(view(&path, &state).expect("read").tally.spent("calls"), 2);
    }

    #[test]
    fn a_spend_with_a_target_keeps_to_the_names() {
        let (_dir, path, state) = setup();
        let named = GOOD.replacen(
            "[ceilings]",
            "[[destination]]\nlabel = \"shared\"\naddress = \"198.51.100.7\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"app.example.com\"]\n\n[ceilings]",
            1,
        );
        fs::write(&path, named).expect("write");
        let target: Target = "198.51.100.7:443/tcp".parse().expect("target");
        let app: HostName = "App.Example.com.".parse().expect("name");
        let other: HostName = "other.example.org".parse().expect("name");
        for (name, want) in [
            (None, Some(RefusalCode::NameRequired)),
            (Some(&other), Some(RefusalCode::NameNotListed)),
            (Some(&app), None),
        ] {
            let mut call = request("requests", 1);
            call.target = Some(target);
            call.name = name;
            let out = spend_in(&path, &call, NOW, &state).expect("spend");
            assert_eq!(out.refusal.map(|r| r.code), want, "{name:?}");
        }
        assert_eq!(
            view(&path, &state).expect("read").tally.spent("requests"),
            1
        );
        // A name without a target is a mistake in the request.
        let mut lone = request("requests", 1);
        lone.name = Some(&app);
        assert!(matches!(
            spend_in(&path, &lone, NOW, &state),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn a_destination_removed_from_the_pass_stops_the_next_spend() {
        // The pass is read again under the lock: an edit takes effect for
        // the very next spend, with no second question in between.
        let (_dir, path, state) = setup();
        let mut call = request("calls", 1);
        call.target = Some("192.0.2.10:5060/udp".parse().expect("target"));
        assert_eq!(
            spend_in(&path, &call, NOW, &state).expect("spend").refusal,
            None
        );
        fs::write(&path, GOOD.replace("192.0.2.10", "192.0.2.20")).expect("edit");
        let out = spend_in(&path, &call, NOW, &state).expect("spend");
        assert_eq!(
            out.refusal.map(|r| r.code),
            Some(RefusalCode::AddressNotListed)
        );
        assert_eq!(out.spent, 1);
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
        // Invisible format characters show.
        assert_eq!(display_safe("a\u{200b}b"), "a\\u{200b}b");
        assert_eq!(display_safe("\u{feff}a\u{ad}"), "\\u{feff}a\\u{00ad}");
        assert_eq!(display_safe("t\u{e0065}"), "t\\u{e0065}");
        // So do the other invisible characters and the look-alike spaces;
        // the ASCII space stays a space.
        assert_eq!(display_safe("a\u{34f}b\u{fe0f}"), "a\\u{034f}b\\u{fe0f}");
        assert_eq!(display_safe("\u{3164}x\u{e0100}"), "\\u{3164}x\\u{e0100}");
        assert_eq!(display_safe("a\u{a0}b c\u{2003}"), "a\\u{00a0}b c\\u{2003}");
        // A quote needs no escape outside quotes.
        assert_eq!(display_safe("a\"b"), "a\"b");
    }

    #[test]
    fn describe_disguising_names_the_kind_of_character() {
        for (c, shown) in [
            ('\u{2028}', "a line separator (U+2028)"),
            ('\u{202e}', "a bidirectional text control (U+202E)"),
            ('\u{200b}', "a Unicode format character (U+200B)"),
            ('\u{e0001}', "a Unicode format character (U+E0001)"),
            ('\u{a0}', "a look-alike space (U+00A0)"),
            ('\u{3000}', "a look-alike space (U+3000)"),
            ('\u{34f}', "an invisible character (U+034F)"),
            ('\u{fe0f}', "an invisible character (U+FE0F)"),
            ('\u{e0000}', "an invisible character (U+E0000)"),
        ] {
            assert!(is_disguising(c), "{shown}");
            assert_eq!(describe_disguising(c), shown);
        }
    }

    #[test]
    fn display_quoted_escapes_each_character_once() {
        assert_eq!(display_quoted("plain"), "\"plain\"");
        assert_eq!(display_quoted("q\"uote"), "\"q\\\"uote\"");
        assert_eq!(display_quoted("back\\slash"), "\"back\\\\slash\"");
        assert_eq!(display_quoted("a\u{200b}\n"), "\"a\\u{200b}\\u{000a}\"");
        assert_eq!(display_quoted(""), "\"\"");
    }

    /// Undo [`display_quoted`]: the text between the quotes, with `\"`,
    /// `\\` and `\u{…}` decoded; `None` for anything else.
    fn unquote(shown: &str) -> Option<String> {
        let inner = shown.strip_prefix('"')?.strip_suffix('"')?;
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return None,
                '\\' => match chars.next()? {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'u' => {
                        let rest = chars.as_str().strip_prefix('{')?;
                        let end = rest.find('}')?;
                        out.push(char::from_u32(u32::from_str_radix(&rest[..end], 16).ok()?)?);
                        chars = rest[end + 1..].chars();
                    }
                    _ => return None,
                },
                c => out.push(c),
            }
        }
        Some(out)
    }

    proptest::proptest! {
        #[test]
        fn display_safe_is_one_plain_line(text in ".*") {
            let shown = display_safe(&text);
            proptest::prop_assert!(!shown.chars().any(|c| c.is_control() || is_disguising(c)));
        }

        #[test]
        fn display_quoted_is_one_value_that_decodes_back(text in ".*") {
            let shown = display_quoted(&text);
            proptest::prop_assert!(!shown.chars().any(|c| c.is_control() || is_disguising(c)));
            proptest::prop_assert_eq!(unquote(&shown), Some(text));
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
                assert!(e.to_string().contains("ends at sequence 1"), "{e}");
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
        // where the intact ledger of that id is.
        match spend_in(&other, &request("calls", 1), NOW, &state) {
            Err(e @ Error::LedgerElsewhere(_)) => {
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
            Err(e @ Error::LedgerElsewhere(_)) => {
                assert!(
                    e.to_string()
                        .contains(&ledger_identity(&ledger_path(&other))),
                    "{e}"
                );
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
                Err(Error::LedgerChanged { .. } | Error::LedgerElsewhere(_)) => {}
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
        assert!(v.warnings[0].contains("an allowed spend records one"));
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
