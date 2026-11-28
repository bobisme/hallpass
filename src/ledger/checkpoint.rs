//! Retained checkpoints: reading one exactly as `verify-checkpoint` does,
//! and what one shows about the ledger beside a pass, for
//! `doctor --checkpoint` and `adopt --checkpoint`.
//!
//! A checkpoint commits to one ledger line by its sequence and hash, and
//! records the totals the ledger counted through that line. A ledger that
//! holds the line verifies against it. A ledger that ends before the line
//! cannot: the checkpoint then shows that the ledger once held more
//! entries, and its totals say what the checkpointed history counted. The
//! hash does not cover the totals, and nothing authenticates the checkpoint
//! beyond the operator who kept it.
//!
//! A shorter ledger is not always an older copy of the checkpointed
//! history: after a whole-machine restore, a worker may spend before anyone
//! compares the ledger with the checkpoint, and then the ledger's last
//! entries are new ones at the sequences the lost ones had. So an adoption
//! takes as shared only the ledger lines the checkpoint proves are its own:
//! the lines through the last of its line hashes (`anchors`) that the
//! ledger holds. Every later ledger line counts as new. The carry is the
//! checkpoint's totals less what the shared lines count, so the result is at
//! least the checkpoint's totals plus every spend since the restore. When a
//! line the checkpoint cannot place was in fact an older copy of a
//! checkpointed one, it counts twice: on the safe side for spending. Times
//! never prove a line shared, because a restored clock may run behind; a
//! line later than the checkpoint's latest time only proves the ledger has
//! entries the checkpoint does not show.
//!
//! The same placement holds for a ledger that reaches the checkpoint's
//! sequence with another line there: after a restore, a worker that spent
//! more than the entries lost carries the ledger to or past the
//! checkpoint's sequence with lines of its own. The anchors prove the same
//! shared lines as for a shorter ledger, and an adoption carries the same
//! way. With no shared anchor, or a checkpoint without anchors, no line is
//! shared and every ledger line counts as new: a count that may be too
//! high, never too low.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{
    Checkpoint, Parsed, exists, inspect_candidate, inspect_candidate_checkpoints, ledger_path,
};
use crate::error::Error;
use crate::files::{Digest, LoadedPass};
use crate::pass::MAX_CEILING;
use crate::witness::{quote_path, totals_text, valid_totals};

/// The largest checkpoint file hallpass reads, in bytes.
pub const MAX_CHECKPOINT_BYTES: usize = 65536;

/// The most line hashes (`anchors`) a checkpoint may hold. An export holds
/// at most 16 and two per power of two below its sequence (144).
const MAX_ANCHORS: usize = 256;

/// The lines just before a checkpoint's own that it records the hash of.
const RECENT_ANCHORS: u64 = 16;

/// The sequences whose line hashes a checkpoint at `seq` records: the 16
/// lines just before it, and the lines a power of two after the header or
/// before it. A ledger restored from any older copy then holds an anchor no
/// further back than about as many lines as it lost, so few of its lines
/// are left that the checkpoint cannot place. A sequence inside a debit
/// batch line has no line of its own and no hash.
pub(super) fn anchor_seqs(seq: u64) -> BTreeSet<u64> {
    let mut wanted: BTreeSet<u64> = (1..=RECENT_ANCHORS)
        .filter_map(|back| seq.checked_sub(back))
        .collect();
    let mut step = 1_u64;
    while step < seq {
        wanted.insert(step);
        wanted.insert(seq - step);
        let Some(next) = step.checked_mul(2) else {
            break;
        };
        step = next;
    }
    wanted.remove(&0);
    wanted
}

/// Check the fields of a checkpoint, and return the hash it commits to.
pub(super) fn check(checkpoint: &Checkpoint) -> Result<Digest, Error> {
    if checkpoint.version != 1 || !crate::pass::is_identifier(&checkpoint.pass_id) {
        return Err(Error::Usage(
            "invalid checkpoint version or pass ID".to_owned(),
        ));
    }
    let hash = checkpoint.hash.parse::<Digest>().map_err(Error::Usage)?;
    if checkpoint.totals.as_ref().is_some_and(|t| !valid_totals(t)) {
        return Err(Error::Usage(format!(
            "invalid checkpoint totals: each must be a counter name with a whole number from 0 to {MAX_CEILING}; export the checkpoint again with `hallpass checkpoint`"
        )));
    }
    if checkpoint.latest.is_some() && latest(checkpoint).is_none() {
        return Err(Error::Usage(
            "invalid checkpoint latest time: it must be an RFC 3339 time such as 2026-11-28T09:00:00Z; export the checkpoint again with `hallpass checkpoint`".to_owned(),
        ));
    }
    if let Some(anchors) = &checkpoint.anchors
        && (anchors.len() > MAX_ANCHORS
            || anchors.iter().any(|(seq, hash)| {
                *seq == 0 || *seq >= checkpoint.seq || hash.parse::<Digest>().is_err()
            }))
    {
        return Err(Error::Usage(format!(
            "invalid checkpoint anchors: at most {MAX_ANCHORS}, each a sequence from 1 to below the checkpoint's own with a line hash; export the checkpoint again with `hallpass checkpoint`"
        )));
    }
    Ok(hash)
}

/// The checkpoint's latest time, if it records a valid one.
fn latest(checkpoint: &Checkpoint) -> Option<OffsetDateTime> {
    let text = checkpoint.latest.as_deref()?;
    if text.len() > 64 {
        return None;
    }
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// Read a retained checkpoint file as `verify-checkpoint` reads it.
///
/// The file holds the JSON that `hallpass --format json checkpoint`
/// prints, or the checkpoint object alone, at most
/// [`MAX_CHECKPOINT_BYTES`]. It is opened under the trusted signers
/// file's owner and mode rule and symbolic link handling
/// ([`crate::open_trusted_checkpoint`]): a file that group or others can
/// write is refused.
///
/// # Errors
/// [`Error::Usage`] for a file that cannot be read, is too large, or is not
/// a valid checkpoint; as [`crate::open_trusted_checkpoint`] for one that
/// cannot be opened or is not trusted.
pub fn read_checkpoint(path: &Path) -> Result<Checkpoint, Error> {
    let file = crate::files::open_trusted_checkpoint(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Usage(format!("cannot read checkpoint: {e}")))?;
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::Usage("checkpoint too large".to_owned()));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Usage(format!("invalid checkpoint JSON: {e}")))?;
    let value = value.get("checkpoint").cloned().unwrap_or(value);
    let checkpoint: Checkpoint = serde_json::from_value(value)
        .map_err(|e| Error::Usage(format!("invalid checkpoint: {e}")))?;
    check(&checkpoint)?;
    Ok(checkpoint)
}

/// What a ledger that ends before a checkpoint's line holds, against it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckpointGap {
    /// The ledger's last sequence (0 for a missing ledger).
    pub ledger_seq: u64,
    /// The checkpoint's sequence.
    pub checkpoint_seq: u64,
    /// The ledger's totals.
    pub present: BTreeMap<String, u64>,
    /// The checkpoint's totals; `None` for a checkpoint that records none.
    pub recorded: Option<BTreeMap<String, u64>>,
    /// The last ledger sequence the checkpoint proves is its own history:
    /// the ledger's lines through it are the checkpointed ones, by a line
    /// hash the checkpoint records (0: only the header). When it is
    /// `ledger_seq`, the ledger is an older copy of the checkpointed history
    /// and entries `ledger_seq + 1` to `checkpoint_seq` are missing.
    pub shared: u64,
    /// The ledger's totals through `shared`.
    pub shared_spent: BTreeMap<String, u64>,
    /// The first ledger line the checkpoint proves is not its own, if any:
    /// a line hash it records differs there, or the line's time is later
    /// than every checkpointed line's. That line and every later one were
    /// written after the histories parted (for example by a spend after a
    /// whole-machine restore).
    pub new_from: Option<u64>,
    /// Whether the checkpoint records line hashes; one from a hallpass
    /// before they were exported does not, and then proves no line shared.
    pub anchored: bool,
    /// Per counter, what the checkpoint records beyond what the shared
    /// lines count: what an adoption carries. Every ledger line after
    /// `shared` counts as new on top of it.
    pub carry: BTreeMap<String, u64>,
    /// The counters the shared lines count more of than the checkpoint
    /// records, with what they count. Counts only grow, so a checkpoint
    /// that records less than its own lines count is not one hallpass
    /// carries from.
    pub above: BTreeMap<String, u64>,
    /// The hash of the ledger's last line when it was compared (`None` for
    /// a missing ledger): an adoption refuses a ledger that changed since.
    tail: Option<Digest>,
}

impl CheckpointGap {
    /// Whether the ledger is proved an older copy of the checkpointed
    /// history: every line of it is a checkpointed one.
    #[must_use]
    pub const fn exact(&self) -> bool {
        self.shared == self.ledger_seq
    }

    /// Whether the ledger reaches the checkpoint's sequence, with another
    /// line there than the one the checkpoint commits to
    /// (`verify-checkpoint` says relation mismatch).
    #[must_use]
    pub const fn reaches(&self) -> bool {
        self.ledger_seq >= self.checkpoint_seq
    }

    /// One line for the doctor's headline: what is missing, as far as the
    /// checkpoint proves it.
    #[must_use]
    pub fn headline(&self) -> String {
        if self.exact() {
            format!(
                "the ledger is behind a retained checkpoint: entries {} to {} are missing",
                self.ledger_seq + 1,
                self.checkpoint_seq
            )
        } else if self.reaches() {
            format!(
                "the ledger has entries a retained checkpoint does not show: checkpointed entries after sequence {} are missing",
                self.shared
            )
        } else if self.new_from.is_some() {
            format!(
                "the ledger is behind a retained checkpoint and has entries it does not show: checkpointed entries after sequence {} are missing",
                self.shared
            )
        } else {
            format!(
                "the ledger is behind a retained checkpoint: checkpointed entries after sequence {} are missing, and its entries {} to {} cannot be placed",
                self.shared,
                self.shared + 1,
                self.ledger_seq
            )
        }
    }

    /// What the checkpoint proves about the ledger's lines, and how an
    /// adoption counts them, in sentences.
    #[must_use]
    pub fn placement(&self) -> String {
        let (m, n, k) = (self.ledger_seq, self.checkpoint_seq, self.shared);
        if self.exact() {
            if m == 0 {
                return format!(
                    "The ledger holds no entries, so all checkpointed entries, 1 to {n}, are missing."
                );
            }
            return format!(
                "The checkpoint's line hashes prove that the ledger's {} checkpointed: the ledger is an older copy of the checkpointed history, and its {} missing.",
                span(1, m, "are", "is"),
                span(m + 1, n, "are", "is")
            );
        }
        let shared = if k == 0 {
            "no ledger entry is proved a checkpointed one".to_owned()
        } else {
            format!("the ledger's {} checkpointed", span(1, k, "are", "is"))
        };
        let mut text = match (self.new_from, self.anchored) {
            (Some(f), anchored) => {
                let (part, unknown) = if f > k + 1 {
                    (
                        format!("after a sequence from {k} to {}", f - 1),
                        format!(
                            " Its {} either: the checkpoint has no line hash to tell.",
                            span(k + 1, f - 1, "may be", "may be")
                        ),
                    )
                } else if k == 0 {
                    ("from the first entry".to_owned(), String::new())
                } else {
                    (format!("after sequence {k}"), String::new())
                };
                let shown = if anchored {
                    format!(
                        "The checkpoint's line hashes and latest time show that {shared}, but that"
                    )
                } else {
                    "The checkpoint records no line hashes before its own (a hallpass before this one exported it), so no ledger entry is proved a checkpointed one. Its own line hash and latest time show that".to_owned()
                };
                format!(
                    "{shown} the ledger's entry {f} is not a checkpointed one: the two histories part {part}, and the ledger's {} written since (for example by a spend after a whole-machine restore).{unknown} The checkpointed entries after the point where they part are missing.",
                    span(f, m, "were", "was")
                )
            }
            (None, false) => format!(
                "The checkpoint records no line hashes (a hallpass before this one exported it), so it cannot show whether the ledger's {} older copies of checkpointed ones or spends since a restore.",
                span(1, m, "are", "is")
            ),
            (None, true) => format!(
                "The checkpoint's line hashes show that {shared}, but it has no line hash to tell whether the ledger's {} older copies of checkpointed ones or spends since a restore.",
                span(k + 1, m, "are", "is")
            ),
        };
        let twice = self.new_from.map_or(m, |f| f - 1) > k;
        let _ = write!(
            text,
            " An adoption counts the ledger's {} new, so no spend since a restore is lost{}.",
            span(k + 1, m, "as", "as"),
            if twice {
                ", but a spend from before it may count twice"
            } else {
                ""
            }
        );
        text
    }
}

/// `entries FROM to TO` and the plural verb, or `entry FROM` and the
/// singular one.
fn span(from: u64, to: u64, plural: &str, single: &str) -> String {
    if from == to {
        format!("entry {from} {single}")
    } else {
        format!("entries {from} to {to} {plural}")
    }
}

/// What a retained checkpoint shows about the ledger beside a pass.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckpointCover {
    /// The ledger holds the checkpointed line, followed by `added` more
    /// entries (`verify-checkpoint` says exact or extended): nothing the
    /// checkpoint commits to is missing.
    Holds {
        /// Entries after the checkpointed one.
        added: u64,
    },
    /// The adoption at `seq` in this ledger acted on this checkpoint.
    Adopted {
        /// The adoption's sequence.
        seq: u64,
    },
    /// The ledger ends before the checkpointed line (`verify-checkpoint`
    /// says relation shorter).
    Behind(CheckpointGap),
    /// The ledger reaches the checkpointed sequence with another line there
    /// (`verify-checkpoint` says relation mismatch), placed by the
    /// checkpoint's line hashes as a shorter ledger is: the lines it proves
    /// its own, and the carry that counts every other line as new.
    Parted(CheckpointGap),
    /// Another history at the checkpointed sequence, with nothing placed.
    /// [`compare_checkpoint`] no longer returns it: it returns
    /// [`CheckpointCover::Parted`] instead.
    Forked {
        /// The ledger's last sequence.
        ledger_seq: u64,
    },
    /// The checkpoint is for another pass.
    Foreign {
        /// The pass id the checkpoint names.
        checkpoint_id: String,
    },
}

/// Compare the ledger beside the pass with a retained checkpoint, read only
/// (a shared lock on the ledger). A missing ledger is one with no entries.
///
/// # Errors
/// A checkpoint that [`read_checkpoint`] would refuse; a ledger that cannot
/// be read, is damaged, or is another pass's.
pub fn compare_checkpoint(
    loaded: &LoadedPass,
    checkpoint: &Checkpoint,
) -> Result<CheckpointCover, Error> {
    let hash = check(checkpoint)?;
    if checkpoint.pass_id != loaded.pass.id {
        return Ok(CheckpointCover::Foreign {
            checkpoint_id: checkpoint.pass_id.clone(),
        });
    }
    let path = ledger_path(&loaded.path);
    let mut wanted: BTreeSet<u64> = checkpoint
        .anchors
        .iter()
        .flatten()
        .map(|(s, _)| *s)
        .collect();
    wanted.insert(checkpoint.seq);
    let (parsed, found) = if exists(&path)? {
        let (parsed, found) = inspect_candidate_checkpoints(&path, &wanted)?;
        (Some(parsed.for_pass(&path, &loaded.pass.id)?), found)
    } else {
        (None, BTreeMap::new())
    };
    if let Some(seq) = adopted(parsed.as_ref(), checkpoint, hash) {
        return Ok(CheckpointCover::Adopted { seq });
    }
    let ledger_seq = parsed.as_ref().map_or(0, |p| p.seq);
    if ledger_seq < checkpoint.seq {
        return gap(&path, parsed.as_ref(), &found, checkpoint).map(CheckpointCover::Behind);
    }
    let holds = parsed.as_ref().map_or(checkpoint.seq == 0, |_| {
        found.get(&checkpoint.seq) == Some(&hash)
    });
    if holds {
        Ok(CheckpointCover::Holds {
            added: ledger_seq - checkpoint.seq,
        })
    } else {
        gap(&path, parsed.as_ref(), &found, checkpoint).map(CheckpointCover::Parted)
    }
}

/// The latest adoption in `parsed` that acted on `checkpoint`, if any.
fn adopted(parsed: Option<&Parsed>, checkpoint: &Checkpoint, hash: Digest) -> Option<u64> {
    parsed?
        .checkpoint_adoptions
        .iter()
        .rev()
        .find(|(_, seq, h)| *seq == checkpoint.seq && *h == hash)
        .map(|(at, _, _)| *at)
}

/// Place a ledger that ends before the checkpoint's line, or holds another
/// line at its sequence: the lines the checkpoint proves are its own, the
/// first it proves is not, and the carry that counts every other line as
/// new.
fn gap(
    path: &Path,
    parsed: Option<&Parsed>,
    found: &BTreeMap<u64, Digest>,
    checkpoint: &Checkpoint,
) -> Result<CheckpointGap, Error> {
    let present = parsed.map_or_else(BTreeMap::new, |p| p.tally.spent.clone());
    let ledger_seq = parsed.map_or(0, |p| p.seq);
    // The anchors in order: the ledger holds the checkpointed history
    // through each one whose hash it has at that sequence (a hash covers
    // every line before it), and parts from it before the first it lacks.
    let mut shared = 0;
    let mut new_from = None;
    for (seq, text) in checkpoint.anchors.iter().flatten() {
        if *seq > ledger_seq {
            break;
        }
        if text
            .parse::<Digest>()
            .is_ok_and(|h| found.get(seq) == Some(&h))
        {
            shared = *seq;
        } else {
            new_from = Some(*seq);
            break;
        }
    }
    // A ledger that reaches the checkpoint's sequence without its line
    // there parts from it at or before that line: the checkpoint's own hash
    // is one more anchor the ledger does not have.
    if ledger_seq >= checkpoint.seq
        && found.get(&checkpoint.seq).copied() != checkpoint.hash.parse::<Digest>().ok()
    {
        new_from = Some(new_from.map_or(checkpoint.seq, |f| f.min(checkpoint.seq)));
    }
    // A line later than every checkpointed line is not one of them, and
    // neither is any line after it.
    if let (Some(limit), Some((time, seq))) = (latest(checkpoint), parsed.and_then(|p| p.latest))
        && time > limit
        && seq > shared
    {
        new_from = Some(new_from.map_or(seq, |f| f.min(seq)));
    }
    let shared_spent = match parsed {
        _ if shared == 0 => BTreeMap::new(),
        Some(p) if shared == p.seq => p.tally.spent.clone(),
        Some(p) => {
            // The totals through the last shared line, from a second scan
            // that must find the same ledger.
            let again = inspect_candidate(path, Some(shared))?;
            let hash = found.get(&shared).copied();
            match again.prefix_spent {
                Some(spent)
                    if again.seq == p.seq
                        && again.tail == p.tail
                        && again.prefix.map(|(_, h)| h) == hash =>
                {
                    spent
                }
                _ => {
                    return Err(Error::Usage(format!(
                        "the ledger {} changed while hallpass compared it with the checkpoint; run the command again",
                        quote_path(path)
                    )));
                }
            }
        }
        None => BTreeMap::new(),
    };
    let mut carry = BTreeMap::new();
    let mut above = BTreeMap::new();
    if let Some(recorded) = &checkpoint.totals {
        for (counter, n) in recorded {
            let have = shared_spent.get(counter).copied().unwrap_or(0);
            if *n > have {
                carry.insert(counter.clone(), n - have);
            }
        }
        for (counter, n) in &shared_spent {
            if *n > recorded.get(counter).copied().unwrap_or(0) {
                above.insert(counter.clone(), *n);
            }
        }
    }
    Ok(CheckpointGap {
        ledger_seq,
        checkpoint_seq: checkpoint.seq,
        present,
        recorded: checkpoint.totals.clone(),
        shared,
        shared_spent,
        new_from,
        anchored: checkpoint.anchors.is_some(),
        carry,
        above,
        tail: parsed.map(|p| p.tail),
    })
}

/// The checkpoint an adoption acts on: the file named and what it holds.
#[derive(Clone, Debug)]
pub(super) struct Given {
    pub(super) file: std::path::PathBuf,
    pub(super) checkpoint: Checkpoint,
}

impl Given {
    /// Read the file, as [`read_checkpoint`] does.
    pub(super) fn read(file: &Path) -> Result<Self, Error> {
        Ok(Self {
            file: file.to_owned(),
            checkpoint: read_checkpoint(file)?,
        })
    }

    /// The gap this checkpoint shows the ledger has, or the refusal that
    /// says why an adoption cannot act on it.
    pub(super) fn behind(&self, loaded: &LoadedPass) -> Result<CheckpointGap, Error> {
        let cover = compare_checkpoint(loaded, &self.checkpoint)?;
        let pass = loaded.path.display();
        let file = self.file.display();
        let cp = &self.checkpoint;
        let id = &loaded.pass.id;
        let ledger = quote_path(ledger_path(&loaded.path));
        let refuse = |why: String| Error::Usage(format!("--checkpoint: {why}"));
        match cover {
            CheckpointCover::Behind(gap) | CheckpointCover::Parted(gap)
                if gap.recorded.is_none() =>
            {
                Err(refuse(format!(
                    "the checkpoint {} records no totals (a hallpass before this one exported it), so it shows that entries of pass `{id}` up to sequence {} are missing, but not what they counted; nothing was recorded. {}",
                    quote_path(&self.file),
                    gap.checkpoint_seq,
                    no_merge_step(&file, cp.seq)
                )))
            }
            CheckpointCover::Behind(gap) | CheckpointCover::Parted(gap)
                if !gap.above.is_empty() =>
            {
                Err(refuse(format!(
                    "the entries 1 to {} of {ledger} are checkpointed ones by the checkpoint's line hashes, but they count more than the checkpoint records for its sequence {} (spent in them: {}; in the checkpoint: {}). Counts only grow, so the checkpoint's totals do not belong to its line hashes, and hallpass does not carry from it. Nothing was recorded. {}",
                    gap.shared,
                    gap.checkpoint_seq,
                    totals_text(&gap.above),
                    totals_text(gap.recorded.as_ref().unwrap_or(&BTreeMap::new())),
                    no_merge_step(&file, cp.seq)
                )))
            }
            CheckpointCover::Behind(gap) | CheckpointCover::Parted(gap) => Ok(gap),
            CheckpointCover::Holds { added } => Err(refuse(format!(
                "{ledger} holds the line the checkpoint commits to (sequence {}){}, so nothing it records is missing and there is nothing to adopt from it; nothing was recorded. Run `hallpass doctor {pass}` to see whether anything else needs an adoption",
                cp.seq,
                if added == 0 {
                    String::new()
                } else {
                    format!(" and {added} later entries")
                }
            ))),
            CheckpointCover::Adopted { seq } => Err(refuse(format!(
                "the adoption at entry {seq} of {ledger} already acted on this checkpoint (sequence {}), so there is nothing left to carry from it; nothing was recorded. Run `hallpass doctor {pass} --checkpoint {file}`",
                cp.seq
            ))),
            CheckpointCover::Forked { ledger_seq } => Err(refuse(format!(
                "{ledger} reaches sequence {} (it ends at {ledger_seq}), but its line there is not the one the checkpoint commits to: the ledger and the checkpoint record different histories of pass `{id}`, and hallpass does not merge them. Nothing was recorded. {}",
                cp.seq,
                no_merge_step(&file, cp.seq)
            ))),
            CheckpointCover::Foreign { checkpoint_id } => Err(refuse(format!(
                "the checkpoint {} is for pass `{checkpoint_id}`, not `{id}`; nothing was recorded. Give the checkpoint exported for this pass",
                quote_path(&self.file)
            ))),
        }
    }

    /// Under the ledger lock: refuse unless the scanned ledger is still the
    /// one `gap` was found for (the same last line, so the same lines).
    pub(super) fn still_behind(
        &self,
        gap: &CheckpointGap,
        parsed: &Parsed,
        pass_path: &Path,
    ) -> Result<(), Error> {
        if parsed.seq == gap.ledger_seq && gap.tail.is_none_or(|t| t == parsed.tail()) {
            return Ok(());
        }
        Err(Error::Usage(format!(
            "--checkpoint: the ledger changed while the adoption waited for its lock (it now ends at sequence {}, not {}), so what the checkpoint shows about it must be found again; nothing was recorded. Run `hallpass doctor {} --checkpoint {}` again",
            parsed.seq,
            gap.ledger_seq,
            pass_path.display(),
            self.file.display()
        )))
    }

    /// Raise `carried` to what `gap` carries: the ledger's totals plus it
    /// reach, per counter, the checkpoint's totals plus what the ledger
    /// counts after the lines the checkpoint proves are its own.
    pub(super) fn raise(gap: &CheckpointGap, carried: &mut BTreeMap<String, u64>) {
        for (counter, n) in &gap.carry {
            let carry = carried.entry(counter.clone()).or_insert(0);
            *carry = (*carry).max(*n);
        }
    }

    /// The checkpoint as the adoption line records it: what it commits to
    /// and the totals, without the line hashes and time that placed the
    /// ledger, so that the line keeps the shape older hallpass reads.
    pub(super) fn recorded(&self) -> Checkpoint {
        Checkpoint {
            latest: None,
            anchors: None,
            ..self.checkpoint.clone()
        }
    }
}

/// The next step when a checkpoint shows lost entries that hallpass cannot
/// count: find the checkpointed history, or have the owner decide.
fn no_merge_step(file: &impl std::fmt::Display, seq: u64) -> String {
    format!(
        "Find a copy of the ledger that holds sequence {seq} (`hallpass verify-checkpoint COPY {file}` says exact or extended for it) and put it back beside the pass. If no copy is left, the lost entries are not counted here: stop spending under this pass and have the owner decide, for example on a new pass with lower ceilings"
    )
}
