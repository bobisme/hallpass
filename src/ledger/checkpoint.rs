//! Retained checkpoints: reading one exactly as `verify-checkpoint` does,
//! and what one shows about the ledger beside a pass, for
//! `doctor --checkpoint` and `adopt --checkpoint`.
//!
//! A checkpoint commits to one ledger line by its sequence and hash, and
//! records the totals the ledger counted through that line. A ledger that
//! holds the line verifies against it. A ledger that ends before the line
//! cannot: the checkpoint then shows only that the ledger once held more
//! entries, and its totals say what those entries counted. The hash does
//! not cover the totals, and nothing authenticates the checkpoint beyond
//! the operator who kept it. Carrying its totals only raises a count, so
//! the doubt is on the safe side for spending.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use super::{Checkpoint, Parsed, exists, inspect_candidate, ledger_path};
use crate::error::Error;
use crate::files::{Digest, LoadedPass};
use crate::pass::MAX_CEILING;
use crate::witness::{quote_path, totals_text, valid_totals};

/// The largest checkpoint file hallpass reads, in bytes.
pub const MAX_CHECKPOINT_BYTES: usize = 65536;

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
    Ok(hash)
}

/// Read a retained checkpoint file as `verify-checkpoint` reads it.
///
/// The file holds the JSON that `hallpass --format json checkpoint`
/// prints, or the checkpoint object alone, at most
/// [`MAX_CHECKPOINT_BYTES`]; it is opened without following a symbolic
/// link.
///
/// # Errors
/// [`Error::Usage`] for a file that cannot be read, is too large, or is not
/// a valid checkpoint; as [`crate::open_input`] for one that cannot be
/// opened.
pub fn read_checkpoint(path: &Path) -> Result<Checkpoint, Error> {
    let file = crate::files::open_input(path)?;
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
    /// The checkpoint's sequence: entries after `ledger_seq` up to it are
    /// not in the ledger.
    pub checkpoint_seq: u64,
    /// The ledger's totals.
    pub present: BTreeMap<String, u64>,
    /// The checkpoint's totals; `None` for a checkpoint that records none.
    pub recorded: Option<BTreeMap<String, u64>>,
    /// Per counter, what the checkpoint records beyond the ledger: what an
    /// adoption carries.
    pub carry: BTreeMap<String, u64>,
    /// The counters the ledger counts more of than the checkpoint records,
    /// with the ledger's total. An older copy of the checkpointed history
    /// never does (counts only grow), so it is not one.
    pub above: BTreeMap<String, u64>,
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
    /// (`verify-checkpoint` says relation mismatch): another history.
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
    let parsed = if exists(&path)? {
        Some(inspect_candidate(&path, Some(checkpoint.seq))?.for_pass(&path, &loaded.pass.id)?)
    } else {
        None
    };
    if let Some(seq) = adopted(parsed.as_ref(), checkpoint, hash) {
        return Ok(CheckpointCover::Adopted { seq });
    }
    let ledger_seq = parsed.as_ref().map_or(0, |p| p.seq);
    if ledger_seq < checkpoint.seq {
        return Ok(CheckpointCover::Behind(gap(parsed.as_ref(), checkpoint)));
    }
    let holds = parsed.as_ref().map_or(checkpoint.seq == 0, |p| {
        p.prefix == Some((checkpoint.seq, hash))
    });
    if holds {
        Ok(CheckpointCover::Holds {
            added: ledger_seq - checkpoint.seq,
        })
    } else {
        Ok(CheckpointCover::Forked { ledger_seq })
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

fn gap(parsed: Option<&Parsed>, checkpoint: &Checkpoint) -> CheckpointGap {
    let present = parsed.map_or_else(BTreeMap::new, |p| p.tally.spent.clone());
    let mut carry = BTreeMap::new();
    let mut above = BTreeMap::new();
    if let Some(recorded) = &checkpoint.totals {
        for (counter, n) in recorded {
            let have = present.get(counter).copied().unwrap_or(0);
            if *n > have {
                carry.insert(counter.clone(), n - have);
            }
        }
        for (counter, n) in &present {
            if *n > recorded.get(counter).copied().unwrap_or(0) {
                above.insert(counter.clone(), *n);
            }
        }
    }
    CheckpointGap {
        ledger_seq: parsed.map_or(0, |p| p.seq),
        checkpoint_seq: checkpoint.seq,
        present,
        recorded: checkpoint.totals.clone(),
        carry,
        above,
    }
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
            CheckpointCover::Behind(gap) if gap.recorded.is_none() => Err(refuse(format!(
                "the checkpoint {} records no totals (a hallpass before this one exported it), so it shows that entries {} to {} of pass `{id}` are missing, but not what they counted; nothing was recorded. {}",
                quote_path(&self.file),
                gap.ledger_seq + 1,
                gap.checkpoint_seq,
                no_merge_step(&file, cp.seq)
            ))),
            CheckpointCover::Behind(gap) if !gap.above.is_empty() => Err(refuse(format!(
                "{ledger} ends at sequence {}, before the checkpoint's sequence {}, but it counts more than the checkpoint records (spent here: {}; in the checkpoint: {}). Counts only grow, so the ledger is not an older copy of the checkpointed history: the two histories differ, and hallpass does not merge them. Nothing was recorded. {}",
                gap.ledger_seq,
                gap.checkpoint_seq,
                totals_text(&gap.above),
                totals_text(gap.recorded.as_ref().unwrap_or(&BTreeMap::new())),
                no_merge_step(&file, cp.seq)
            ))),
            CheckpointCover::Behind(gap) => Ok(gap),
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

    /// Under the ledger lock: refuse unless the scanned ledger still ends
    /// before the checkpointed line and no adoption in it acted on it.
    pub(super) fn still_behind(&self, parsed: &Parsed, pass_path: &Path) -> Result<(), Error> {
        let cp = &self.checkpoint;
        let hash = check(cp)?;
        let gap = gap(Some(parsed), cp);
        if parsed.seq < cp.seq && adopted(Some(parsed), cp, hash).is_none() && gap.above.is_empty()
        {
            return Ok(());
        }
        Err(Error::Usage(format!(
            "--checkpoint: the ledger changed while the adoption waited for its lock, and it is no longer behind the checkpoint as it was (it now ends at sequence {}); nothing was recorded. Run `hallpass doctor {} --checkpoint {}` again",
            parsed.seq,
            pass_path.display(),
            self.file.display()
        )))
    }

    /// Raise `carried` so that the ledger's totals `present` plus it reach,
    /// per counter, what the checkpoint records.
    pub(super) fn raise(
        &self,
        present: &BTreeMap<String, u64>,
        carried: &mut BTreeMap<String, u64>,
    ) {
        for (counter, n) in self.checkpoint.totals.iter().flatten() {
            let have = present.get(counter).copied().unwrap_or(0);
            if *n > have {
                let carry = carried.entry(counter.clone()).or_insert(0);
                *carry = (*carry).max(n - have);
            }
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
