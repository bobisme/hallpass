//! `hallpass doctor FILE --checkpoint CHECKPOINT`: compare the ledger with
//! a retained checkpoint, read only, as `verify-checkpoint` does, and say
//! what the result means for the count.
//!
//! A ledger behind the checkpoint, or holding another history at its
//! sequence, blocks: the ledger and its witness may both be an older copy
//! (a whole-machine restore), and then they agree while entries are lost.

use std::path::Path;

use hallpass::{Checkpoint, CheckpointCover, CheckpointGap, Error, LoadedPass, StateDir};

use super::{Diagnosis, Issue, argv, error_issue, lock_issue, shown};

/// The checkpoint's findings, or the problem it shows.
pub(super) fn findings(
    d: &mut Diagnosis,
    file: &Path,
    loaded: &LoadedPass,
    path: &Path,
    cp: &Checkpoint,
    state: &StateDir,
) {
    let named = hallpass::display_quoted(&shown(path));
    match hallpass::compare_checkpoint(loaded, cp) {
        Err(Error::LockTimeout { path }) => d.block(lock_issue(file, &path)),
        Err(e) => d.block(error_issue(file, state, &e)),
        Ok(CheckpointCover::Holds { added }) => d.find(
            "checkpoint-holds",
            format!(
                "the ledger holds the line the checkpoint {named} commits to (sequence {}){}, so nothing it records is missing",
                cp.seq,
                if added == 0 {
                    String::new()
                } else {
                    format!(", followed by {added} later entries")
                }
            ),
        ),
        Ok(CheckpointCover::Adopted { seq }) => d.find(
            "checkpoint-adopted",
            format!(
                "the adoption at entry {seq} acted on the checkpoint {named} (sequence {}): the ledger was behind it, and the adoption carried what its totals recorded beyond the ledger's",
                cp.seq
            ),
        ),
        Ok(CheckpointCover::Behind(gap)) => d.block(behind_issue(file, path, &named, cp, &gap)),
        Ok(CheckpointCover::Forked { ledger_seq }) => d.block(Issue {
            code: "checkpoint-fork".to_owned(),
            headline: Some(
                "the ledger and a retained checkpoint record different histories".to_owned(),
            ),
            lines: vec![
                format!(
                    "the ledger reaches sequence {} (it ends at {ledger_seq}), but its line there is not the one the checkpoint {named} commits to: from some entry on, the ledger and the checkpoint record different histories of pass `{}` (verify-checkpoint says relation mismatch).",
                    cp.seq, loaded.pass.id
                ),
                "hallpass does not merge two histories, and the entries of the other one are not counted here.".to_owned(),
            ],
            next: None,
            step: no_merge_step(path, cp.seq),
        }),
        Ok(CheckpointCover::Foreign { checkpoint_id }) => d.block(Issue {
            code: "checkpoint-foreign".to_owned(),
            headline: Some("the checkpoint is for another pass".to_owned()),
            lines: vec![format!(
                "the checkpoint {named} is for pass `{checkpoint_id}`, not `{}`, so it shows nothing about this ledger.",
                loaded.pass.id
            )],
            next: None,
            step: format!(
                "Give the checkpoint exported for this pass, then run `hallpass doctor {} --checkpoint CHECKPOINT` again.",
                shown(file)
            ),
        }),
        Ok(_) => {}
    }
}

/// The problem for a ledger that ends before the checkpointed line.
fn behind_issue(
    file: &Path,
    path: &Path,
    named: &str,
    cp: &Checkpoint,
    gap: &CheckpointGap,
) -> Issue {
    let missing = format!(
        "the ledger ends at sequence {}, but the checkpoint {named} commits to sequence {}: the ledger once held entries {} to {}, and they are not here (for example the ledger and the state directory were both restored from an older copy). A spend now counts only what the ledger holds.",
        gap.ledger_seq,
        gap.checkpoint_seq,
        gap.ledger_seq + 1,
        gap.checkpoint_seq
    );
    let Some(recorded) = &gap.recorded else {
        return Issue {
            code: "checkpoint-behind".to_owned(),
            headline: Some(headline(gap)),
            lines: vec![
                missing,
                "The checkpoint records no totals (a hallpass before this one exported it), so it cannot show what the missing entries counted, and an adoption cannot carry them.".to_owned(),
            ],
            next: None,
            step: no_merge_step(path, cp.seq),
        };
    };
    if !gap.above.is_empty() {
        return Issue {
            code: "checkpoint-fork".to_owned(),
            headline: Some(
                "the ledger and a retained checkpoint record different histories".to_owned(),
            ),
            lines: vec![
                missing,
                format!(
                    "But the ledger counts more than the checkpoint records (spent here: {}; in the checkpoint: {}). Counts only grow, so the ledger is not an older copy of the checkpointed history: the two differ, and hallpass does not merge them.",
                    hallpass::totals_text(&gap.above),
                    hallpass::totals_text(recorded)
                ),
            ],
            next: None,
            step: no_merge_step(path, cp.seq),
        };
    }
    let pass = shown(file);
    let cp_file = shown(path);
    Issue {
        code: "checkpoint-behind".to_owned(),
        headline: Some(headline(gap)),
        lines: vec![
            missing,
            format!(
                "The checkpoint records spent: {}; the ledger counts spent: {}. It cannot show what the missing entries were, and its hash does not cover its totals: they are what the checkpoint file says.",
                hallpass::totals_text(recorded),
                hallpass::totals_text(&gap.present)
            ),
        ],
        next: argv([
            "hallpass",
            "adopt",
            &pass,
            "--checkpoint",
            &cp_file,
            "--preview",
        ]),
        step: format!(
            "If a copy of the ledger that holds sequence {seq} is left (`hallpass verify-checkpoint COPY {cp_file}` says exact or extended for it), put it back instead: it keeps the receipts. Otherwise the preview shows an adoption that carries, per counter, what the checkpoint records beyond the ledger ({carry}), so no count goes down, and prints its token. Compare the totals with your run records, then run `hallpass adopt {pass} --checkpoint {cp_file} --reason \"...\" --token TOKEN`. After it, a spend with --require-new-ref is refused as reference-inconclusive until the references that may be in the lost entries are reconciled; doctor then names that command.",
            seq = cp.seq,
            carry = hallpass::totals_text(&gap.carry),
        ),
    }
}

fn headline(gap: &CheckpointGap) -> String {
    format!(
        "the ledger is behind a retained checkpoint: entries {} to {} are missing",
        gap.ledger_seq + 1,
        gap.checkpoint_seq
    )
}

/// The step when hallpass cannot count what the checkpoint shows is lost.
fn no_merge_step(path: &Path, seq: u64) -> String {
    format!(
        "Find a copy of the ledger that holds sequence {seq} (`hallpass verify-checkpoint COPY {}` says exact or extended for it) and put it back beside the pass. If no copy is left, stop spending under this pass and have the owner decide, for example on a new pass with lower ceilings.",
        shown(path)
    )
}
