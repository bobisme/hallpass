//! Appending a line to the locked ledger, and rolling a failed append back.
//!
//! Every writer (a spend, a debit, a debit batch, an adoption, a reference
//! reconciliation) appends through [`append_line`] while it holds both writer
//! locks, and before it updates the witness. So when the append fails, no
//! other hallpass process has read or written the ledger since, and the
//! witness still describes the ledger as it was before.
//!
//! What a failure leaves:
//!
//! - The write fails (a short write from a full disk or a file size limit,
//!   or any other write error): the line was never complete, and it was never
//!   synced. The ledger is cut back to its length before the write and that
//!   is synced. When both succeed and the length reads back as before, the
//!   ledger holds exactly its previous bytes: an append only adds bytes at
//!   the end, so the bytes before that length were never touched. The error
//!   is [`Error::AppendRolledBack`]: nothing was recorded.
//! - The rollback fails too: [`Error::AppendUncertain`]. A part of a line may
//!   be left at the end; `hallpass repair --drop-torn-tail` can remove it.
//! - The write succeeds but the sync fails: [`Error::AppendUncertain`], and
//!   the line is left in place. After a failed sync the page cache no longer
//!   tells what is on disk: the line may be there, partly there or not at
//!   all, and a second sync can report success without writing it. Cutting
//!   the line off would not make the outcome sure either, and a line that
//!   stays counts against the ceiling, which is the safe side.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::error::Error;

/// Append `bytes` (one or more whole lines, each with its line end) to the
/// locked `file` and sync it; on a failed write, roll the file back as the
/// module documentation says.
pub(super) fn append_line(
    file: &mut File,
    path: &Path,
    bytes: &[u8],
    what: &str,
) -> Result<(), Error> {
    let before = file.metadata().map_err(|e| Error::io(path, &e))?.len();
    if let Err(write_error) = write(file, bytes) {
        return Err(roll_back(file, path, before, what, &write_error));
    }
    sync(file).map_err(|e| Error::AppendUncertain {
        path: path.to_path_buf(),
        event: what.to_owned(),
        detail: format!(
            "the line was written in full, but syncing it to disk failed: {e}; the line stays in the ledger and counts"
        ),
    })
}

/// Cut `file` back to `before` bytes and sync it. The error to return says
/// whether that worked.
fn roll_back(file: &File, path: &Path, before: u64, what: &str, write_error: &io::Error) -> Error {
    let undone = truncate(file, before)
        .and_then(|()| file.sync_all())
        .and_then(|()| file.metadata())
        .map(|m| m.len());
    match undone {
        Ok(len) if len == before => Error::AppendRolledBack {
            path: path.to_path_buf(),
            event: what.to_owned(),
            detail: write_error.to_string(),
        },
        Ok(len) => Error::AppendUncertain {
            path: path.to_path_buf(),
            event: what.to_owned(),
            detail: format!(
                "the write failed ({write_error}), and after cutting the ledger back to {before} bytes it has {len}"
            ),
        },
        Err(e) => Error::AppendUncertain {
            path: path.to_path_buf(),
            event: what.to_owned(),
            detail: format!(
                "the write failed ({write_error}), and cutting the ledger back to its length before the write failed too ({e}); its last line may be cut short"
            ),
        },
    }
}

fn write(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if let Some(kept) = fault::WRITE.take() {
        file.write_all(&bytes[..kept.min(bytes.len())])?;
        return Err(io::Error::from(io::ErrorKind::StorageFull));
    }
    file.write_all(bytes)
}

fn sync(file: &File) -> io::Result<()> {
    #[cfg(test)]
    if fault::SYNC.take() {
        return Err(io::Error::other("injected sync failure"));
    }
    file.sync_data()
}

fn truncate(file: &File, len: u64) -> io::Result<()> {
    #[cfg(test)]
    if fault::TRUNCATE.take() {
        return Err(io::Error::other("injected truncate failure"));
    }
    file.set_len(len)
}

/// Faults the unit tests inject into the next append on this thread.
#[cfg(test)]
pub(super) mod fault {
    use std::cell::Cell;

    thread_local! {
        /// Write only this many bytes of the next append, then fail it.
        pub(in crate::ledger) static WRITE: Cell<Option<usize>> = const { Cell::new(None) };
        /// Fail the next sync of an append.
        pub(in crate::ledger) static SYNC: Cell<bool> = const { Cell::new(false) };
        /// Fail the next rollback's truncate.
        pub(in crate::ledger) static TRUNCATE: Cell<bool> = const { Cell::new(false) };
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use time::OffsetDateTime;
    use time::macros::datetime;

    use super::fault;
    use crate::{
        Charge, Error, SpendChargesBatchRequest, SpendChargesRequest, SpendRequest, StateDir,
        WitnessStatus, drop_torn_tail, ledger_path, load, preview_drop_torn_tail, read_ledger,
        spend_charges_batch_in, spend_in,
    };

    const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

    fn setup() -> (tempfile::TempDir, PathBuf, StateDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.toml");
        fs::write(&path, crate::pass::tests::GOOD).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let state = StateDir::new(dir.path().join("state"));
        spend_in(&path, &SpendRequest::new("calls", 1), NOW, &state).expect("first spend");
        (dir, path, state)
    }

    fn spend(path: &std::path::Path, state: &StateDir) -> Result<crate::SpendOutcome, Error> {
        spend_in(path, &SpendRequest::new("calls", 1), NOW, state)
    }

    fn view(path: &std::path::Path, state: &StateDir) -> crate::LedgerView {
        read_ledger(&load(path).expect("pass"), state).expect("ledger")
    }

    #[test]
    fn a_short_write_is_rolled_back_and_records_nothing() {
        let (_dir, path, state) = setup();
        let before = fs::read(ledger_path(&path)).expect("ledger");
        fault::WRITE.set(Some(20));
        let failed = spend(&path, &state).expect_err("short write");
        assert!(matches!(failed, Error::AppendRolledBack { .. }), "{failed}");
        assert_eq!(failed.code(), "ledger-append-failed");
        assert_eq!(fs::read(ledger_path(&path)).expect("ledger"), before);
        let seen = view(&path, &state);
        assert_eq!(seen.witness, WitnessStatus::Matches);
        assert_eq!(seen.tally.spent("calls"), 1);
        let next = spend(&path, &state).expect("next spend");
        assert_eq!(next.seq, Some(2));
    }

    #[test]
    fn a_failed_batch_write_is_rolled_back_whole() {
        let (_dir, path, state) = setup();
        let before = fs::read(ledger_path(&path)).expect("ledger");
        let charges = [Charge {
            counter: "calls",
            amount: 1,
        }];
        let units: Vec<SpendChargesRequest<'_>> = ["unit/1", "unit/2", "unit/3"]
            .iter()
            .map(|reference| {
                let mut unit = SpendChargesRequest::new(&charges);
                unit.caller_ref = Some(reference);
                unit.require_new_ref = true;
                unit
            })
            .collect();
        let batch = SpendChargesBatchRequest::new(&units);
        fault::WRITE.set(Some(150));
        let failed = spend_charges_batch_in(&path, &batch, NOW, &state).expect_err("short write");
        assert!(matches!(failed, Error::AppendRolledBack { .. }), "{failed}");
        assert_eq!(fs::read(ledger_path(&path)).expect("ledger"), before);
        assert_eq!(view(&path, &state).witness, WitnessStatus::Matches);
        let outcome = spend_charges_batch_in(&path, &batch, NOW, &state).expect("batch");
        assert!(outcome.refusal.is_none());
        assert_eq!(view(&path, &state).tally.spent("calls"), 4);
    }

    #[test]
    fn a_failed_sync_leaves_the_line_and_is_uncertain() {
        let (_dir, path, state) = setup();
        fault::SYNC.set(true);
        let failed = spend(&path, &state).expect_err("sync");
        assert!(matches!(failed, Error::AppendUncertain { .. }), "{failed}");
        assert!(failed.to_string().contains("written in full"), "{failed}");
        // The line stays and counts; the witness is one line behind.
        let seen = view(&path, &state);
        assert_eq!(seen.witness, WitnessStatus::Extended { added: 1 });
        assert_eq!(seen.tally.spent("calls"), 2);
    }

    #[test]
    fn a_failed_rollback_is_uncertain_and_the_torn_line_can_be_dropped() {
        let (_dir, path, state) = setup();
        let ledger = ledger_path(&path);
        let before = fs::read(&ledger).expect("ledger");
        fault::WRITE.set(Some(20));
        fault::TRUNCATE.set(true);
        let failed = spend(&path, &state).expect_err("short write");
        assert!(matches!(failed, Error::AppendUncertain { .. }), "{failed}");
        assert!(failed.to_string().contains("cut short"), "{failed}");
        let torn = fs::read(&ledger).expect("ledger");
        assert_eq!(torn.len(), before.len() + 20);
        assert!(matches!(
            read_ledger(&load(&path).expect("pass"), &state),
            Err(Error::LedgerCorrupt { last: true, .. })
        ));

        let preview = preview_drop_torn_tail(&path, &state).expect("preview");
        assert_eq!((preview.seq, preview.witness_seq), (1, 1));
        assert_eq!(preview.removed_bytes, 20);
        assert_eq!(
            fs::read(&ledger).expect("ledger"),
            torn,
            "a preview changes nothing"
        );
        let repaired = drop_torn_tail(&path, &state, &preview.token).expect("repair");
        assert_eq!(fs::read(&ledger).expect("ledger"), before);
        let copy = repaired.copy.expect("copy");
        assert_eq!(fs::read(&copy).expect("copy"), &torn[before.len()..]);
        assert_eq!(view(&path, &state).witness, WitnessStatus::Matches);
        assert_eq!(spend(&path, &state).expect("next spend").seq, Some(2));
    }
}
