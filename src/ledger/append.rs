//! Appending a line to the locked ledger, and rolling a failed append back.
//!
//! Every writer (a spend, a debit, a debit batch, an adoption, a reference
//! reconciliation) appends through [`append_line`] while it holds both writer
//! locks, and before it updates the witness. So when the append fails, no
//! other hallpass process has read or written the ledger since, and the
//! witness still describes the ledger as it was before.
//!
//! An append that would take the ledger past the file size limit
//! (`RLIMIT_FSIZE`) is refused before anything is written, since the kernel
//! would otherwise end the process with `SIGXFSZ` partway through the line
//! ([`crate::files::write_within_size_limit`]). It then takes the first case
//! below, with nothing to cut back.
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
use std::io;
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
        io::Write::write_all(file, &bytes[..kept.min(bytes.len())])?;
        return Err(io::Error::from(io::ErrorKind::StorageFull));
    }
    crate::files::write_within_size_limit(file, bytes)
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
    use crate::files::size_limit_fault::LIMIT;
    use crate::{
        Charge, Error, SpendChargesBatchRequest, SpendChargesRequest, SpendRequest, StateDir,
        WitnessStatus, adopt, drop_torn_tail, ledger_path, load, preview_drop_torn_tail,
        read_ledger, reconcile_references, spend_charges_batch_in, spend_in,
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

    /// Run `f` with a file size limit of `limit` bytes on this thread.
    fn with_limit<T>(limit: u64, f: impl FnOnce() -> T) -> T {
        LIMIT.set(Some(limit));
        let result = f();
        LIMIT.set(None);
        result
    }

    fn assert_refused_at_the_limit(failed: &Error) {
        assert!(matches!(failed, Error::AppendRolledBack { .. }), "{failed}");
        assert_eq!(failed.code(), "ledger-append-failed");
        assert!(
            failed.to_string().contains("file size limit of"),
            "{failed}"
        );
    }

    #[test]
    fn an_append_past_the_file_size_limit_is_refused_before_writing() {
        let (_dir, path, state) = setup();
        let ledger = ledger_path(&path);
        let before = fs::read(&ledger).expect("ledger");
        let len = u64::try_from(before.len()).expect("len");
        let failed = with_limit(len + 10, || spend(&path, &state)).expect_err("limit");
        assert_refused_at_the_limit(&failed);
        assert_eq!(fs::read(&ledger).expect("ledger"), before);
        assert_eq!(view(&path, &state).witness, WitnessStatus::Matches);
        // A limit the whole line fits under is no obstacle.
        let next = with_limit(len + 4096, || spend(&path, &state)).expect("next spend");
        assert_eq!(next.seq, Some(2));
    }

    #[test]
    fn a_batch_past_the_file_size_limit_is_refused_whole() {
        let (_dir, path, state) = setup();
        let ledger = ledger_path(&path);
        let before = fs::read(&ledger).expect("ledger");
        let charges = [Charge {
            counter: "calls",
            amount: 1,
        }];
        let units: Vec<SpendChargesRequest<'_>> = ["unit/1", "unit/2"]
            .iter()
            .map(|reference| {
                let mut unit = SpendChargesRequest::new(&charges);
                unit.caller_ref = Some(reference);
                unit.require_new_ref = true;
                unit
            })
            .collect();
        let batch = SpendChargesBatchRequest::new(&units);
        // Measure the batch on a twin ledger, then leave room for all of it
        // but one byte: its first line would fit, the whole batch does not.
        let (_twin_dir, twin, twin_state) = setup();
        let twin_before = fs::metadata(ledger_path(&twin)).expect("twin").len();
        spend_charges_batch_in(&twin, &batch, NOW, &twin_state).expect("twin batch");
        let grown = fs::metadata(ledger_path(&twin)).expect("twin").len() - twin_before;
        let limit = u64::try_from(before.len()).expect("len") + grown - 1;
        let failed = with_limit(limit, || spend_charges_batch_in(&path, &batch, NOW, &state))
            .expect_err("limit");
        assert_refused_at_the_limit(&failed);
        assert_eq!(fs::read(&ledger).expect("ledger"), before);
        assert_eq!(view(&path, &state).tally.spent("calls"), 1);
    }

    #[test]
    fn an_adoption_and_a_reconciliation_past_the_file_size_limit_are_refused() {
        let (_dir, path, state) = setup();
        let ledger = ledger_path(&path);
        let older = fs::read(&ledger).expect("ledger");
        spend(&path, &state).expect("second spend");
        fs::write(&ledger, &older).expect("restore");
        let failed = with_limit(u64::try_from(older.len()).expect("len"), || {
            adopt(&path, "restored an older ledger", NOW, &state)
        })
        .expect_err("limit");
        assert_refused_at_the_limit(&failed);
        assert_eq!(fs::read(&ledger).expect("ledger"), older);

        let adopted = adopt(&path, "restored an older ledger", NOW, &state).expect("adopt");
        let adopted_bytes = fs::read(&ledger).expect("ledger");
        let failed = with_limit(u64::try_from(adopted_bytes.len()).expect("len"), || {
            reconcile_references(
                &path,
                adopted.adoption.seq,
                &["unit/1".to_owned()],
                "from the run log",
                NOW,
                &state,
            )
        })
        .expect_err("limit");
        assert_refused_at_the_limit(&failed);
        assert_eq!(fs::read(&ledger).expect("ledger"), adopted_bytes);
    }

    #[test]
    fn a_new_ledger_past_the_file_size_limit_is_not_created() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("p.toml");
        fs::write(&path, crate::pass::tests::GOOD).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let state = StateDir::new(dir.path().join("home/state"));
        fs::create_dir(dir.path().join("home")).expect("home");
        let failed = with_limit(10, || spend(&path, &state)).expect_err("limit");
        assert!(
            failed.to_string().contains("file size limit of 10 bytes"),
            "{failed}"
        );
        let mut left: Vec<_> = fs::read_dir(dir.path())
            .expect("dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["home", "p.toml"], "no ledger and no temporary file");
        assert_eq!(spend(&path, &state).expect("spend").seq, Some(1));
    }

    #[test]
    fn a_repair_copy_past_the_file_size_limit_changes_nothing() {
        let (dir, path, state) = setup();
        let ledger = ledger_path(&path);
        fault::WRITE.set(Some(20));
        fault::TRUNCATE.set(true);
        spend(&path, &state).expect_err("short write");
        let torn = fs::read(&ledger).expect("ledger");
        let preview = preview_drop_torn_tail(&path, &state).expect("preview");
        // The copy of the 20 removed bytes does not fit under 10 bytes.
        let failed =
            with_limit(10, || drop_torn_tail(&path, &state, &preview.token)).expect_err("limit");
        assert!(
            failed.to_string().contains("file size limit of 10 bytes"),
            "{failed}"
        );
        assert_eq!(fs::read(&ledger).expect("ledger"), torn);
        let copies = fs::read_dir(dir.path())
            .expect("dir")
            .filter(|e| {
                e.as_ref()
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".torn-")
            })
            .count();
        assert_eq!(copies, 0, "no copy is left behind");
        drop_torn_tail(&path, &state, &preview.token).expect("repair");
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
