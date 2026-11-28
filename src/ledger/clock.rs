//! The test-clock marker on ledger lines.
//!
//! A line written inside [`with_test_clock`] carries `"test_clock":true`,
//! just before its `prev`, so the marker is in the hash chain like every
//! other field. A line without it was written at the time the caller gave as
//! real. A ledger holds lines of one kind only: a writer refuses to add a
//! line of the other kind ([`check_kind`]), so a rehearsal never runs on in a
//! live ledger and a live spend never runs on in a rehearsal ledger.

use std::cell::Cell;
use std::path::Path;

use super::{LedgerView, Parsed};
use crate::Error;

thread_local! {
    static TEST_CLOCK: Cell<bool> = const { Cell::new(false) };
}

/// Run `f` with every ledger line it writes on this thread marked as
/// written under a test clock (`"test_clock":true`).
///
/// The `hallpass` binary calls it only when it honours
/// `HALLPASS_UNSAFE_TEST_CLOCK`, which a release build never does. A
/// library caller that passes a clock other than the real one (a test, a
/// rehearsal) calls it around the writes, so that those lines are marked.
///
/// A ledger holds lines of one kind: inside this scope, a write to a ledger
/// that holds unmarked lines fails with [`Error::LedgerClockMix`], and so
/// does a write outside it to a ledger that holds marked lines. Audits
/// report each marked line as the gap `test-clock-entry`, so an audit of
/// such a ledger is never `complete`.
///
/// The scope holds on this thread only, for the duration of `f`; the scope
/// before it is restored afterwards, even if `f` panics.
pub fn with_test_clock<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_CLOCK.set(self.0);
        }
    }
    let _restore = Restore(TEST_CLOCK.replace(true));
    f()
}

/// The marker for a line written now: `Some(true)` inside
/// [`with_test_clock`], `None` (no field) otherwise.
pub(super) fn marker() -> Option<bool> {
    TEST_CLOCK.get().then_some(true)
}

/// Refuse a write that would mix test-clock and real-clock lines in the
/// ledger at `path`.
pub(super) fn check_kind(path: &Path, parsed: &Parsed) -> Result<(), Error> {
    check_seqs(path, parsed.test_clock_seq, parsed.real_clock_seq)
}

/// Refuse in a preview what the write would refuse ([`check_kind`]).
pub(super) fn check_view(view: &LedgerView) -> Result<(), Error> {
    check_seqs(&view.path, view.test_clock_from, view.real_clock_from)
}

impl LedgerView {
    /// [`Error::LedgerClockMix`] when a write on this thread, in or out of
    /// [`with_test_clock`], would mix test-clock and real-clock lines in this
    /// ledger, as a spend, an adoption or a reconciliation would refuse it.
    /// Reads only.
    ///
    /// # Errors
    /// [`Error::LedgerClockMix`].
    pub fn check_clock_kind(&self) -> Result<(), Error> {
        check_view(self)
    }

    /// The latest time recorded in the ledger, for the clock-rollback
    /// warning: `None` when the ledger holds only test-clock lines and this
    /// thread uses the real clock, since a rehearsal's times say nothing about
    /// the real clock.
    pub(super) fn rollback_latest(&self) -> Option<(time::OffsetDateTime, u64)> {
        let rehearsal_only = self.test_clock_from.is_some() && self.real_clock_from.is_none();
        if rehearsal_only && marker().is_none() {
            return None;
        }
        self.latest_time
    }
}

/// `test` and `real`: the first test-clock and real-clock entry, if any.
fn check_seqs(path: &Path, test: Option<u64>, real: Option<u64>) -> Result<(), Error> {
    let conflict = if TEST_CLOCK.get() {
        real.map(|seq| (seq, false))
    } else {
        test.map(|seq| (seq, true))
    };
    match conflict {
        None => Ok(()),
        Some((seq, rehearsal)) => Err(Error::LedgerClockMix {
            path: path.to_owned(),
            seq,
            rehearsal,
        }),
    }
}

/// Check the marker read from a line: absent or `true`. `false` is not a
/// spelling hallpass writes, so a line with it is not valid.
pub(super) const fn read_marker(marker: Option<bool>) -> Result<bool, &'static str> {
    match marker {
        None => Ok(false),
        Some(true) => Ok(true),
        Some(false) => Err(
            "the test_clock marker is false, but hallpass writes it only as true, or not at all",
        ),
    }
}
