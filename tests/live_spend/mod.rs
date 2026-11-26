//! A debit recorded through the library at a fixed instant, without the
//! test clock, so that the ledger holds real-clock lines.
//!
//! The command line marks every line it writes under
//! `HALLPASS_UNSAFE_TEST_CLOCK` as a test-clock line, and an audit of such a
//! ledger is never `complete` (bn-2mm). The audit tests that need a
//! `complete` audit at a pinned date record their debits here instead. The
//! line is the one `spend --charge requests=N --to TARGET --record-target`
//! writes, without the marker.

use std::path::Path;

use hallpass::time::{OffsetDateTime, format_description::well_known::Rfc3339};
use hallpass::{Charge, HostName, SpendChargesRequest, StateDir, Target};

/// Debit `requests=n` from the pass at `pass` for `to`
/// (`ADDRESS:PORT/PROTOCOL`, optionally `@NAME`), recording the target, at
/// `at` (RFC 3339). `state` is the test's `XDG_STATE_HOME`. Returns the
/// ledger sequence of the debit.
pub fn spend(pass: &Path, state: &Path, to: &str, n: u64, at: &str) -> u64 {
    let (target, name) = to
        .split_once('@')
        .map_or((to, None), |(target, name)| (target, Some(name)));
    let target: Target = target.parse().expect("target");
    let name = name.map(|name| name.parse::<HostName>().expect("host name"));
    let charges = [Charge {
        counter: "requests",
        amount: n,
    }];
    let mut request = SpendChargesRequest::new(&charges);
    request.policy.target = Some(target);
    request.policy.name = name.as_ref();
    request.record_targets = true;
    let now = OffsetDateTime::parse(at, &Rfc3339).expect("RFC 3339 time");
    let outcome =
        hallpass::spend_charges_in(pass, &request, now, &StateDir::new(state.join("hallpass")))
            .expect("spend");
    assert!(outcome.refusal.is_none(), "{:?}", outcome.refusal);
    outcome.seq.expect("a recorded debit has a sequence")
}
