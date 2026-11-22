//! hallpass: the written permission slip for an authorized test.
//!
//! A *pass* records who approved a test, which literal network destinations
//! may be touched, from when until when, and how much. This library reads a
//! pass, decides whether something is permitted at a given instant, and
//! keeps a ledger so that ceilings hold across processes.
//!
//! hallpass is advisory: a tool must ask it and obey the answer. It does not
//! stop a tool that does not ask.
//!
//! ```no_run
//! use std::path::Path;
//! use hallpass::{Decision, SpendRequest, Target, time};
//!
//! let path = Path::new("engagement.pass.toml");
//! let loaded = hallpass::load(path)?;
//! let now = time::OffsetDateTime::now_utc();
//! let target: Target = "192.0.2.10:5060/udp".parse().map_err(hallpass::Error::Usage)?;
//! match loaded.pass.permits(&target, now, time::Duration::ZERO) {
//!     Decision::Allowed { label } => println!("allowed by {label}"),
//!     Decision::Refused(refusal) => println!("refused: {refusal}"),
//! }
//! // One call that decides the destination, the window and the ceiling
//! // together, and records the spend only if all three allow it.
//! let mut request = SpendRequest::new("calls", 1);
//! request.target = Some(target);
//! request.note = Some("first call");
//! request.expect_digest = Some(loaded.digest);
//! request.needed = time::Duration::minutes(2);
//! let outcome = hallpass::spend(path, &request, now)?;
//! if let Some(refusal) = outcome.refusal {
//!     println!("do not send: {refusal}");
//! }
//! # Ok::<(), hallpass::Error>(())
//! ```
//!
//! [`Pass::permits`] evaluates a target against a loaded approval at a supplied
//! instant. [`permits_with_clock_in`] also verifies accounting evidence and
//! samples the clock after reading it.
//!
//! Besides the ledger beside the pass, [`spend`] keeps a *witness* of the
//! ledger's last line in the user's state directory ([`StateDir`]), so that
//! a lost, replaced or rewound ledger is refused instead of counting from
//! zero. [`spend`] finds that directory from the environment; [`spend_in`]
//! takes it explicitly (tests should always point it at a temporary
//! directory).

mod address;
mod archive;
mod decision;
mod error;
mod files;
mod ledger;
mod literal;
mod name;
mod pass;
mod ports;
mod request;
pub use request::{
    MAX_TARGETS, NamedTarget, PermitOutcome, TargetRefusal, permits_in, permits_with_clock_in,
};
pub mod review;
mod template;
mod witness;

pub use address::{
    AddressError, Ipv6Transition, Network, Protocol, Target, embedded_ipv4, ipv6_transition,
    parse_address, parse_network,
};
pub use archive::{archive_pass, retrieve_pass};
pub use decision::{Decision, Refusal, RefusalCode, WindowState, span, stamp};
pub use error::{Error, MissingLedger};
pub use files::{Digest, LoadedPass, MAX_PASS_BYTES, load, load_with_bytes};
pub use ledger::{
    AdoptCase, AdoptOutcome, AdoptPreview, Adoption, Charge, ChargeOutcome, Checkpoint,
    CheckpointStatus, DebitCharge, DebitReceipt, LedgerDebit, LedgerEntry, LedgerView,
    MAX_CALLER_REF, MAX_NOTE, RecordedTarget, SpendChargesOutcome, SpendChargesRequest,
    SpendOutcome, SpendRequest, Tally, WitnessStatus, adopt, adopt_guarded, display_safe,
    export_checkpoint, ledger_path, preview_adopt, preview_spend_in, preview_spend_with_clock_in,
    read_ledger, read_summary, spend, spend_charges, spend_charges_in, spend_charges_with_clock_in,
    spend_in, spend_with_clock_in, tally, verify_checkpoint,
};
pub use ledger::{capacity, evidence, scenario};
pub use name::{HostName, MAX_NAMES};
pub use pass::{
    Approval, Destination, FORMAT_VERSION, IPV4_CAP, IPV4_FLOOR, IPV6_CAP, IPV6_FLOOR, MAX_CEILING,
    MAX_COUNTERS, MAX_DESTINATIONS, Pass, Problem, is_counter_name,
};
pub use ports::PortSet;
pub use template::{TEMPLATE, write_template};
pub use time;
pub use witness::{StateDir, Witnessed, totals_text};

/// Compiles the Rust example of `docs/INTEGRATING.md` as a documentation
/// test, so the document cannot show code that no longer builds.
#[cfg(doctest)]
#[doc = include_str!("../docs/INTEGRATING.md")]
pub struct IntegratingDoc;
