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
//! let outcome = hallpass::spend(
//!     path,
//!     &SpendRequest {
//!         counter: "calls",
//!         amount: 1,
//!         note: Some("first call"),
//!         expect_digest: Some(loaded.digest),
//!         needed: time::Duration::minutes(2),
//!     },
//!     now,
//! )?;
//! if let Some(refusal) = outcome.refusal {
//!     println!("do not proceed: {refusal}");
//! }
//! # Ok::<(), hallpass::Error>(())
//! ```
//!
//! Everything that decides is pure and takes `now` from the caller; only
//! [`load`], [`tally`], [`spend`] and [`write_template`] touch the file
//! system.

mod address;
mod decision;
mod error;
mod files;
mod ledger;
mod pass;
mod ports;
mod template;

pub use address::{
    AddressError, Network, Protocol, Target, embedded_ipv4, parse_address, parse_network,
};
pub use decision::{Decision, Refusal, RefusalCode, WindowState, span, stamp};
pub use error::Error;
pub use files::{Digest, LoadedPass, MAX_PASS_BYTES, load};
pub use ledger::{MAX_NOTE, SpendOutcome, SpendRequest, Tally, ledger_path, spend, tally};
pub use pass::{
    Approval, Destination, FORMAT_VERSION, IPV4_CAP, IPV4_FLOOR, IPV6_CAP, IPV6_FLOOR, MAX_CEILING,
    MAX_COUNTERS, MAX_DESTINATIONS, Pass, Problem, is_counter_name,
};
pub use ports::PortSet;
pub use template::{TEMPLATE, write_template};
pub use time;
