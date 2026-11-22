//! Exact-reference checks for cooperating guarded debit submitters.

use serde::Serialize;
use time::OffsetDateTime;

use super::{VerifiedEvent, evidence, refused_spend};
use crate::{LoadedPass, Refusal, RefusalCode, SpendRequest, request::check_revision_window};

/// Bounded history from a refused guarded debit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ReferenceEvidence {
    pub caller_ref: String,
    /// Every occurrence, including those beyond the detail limit.
    pub match_count: u64,
    /// The first matching sequences in ledger order.
    pub sequences: Vec<u64>,
    /// Additional matching sequences were omitted.
    pub truncated: bool,
}

pub(super) struct ReferenceMatches<'a> {
    reference: Option<&'a str>,
    count: u64,
    sequences: Vec<u64>,
}

impl<'a> ReferenceMatches<'a> {
    pub(super) const fn new(reference: Option<&'a str>) -> Self {
        Self {
            reference,
            count: 0,
            sequences: Vec::new(),
        }
    }

    pub(super) fn observe(&mut self, event: &VerifiedEvent) {
        if let Some(reference) = self.reference
            && let Some((debit, _)) = evidence::match_reference(event, reference)
        {
            self.count += 1;
            if self.sequences.len() < evidence::DETAIL_LIMIT {
                self.sequences.push(debit.seq);
            }
        }
    }

    pub(super) fn refusal(
        self,
        loaded: &LoadedPass,
        policy: &SpendRequest<'_>,
        now: OffsetDateTime,
        adopted: bool,
        unanchored: bool,
    ) -> Option<(Refusal, ReferenceEvidence)> {
        let reference = self.reference?;
        let (code, message) = if let Some(first) = self.sequences.first() {
            (
                RefusalCode::DuplicateReference,
                format!(
                    "the caller reference already occurs at ledger sequence {first}; reconcile it with your run record"
                ),
            )
        } else if adopted || unanchored {
            let detail = if adopted {
                "the ledger contains an adoption, which may have lost earlier references"
            } else {
                "the nonempty ledger has no local witness"
            };
            (
                RefusalCode::ReferenceInconclusive,
                format!(
                    "cannot establish that the caller reference is new because {detail}; reconcile it with your run record"
                ),
            )
        } else {
            return None;
        };
        check_revision_window(loaded, policy.expect_digest, now, policy.needed).ok()?;
        Some((
            refused_spend(code, message),
            ReferenceEvidence {
                caller_ref: reference.to_owned(),
                match_count: self.count,
                truncated: self.count > self.sequences.len() as u64,
                sequences: self.sequences,
            },
        ))
    }
}
