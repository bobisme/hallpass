//! Exact-reference checks for cooperating guarded debit submitters.

use serde::Serialize;
use time::OffsetDateTime;

use super::{Adoption, VerifiedEvent, evidence, refused_spend};
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
    /// Lines after the header (spends, debits and adoptions).
    lines: u64,
    /// The sequence of the first adoption that may have lost references.
    lossy_adoption: Option<u64>,
}

/// Whether the ledger an adoption accepted may lack lines, and so caller
/// references, that hallpass had recorded.
///
/// hallpass writes three kinds of adoption. Without a witness it appends to
/// the ledger as it stands: it records no previous witness and carries
/// nothing, and the hash chain shows that every earlier line is still there.
/// A missing ledger starts a new ledger that carries the witnessed totals,
/// and a changed ledger carries what the witness recorded beyond it. Both
/// record a previous witness of at least one line that the adopted ledger
/// does not hold (that is what made them adoptable), so references on the
/// witnessed lines may be gone even when nothing is carried. A carried
/// amount always stands for lines this ledger does not hold.
fn may_have_lost_references(adoption: &Adoption) -> bool {
    !adoption.carried.is_empty() || adoption.previous.as_ref().is_some_and(|w| w.seq > 0)
}

impl<'a> ReferenceMatches<'a> {
    pub(super) const fn new(reference: Option<&'a str>) -> Self {
        Self {
            reference,
            count: 0,
            sequences: Vec::new(),
            lines: 0,
            lossy_adoption: None,
        }
    }

    pub(super) fn observe(&mut self, event: &VerifiedEvent) {
        let Some(reference) = self.reference else {
            return;
        };
        self.lines += 1;
        if let Some((debit, _)) = evidence::match_reference(event, reference) {
            self.count += 1;
            if self.sequences.len() < evidence::DETAIL_LIMIT {
                self.sequences.push(debit.seq);
            }
        }
        if let VerifiedEvent::Adopt(adoption) = event
            && self.lossy_adoption.is_none()
            && may_have_lost_references(adoption)
        {
            self.lossy_adoption = Some(adoption.seq);
        }
    }

    /// `witnessed` is false when there was no local witness for the ledger.
    pub(super) fn refusal(
        self,
        loaded: &LoadedPass,
        policy: &SpendRequest<'_>,
        now: OffsetDateTime,
        witnessed: bool,
    ) -> Option<(Refusal, ReferenceEvidence)> {
        let reference = self.reference?;
        let (code, message) = if let Some(first) = self.sequences.first() {
            (
                RefusalCode::DuplicateReference,
                format!(
                    "the caller reference already occurs at ledger sequence {first}; reconcile it with your run record"
                ),
            )
        } else if let Some(seq) = self.lossy_adoption {
            (
                RefusalCode::ReferenceInconclusive,
                format!(
                    "cannot establish that the caller reference is new because the adoption at ledger sequence {seq} accepted a ledger that lacks lines hallpass had recorded, so earlier references may be missing from it. This lasts for the rest of this ledger: check the reference against your run record, and spend without --require-new-ref only if that record shows the unit was never submitted"
                ),
            )
        } else if !witnessed && self.lines > 0 {
            (
                RefusalCode::ReferenceInconclusive,
                format!(
                    "cannot establish that the caller reference is new because the ledger has {} line(s) but no local witness, so hallpass cannot tell whether later lines were lost (for example in a partial copy). If this ledger is the complete history (for example it moved here with the pass), run `hallpass adopt {} --reason \"...\"`: the adoption keeps every line and carries nothing, a witness is recorded, and later guarded spends check references against this ledger. Otherwise reconcile the reference with your run record",
                    self.lines,
                    loaded.path.display()
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
