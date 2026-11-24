//! Replay numerical and mandatory charge terms against archived revisions.
use super::evidence::{
    DETAIL_LIMIT, EvidenceGap, Reverify, RevisionGroup, RevisionTracker, SignatureCheck,
    archive_revision, record_gap, record_revision_gap,
};
use super::{VerifiedEvent, add, check_required_charges, decide_ceiling, visit_view};
use crate::{Digest, Error, LoadedPass, Pass, StateDir};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ChargeMismatch {
    pub seq: u64,
    pub counter: String,
    pub reason: &'static str,
}
#[derive(Default, Debug, Serialize)]
pub struct ChargeMismatches {
    pub count: u64,
    pub details: Vec<ChargeMismatch>,
    pub truncated: bool,
}
#[derive(Debug, Serialize)]
pub struct ChargeAudit {
    pub pass_id: String,
    pub result: &'static str,
    pub checked_debits: u64,
    pub mismatches: ChargeMismatches,
    pub gaps: BTreeMap<&'static str, EvidenceGap>,
    pub revisions: RevisionGroup,
    pub signatures: SignatureCheck,
    pub witness: &'static str,
    pub warnings: Vec<String>,
}
fn mismatch(group: &mut ChargeMismatches, seq: u64, counter: &str, reason: &'static str) {
    group.count += 1;
    if group.details.len() < DETAIL_LIMIT {
        group.details.push(ChargeMismatch {
            seq,
            counter: counter.into(),
            reason,
        });
    } else {
        group.truncated = true;
    }
}
/// Audit recorded charges independently of endpoints or external actions.
///
/// Signature records are read without being verified again, so the result
/// is never `complete` for a revision with a signature record: use
/// [`audit_charges_with`].
///
/// # Errors
/// Returns an error for invalid archive data or failed ledger verification.
pub fn audit_charges(
    loaded: &LoadedPass,
    state: &StateDir,
    directory: &Path,
) -> Result<ChargeAudit, Error> {
    audit_charges_with(loaded, state, directory, None)
}

/// [`audit_charges`], verifying every recorded signature again with
/// `reverify` when it is given, as
/// [`audit_receipts_with`](super::evidence::audit_receipts_with) does.
///
/// # Errors
/// As [`audit_charges`], and any error of `reverify.check`, or a signature
/// or record that changed while it was verified.
pub fn audit_charges_with(
    loaded: &LoadedPass,
    state: &StateDir,
    directory: &Path,
    reverify: Option<Reverify<'_>>,
) -> Result<ChargeAudit, Error> {
    crate::archive::check_directory(directory)?;
    let mut totals = BTreeMap::new();
    let mut cache: Option<(Digest, Option<Pass>)> = None;
    let mut mismatches = ChargeMismatches::default();
    let mut gaps = BTreeMap::new();
    let mut revisions = RevisionTracker::new(directory, reverify);
    let mut checked = 0;
    let mut debits = 0;
    let view = visit_view(loaded, state, false, &mut |event| {
        let (seq, digest, charges): (_, _, Vec<(&str, u64)>) = match event {
            VerifiedEvent::Adopt(a) => {
                if !a.carried.is_empty() {
                    record_gap(&mut gaps, "adoption-carry", a.seq);
                }
                for (counter, amount) in &a.carried {
                    let _ = add(&mut totals, counter, *amount);
                }
                return Ok(());
            }
            // A reference reconciliation charges nothing.
            VerifiedEvent::Reconcile(_) => return Ok(()),
            VerifiedEvent::Spend(s) => (s.seq, s.digest, vec![(&s.counter, s.amount)]),
            VerifiedEvent::Debit(d) => (
                d.seq,
                d.digest,
                d.charges
                    .iter()
                    .map(|c| (c.counter.as_str(), c.amount))
                    .collect(),
            ),
        };
        debits += 1;
        revisions.note(digest, seq, &mut gaps)?;
        if cache.as_ref().is_none_or(|(key, _)| *key != digest) {
            cache = Some((
                digest,
                archive_revision(directory, digest, &loaded.pass.id)?,
            ));
        }
        if let Some(pass) = cache.as_ref().and_then(|(_, p)| p.as_ref()) {
            checked += 1;
            if check_required_charges(pass, |name| charges.iter().any(|(c, _)| *c == name)).is_err()
            {
                for name in &pass.required_counters {
                    if !charges.iter().any(|(c, _)| *c == name) {
                        mismatch(&mut mismatches, seq, name, "required-counter-missing");
                    }
                }
            }
            for (counter, amount) in &charges {
                let spent = totals.get(*counter).copied().unwrap_or(0);
                if let Err(reason) = decide_ceiling(pass, counter, *amount, spent) {
                    mismatch(&mut mismatches, seq, counter, reason.code.as_str());
                }
            }
        } else {
            record_revision_gap(&mut gaps, "archive-missing", seq, digest);
        }
        for (counter, amount) in charges {
            let _ = add(&mut totals, counter, amount);
        }
        Ok(())
    })?;
    let (revisions, signatures) = revisions.report();
    // `complete` needs a signature this audit verified over every revision used.
    let result = if mismatches.count > 0 {
        "mismatch"
    } else if debits == 0 && gaps.is_empty() {
        "empty"
    } else if !gaps.is_empty() || revisions.unverified > 0 {
        "incomplete"
    } else {
        "complete"
    };
    Ok(ChargeAudit {
        pass_id: loaded.pass.id.clone(),
        result,
        checked_debits: checked,
        mismatches,
        gaps,
        revisions,
        signatures,
        witness: view.witness.as_str(),
        warnings: view.warnings,
    })
}
