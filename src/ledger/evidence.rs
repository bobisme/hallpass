//! Local, read-only reconciliation, receipt auditing and backup comparison.
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{
    Checkpoint, DebitCharge, DebitReceipt, LedgerDebit, RecordedTarget, VerifiedEvent, debit,
    exists, inspect_candidate, rfc3339, visit_view,
};
use crate::{
    Decision, Digest, Error, HostName, LoadedPass, Pass, StateDir, Target, retrieve_pass,
    time::Duration,
};
use std::path::{Path, PathBuf};

/// The first 64 matching receipts, endpoint details per category, or sequences per gap reason are retained.
pub const DETAIL_LIMIT: usize = 64;
/// Maximum number of explicit backup paths per comparison.
pub const MAX_BACKUPS: usize = 32;

#[derive(Debug, Serialize)]
pub struct FoundReceipt {
    pub seq: u64,
    pub time: String,
    pub digest: String,
    pub charges: Vec<DebitCharge>,
    pub targets: Vec<RecordedTarget>,
}

#[derive(Debug, Serialize)]
pub struct ReceiptLookup {
    pub pass_id: String,
    pub caller_ref: String,
    pub result: &'static str,
    pub match_count: u64,
    pub matches: Vec<FoundReceipt>,
    pub truncated: bool,
    pub adoption_count: u64,
    pub witness: &'static str,
    pub warnings: Vec<String>,
}

pub(super) fn match_reference<'a>(
    event: &'a VerifiedEvent,
    reference: &str,
) -> Option<(&'a LedgerDebit, &'a DebitReceipt)> {
    let VerifiedEvent::Debit(debit) = event else {
        return None;
    };
    let receipt = debit.receipt.as_ref()?;
    (receipt.caller_ref.as_deref() == Some(reference)).then_some((debit, receipt))
}

/// Look up exact caller references across revisions. A result describes only the available history.
///
/// # Errors
/// Returns an error for invalid references, inconsistent history or an unreadable witness.
pub fn lookup_receipt(
    loaded: &LoadedPass,
    state: &StateDir,
    reference: &str,
) -> Result<ReceiptLookup, Error> {
    if !debit::valid_text(reference, crate::MAX_CALLER_REF) {
        return Err(Error::Usage(format!(
            "supply a nonblank, printable caller reference of at most {} characters",
            crate::MAX_CALLER_REF
        )));
    }
    let mut count = 0;
    let mut matches = Vec::new();
    let view = visit_view(loaded, state, false, &mut |event| {
        if let Some((d, r)) = match_reference(event, reference) {
            count += 1;
            if matches.len() < DETAIL_LIMIT {
                matches.push(FoundReceipt {
                    seq: d.seq,
                    time: rfc3339(d.time),
                    digest: d.digest.to_string(),
                    charges: d.charges.clone(),
                    targets: r.targets.clone(),
                });
            }
        }
        Ok(())
    })?;
    if let crate::WitnessStatus::NotChecked { reason } = view.witness {
        return Err(Error::WitnessUnavailable {
            pass_id: loaded.pass.id.clone(),
            dir: state.path().ok().map(Path::to_owned),
            detail: reason,
        });
    }
    let mut warnings = view.warnings;
    if count == 0 {
        warnings.push("No matching debit appears in the available ledger history.".into());
    }
    if view.adoption_count > 0 {
        warnings.push("The available history includes adoption. Carried totals can survive even when individual receipts are missing.".into());
    }
    Ok(ReceiptLookup {
        pass_id: loaded.pass.id.clone(),
        caller_ref: reference.into(),
        result: match count {
            0 => "absent",
            1 => "found",
            _ => "ambiguous",
        },
        match_count: count,
        truncated: count > matches.len() as u64,
        matches,
        adoption_count: view.adoption_count,
        witness: view.witness.as_str(),
        warnings,
    })
}

#[derive(Debug, Serialize)]
pub struct AuditEndpoint {
    pub seq: u64,
    /// One-based index into the recorded debit.
    pub index: usize,
    pub time: String,
    pub digest: String,
    #[serde(flatten)]
    pub recorded: RecordedTarget,
    pub matched_label: Option<String>,
    pub refusal_code: Option<&'static str>,
}

#[derive(Default, Debug, Serialize)]
pub struct EndpointGroup {
    pub count: u64,
    pub details: Vec<AuditEndpoint>,
    pub truncated: bool,
}

#[derive(Default, Debug, Serialize)]
pub struct EvidenceGap {
    pub count: u64,
    pub sequences: Vec<u64>,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct ReceiptAudit {
    pub pass_id: String,
    pub result: &'static str,
    pub corroborated: EndpointGroup,
    pub mismatches: EndpointGroup,
    pub gaps: BTreeMap<&'static str, EvidenceGap>,
    pub witness: &'static str,
    pub warnings: Vec<String>,
}

fn record_gap(gaps: &mut BTreeMap<&'static str, EvidenceGap>, reason: &'static str, seq: u64) {
    let group = gaps.entry(reason).or_default();
    group.count += 1;
    if group.sequences.len() < DETAIL_LIMIT {
        group.sequences.push(seq);
    } else {
        group.truncated = true;
    }
}

// Cache only the last revision. Consecutive ledger entries usually share it.
// Missing revisions are cached under the same key as successfully parsed ones.
fn archive_revision(directory: &Path, digest: Digest, id: &str) -> Result<Option<Pass>, Error> {
    let bytes = match retrieve_pass(directory, digest) {
        Ok(bytes) => bytes,
        Err(Error::Io { path, .. }) if !exists(&path)? => return Ok(None),
        Err(error) => return Err(error),
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::Usage(format!("archived revision {digest} is not UTF-8")))?;
    let pass = Pass::parse(text).map_err(|problems| Error::Invalid {
        path: directory.join(digest.to_string()),
        problems,
    })?;
    if pass.id != id {
        return Err(Error::Usage(format!(
            "archived revision {digest} belongs to pass {}, expected {id}",
            pass.id
        )));
    }
    Ok(Some(pass))
}

/// Replay retained endpoints at each debit's recorded instant. Groups include counts even after detail limits are reached.
///
/// # Errors
/// Any failure to verify ledger or archive integrity is an error. Missing archive revisions are reported as gaps.
pub fn audit_receipts(
    loaded: &LoadedPass,
    state: &StateDir,
    directory: &Path,
) -> Result<ReceiptAudit, Error> {
    let mut corroborated = EndpointGroup::default();
    let mut mismatches = EndpointGroup::default();
    let mut gaps = BTreeMap::new();
    let mut cached: Option<(Digest, Option<Pass>)> = None;
    let view = visit_view(loaded, state, false, &mut |event| {
        match event {
            VerifiedEvent::Spend(s) => record_gap(&mut gaps, "legacy-spend", s.seq),
            VerifiedEvent::Adopt(a) if !a.carried.is_empty() => {
                record_gap(&mut gaps, "adoption-carry", a.seq);
            }
            VerifiedEvent::Adopt(_) => (),
            VerifiedEvent::Debit(d) => {
                let Some(receipt) = d.receipt.as_ref().filter(|r| !r.targets.is_empty()) else {
                    record_gap(&mut gaps, "targets-unrecorded", d.seq);
                    return Ok(());
                };
                if cached.as_ref().is_none_or(|(key, _)| *key != d.digest) {
                    cached = Some((
                        d.digest,
                        archive_revision(directory, d.digest, &loaded.pass.id)?,
                    ));
                }
                let Some(pass) = cached.as_ref().and_then(|(_, p)| p.as_ref()) else {
                    record_gap(&mut gaps, "archive-missing", d.seq);
                    return Ok(());
                };
                for (index, t) in receipt.targets.iter().enumerate() {
                    let target = t.target.parse::<Target>().map_err(Error::Usage)?;
                    let name = t
                        .name
                        .as_deref()
                        .map(HostName::canonical)
                        .transpose()
                        .map_err(Error::Usage)?;
                    let (group, matched_label, refusal_code) =
                        match pass.permits_named(&target, name.as_ref(), d.time, Duration::ZERO) {
                            Decision::Allowed { label } if label == t.label => {
                                (&mut corroborated, Some(label), None)
                            }
                            Decision::Allowed { label } => (&mut mismatches, Some(label), None),
                            Decision::Refused(r) => (&mut mismatches, None, Some(r.code.as_str())),
                        };
                    group.count += 1;
                    if group.details.len() < DETAIL_LIMIT {
                        group.details.push(AuditEndpoint {
                            seq: d.seq,
                            index: index + 1,
                            time: rfc3339(d.time),
                            digest: d.digest.to_string(),
                            recorded: t.clone(),
                            matched_label,
                            refusal_code,
                        });
                    } else {
                        group.truncated = true;
                    }
                }
            }
        }
        Ok(())
    })?;
    let result = if mismatches.count > 0 {
        "mismatch"
    } else if corroborated.count == 0 || !gaps.is_empty() {
        "incomplete"
    } else {
        "complete"
    };
    Ok(ReceiptAudit {
        pass_id: loaded.pass.id.clone(),
        result,
        corroborated,
        mismatches,
        gaps,
        witness: view.witness.as_str(),
        warnings: view.warnings,
    })
}

#[derive(Debug, Serialize)]
pub struct BackupCandidate {
    pub path: String,
    pub relation: &'static str,
    pub tip: Option<Checkpoint>,
    /// The first candidate (one-based) with the same verified tip.
    pub tip_group: Option<usize>,
    pub error: Option<BackupError>,
}

#[derive(Debug, Serialize)]
pub struct BackupError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct BackupReport {
    pub pass_id: String,
    pub anchor: Option<Checkpoint>,
    pub assessment: &'static str,
    pub candidates: Vec<BackupCandidate>,
    pub errors: usize,
    pub warnings: Vec<String>,
}

/// Compare individually verified backup tips with one captured witness, including when the live ledger is absent.
///
/// # Errors
/// Requires between one and `MAX_BACKUPS` explicit paths. Per-file errors remain in input order.
pub fn compare_backups(
    loaded: &LoadedPass,
    state: &StateDir,
    paths: &[PathBuf],
) -> Result<BackupReport, Error> {
    if !(1..=MAX_BACKUPS).contains(&paths.len()) {
        return Err(Error::Usage(format!(
            "supply 1 to {MAX_BACKUPS} explicit backup paths"
        )));
    }
    let id = &loaded.pass.id;
    let mut warnings = Vec::new();
    let witness = match state.read(id) {
        Ok(Some(w)) => Some(w),
        Ok(None) => {
            warnings.push(format!("There is no local witness for pass {id}."));
            None
        }
        Err(e) => {
            warnings.push(e.to_string());
            None
        }
    };
    let anchor = witness.as_ref().map(|w| Checkpoint {
        version: 1,
        pass_id: id.clone(),
        seq: w.seq,
        hash: w.tail.to_string(),
    });
    let mut groups = BTreeMap::new();
    let mut extensions = BTreeSet::new();
    let mut exact = false;
    let mut errors = 0;
    let mut candidates = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let mut row = BackupCandidate {
            path: path.display().to_string(),
            relation: "error",
            tip: None,
            tip_group: None,
            error: None,
        };
        match inspect_candidate(path, witness.as_ref().map(|w| w.seq)) {
            Ok(parsed) => {
                let tip = Checkpoint {
                    version: 1,
                    pass_id: parsed.pass_id,
                    seq: parsed.seq,
                    hash: parsed.tail.to_string(),
                };
                let group = *groups
                    .entry((tip.pass_id.clone(), tip.seq, tip.hash.clone()))
                    .or_insert(i + 1);
                row.tip_group = Some(group);
                row.relation = match &witness {
                    _ if tip.pass_id != *id => "foreign",
                    None => "unanchored",
                    Some(w) if tip.seq < w.seq => "shorter",
                    Some(w) if parsed.prefix != Some((w.seq, w.tail)) => "mismatch",
                    Some(w) if tip.seq == w.seq => {
                        exact = true;
                        "exact"
                    }
                    Some(_) => {
                        extensions.insert(group);
                        "extended"
                    }
                };
                row.tip = Some(tip);
            }
            Err(e) => {
                errors += 1;
                row.error = Some(BackupError {
                    code: e.code(),
                    message: e.to_string(),
                });
            }
        }
        candidates.push(row);
    }
    let assessment = if anchor.is_none() {
        "inconclusive"
    } else if extensions.len() > 1 {
        "ambiguous"
    } else if exact || !extensions.is_empty() {
        "preserved"
    } else {
        "no-match"
    };
    Ok(BackupReport {
        pass_id: id.clone(),
        anchor,
        assessment,
        candidates,
        errors,
        warnings,
    })
}
