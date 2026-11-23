//! Local, read-only reconciliation, receipt auditing and backup comparison.
pub use super::evidence_charges::{ChargeAudit, ChargeMismatch, ChargeMismatches, audit_charges};
pub use super::evidence_manifest::{
    MAX_MANIFEST_BYTES, MAX_MANIFEST_ROWS, ReconcileDifference, ReconcileRow, Reconciliation,
    reconcile,
};

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use super::{
    Checkpoint, DebitCharge, DebitReceipt, LedgerDebit, RecordedTarget, VerifiedEvent, debit,
    exists, inspect_candidate, inspect_candidate_checkpoints, rfc3339, visit_view,
};
use crate::{
    Decision, Digest, Error, HostName, LoadedPass, Pass, Provenance, SignedApproval, StateDir,
    Target, archive_provenance, retrieve_pass, time::Duration,
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
    /// How the revision it was replayed against was archived:
    /// `signature-verified` or `unsigned`.
    pub provenance: &'static str,
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
    /// For a gap about a pass revision (`archive-missing`,
    /// `approval-unverified`), each digest with its own sequences, in order of
    /// first use. Empty for the other reasons.
    pub digests: Vec<GapDigest>,
    /// More digests than [`DETAIL_LIMIT`] had this gap; `count` still covers them.
    pub digests_truncated: bool,
}

/// The lines of one gap that were decided under one pass revision.
#[derive(Debug, Serialize)]
pub struct GapDigest {
    pub digest: String,
    pub count: u64,
    pub sequences: Vec<u64>,
    pub truncated: bool,
    #[serde(skip)]
    key: Digest,
}

/// One pass revision that ledger debits were decided under.
#[derive(Debug, Serialize)]
pub struct RevisionUse {
    pub digest: String,
    /// The first and last ledger sequence decided under it.
    pub first_seq: u64,
    pub last_seq: u64,
    /// How many spend and debit lines were decided under it.
    pub lines: u64,
    /// `signature-verified`, `unsigned` (archived without a signature
    /// record) or `missing` (not in the archive).
    pub provenance: &'static str,
    /// The retained signature record, for `signature-verified`.
    pub approval: Option<SignedApproval>,
}

/// The revisions the ledger's debits used, in order of first use.
#[derive(Default, Debug, Serialize)]
pub struct RevisionGroup {
    /// Distinct digests.
    pub count: u64,
    pub details: Vec<RevisionUse>,
    pub truncated: bool,
    /// How many distinct digests are not `signature-verified`.
    pub unverified: u64,
}

#[derive(Debug, Serialize)]
pub struct ReceiptAudit {
    pub pass_id: String,
    pub result: &'static str,
    pub corroborated: EndpointGroup,
    pub mismatches: EndpointGroup,
    pub gaps: BTreeMap<&'static str, EvidenceGap>,
    pub revisions: RevisionGroup,
    pub witness: &'static str,
    pub warnings: Vec<String>,
}

pub(super) fn record_gap(
    gaps: &mut BTreeMap<&'static str, EvidenceGap>,
    reason: &'static str,
    seq: u64,
) {
    let group = gaps.entry(reason).or_default();
    group.count += 1;
    if group.sequences.len() < DETAIL_LIMIT {
        group.sequences.push(seq);
    } else {
        group.truncated = true;
    }
}

/// Record a gap about the revision `digest`, also under that digest.
pub(super) fn record_revision_gap(
    gaps: &mut BTreeMap<&'static str, EvidenceGap>,
    reason: &'static str,
    seq: u64,
    digest: Digest,
) {
    record_gap(gaps, reason, seq);
    let group = gaps.entry(reason).or_default();
    // Consecutive lines usually share a revision, so look from the end.
    let i = if let Some(i) = group.digests.iter().rposition(|d| d.key == digest) {
        i
    } else if group.digests.len() < DETAIL_LIMIT {
        group.digests.push(GapDigest {
            digest: digest.to_string(),
            count: 0,
            sequences: Vec::new(),
            truncated: false,
            key: digest,
        });
        group.digests.len() - 1
    } else {
        group.digests_truncated = true;
        return;
    };
    let entry = &mut group.digests[i];
    entry.count += 1;
    if entry.sequences.len() < DETAIL_LIMIT {
        entry.sequences.push(seq);
    } else {
        entry.truncated = true;
    }
}

struct Used {
    digest: Digest,
    first_seq: u64,
    last_seq: u64,
    lines: u64,
    provenance: Provenance,
}

/// The provenance of every revision the ledger used, looked up once per digest.
pub(super) struct RevisionTracker<'a> {
    directory: &'a Path,
    index: HashMap<Digest, usize>,
    used: Vec<Used>,
}

impl<'a> RevisionTracker<'a> {
    pub(super) fn new(directory: &'a Path) -> Self {
        Self {
            directory,
            index: HashMap::new(),
            used: Vec::new(),
        }
    }

    /// Note that line `seq` was decided under `digest`, record an
    /// `approval-unverified` gap unless a verified signature approved that
    /// revision, and return its provenance word.
    pub(super) fn note(
        &mut self,
        digest: Digest,
        seq: u64,
        gaps: &mut BTreeMap<&'static str, EvidenceGap>,
    ) -> Result<&'static str, Error> {
        let i = if let Some(&i) = self.index.get(&digest) {
            i
        } else {
            self.used.push(Used {
                digest,
                first_seq: seq,
                last_seq: seq,
                lines: 0,
                provenance: archive_provenance(self.directory, digest)?,
            });
            self.index.insert(digest, self.used.len() - 1);
            self.used.len() - 1
        };
        let entry = &mut self.used[i];
        entry.last_seq = seq;
        entry.lines += 1;
        if !matches!(entry.provenance, Provenance::SignatureVerified(_)) {
            record_revision_gap(gaps, "approval-unverified", seq, digest);
        }
        Ok(entry.provenance.as_str())
    }

    pub(super) fn report(self) -> RevisionGroup {
        let mut group = RevisionGroup {
            count: self.used.len() as u64,
            ..RevisionGroup::default()
        };
        for used in self.used {
            if !matches!(used.provenance, Provenance::SignatureVerified(_)) {
                group.unverified += 1;
            }
            if group.details.len() < DETAIL_LIMIT {
                group.details.push(RevisionUse {
                    digest: used.digest.to_string(),
                    first_seq: used.first_seq,
                    last_seq: used.last_seq,
                    lines: used.lines,
                    provenance: used.provenance.as_str(),
                    approval: used.provenance.approval().cloned(),
                });
            } else {
                group.truncated = true;
            }
        }
        group
    }
}

// Cache only the last revision. Consecutive ledger entries usually share it.
// Missing revisions are cached under the same key as successfully parsed ones.
pub(super) fn archive_revision(
    directory: &Path,
    digest: Digest,
    id: &str,
) -> Result<Option<Pass>, Error> {
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
    crate::archive::check_directory(directory)?;
    let mut corroborated = EndpointGroup::default();
    let mut mismatches = EndpointGroup::default();
    let mut gaps = BTreeMap::new();
    let mut revisions = RevisionTracker::new(directory);
    let mut cached: Option<(Digest, Option<Pass>)> = None;
    let view = visit_view(loaded, state, false, &mut |event| {
        match event {
            // A scalar spend line has no field for a target.
            VerifiedEvent::Spend(s) => {
                revisions.note(s.digest, s.seq, &mut gaps)?;
                record_gap(&mut gaps, "targets-unrecorded", s.seq);
            }
            VerifiedEvent::Adopt(a) if !a.carried.is_empty() => {
                record_gap(&mut gaps, "adoption-carry", a.seq);
            }
            VerifiedEvent::Adopt(_) => (),
            VerifiedEvent::Debit(d) => {
                let provenance = revisions.note(d.digest, d.seq, &mut gaps)?;
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
                    record_revision_gap(&mut gaps, "archive-missing", d.seq, d.digest);
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
                            provenance,
                        });
                    } else {
                        group.truncated = true;
                    }
                }
            }
        }
        Ok(())
    })?;
    let revisions = revisions.report();
    // `complete` needs a verified signature over every revision used.
    let result = if mismatches.count > 0 {
        "mismatch"
    } else if corroborated.count == 0 || !gaps.is_empty() || revisions.unverified > 0 {
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
        revisions,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestry: Option<BackupAncestry>,
}

#[derive(Debug, Serialize)]
pub struct BackupAncestry {
    /// Pairs of one-based tip group indices, from prefix to extension.
    pub prefix_links: Vec<(usize, usize)>,
    pub maximal_groups: Vec<usize>,
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
    compare_backups_with_ancestry(loaded, state, paths, false)
}

/// Compare backup tips, optionally verifying ancestry among witnessed extensions.
///
/// # Errors
/// Requires between one and `MAX_BACKUPS` explicit paths.
pub fn compare_backups_with_ancestry(
    loaded: &LoadedPass,
    state: &StateDir,
    paths: &[PathBuf],
    ancestry: bool,
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
    let ancestry_result = ancestry.then(|| analyze_ancestry(paths, &mut candidates, &mut errors));
    let extension_count = ancestry_result
        .as_ref()
        .map_or(extensions.len(), |a| a.maximal_groups.len());
    let assessment = if anchor.is_none() {
        "inconclusive"
    } else if extension_count > 1 {
        "ambiguous"
    } else if exact || extension_count > 0 {
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
        ancestry: ancestry_result,
    })
}

fn analyze_ancestry(
    paths: &[PathBuf],
    candidates: &mut [BackupCandidate],
    errors: &mut usize,
) -> BackupAncestry {
    let wanted: BTreeSet<u64> = candidates
        .iter()
        .filter(|c| c.relation == "extended")
        .filter_map(|c| c.tip.as_ref().map(|t| t.seq))
        .collect();
    let mut scans = BTreeMap::new();
    for (i, row) in candidates.iter_mut().enumerate() {
        if row.relation != "extended" {
            continue;
        }
        match inspect_candidate_checkpoints(&paths[i], &wanted) {
            Ok((parsed, hashes))
                if row.tip.as_ref().is_some_and(|tip| {
                    tip.pass_id == parsed.pass_id
                        && tip.seq == parsed.seq
                        && tip.hash == parsed.tail.to_string()
                }) =>
            {
                scans.insert(i + 1, hashes);
            }
            result => {
                *errors += 1;
                row.relation = "changed";
                row.tip = None;
                row.tip_group = None;
                row.error = Some(match result {
                    Err(e) => BackupError {
                        code: e.code(),
                        message: e.to_string(),
                    },
                    Ok(_) => BackupError {
                        code: "candidate-changed",
                        message: "Candidate changed between verification scans.".into(),
                    },
                });
            }
        }
    }
    regroup_verified(candidates);
    ancestry_links(candidates, &scans)
}

fn regroup_verified(candidates: &mut [BackupCandidate]) {
    let mut groups = BTreeMap::new();
    for (i, row) in candidates.iter_mut().enumerate() {
        if let Some(tip) = &row.tip {
            row.tip_group = Some(
                *groups
                    .entry((tip.pass_id.clone(), tip.seq, tip.hash.clone()))
                    .or_insert(i + 1),
            );
        }
    }
}

fn ancestry_links(
    candidates: &[BackupCandidate],
    scans: &BTreeMap<usize, BTreeMap<u64, Digest>>,
) -> BackupAncestry {
    let mut links = BTreeSet::new();
    let mut valid_groups = BTreeSet::new();
    for a in candidates {
        if a.relation != "extended" {
            continue;
        }
        let Some(atip) = &a.tip else {
            continue;
        };
        let Some(agroup) = a.tip_group else {
            continue;
        };
        valid_groups.insert(agroup);
        for (j, b) in candidates.iter().enumerate() {
            if b.relation != "extended" {
                continue;
            }
            let Some(btip) = &b.tip else {
                continue;
            };
            let Some(bgroup) = b.tip_group else {
                continue;
            };
            if atip.seq < btip.seq
                && scans
                    .get(&(j + 1))
                    .and_then(|h| h.get(&atip.seq))
                    .is_some_and(|hash| hash.to_string() == atip.hash)
            {
                links.insert((agroup, bgroup));
            }
        }
    }
    let maximal_groups = valid_groups
        .into_iter()
        .filter(|g| !links.iter().any(|(a, _)| a == g))
        .collect();
    BackupAncestry {
        prefix_links: links.into_iter().collect(),
        maximal_groups,
    }
}

#[cfg(test)]
mod ancestry_tests {
    use super::*;
    #[test]
    fn changed_first_duplicate_is_not_a_group_representative() {
        use crate::{SpendRequest, ledger_path, spend_in};
        use std::fs;
        let temp = tempfile::tempdir().expect("temporary directory");
        let pass = temp.path().join("approval");
        fs::write(
            &pass,
            format!(
                "{}\n[ceilings]\ncalls = 3\n",
                include_str!("../../docs/review-approval.toml")
            ),
        )
        .expect("pass");
        let state = StateDir::new(temp.path().join("state"));
        let now = time::macros::datetime!(2026-11-20 12:00 UTC);
        spend_in(&pass, &SpendRequest::new("calls", 1), now, &state).expect("debit");
        let ledger = ledger_path(&pass);
        let copy = temp.path().join("copy");
        fs::copy(&ledger, &copy).expect("duplicate");
        let paths = [ledger, copy];
        // Both paths were observed at the same tip during the first scan.
        let mut candidates: Vec<_> = paths
            .iter()
            .map(|path| {
                let scan = inspect_candidate(path, None).expect("initial scan");
                let tip = Checkpoint {
                    version: 1,
                    pass_id: scan.pass_id,
                    seq: scan.seq,
                    hash: scan.tail.to_string(),
                };
                BackupCandidate {
                    path: path.display().to_string(),
                    relation: "extended",
                    tip: Some(tip),
                    tip_group: Some(1),
                    error: None,
                }
            })
            .collect();
        spend_in(&pass, &SpendRequest::new("calls", 1), now, &state).expect("advance first copy");
        let mut errors = 0;
        let ancestry = analyze_ancestry(&paths, &mut candidates, &mut errors);
        assert_eq!(errors, 1);
        assert_eq!(candidates[0].relation, "changed");
        assert!(candidates[0].tip.is_none());
        assert_eq!(candidates[0].tip_group, None);
        assert_eq!(candidates[1].tip_group, Some(2));
        assert_eq!(ancestry.maximal_groups, vec![2]);
    }
}
