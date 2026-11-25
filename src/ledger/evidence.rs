//! Local, read-only reconciliation, receipt auditing and backup comparison.
pub use super::evidence_charges::{
    ChargeAudit, ChargeMismatch, ChargeMismatches, audit_charges, audit_charges_with,
};
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
    Decision, Digest, Error, HostName, LoadedPass, Pass, SignedApproval, StateDir, Target,
    archive::read_revision,
    retrieve_pass,
    time::{Duration, OffsetDateTime},
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
    /// The first 64 sequences of reference reconciliations that list the
    /// reference: the operator recorded that a debit for it may be in lines
    /// an adoption lost.
    pub reconciled_at: Vec<u64>,
    pub witness: &'static str,
    pub warnings: Vec<String>,
}

/// The sequence and adoption of a reference reconciliation that lists
/// `reference`.
pub(super) fn match_reconciled(event: &VerifiedEvent, reference: &str) -> Option<(u64, u64)> {
    let VerifiedEvent::Reconcile(r) = event else {
        return None;
    };
    r.references
        .iter()
        .any(|listed| listed == reference)
        .then_some((r.seq, r.adoption))
}

/// The warning for a reference that reference reconciliations list.
pub(super) fn reconciled_warning(reconciled: &[(u64, u64)]) -> Option<String> {
    let (seq, adoption) = reconciled.first()?;
    Some(format!(
        "The reference is listed in the reference reconciliation at ledger sequence {seq}: the operator recorded that a debit for it may be in lines lost before the adoption at sequence {adoption}, so this history cannot show that it was never debited."
    ))
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
    let mut reconciled = Vec::new();
    let view = visit_view(loaded, state, false, &mut |event| {
        if let Some(found) = match_reconciled(event, reference)
            && reconciled.len() < DETAIL_LIMIT
        {
            reconciled.push(found);
        }
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
    warnings.extend(reconciled_warning(&reconciled));
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
        reconciled_at: reconciled.into_iter().map(|(seq, _)| seq).collect(),
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
    /// The provenance of the revision it was replayed against, as in
    /// [`RevisionUse::provenance`]: never `missing`.
    pub provenance: &'static str,
    #[serde(skip)]
    key: Digest,
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
    /// Why the recorded signature did not verify again, for a
    /// `signature-rejected` gap only (absent from the other gaps).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The principal the signature verified for, which its record names,
    /// for a `signer-not-pinned` gap only (absent from the other gaps).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
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
    /// The time of the first line decided under it: when it was first used.
    pub first_time: String,
    /// How many spend and debit lines were decided under it.
    pub lines: u64,
    /// `signature-verified` (this audit verified the recorded signature
    /// again and the verifier accepted it), `signature-rejected` (it did not),
    /// `signature-recorded` (a signature record that this audit did not
    /// verify again), `unsigned` (archived without a signature record) or
    /// `missing` (not in the archive).
    pub provenance: &'static str,
    /// The retained signature record, or null for `unsigned` and `missing`.
    pub approval: Option<SignedApproval>,
    /// Why the verifier rejected the signature, for `signature-rejected`.
    pub reason: Option<&'static str>,
    /// The instant the signature was verified as of ([`AsOf`]), or null when
    /// this audit did not verify it.
    pub verify_time: Option<String>,
    /// The principal the signature verified for, for `signature-verified`.
    pub verified_for: Option<String>,
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

/// Whether an audit verified the archive's signature records again.
#[derive(Default, Debug, Serialize)]
pub struct SignatureCheck {
    /// True when the audit ran the verifier again over every signature
    /// record it read (`--allowed-signers`); each revision's `provenance`
    /// gives the outcome. False when it only read the records.
    pub reverified: bool,
    /// The digest of the trusted signers file the signatures were verified
    /// against, when `reverified`.
    pub allowed_signers: Option<String>,
    /// The principals the auditor named: each signature had to verify for
    /// one of them. Empty when none was named, so that each signature was
    /// verified for the principal its record names and the audit has a
    /// `signer-not-pinned` gap, and when the audit did not verify again.
    pub principals: Vec<String>,
    /// What the signatures were verified as of: `first-use` (the time of
    /// the first line decided under each revision) or one instant for all,
    /// in RFC 3339. Null when the audit did not verify again.
    pub as_of: Option<String>,
}

/// The time an audit verifies each recorded signature as of. A trusted
/// signers file can limit a key to a window with `valid-after` and
/// `valid-before`, and a key counts only for a time inside its window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsOf {
    /// The time of the first ledger line decided under each revision. A key
    /// that has expired since still approves what it signed before, and a
    /// key that was not yet valid when the revision was first used does not.
    FirstUse,
    /// One instant for every revision, such as now.
    Instant(OffsetDateTime),
}

/// One archived revision whose recorded signature an audit verifies again.
///
/// The audit reads all of it under the shared ledger lock, then releases the
/// lock and calls [`Reverify::check`]. So it holds bytes, not paths: verify
/// exactly these bytes, whatever the archive files hold by then.
#[derive(Debug)]
pub struct SignatureToCheck<'a> {
    pub digest: Digest,
    /// The archived bytes, already checked against `digest`.
    pub bytes: &'a [u8],
    /// The archived detached signature (`DIGEST.sig`), read together with
    /// the record and already checked against its `signature` digest.
    pub signature: &'a [u8],
    pub approval: &'a SignedApproval,
    /// The principal to verify for: one that [`Reverify::principals`]
    /// names, or the record's when it names none.
    pub principal: &'a str,
    /// Verify as of this instant ([`Reverify::as_of`]): a key that the
    /// trusted signers file limits to a window that does not hold it does
    /// not count.
    pub as_of: OffsetDateTime,
}

/// What the verifier said about one recorded signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recheck {
    /// It accepted the signature over the archived bytes.
    Verified,
    /// It did not, for the reason code given.
    Rejected(&'static str),
}

/// How an audit verifies signature records again, instead of trusting them.
///
/// Anyone who can write the archive can write a record, so an audit without
/// a `Reverify` treats every recorded signature as `signature-recorded` and
/// is never `complete`.
pub struct Reverify<'a> {
    /// The digest of the trusted signers file that `check` verifies against.
    /// It is reported, not read: read the file once, verify against those
    /// bytes, and give the digest of that same read.
    pub allowed_signers: Digest,
    /// The principals that may approve, such as the owner's. Each revision's
    /// signature must verify for one of them. The trusted signers file
    /// decides whose keys count; these decide who must have approved.
    ///
    /// When it is empty, each signature is verified for the principal its
    /// record names. Whoever writes the archive picks that principal, so a
    /// revision that verifies is a `signer-not-pinned` gap, and the audit is
    /// never `complete`.
    pub principals: &'a [&'a str],
    /// The time each signature is verified as of.
    pub as_of: AsOf,
    /// Verifies one signature for one principal. It runs once per digest,
    /// in order of first use, and once more for each further principal in
    /// `principals` until one verifies: the record's principal first when
    /// `principals` names it. It runs after the audit has read the ledger
    /// and released the ledger lock, so a slow verifier does not hold up
    /// spends. An error ends the audit, so a verifier that cannot run is
    /// never a pass.
    pub check: &'a mut dyn FnMut(&SignatureToCheck<'_>) -> Result<Recheck, Error>,
}

#[derive(Debug, Serialize)]
pub struct ReceiptAudit {
    pub pass_id: String,
    pub result: &'static str,
    pub corroborated: EndpointGroup,
    pub mismatches: EndpointGroup,
    pub gaps: BTreeMap<&'static str, EvidenceGap>,
    pub revisions: RevisionGroup,
    pub signatures: SignatureCheck,
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
            reason: None,
            principal: None,
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

/// How one revision's approval stands in this audit.
enum Approval {
    Missing,
    Unsigned,
    /// A signature record this audit did not verify again.
    Recorded(SignedApproval),
    /// A signature record to verify again once the ledger lock is released,
    /// with what was read under the lock.
    Pending(SignedApproval, Pending),
    /// A recorded signature that the verifier accepted again, for
    /// `principal`. `pinned` when the auditor named that principal.
    Verified {
        record: SignedApproval,
        principal: String,
        pinned: bool,
    },
    /// A recorded signature that the verifier rejected, and why.
    Rejected(SignedApproval, &'static str),
}

/// What verifying one recorded signature again needs, as read under the
/// ledger lock.
struct Pending {
    /// The archived bytes, checked against their digest.
    bytes: Vec<u8>,
    /// The `.sig` bytes, checked against the record's `signature` digest.
    signature: Vec<u8>,
}

impl Approval {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Unsigned => "unsigned",
            Self::Recorded(_) | Self::Pending(..) => "signature-recorded",
            Self::Verified { .. } => "signature-verified",
            Self::Rejected(..) => "signature-rejected",
        }
    }

    const fn record(&self) -> Option<&SignedApproval> {
        match self {
            Self::Missing | Self::Unsigned => None,
            Self::Recorded(a)
            | Self::Pending(a, _)
            | Self::Verified { record: a, .. }
            | Self::Rejected(a, _) => Some(a),
        }
    }

    /// The gap of a line decided under this revision: none when a signature
    /// this audit verified, for a principal the auditor named, approved it.
    const fn gap(&self) -> Option<&'static str> {
        match self {
            Self::Verified { pinned: true, .. } => None,
            Self::Verified { pinned: false, .. } => Some("signer-not-pinned"),
            Self::Missing | Self::Unsigned => Some("approval-unverified"),
            Self::Recorded(_) | Self::Pending(..) => Some("signature-not-reverified"),
            Self::Rejected(..) => Some("signature-rejected"),
        }
    }
}

/// The gaps that [`RevisionTracker::finish`] records, about a revision's
/// approval.
const APPROVAL_GAPS: [&str; 4] = [
    "approval-unverified",
    "signature-not-reverified",
    "signature-rejected",
    "signer-not-pinned",
];

struct Used {
    digest: Digest,
    first_seq: u64,
    last_seq: u64,
    /// The time of the first line decided under it.
    first_time: OffsetDateTime,
    lines: u64,
    /// The first [`DETAIL_LIMIT`] sequences decided under it.
    sequences: Vec<u64>,
    approval: Approval,
    /// The instant its signature was verified as of, once it was.
    verify_time: Option<OffsetDateTime>,
}

/// The provenance of every revision the ledger used, read once per digest
/// while the ledger is read, and with [`Reverify`] verified again once the
/// ledger lock is released.
pub(super) struct RevisionTracker<'a, 'r> {
    directory: &'a Path,
    index: HashMap<Digest, usize>,
    used: Vec<Used>,
    reverify: Option<Reverify<'r>>,
}

impl<'a, 'r> RevisionTracker<'a, 'r> {
    pub(super) fn new(directory: &'a Path, reverify: Option<Reverify<'r>>) -> Self {
        Self {
            directory,
            index: HashMap::new(),
            used: Vec::new(),
            reverify,
        }
    }

    /// Note that line `seq`, recorded at `time`, was decided under
    /// `digest`. This runs under the ledger lock, so it only reads the
    /// archive, once per digest.
    pub(super) fn note(
        &mut self,
        digest: Digest,
        seq: u64,
        time: OffsetDateTime,
    ) -> Result<(), Error> {
        let i = if let Some(&i) = self.index.get(&digest) {
            i
        } else {
            let approval = self.read(digest)?;
            self.used.push(Used {
                digest,
                first_seq: seq,
                last_seq: seq,
                first_time: time,
                lines: 0,
                sequences: Vec::new(),
                approval,
                verify_time: None,
            });
            self.index.insert(digest, self.used.len() - 1);
            self.used.len() - 1
        };
        let entry = &mut self.used[i];
        entry.last_seq = seq;
        entry.lines += 1;
        if entry.sequences.len() < DETAIL_LIMIT {
            entry.sequences.push(seq);
        }
        Ok(())
    }

    /// The archive's provenance of `digest`. With [`Reverify`], a revision
    /// with a signature record keeps the bytes and the signature as this one
    /// read found them, so that what is verified later is what was read.
    fn read(&self, digest: Digest) -> Result<Approval, Error> {
        let Some(revision) = read_revision(self.directory, digest)? else {
            return Ok(Approval::Missing);
        };
        Ok(match revision.signed {
            None => Approval::Unsigned,
            Some((record, signature)) if self.reverify.is_some() => Approval::Pending(
                record,
                Pending {
                    bytes: revision.bytes,
                    signature,
                },
            ),
            Some((record, _)) => Approval::Recorded(record),
        })
    }

    /// Call this after the ledger lock is released. Verify each pending
    /// signature, in order of first use, then record a gap for every line
    /// decided under a revision that no signature verified here, for a
    /// principal the auditor named, approved.
    ///
    /// Nothing is read again after a check. The verifier gets the bytes read
    /// under the lock, which are the bytes the report describes, so a file
    /// that changes on disk meanwhile cannot make the two differ.
    pub(super) fn finish(
        mut self,
        gaps: &mut BTreeMap<&'static str, EvidenceGap>,
    ) -> Result<Revisions, Error> {
        if let Some(reverify) = self.reverify.as_mut() {
            for used in &mut self.used {
                used.approval = match std::mem::replace(&mut used.approval, Approval::Missing) {
                    Approval::Pending(record, pending) => {
                        let as_of = match reverify.as_of {
                            AsOf::FirstUse => used.first_time,
                            AsOf::Instant(instant) => instant,
                        };
                        used.verify_time = Some(as_of);
                        verify(reverify, used.digest, record, &pending, as_of)?
                    }
                    other => other,
                };
            }
        }
        approval_gaps(&self.used, gaps);
        let signatures = self
            .reverify
            .as_ref()
            .map_or_else(SignatureCheck::default, |r| SignatureCheck {
                reverified: true,
                allowed_signers: Some(r.allowed_signers.to_string()),
                principals: pinned(r.principals).map(str::to_owned).collect(),
                as_of: Some(match r.as_of {
                    AsOf::FirstUse => "first-use".to_owned(),
                    AsOf::Instant(instant) => rfc3339(instant),
                }),
            });
        Ok(Revisions {
            index: self.index,
            used: self.used,
            signatures,
        })
    }
}

/// The principals named, each once, in the order given.
fn pinned<'p>(principals: &'p [&'p str]) -> impl Iterator<Item = &'p str> {
    principals
        .iter()
        .enumerate()
        .filter(|&(i, p)| !principals[..i].contains(p))
        .map(|(_, p)| *p)
}

/// Verify one recorded signature as of `as_of`: for the principal its record
/// names when the auditor named none, else for each principal named, the
/// record's first, until one verifies. A rejection keeps the reason of the
/// first try, which is the record's principal when it was named.
fn verify(
    reverify: &mut Reverify<'_>,
    digest: Digest,
    record: SignedApproval,
    pending: &Pending,
    as_of: OffsetDateTime,
) -> Result<Approval, Error> {
    let named: Vec<&str> = pinned(reverify.principals).collect();
    let tries: Vec<String> = if named.is_empty() {
        vec![record.principal.clone()]
    } else {
        let (first, rest): (Vec<&str>, Vec<&str>) =
            named.iter().partition(|p| **p == record.principal);
        first.into_iter().chain(rest).map(str::to_owned).collect()
    };
    let mut reason = None;
    for principal in tries {
        let verdict = (reverify.check)(&SignatureToCheck {
            digest,
            bytes: &pending.bytes,
            signature: &pending.signature,
            approval: &record,
            principal: &principal,
            as_of,
        })?;
        match verdict {
            Recheck::Verified => {
                return Ok(Approval::Verified {
                    record,
                    principal,
                    pinned: !named.is_empty(),
                });
            }
            Recheck::Rejected(why) => {
                reason.get_or_insert(why);
            }
        }
    }
    Ok(Approval::Rejected(record, reason.unwrap_or("unknown")))
}

/// Record the approval gaps of the lines decided under `used`, which is in
/// order of first use.
fn approval_gaps(used: &[Used], gaps: &mut BTreeMap<&'static str, EvidenceGap>) {
    for reason in APPROVAL_GAPS {
        let rows: Vec<&Used> = used
            .iter()
            .filter(|used| used.approval.gap() == Some(reason))
            .collect();
        if !rows.is_empty() {
            gaps.insert(reason, approval_gap(&rows));
        }
    }
}

/// The gap of every line decided under `rows`, which are in order of first
/// use: the same gap that recording each line in ledger order gives.
fn approval_gap(rows: &[&Used]) -> EvidenceGap {
    let count = rows.iter().map(|used| used.lines).sum();
    // The first sequences of all the rows are among the first of each row.
    let mut sequences: Vec<u64> = rows
        .iter()
        .flat_map(|used| used.sequences.iter().copied())
        .collect();
    sequences.sort_unstable();
    sequences.truncate(DETAIL_LIMIT);
    EvidenceGap {
        count,
        sequences,
        truncated: count > DETAIL_LIMIT as u64,
        digests: rows
            .iter()
            .take(DETAIL_LIMIT)
            .map(|used| GapDigest {
                digest: used.digest.to_string(),
                count: used.lines,
                sequences: used.sequences.clone(),
                truncated: used.lines > DETAIL_LIMIT as u64,
                reason: match used.approval {
                    Approval::Rejected(_, why) => Some(why),
                    _ => None,
                },
                principal: match &used.approval {
                    Approval::Verified {
                        principal,
                        pinned: false,
                        ..
                    } => Some(principal.clone()),
                    _ => None,
                },
                key: used.digest,
            })
            .collect(),
        digests_truncated: rows.len() > DETAIL_LIMIT,
    }
}

/// The revisions an audit used, with their signatures checked.
pub(super) struct Revisions {
    index: HashMap<Digest, usize>,
    used: Vec<Used>,
    signatures: SignatureCheck,
}

impl Revisions {
    /// The provenance of `digest`, as [`RevisionUse::provenance`] gives it.
    pub(super) fn provenance(&self, digest: Digest) -> &'static str {
        self.index
            .get(&digest)
            .map_or("missing", |&i| self.used[i].approval.as_str())
    }

    /// The revisions used, and how their signatures were checked.
    pub(super) fn report(self) -> (RevisionGroup, SignatureCheck) {
        let mut group = RevisionGroup {
            count: self.used.len() as u64,
            ..RevisionGroup::default()
        };
        for used in self.used {
            if !matches!(used.approval, Approval::Verified { .. }) {
                group.unverified += 1;
            }
            if group.details.len() < DETAIL_LIMIT {
                group.details.push(RevisionUse {
                    digest: used.digest.to_string(),
                    first_seq: used.first_seq,
                    last_seq: used.last_seq,
                    first_time: rfc3339(used.first_time),
                    lines: used.lines,
                    provenance: used.approval.as_str(),
                    approval: used.approval.record().cloned(),
                    reason: match used.approval {
                        Approval::Rejected(_, why) => Some(why),
                        _ => None,
                    },
                    verify_time: used.verify_time.map(rfc3339),
                    verified_for: match &used.approval {
                        Approval::Verified { principal, .. } => Some(principal.clone()),
                        _ => None,
                    },
                });
            } else {
                group.truncated = true;
            }
        }
        (group, self.signatures)
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

/// Replay retained endpoints at each debit's recorded instant.
///
/// Signature records are read without being verified again, so the result
/// is never `complete` for a revision with a signature record: use
/// [`audit_receipts_with`]. Groups include counts even after detail limits are
/// reached.
///
/// # Errors
/// Any failure to verify ledger or archive integrity is an error. Missing archive revisions are reported as gaps.
pub fn audit_receipts(
    loaded: &LoadedPass,
    state: &StateDir,
    directory: &Path,
) -> Result<ReceiptAudit, Error> {
    audit_receipts_with(loaded, state, directory, None)
}

/// [`audit_receipts`], verifying every recorded signature again with
/// `reverify` when it is given.
///
/// A rejected signature is a `signature-rejected` gap. A signature that
/// verified with no [`Reverify::principals`] named is a `signer-not-pinned`
/// gap.
///
/// The ledger is read under its shared lock, and with it each archived
/// revision, signature record and signature it used. `reverify.check` runs
/// after the lock is released, over the bytes read.
///
/// # Errors
/// As [`audit_receipts`], and any error of `reverify.check`.
pub fn audit_receipts_with(
    loaded: &LoadedPass,
    state: &StateDir,
    directory: &Path,
    reverify: Option<Reverify<'_>>,
) -> Result<ReceiptAudit, Error> {
    crate::archive::check_directory(directory)?;
    let mut corroborated = EndpointGroup::default();
    let mut mismatches = EndpointGroup::default();
    let mut gaps = BTreeMap::new();
    let mut revisions = RevisionTracker::new(directory, reverify);
    let mut cached: Option<(Digest, Option<Pass>)> = None;
    let view = visit_view(loaded, state, false, &mut |event| {
        match event {
            // A scalar spend line has no field for a target.
            VerifiedEvent::Spend(s) => {
                revisions.note(s.digest, s.seq, s.time)?;
                record_gap(&mut gaps, "targets-unrecorded", s.seq);
            }
            VerifiedEvent::Adopt(a) if !a.carried.is_empty() => {
                record_gap(&mut gaps, "adoption-carry", a.seq);
            }
            VerifiedEvent::Adopt(_) | VerifiedEvent::Reconcile(_) => (),
            VerifiedEvent::Debit(d) => {
                revisions.note(d.digest, d.seq, d.time)?;
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
                            // Set below, once the signatures are verified.
                            provenance: "",
                            key: d.digest,
                        });
                    } else {
                        group.truncated = true;
                    }
                }
            }
        }
        Ok(())
    })?;
    // The ledger lock is released: verify the signatures now.
    let revisions = revisions.finish(&mut gaps)?;
    for row in corroborated
        .details
        .iter_mut()
        .chain(mismatches.details.iter_mut())
    {
        row.provenance = revisions.provenance(row.key);
    }
    let (revisions, signatures) = revisions.report();
    // `complete` needs a signature this audit verified over every revision used.
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
        signatures,
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

/// Refuse a wrong number of backup paths, or a path that is not a regular
/// file or a link, before reading any of them.
fn check_backup_paths(paths: &[PathBuf]) -> Result<(), Error> {
    if !(1..=MAX_BACKUPS).contains(&paths.len()) {
        return Err(Error::Usage(format!(
            "supply 1 to {MAX_BACKUPS} explicit backup paths"
        )));
    }
    if let Some(path) = paths.iter().find(|path| {
        std::fs::symlink_metadata(path)
            .is_ok_and(|meta| !meta.file_type().is_file() && !meta.file_type().is_symlink())
    }) {
        return Err(Error::NotRegular { path: path.clone() });
    }
    Ok(())
}

/// Compare backup tips, optionally verifying ancestry among witnessed extensions.
///
/// # Errors
/// Requires between one and `MAX_BACKUPS` explicit paths, and refuses with
/// [`Error::NotRegular`], before reading any, a path that is a FIFO, a
/// device, a socket or a directory: that is a wrong argument, not a damaged
/// backup. A link, a missing file or a damaged ledger is reported in its row.
pub fn compare_backups_with_ancestry(
    loaded: &LoadedPass,
    state: &StateDir,
    paths: &[PathBuf],
    ancestry: bool,
) -> Result<BackupReport, Error> {
    check_backup_paths(paths)?;
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
            // A lock still held says nothing about the backup: try again.
            Err(e @ Error::LockTimeout { .. }) => return Err(e),
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
    let ancestry_result = ancestry
        .then(|| analyze_ancestry(paths, &mut candidates, &mut errors))
        .transpose()?;
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
) -> Result<BackupAncestry, Error> {
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
            Err(e @ Error::LockTimeout { .. }) => return Err(e),
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
    Ok(ancestry_links(candidates, &scans))
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
mod gap_tests {
    use super::*;

    /// A small generator, so that the cases are the same on every run.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    fn record(n: u64) -> SignedApproval {
        SignedApproval {
            principal: format!("owner-{n}@example.org"),
            namespace: crate::APPROVAL_NAMESPACE.to_owned(),
            allowed_signers: Digest::of(b"t"),
            signature: Digest::of(&n.to_le_bytes()),
        }
    }

    /// The approval of revision `n` for kind 0 to 5.
    fn approval(n: u64, kind: u64) -> Approval {
        match kind {
            0 => Approval::Missing,
            1 => Approval::Unsigned,
            2 => Approval::Recorded(record(n)),
            3 | 5 => Approval::Verified {
                record: record(n),
                principal: format!("owner-{n}@example.org"),
                pinned: kind == 3,
            },
            _ => Approval::Rejected(record(n), "untrusted-key"),
        }
    }

    /// Compare the gaps built after the verdicts are known with the gaps
    /// that recording each line in ledger order gives. `lines` names the
    /// revision of each line, and `kinds` the approval of each revision.
    /// Returns which detail limits were passed: the sequences of a gap, of
    /// one digest, and the digests of a gap.
    fn compare(lines: &[u64], kinds: &[u64]) -> [bool; 3] {
        let mut expected = BTreeMap::new();
        let mut index = HashMap::new();
        let mut used: Vec<Used> = Vec::new();
        for (seq, &n) in (1..).zip(lines) {
            let digest = Digest::of(&n.to_le_bytes());
            let i = *index.entry(digest).or_insert_with(|| {
                let kind = kinds[usize::try_from(n).expect("index")];
                used.push(Used {
                    digest,
                    first_seq: seq,
                    last_seq: seq,
                    first_time: OffsetDateTime::UNIX_EPOCH,
                    lines: 0,
                    sequences: Vec::new(),
                    approval: approval(n, kind),
                    verify_time: None,
                });
                used.len() - 1
            });
            let entry = &mut used[i];
            entry.last_seq = seq;
            entry.lines += 1;
            if entry.sequences.len() < DETAIL_LIMIT {
                entry.sequences.push(seq);
            }
            if let Some(reason) = entry.approval.gap() {
                record_revision_gap(&mut expected, reason, seq, digest);
            }
        }
        if let Some(rejected) = expected.get_mut("signature-rejected") {
            for row in &mut rejected.digests {
                row.reason = Some("untrusted-key");
            }
        }
        if let Some(unpinned) = expected.get_mut("signer-not-pinned") {
            for row in &mut unpinned.digests {
                let n = lines[usize::try_from(row.sequences[0] - 1).expect("line")];
                row.principal = Some(format!("owner-{n}@example.org"));
            }
        }
        let mut actual = BTreeMap::new();
        approval_gaps(&used, &mut actual);
        assert_eq!(
            serde_json::to_value(&actual).expect("json"),
            serde_json::to_value(&expected).expect("json"),
            "lines {lines:?}, kinds {kinds:?}"
        );
        let mut passed = [false; 3];
        for gap in actual.values() {
            passed[0] |= gap.truncated;
            passed[1] |= gap.digests.iter().any(|d| d.truncated);
            passed[2] |= gap.digests_truncated;
        }
        passed
    }

    #[test]
    fn approval_gaps_match_recording_each_line() {
        let mut reached = [false; 3];
        for seed in 0..60 {
            let mut rng = Lcg(seed);
            // Every third case has many revisions, all in one gap.
            let wide = seed % 3 == 0;
            let count = if wide { 70 } else { 1 } + rng.below(if wide { 20 } else { 90 });
            let same = wide.then(|| rng.below(6));
            let kinds: Vec<u64> = (0..count)
                .map(|_| same.unwrap_or_else(|| rng.below(6)))
                .collect();
            // Many lines go to a few revisions, so some pass the detail limit.
            let lines: Vec<u64> = (0..if wide { 300 } else { 1 } + rng.below(400))
                .map(|_| {
                    if rng.below(if wide { 2 } else { 3 }) == 0 {
                        rng.below(count)
                    } else {
                        rng.below(3.min(count))
                    }
                })
                .collect();
            for (seen, now) in reached.iter_mut().zip(compare(&lines, &kinds)) {
                *seen |= now;
            }
        }
        assert_eq!(reached, [true; 3]);

        // At each limit and one past it. A revision verified for a principal
        // the auditor named has no gap.
        let limit = DETAIL_LIMIT as u64;
        for kind in 0..6 {
            for extra in [0, 1] {
                let past = extra == 1 && kind != 3;
                // One revision: the sequences of the gap and of the digest.
                let one = vec![0; usize::try_from(limit + extra).expect("lines")];
                assert_eq!(compare(&one, &[kind]), [past, past, false]);
                // As many revisions as lines: the digests of the gap.
                let many: Vec<u64> = (0..limit + extra).collect();
                let kinds = vec![kind; many.len()];
                assert_eq!(compare(&many, &kinds), [past, false, past]);
            }
        }
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
        let ancestry = analyze_ancestry(&paths, &mut candidates, &mut errors).expect("ancestry");
        assert_eq!(errors, 1);
        assert_eq!(candidates[0].relation, "changed");
        assert!(candidates[0].tip.is_none());
        assert_eq!(candidates[0].tip_group, None);
        assert_eq!(candidates[1].tip_group, Some(2));
        assert_eq!(ancestry.maximal_groups, vec![2]);
    }
}
