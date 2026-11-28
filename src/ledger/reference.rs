//! Exact-reference checks for cooperating guarded debit submitters, and the
//! reference reconciliation that lets them resume after an adoption that may
//! have lost lines.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{
    Adoption, Parsed, VerifiedEvent, WitnessStatus, append, check_clock, check_new_note, compare,
    debit, evidence, exists, ledger_path, lock_for_writing, prepare_witness, read_view,
    refused_spend, rfc3339, valid_recorded_reason,
};
use crate::files::{load, open_no_follow};
use crate::witness::Witnessed;
use crate::{
    Digest, Error, LoadedPass, MAX_CALLER_REF, Refusal, RefusalCode, SpendRequest, StateDir,
    display_quoted, display_safe, request::check_revision_window, stamp,
};

/// The most caller references one reference reconciliation may list.
pub const MAX_RECONCILED_REFERENCES: usize = 10_000;
/// The largest reference list that [`read_reference_list`] reads, in bytes.
pub const MAX_REFERENCE_LIST_BYTES: u64 = 8 * 1_048_576;

/// The `event` of a reference reconciliation line.
pub(super) const RECONCILE_EVENT: &str = "reconcile-references";

/// Bounded history from a refused guarded debit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ReferenceEvidence {
    pub caller_ref: String,
    /// Every occurrence in a debit, including those beyond the detail limit.
    pub match_count: u64,
    /// The first matching debit sequences in ledger order.
    pub sequences: Vec<u64>,
    /// Additional matching sequences were omitted.
    pub truncated: bool,
    /// The first sequences, in ledger order, of the reference
    /// reconciliations that list the reference. Absent from JSON when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reconciled_at: Vec<u64>,
}

/// A reference reconciliation recorded in the ledger.
///
/// After an adoption that may have lost lines, the operator lists the caller references that may be
/// in those lines, from their run records, and gives a reason. From this
/// line on, a guarded spend refuses a listed reference as a duplicate and
/// checks any other reference against the ledger, until a later adoption
/// may lose lines again. It sits in the hash chain like a spend.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReferenceReconciliation {
    /// The sequence number (shared with spends and adoptions).
    pub seq: u64,
    /// When it was recorded.
    pub time: OffsetDateTime,
    /// The adoption it reconciles: the latest adoption before it that may
    /// have lost lines. It also covers every earlier one.
    pub adoption: u64,
    /// Why the list is complete, in the operator's words. Escape it before
    /// showing it on a terminal.
    pub reason: String,
    /// The digest of the pass at the time.
    pub digest: Digest,
    /// The caller references that may be in the lost lines, in the order
    /// given. Escape each before showing it on a terminal.
    pub references: Vec<String>,
    /// True when the line was written under a test clock
    /// ([`crate::with_test_clock`]): its time is not the real time.
    pub test_clock: bool,
}

/// A reference reconciliation line as written. Its field `references` is
/// one that no other line shape accepts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReconcileLine {
    pub(super) seq: u64,
    pub(super) time: String,
    pub(super) event: String,
    pub(super) adoption: u64,
    pub(super) reason: String,
    pub(super) digest: String,
    pub(super) references: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) test_clock: Option<bool>,
    pub(super) prev: String,
}

/// Check the reference list of a new reconciliation: at most
/// [`MAX_RECONCILED_REFERENCES`] references, each a new caller reference
/// ([`debit::check_new_reference`]), none twice. The message names the first
/// bad entry (counted from 1).
fn check_new_references(references: &[String]) -> Result<(), String> {
    check_reference_list(references, |reference| {
        debit::check_new_reference(reference)
            .map_err(|problem| format!("{problem}. {}", debit::new_reference_rule()))
    })
}

/// Check the reference list of a recorded reconciliation as
/// [`check_new_references`] does, with each reference checked as a recorded
/// caller reference ([`debit::valid_text`]), so a line written earlier stays
/// readable.
fn check_recorded_references(references: &[String]) -> Result<(), String> {
    check_reference_list(references, |reference| {
        if debit::valid_text(reference, MAX_CALLER_REF) {
            Ok(())
        } else {
            Err("is not a recorded caller reference".to_owned())
        }
    })
}

fn check_reference_list(
    references: &[String],
    check: impl Fn(&str) -> Result<(), String>,
) -> Result<(), String> {
    if references.len() > MAX_RECONCILED_REFERENCES {
        return Err(format!(
            "the list has {} references, more than the {MAX_RECONCILED_REFERENCES} one reconciliation may hold. Split it into parts of at most {MAX_RECONCILED_REFERENCES} and record them back to back with the same --adoption, before any spend: each part adds to the earlier ones, but until the last is recorded a reference not yet listed is accepted as new",
            references.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for (index, reference) in references.iter().enumerate() {
        if let Err(problem) = check(reference) {
            return Err(format!(
                "reference {} ({}) is not a caller reference: it {problem}",
                index + 1,
                display_quoted(reference)
            ));
        }
        if !seen.insert(reference.as_str()) {
            return Err(format!(
                "reference {} ({}) is listed twice; list each reference once",
                index + 1,
                display_quoted(reference)
            ));
        }
    }
    Ok(())
}

/// Verify a reference reconciliation line read from the ledger. It must
/// name the latest adoption before it that may have lost lines, as hallpass
/// writes it.
pub(super) fn parse_reconcile(
    parsed: &mut Parsed,
    line: ReconcileLine,
) -> Result<ReferenceReconciliation, &'static str> {
    let bad = "the reference reconciliation record is not valid";
    let (Ok(digest), Ok(time)) = (
        line.digest.parse::<Digest>(),
        OffsetDateTime::parse(&line.time, &Rfc3339),
    ) else {
        return Err(bad);
    };
    if line.event != RECONCILE_EVENT
        || !valid_recorded_reason(&line.reason)
        || check_recorded_references(&line.references).is_err()
    {
        return Err(bad);
    }
    if parsed.lossy_adoption != Some(line.adoption) {
        return Err(
            "the reference reconciliation does not name the latest adoption before it that may have lost lines",
        );
    }
    parsed.last_time = Some(time);
    parsed.reconciled_adoption = Some(line.adoption);
    Ok(ReferenceReconciliation {
        seq: line.seq,
        time,
        adoption: line.adoption,
        reason: line.reason,
        digest,
        references: line.references,
        test_clock: line.test_clock == Some(true),
    })
}

pub(super) struct ReferenceMatches<'a> {
    reference: Option<&'a str>,
    count: u64,
    sequences: Vec<u64>,
    /// The first reconciliations that list the reference: their sequence
    /// and the adoption each names.
    reconciled: Vec<(u64, u64)>,
    /// Logical entries after the header (spends, debits, adoptions, reconciliations).
    lines: u64,
    /// The latest adoption that may have lost references, while no
    /// reconciliation follows it.
    unreconciled: Option<u64>,
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
    may_lose_references(&adoption.carried, adoption.previous.as_ref())
}

/// [`may_have_lost_references`] for an adoption not yet recorded, from what
/// it would carry and the witness it would record as previous.
pub(super) fn may_lose_references(
    carried: &std::collections::BTreeMap<String, u64>,
    previous: Option<&crate::Witnessed>,
) -> bool {
    !carried.is_empty() || previous.is_some_and(|w| w.seq > 0)
}

impl<'a> ReferenceMatches<'a> {
    pub(super) const fn new(reference: Option<&'a str>) -> Self {
        Self {
            reference,
            count: 0,
            sequences: Vec::new(),
            reconciled: Vec::new(),
            lines: 0,
            unreconciled: None,
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
        match event {
            VerifiedEvent::Adopt(adoption) if may_have_lost_references(adoption) => {
                self.unreconciled = Some(adoption.seq);
            }
            // The scan accepts a reconciliation only when it names the
            // latest adoption that may have lost lines.
            VerifiedEvent::Reconcile(reconciliation) => {
                self.unreconciled = None;
                if self.reconciled.len() < evidence::DETAIL_LIMIT
                    && reconciliation.references.iter().any(|r| r == reference)
                {
                    self.reconciled
                        .push((reconciliation.seq, reconciliation.adoption));
                }
            }
            _ => {}
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
        } else if let Some((seq, adoption)) = self.reconciled.first() {
            (
                RefusalCode::DuplicateReference,
                format!(
                    "the caller reference is listed in the reference reconciliation at ledger sequence {seq}, which records that it may have been used in a line lost before the adoption at ledger sequence {adoption}; reconcile it with your run record"
                ),
            )
        } else if let Some(seq) = self.unreconciled {
            (
                RefusalCode::ReferenceInconclusive,
                format!(
                    "cannot establish that the caller reference is new because the adoption at ledger sequence {seq} accepted a ledger that lacks lines hallpass had recorded, so earlier references may be missing from it, and no reference reconciliation follows that adoption. Check the reference against your run record. To let guarded spends resume, list every caller reference that may be in the lost lines (every reference your run records used on this pass) and record the list with `hallpass reconcile-references {} --adoption {seq} --references LIST --reason \"...\"`: guarded spends then refuse the listed references as duplicates and check others against the ledger. Spend without --require-new-ref only if your run record shows this unit was never submitted",
                    loaded.path.display()
                ),
            )
        } else if !witnessed && self.lines > 0 {
            (
                RefusalCode::ReferenceInconclusive,
                format!(
                    "cannot establish that the caller reference is new because the ledger's last logical sequence is {} but there is no local witness, so hallpass cannot tell whether later ledger data was lost (for example in a partial copy). If this ledger is the complete history (for example it moved here with the pass), run `hallpass adopt {} --reason \"...\"`: the adoption keeps every line and carries nothing, a witness is recorded, and later guarded spends check references against this ledger. Otherwise reconcile the reference with your run record",
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
                reconciled_at: self.reconciled.into_iter().map(|(seq, _)| seq).collect(),
            },
        ))
    }
}

/// A reference list file: `{"version": 1, "pass_id": ..., "references": [...]}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceList {
    version: u32,
    pass_id: String,
    references: Vec<String>,
}

/// Read a reference list for [`reconcile_references`] from a JSON file.
///
/// The file holds `{"version": 1, "pass_id": "ID", "references": ["REF", ...]}`, at most
/// [`MAX_REFERENCE_LIST_BYTES`] long. `pass_id` must be `pass_id`, and the
/// references follow the rules of a caller reference, each at most once, at
/// most [`MAX_RECONCILED_REFERENCES`] of them. The list may be empty.
///
/// # Errors
///
/// [`Error::Usage`] for a list that breaks these rules; the file errors of
/// any input (a link, not a regular file, unreadable).
pub fn read_reference_list(path: &Path, pass_id: &str) -> Result<Vec<String>, Error> {
    let file = open_no_follow(path, std::fs::OpenOptions::new().read(true))?;
    let mut bytes = Vec::new();
    file.take(MAX_REFERENCE_LIST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(path, &e))?;
    let usage = |problem: String| {
        Error::Usage(format!(
            "the reference list {}: {problem}; nothing was recorded",
            display_safe(&path.display().to_string())
        ))
    };
    if bytes.len() as u64 > MAX_REFERENCE_LIST_BYTES {
        return Err(usage(format!(
            "is longer than {MAX_REFERENCE_LIST_BYTES} bytes"
        )));
    }
    let list: ReferenceList = serde_json::from_slice(&bytes).map_err(|e| {
        usage(format!(
            "is not a list of the form {{\"version\": 1, \"pass_id\": \"ID\", \"references\": [\"REF\", ...]}} ({e})"
        ))
    })?;
    if list.version != 1 {
        return Err(usage(format!("has version {}; it must be 1", list.version)));
    }
    if list.pass_id != pass_id {
        return Err(usage(format!(
            "is for pass {}, but this pass is {}; use the list written for this pass",
            display_quoted(&list.pass_id),
            display_quoted(pass_id)
        )));
    }
    check_new_references(&list.references).map_err(usage)?;
    Ok(list.references)
}

/// What [`reconcile_references`] recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReconcileReferencesOutcome {
    /// The reconciliation as recorded in the ledger.
    pub reconciliation: ReferenceReconciliation,
    /// The ledger file.
    pub ledger: PathBuf,
    /// The pass id.
    pub pass_id: String,
    /// Ledger or witness warnings (a moved ledger, a witness that was behind).
    pub warnings: Vec<String>,
}

fn nothing_recorded(message: &str) -> Error {
    Error::Usage(format!("{message}. Nothing was recorded"))
}

/// Record a reference reconciliation.
///
/// It is the operator's statement, with a reason, that `references` holds
/// every caller reference that may be in the lines lost by the adoption at
/// sequence `adoption` and by any earlier adoption that may have lost lines.
///
/// `adoption` must be the latest adoption in the ledger that may have lost
/// lines ([`crate::Adoption::makes_references_inconclusive`]), so a list
/// made for one adoption never covers a later one. From the new line on, a
/// guarded spend refuses a listed reference as `duplicate-reference` and
/// checks any other reference against the ledger, until another adoption
/// may lose lines. Recording a second reconciliation for the same adoption
/// adds its references. The list may be empty: that states that no
/// reference was lost. A reconciliation permits nothing and changes no
/// count.
///
/// Under both writer locks it checks the ledger against the witness, as a
/// spend does, appends the line and syncs it, then updates the witness.
///
/// # Errors
///
/// [`Error::Usage`] for a reason or reference that breaks the rules, a
/// ledger with no adoption that may have lost lines, an `adoption` that is
/// not the latest such adoption, or a ledger without a witness (adopt it
/// first). Otherwise as [`crate::adopt`]: an invalid pass, a damaged,
/// foreign, missing or changed ledger, an unusable state directory, a
/// failed write.
pub fn reconcile_references(
    pass_path: &Path,
    adoption: u64,
    references: &[String],
    reason: &str,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<ReconcileReferencesOutcome, Error> {
    check_clock(now)?;
    if reason.trim().is_empty() {
        return Err(nothing_recorded(
            "the reason is empty; say why the list holds every reference that may be in the lost lines",
        ));
    }
    check_new_note(reason).map_err(|m| nothing_recorded(&m.replace("the note", "the reason")))?;
    check_new_references(references).map_err(|m| nothing_recorded(&m))?;
    if !exists(&ledger_path(pass_path))? {
        // A lost ledger is `ledger-missing` (adopt it first); with no
        // ledger and no witnessed line, nothing was ever adopted.
        let loaded = load(pass_path)?;
        read_view(&loaded, state, false)?;
        return Err(nothing_recorded(
            "there is no ledger beside the pass, so there is no adoption whose references could be reconciled",
        ));
    }
    let mut locked = lock_for_writing(pass_path, state, false, None, None, &mut |_| Ok(()))?;
    let id = locked.loaded.pass.id.clone();
    let (status, _) = compare(
        pass_path,
        &locked.path,
        Some(&locked.parsed),
        locked.witness.as_ref(),
        state,
        &id,
    )?;
    if status == WitnessStatus::Missing && locked.parsed.seq > 0 {
        return Err(nothing_recorded(&format!(
            "there is no witness for pass `{id}`, so hallpass cannot tell whether this ledger is complete. If it is the complete history, run `hallpass adopt {} --reason \"...\"` first, then reconcile the references",
            pass_path.display()
        )));
    }
    let Some(latest) = locked.parsed.lossy_adoption else {
        return Err(nothing_recorded(
            "no adoption in this ledger may have lost lines, so there are no references to reconcile: guarded spends already check references against this ledger",
        ));
    };
    if adoption != latest {
        return Err(nothing_recorded(&format!(
            "the latest adoption that may have lost lines is at ledger sequence {latest}, not {adoption}. List every caller reference that may be in lines lost before it, and name it with --adoption {latest}"
        )));
    }
    let (here, warnings) = prepare_witness(pass_path, &locked, state, false)?;
    let line = ReconcileLine {
        seq: locked.parsed.seq + 1,
        time: rfc3339(now),
        event: RECONCILE_EVENT.to_owned(),
        adoption,
        reason: reason.to_owned(),
        digest: locked.loaded.digest.to_string(),
        references: references.to_vec(),
        test_clock: super::clock::marker(),
        prev: locked.parsed.tail().to_string(),
    };
    let text = serde_json::to_string(&line).map_err(|e| Error::Usage(e.to_string()))?;
    let prepared = state.prepare(
        &id,
        &Witnessed {
            ledger: here,
            seq: line.seq,
            tail: Digest::of(text.as_bytes()),
            totals: locked.parsed.tally.spent.clone(),
            updated: stamp(now),
        },
    )?;
    append(&mut locked, &text, "reference reconciliation")?;
    state
        .publish(&id, &prepared)
        .map_err(|e| Error::WitnessUnavailable {
            pass_id: id.clone(),
            dir: state.path().ok().map(Path::to_path_buf),
            detail: format!(
                "the reference reconciliation was recorded in the ledger as entry {}, but the witness could not be updated ({e}); the reconciliation stands, so fix the state directory without recording it again",
                line.seq
            ),
        })?;
    Ok(ReconcileReferencesOutcome {
        reconciliation: ReferenceReconciliation {
            seq: line.seq,
            time: now,
            adoption,
            reason: line.reason,
            digest: locked.loaded.digest,
            references: line.references,
            test_clock: line.test_clock == Some(true),
        },
        ledger: locked.path.clone(),
        pass_id: id,
        warnings,
    })
}
