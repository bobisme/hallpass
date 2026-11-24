//! Versioned debit records share the sequence and witness with legacy spends.

use std::collections::BTreeSet;

use super::{
    Parsed, add, check_note, describe_disguising, has_control, is_disguising,
    is_line_or_bidi_control, longer_than,
};
use crate::{Digest, HostName, MAX_CEILING, MAX_COUNTERS, Target, is_counter_name};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const DEBIT_VERSION: u32 = 1;

/// Maximum length of a caller reference, in characters.
pub const MAX_CALLER_REF: usize = 128;

/// A requested charge from one named counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Charge<'a> {
    /// A counter name.
    pub counter: &'a str,
    /// A strictly positive amount.
    pub amount: u64,
}

/// One charge in a recorded debit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebitCharge {
    /// The counter charged.
    pub counter: String,
    /// The amount charged.
    #[serde(rename = "n")]
    pub amount: u64,
}

/// An approved destination the caller chose to retain in the ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedTarget {
    /// Canonical literal address, port and transport protocol.
    pub target: String,
    /// Canonical request name, when provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The matched pass label.
    pub label: String,
}

/// Data retained only at the caller's explicit request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebitReceipt {
    /// The caller's reference, if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_ref: Option<String>,
    /// Every checked target, in request order, when target recording was requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<RecordedTarget>,
}

/// One debit, irrespective of the number of counters charged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LedgerDebit {
    /// Shared ledger sequence number.
    pub seq: u64,
    /// Time recorded.
    pub time: OffsetDateTime,
    /// Distinct positive charges, in request order.
    pub charges: Vec<DebitCharge>,
    /// The pass digest at decision time.
    pub digest: Digest,
    /// The optional spend note.
    pub note: Option<String>,
    /// The optional provenance chosen by the caller.
    pub receipt: Option<DebitReceipt>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DebitLine {
    pub(super) seq: u64,
    pub(super) time: String,
    pub(super) event: String,
    pub(super) version: u32,
    pub(super) charges: Vec<DebitCharge>,
    pub(super) digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) receipt: Option<DebitReceipt>,
    pub(super) prev: String,
}

pub(super) fn check_charges<'a>(
    count: usize,
    charges: impl Iterator<Item = (&'a str, u64)>,
) -> Result<(), &'static str> {
    if !(1..=MAX_COUNTERS).contains(&count) {
        return Err("a debit needs between 1 and MAX_COUNTERS charges");
    }
    // A debit usually charges a few counters: each of the first few is
    // compared with those before it, without allocating; a set holds the rest.
    let mut first = [""; 8];
    let mut rest = BTreeSet::new();
    for (index, (counter, amount)) in charges.enumerate() {
        if !is_counter_name(counter) || !(1..=MAX_CEILING).contains(&amount) {
            return Err("a charge counter or amount is invalid");
        }
        let repeated = if index < first.len() {
            let repeated = first[..index].contains(&counter);
            first[index] = counter;
            repeated
        } else {
            first.contains(&counter) || !rest.insert(counter)
        };
        if repeated {
            return Err("a debit cannot charge a counter more than once");
        }
    }
    Ok(())
}

/// Check a recorded caller reference, or one to look up: nonblank, at most
/// `max` characters, without a control character, line separator or
/// bidirectional control. This is the rule references were written under
/// before every Unicode format character, invisible character, look-alike
/// space and surrounding space was refused, so a ledger written earlier
/// stays readable and its references can still be looked up. A new
/// reference must pass [`check_new_reference`].
pub(super) fn valid_text(text: &str, max: usize) -> bool {
    // The disguising characters are all outside ASCII.
    !text.trim().is_empty()
        && !longer_than(text, max)
        && !has_control(text)
        && (text.is_ascii() || !text.chars().any(is_line_or_bidi_control))
}

/// Check a caller reference before it is recorded: nonblank, at most
/// [`MAX_CALLER_REF`] characters, without a control character, without a
/// disguising character ([`is_disguising`]: a line separator, a Unicode
/// format character such as U+200B or U+202E, another invisible character
/// such as U+034F or U+FE0F, or a look-alike space such as U+00A0) and
/// without leading or trailing spaces. Two references that differ only in
/// such characters could look the same. The error says what is wrong, after
/// "the reference".
pub(super) fn check_new_reference(text: &str) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("is blank".to_owned());
    }
    if longer_than(text, MAX_CALLER_REF) {
        return Err(format!("is longer than {MAX_CALLER_REF} characters"));
    }
    if has_control(text) {
        return Err("contains a control character (such as a newline or tab)".to_owned());
    }
    if let Some(c) = text.chars().find(|c| is_disguising(*c)) {
        return Err(format!(
            "contains {}, which can make it display as something else",
            describe_disguising(c)
        ));
    }
    if text.trim() != text {
        return Err("has leading or trailing spaces".to_owned());
    }
    Ok(())
}

/// The rule of [`check_new_reference`], as a sentence for a message.
pub(super) fn new_reference_rule() -> String {
    format!(
        "A caller reference is nonblank, at most {MAX_CALLER_REF} characters, without leading or trailing spaces, control characters, line separators, Unicode format characters, other invisible characters or spaces other than the ASCII space"
    )
}

/// How many distinct valid recorded targets one ledger scan remembers.
pub(super) const KNOWN_TARGETS: usize = 16;

fn valid_target(entry: &RecordedTarget) -> bool {
    entry
        .target
        .parse::<Target>()
        .is_ok_and(|target| target.to_string() == entry.target)
        && entry
            .name
            .as_deref()
            .is_none_or(|name| HostName::canonical(name).is_ok())
        && crate::pass::is_identifier(&entry.label)
}

/// Check a recorded receipt. A target's validity depends only on its text, so
/// a target in `known` (found valid earlier in the same scan) is not parsed
/// again: a caller that records its targets repeats the same few on every line.
fn valid_receipt(receipt: &DebitReceipt, known: &mut Vec<RecordedTarget>) -> bool {
    (receipt.caller_ref.is_some() || !receipt.targets.is_empty())
        && receipt
            .caller_ref
            .as_deref()
            .is_none_or(|text| valid_text(text, MAX_CALLER_REF))
        && receipt.targets.len() <= MAX_TARGETS
        && receipt.targets.iter().all(|entry| {
            if known.contains(entry) {
                return true;
            }
            let valid = valid_target(entry);
            if valid && known.len() < KNOWN_TARGETS {
                known.push(entry.clone());
            }
            valid
        })
}

pub(super) fn parse_debit(
    parsed: &mut Parsed,
    line: DebitLine,
) -> Result<LedgerDebit, &'static str> {
    if line.event != "debit" || line.version != DEBIT_VERSION {
        return Err("unsupported debit event or version");
    }
    check_charges(
        line.charges.len(),
        line.charges.iter().map(|c| (c.counter.as_str(), c.amount)),
    )?;
    let (Some(digest), Ok(time)) = (
        parsed.pass_digest(&line.digest),
        OffsetDateTime::parse(&line.time, &Rfc3339),
    ) else {
        return Err("the debit time or digest is invalid");
    };
    if line.note.as_deref().is_some_and(|n| check_note(n).is_err())
        || line
            .receipt
            .as_ref()
            .is_some_and(|r| !valid_receipt(r, &mut parsed.valid_targets))
    {
        return Err("the debit note or receipt is invalid");
    }
    for charge in &line.charges {
        add(&mut parsed.tally.spent, &charge.counter, charge.amount)
            .ok_or("the recorded amounts add up beyond any ceiling")?;
    }
    parsed.tally.entries += 1;
    parsed.last_time = Some(time);
    Ok(LedgerDebit {
        seq: line.seq,
        time,
        charges: line.charges,
        digest,
        note: line.note,
        receipt: line.receipt,
    })
}

use std::path::Path;

use super::{
    SpendRequest, append, check_clock, decide_ceiling, decide_spend_targets,
    lock_for_writing_notifying, prepare_witness,
    reference::{ReferenceEvidence, ReferenceMatches},
    rfc3339, validate_spend_policy, visit_preview_snapshot, warn_clock_rollback,
};
use crate::request::TargetRefusal;
use crate::witness::PreparedWitness;
use crate::{
    Error, LoadedPass, MAX_TARGETS, Refusal, StateDir, Tally, WitnessStatus, Witnessed, stamp,
};

/// An atomic debit and the policy inputs shared by all its charges.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SpendChargesRequest<'a> {
    /// All charges for this unit.
    pub charges: &'a [Charge<'a>],
    /// Common spend policy. Its scalar counter and amount are ignored.
    pub policy: SpendRequest<'a>,
    /// Optional caller/run correlation reference retained on disk.
    pub caller_ref: Option<&'a str>,
    /// Refuse a reference already in this pass's verified history or whose absence is inconclusive.
    pub require_new_ref: bool,
    /// Retain the target, request name and matching label on disk.
    pub record_targets: bool,
    /// Evaluate current policy and balances without modifying ledger or witness.
    pub dry_run: bool,
}

impl<'a> SpendChargesRequest<'a> {
    /// Construct a debit, with no provenance collection by default.
    #[must_use]
    pub const fn new(charges: &'a [Charge<'a>]) -> Self {
        let (counter, amount) = match charges.first() {
            Some(charge) => (charge.counter, charge.amount),
            None => ("", 0),
        };
        Self {
            charges,
            policy: SpendRequest::new(counter, amount),
            caller_ref: None,
            require_new_ref: false,
            record_targets: false,
            dry_run: false,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        let usage = |message| Error::Usage(format!("{message}; nothing was recorded"));
        validate_unit(self.charges, &self.policy)?;
        if self.dry_run && self.policy.lock_timeout.is_some() {
            return Err(usage("a lock timeout applies only to a committing spend"));
        }
        if self.policy.target.is_none() && self.record_targets {
            return Err(usage("recording a target requires a target"));
        }
        if self.require_new_ref && self.caller_ref.is_none() {
            return Err(usage(
                "requiring a new reference also requires a caller reference",
            ));
        }
        if let Some(problem) = self
            .caller_ref
            .and_then(|text| check_new_reference(text).err())
        {
            return Err(Error::Usage(format!(
                "the caller reference {problem}. {}; nothing was recorded",
                new_reference_rule()
            )));
        }
        Ok(())
    }

    fn reference_matches(&self) -> ReferenceMatches<'a> {
        ReferenceMatches::new(self.caller_ref.filter(|_| self.require_new_ref))
    }
}

pub(super) fn validate_unit(
    charges: &[Charge<'_>],
    policy: &SpendRequest<'_>,
) -> Result<(), Error> {
    check_charges(charges.len(), charges.iter().map(|c| (c.counter, c.amount)))
        .map_err(|message| Error::Usage(format!("{message}; nothing was recorded")))?;
    validate_spend_policy(policy)
}

/// The balance and requested amount for one counter in a debit decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ChargeOutcome {
    /// The counter.
    pub counter: String,
    /// The requested amount.
    #[serde(rename = "n")]
    pub amount: u64,
    /// The pass's ceiling.
    pub total: Option<u64>,
    /// The recorded amount, including this debit only after it commits.
    pub spent: u64,
    /// The budget available after this decision.
    pub remaining: Option<u64>,
    /// Projected total on a positive dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected_spent: Option<u64>,
}

/// The decision about all requested charges, with one shared sequence on success.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpendChargesOutcome {
    /// A policy refusal, if any.
    pub refusal: Option<Refusal>,
    /// Balances in request order.
    pub charges: Vec<ChargeOutcome>,
    /// Present only after the ledger debit and witness have both succeeded.
    pub seq: Option<u64>,
    /// The digest used for the decision.
    pub digest: Digest,
    /// The clock used for the decision under the ledger lock.
    pub now: OffsetDateTime,
    /// The pass identifier.
    pub pass_id: String,
    /// Matched destination labels in request order, when all charges fit.
    pub labels: Vec<String>,
    /// One-based index of a target-specific refusal.
    pub refused_target: Option<usize>,
    /// Provenance retained by a successful commit.
    pub receipt: Option<DebitReceipt>,
    /// Historical evidence for a duplicate or inconclusive caller reference.
    pub reference_evidence: Option<ReferenceEvidence>,
    /// Ledger or witness warnings.
    pub warnings: Vec<String>,
}

/// Decide an atomic debit using the process's state directory.
///
/// # Errors
///
/// See [`spend_charges_in`].
pub fn spend_charges(
    pass_path: &Path,
    request: &SpendChargesRequest<'_>,
    now: OffsetDateTime,
) -> Result<SpendChargesOutcome, Error> {
    spend_charges_in(pass_path, request, now, &StateDir::from_env())
}

/// Decide an atomic debit using an explicit clock and state directory.
///
/// On a policy refusal every charge keeps its previous balance. On successful
/// commit, one ledger line is appended and synced before the witness records
/// all resulting balances. Only success with a sequence authorizes the caller
/// to proceed. A dry run observes current balances and reserves no funds.
/// A guarded reference checks local history under both writer locks. Use
/// the caller's own execution record to reconcile any observed duplicate.
///
/// # Errors
///
/// Invalid requests, unverifiable state and I/O errors stop the caller. On
/// [`Error::WitnessNotUpdated`] the debit is already synced. After an append
/// I/O error, the ledger may contain the debit or a partial line. Reconcile
/// the sequence and charges with the verified ledger before retrying.
pub fn spend_charges_in(
    pass_path: &Path,
    request: &SpendChargesRequest<'_>,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<SpendChargesOutcome, Error> {
    check_clock(now)?;
    spend_charges_with_clock_in(pass_path, request, state, || now)
}

/// As [`spend_charges_in`], with a clock sampled after acquiring the ledger
/// lock for commit or after reading the ledger for a dry run.
///
/// # Errors
///
/// See [`spend_charges_in`].
pub fn spend_charges_with_clock_in(
    pass_path: &Path,
    request: &SpendChargesRequest<'_>,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
) -> Result<SpendChargesOutcome, Error> {
    spend_using(pass_path, request, state, clock, StateDir::publish)
}

fn spend_using(
    pass_path: &Path,
    request: &SpendChargesRequest<'_>,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
    write_witness: impl FnOnce(&StateDir, &str, &PreparedWitness) -> Result<(), Error>,
) -> Result<SpendChargesOutcome, Error> {
    request.validate()?;
    if request.dry_run {
        return preview(pass_path, request, state, clock);
    }
    let mut matches = request.reference_matches();
    let mut locked = lock_for_writing_notifying(
        pass_path,
        state,
        false,
        None,
        request.policy.lock_timeout,
        request.policy.on_lock_wait,
        &mut |event| {
            matches.observe(event);
            Ok(())
        },
    )?;
    let (identity, warnings) =
        prepare_witness(pass_path, &locked, state, !request.require_new_ref)?;
    let now = clock();
    check_clock(now)?;
    let reference = matches.refusal(
        &locked.loaded,
        &request.policy,
        now,
        locked.witness.is_some(),
    );
    let mut result = decide_debit(
        &locked.loaded,
        &locked.parsed.tally,
        request,
        now,
        warnings,
        locked.parsed.last_time,
        reference,
    );
    if result.refusal.is_some() {
        return Ok(result);
    }
    let entry = DebitLine {
        seq: locked.parsed.seq + 1,
        time: rfc3339(now),
        event: "debit".to_owned(),
        version: DEBIT_VERSION,
        charges: request
            .charges
            .iter()
            .map(|c| DebitCharge {
                counter: c.counter.to_owned(),
                amount: c.amount,
            })
            .collect(),
        digest: result.digest.to_string(),
        note: request.policy.note.map(str::to_owned),
        receipt: make_receipt(request, &result.labels),
        prev: locked.parsed.tail().to_string(),
    };
    let mut totals = locked.parsed.tally.spent.clone();
    for charge in &mut result.charges {
        charge.spent = charge.spent.checked_add(charge.amount).ok_or_else(|| {
            Error::Usage("a charge exceeds the maximum total; nothing was recorded".to_owned())
        })?;
        charge.remaining = charge.total.map(|total| total - charge.spent);
        totals.insert(charge.counter.clone(), charge.spent);
    }
    let line = serde_json::to_string(&entry).map_err(|e| Error::Usage(e.to_string()))?;
    let prepared = state.prepare(
        &result.pass_id,
        &Witnessed {
            ledger: identity,
            seq: entry.seq,
            tail: Digest::of(line.as_bytes()),
            totals,
            updated: stamp(now),
        },
    )?;
    append(&mut locked, &line, "debit")?;
    write_witness(state, &result.pass_id, &prepared).map_err(|e| Error::WitnessNotUpdated {
        path: locked.path,
        seq: entry.seq,
        detail: e.to_string(),
    })?;
    result.seq = Some(entry.seq);
    result.receipt = entry.receipt;
    Ok(result)
}

pub(super) fn decide_debit_policy(
    loaded: &LoadedPass,
    policy: &SpendRequest<'_>,
    charges: &[Charge<'_>],
    now: OffsetDateTime,
) -> Result<Vec<String>, TargetRefusal> {
    let labels = decide_spend_targets(loaded, policy, now)?;
    super::check_known_counters(&loaded.pass, charges.iter().map(|c| c.counter))
        .and_then(|()| {
            super::check_required_charges(&loaded.pass, |name| {
                charges.iter().any(|c| c.counter == name)
            })
        })
        .map_err(|reason| TargetRefusal {
            reason,
            index: None,
        })?;
    Ok(labels)
}

pub(super) fn decide_debit(
    loaded: &LoadedPass,
    tally: &Tally,
    request: &SpendChargesRequest<'_>,
    now: OffsetDateTime,
    mut warnings: Vec<String>,
    last_time: Option<OffsetDateTime>,
    reference: Option<(Refusal, ReferenceEvidence)>,
) -> SpendChargesOutcome {
    warn_clock_rollback(now, last_time, &mut warnings);
    let mut charges: Vec<_> = request
        .charges
        .iter()
        .map(|c| {
            let total = loaded.pass.ceilings.get(c.counter).copied();
            let spent = tally.spent(c.counter);
            ChargeOutcome {
                counter: c.counter.to_owned(),
                amount: c.amount,
                total,
                spent,
                remaining: total.map(|limit| limit.saturating_sub(spent)),
                projected_spent: None,
            }
        })
        .collect();
    let (reference_refusal, reference_evidence) = reference.unzip();
    let decision = reference_refusal
        .map_or(Ok(()), |reason| {
            Err(TargetRefusal {
                reason,
                index: None,
            })
        })
        .and_then(|()| decide_debit_policy(loaded, &request.policy, request.charges, now))
        .and_then(|labels| {
            for c in &charges {
                decide_ceiling(&loaded.pass, &c.counter, c.amount, c.spent).map_err(|reason| {
                    TargetRefusal {
                        reason,
                        index: None,
                    }
                })?;
            }
            Ok(labels)
        });
    let (refusal, refused_target, labels) = match decision {
        Ok(labels) => (None, None, labels),
        Err(refusal) => (Some(refusal.reason), refusal.index, Vec::new()),
    };
    if request.dry_run && refusal.is_none() {
        for charge in &mut charges {
            // decide_ceiling accepted this exact sum for every charge.
            charge.projected_spent = charge.spent.checked_add(charge.amount);
        }
    }
    SpendChargesOutcome {
        refusal,
        charges,
        seq: None,
        digest: loaded.digest,
        now,
        pass_id: loaded.pass.id.clone(),
        labels,
        refused_target,
        receipt: None,
        reference_evidence,
        warnings,
    }
}

fn make_receipt(request: &SpendChargesRequest<'_>, labels: &[String]) -> Option<DebitReceipt> {
    if request.caller_ref.is_none() && !request.record_targets {
        return None;
    }
    let mut targets = Vec::new();
    if request.record_targets {
        targets.extend(
            request
                .policy
                .targets()
                .zip(labels)
                .map(|((target, name), label)| RecordedTarget {
                    target: target.to_string(),
                    name: name.map(ToString::to_string),
                    label: label.clone(),
                }),
        );
    }
    Some(DebitReceipt {
        caller_ref: request.caller_ref.map(str::to_owned),
        targets,
    })
}

fn preview(
    pass_path: &Path,
    request: &SpendChargesRequest<'_>,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
) -> Result<SpendChargesOutcome, Error> {
    let mut matches = request.reference_matches();
    let (loaded, mut view) = visit_preview_snapshot(pass_path, state, &mut |event| {
        matches.observe(event);
        Ok(())
    })?;
    let now = clock();
    check_clock(now)?;
    let reference = matches.refusal(
        &loaded,
        &request.policy,
        now,
        view.witness != WitnessStatus::Missing,
    );
    let outcome = decide_debit(
        &loaded,
        &view.tally,
        request,
        now,
        std::mem::take(&mut view.warnings),
        view.last_time,
        reference,
    );
    if outcome.refusal.is_none() {
        for charge in &outcome.charges {
            view.tally
                .spent
                .insert(charge.counter.clone(), charge.spent + charge.amount);
        }
        view.check_next_witness(state, &loaded.pass.id)?;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, RefusalCode, WitnessStatus, adopt, load, read_ledger, spend_in};
    use proptest::prelude::*;
    use std::{fmt::Write as _, fs, io::Cursor, os::unix::fs::PermissionsExt, path::PathBuf};
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);
    const HEADER: &str = r#"{"hallpass_ledger":1,"pass_id":"example-2026-11"}"#;

    fn setup() -> (tempfile::TempDir, PathBuf, StateDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("accounting.toml");
        let pass = crate::pass::tests::GOOD.replace("requests = 500", "requests = 1\nbytes = 100");
        fs::write(&path, pass).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let state = StateDir::new(dir.path().join("state").join("hallpass"));
        (dir, path, state)
    }

    #[test]
    fn clock_is_sampled_after_preparatory_witness() {
        let (_dir, path, state) = setup();
        let charges = [Charge {
            counter: "calls",
            amount: 1,
        }];
        let req = SpendChargesRequest::new(&charges);
        let result = spend_charges_with_clock_in(&path, &req, &state, || {
            assert!(state.witness_path("acme-2026-11").expect("path").exists());
            datetime!(2026-11-20 17:00 UTC)
        })
        .expect("decision");
        assert_eq!(result.refusal.expect("expired").code, RefusalCode::Expired);
        assert_eq!(
            read_ledger(&load(&path).expect("pass"), &state)
                .expect("ledger")
                .tally
                .entries,
            0
        );
    }

    fn fixture_debit(previous: &str, charges: &str) -> String {
        format!(
            r#"{{"seq":2,"time":"2026-11-20T09:00:00Z","event":"debit","version":1,"charges":{charges},"digest":"{digest}","prev":"{prev}"}}"#,
            digest = Digest::of(b"fixture pass"),
            prev = Digest::of(previous.as_bytes()),
        )
    }

    // The legacy decoder accepted only these two exact record shapes.
    #[derive(Deserialize)]
    #[serde(untagged)]
    #[allow(dead_code)]
    enum LegacyRecord {
        Spend(LegacySpend),
        Adopt(LegacyAdopt),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct LegacySpend {
        seq: u64,
        time: String,
        counter: String,
        n: u64,
        digest: String,
        note: Option<String>,
        prev: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct LegacyAdopt {
        seq: u64,
        time: String,
        event: String,
        reason: String,
        digest: String,
        carried: std::collections::BTreeMap<String, u64>,
        witness: Option<serde_json::Value>,
        prev: String,
    }

    #[test]
    fn hand_written_mixed_ledger_and_incompatible_decoder() {
        let path = Path::new("fixture");
        let legacy = format!(
            r#"{{"seq":1,"time":"2026-11-20T09:00:00Z","counter":"requests","n":1,"digest":"{digest}","note":"old note","prev":"{prev}"}}"#,
            digest = Digest::of(b"fixture pass"),
            prev = Digest::of(HEADER.as_bytes()),
        );
        let charges = r#"[{"counter":"requests","n":1},{"counter":"bytes","n":100}]"#;
        let debit = fixture_debit(&legacy, charges);
        let parse = |text: &str| {
            super::super::parse_ledger(path, Cursor::new(text), "example-2026-11", true, None)
        };
        let parsed = parse(&format!("{HEADER}\n{legacy}\n{debit}\n")).expect("mixed ledger");
        assert_eq!(parsed.tally.entries, 2);
        assert_eq!(parsed.entries[0].note.as_deref(), Some("old note"));
        assert_eq!(parsed.debits.len(), 1);
        assert_eq!(parsed.debits[0].charges.len(), 2);
        assert_eq!(parsed.tally.spent("requests"), 2);
        assert_eq!(parsed.tally.spent("bytes"), 100);
        assert!(serde_json::from_str::<LegacyRecord>(&legacy).is_ok());
        assert!(serde_json::from_str::<LegacyRecord>(&debit).is_err());

        for invalid in [
            debit.replace(r#""version":1"#, r#""version":2"#),
            debit.replace(r#""version":1"#, r#""version":1,"extra":true"#),
            debit.replace(r#""bytes","n":100"#, r#""bytes","n":100,"extra":true"#),
            debit.replace(r#""bytes""#, r#""requests""#),
            debit.replace(r#""n":100"#, r#""n":0"#),
            debit.replace(r#""n":100"#, r#""n":-1"#),
            debit.replace(r#""n":100"#, r#""n":1.5"#),
            debit.replace(r#""n":100"#, &format!(r#""n":{}"#, MAX_CEILING + 1)),
            debit.replace(r#""n":1"#, &format!(r#""n":{MAX_CEILING}"#)),
            debit.replace(&Digest::of(legacy.as_bytes()).to_string(), "wrong"),
        ] {
            assert!(
                parse(&format!("{HEADER}\n{legacy}\n{invalid}\n")).is_err(),
                "{invalid}"
            );
        }
        let invalid_label = debit.replace(
            r#""version":1"#,
            r#""version":1,"receipt":{"targets":[{"target":"192.0.2.10:5060/udp","label":"invalid label"}]}"#,
        );
        assert!(parse(&format!("{HEADER}\n{legacy}\n{invalid_label}\n")).is_err());
        assert!(parse(&format!("{HEADER}\n{legacy}\n{debit}")).is_err());
    }

    const fn costs(bytes: u64) -> [Charge<'static>; 2] {
        [
            Charge {
                counter: "requests",
                amount: 1,
            },
            Charge {
                counter: "bytes",
                amount: bytes,
            },
        ]
    }

    #[test]
    fn refusal_then_success_and_adoption() {
        let (_dir, path, state) = setup();
        let refusal = spend_charges_in(&path, &SpendChargesRequest::new(&costs(101)), NOW, &state)
            .expect("refusal");
        assert_eq!(
            refusal.refusal.expect("refused").code,
            RefusalCode::CeilingReached
        );
        assert!(refusal.charges.iter().all(|c| c.spent == 0));
        let ledger = crate::ledger_path(&path);
        let older = fs::read(&ledger).expect("header");
        let charges = costs(100);
        let mut request = SpendChargesRequest::new(&charges);
        request.caller_ref = Some("run \"unit\" \\ 01");
        request.record_targets = true;
        request.policy.target = Some("192.0.2.10:5060/udp".parse().expect("target"));
        let name = HostName::canonical("sip.example.net").expect("name");
        request.policy.name = Some(&name);
        request.policy.expect_digest = Some(Digest::of(b"stale"));
        let changed_pass = spend_charges_in(&path, &request, NOW, &state).expect("stale");
        assert_eq!(
            changed_pass.refusal.expect("refusal").code,
            RefusalCode::PassChanged
        );
        request.policy.expect_digest = None;
        request.policy.target = Some("192.0.2.11:5060/udp".parse().expect("target"));
        let denied = spend_charges_in(&path, &request, NOW, &state).expect("policy");
        assert!(denied.refusal.is_some());
        assert_eq!(fs::read(&ledger).expect("unchanged"), older);
        request.policy.target = Some("192.0.2.10:5060/udp".parse().expect("target"));
        let committed = spend_charges_in(&path, &request, NOW, &state).expect("commit");
        assert_eq!(committed.seq, Some(1));
        assert!(committed.charges.iter().all(|c| c.remaining == Some(0)));
        let loaded = load(&path).expect("load");
        let view = read_ledger(&loaded, &state).expect("view");
        let summary = crate::read_summary(&loaded, &state).expect("summary");
        assert_eq!(summary.debits, Vec::new());
        assert_eq!(summary.tally, view.tally);
        assert_eq!(summary.last_time, Some(NOW));
        assert_eq!(view.debits[0].receipt, committed.receipt);
        assert_eq!(
            view.debits[0].receipt.as_ref().expect("receipt").targets[0]
                .name
                .as_deref(),
            Some("sip.example.net")
        );

        fs::write(&ledger, older).expect("restore");
        let adopted = adopt(&path, "restored an older ledger", NOW, &state).expect("adopt");
        assert_eq!(adopted.adoption.carried["requests"], 1);
        assert_eq!(adopted.adoption.carried["bytes"], 100);
    }

    #[test]
    fn synced_debit_is_visible_after_witness_failure() {
        let (_dir, path, state) = setup();
        let charges = costs(100);
        let request = SpendChargesRequest::new(&charges);
        let failure = spend_using(
            &path,
            &request,
            &state,
            || NOW,
            |_, _, _| Err(Error::Usage("simulated witness failure".to_owned())),
        );
        assert!(matches!(
            failure,
            Err(Error::WitnessNotUpdated { seq: 1, .. })
        ));
        let view = read_ledger(&load(&path).expect("pass"), &state).expect("reconcile");
        assert_ne!(view.witness, WitnessStatus::Matches);
        assert_eq!(view.debits[0].seq, 1);
        assert_eq!(view.tally.spent("requests"), 1);
        assert_eq!(view.tally.spent("bytes"), 100);
        let retry = spend_charges_in(&path, &request, NOW, &state).expect("retry refused");
        assert_eq!(
            retry.refusal.expect("refusal").code,
            RefusalCode::CeilingReached
        );
        assert_eq!(
            read_ledger(&load(&path).expect("pass"), &state)
                .expect("view")
                .tally
                .entries,
            1
        );
    }

    #[test]
    fn guarded_retry_verifies_past_a_match_after_a_witness_failure() {
        let (_dir, path, state) = setup();
        let charges = costs(100);
        let mut request = SpendChargesRequest::new(&charges);
        request.require_new_ref = true;
        assert!(matches!(
            spend_charges_in(&path, &request, NOW, &state),
            Err(Error::Usage(_))
        ));
        assert!(!crate::ledger_path(&path).exists());
        request.caller_ref = Some("synced");
        let failure = spend_using(
            &path,
            &request,
            &state,
            || NOW,
            |_, _, _| Err(Error::Usage("simulated witness failure".to_owned())),
        );
        assert!(matches!(
            failure,
            Err(Error::WitnessNotUpdated { seq: 1, .. })
        ));
        let loaded = load(&path).expect("pass");
        let ledger = crate::ledger_path(&path);
        let durable = fs::read_to_string(&ledger).expect("synced ledger");
        let summary = crate::read_summary(&loaded, &state).expect("verified extension");
        assert_eq!(summary.witness, WitnessStatus::Extended { added: 1 });

        fs::write(&ledger, format!("{durable}malformed suffix\n")).expect("damage fixture");
        for preview in [false, true] {
            request.dry_run = preview;
            assert!(matches!(
                spend_charges_in(&path, &request, NOW, &state),
                Err(Error::LedgerCorrupt { line: 3, .. })
            ));
        }
        fs::write(&ledger, &durable).expect("restore fixture");
        for preview in [true, false] {
            request.dry_run = preview;
            let outcome = spend_charges_in(&path, &request, NOW, &state).expect("decision");
            assert_eq!(outcome.seq, None);
            assert_eq!(
                outcome.refusal.expect("duplicate").code,
                RefusalCode::DuplicateReference
            );
            assert_eq!(outcome.reference_evidence.expect("evidence").sequences, [1]);
        }
        assert_eq!(fs::read_to_string(ledger).expect("ledger"), durable);
        let summary = crate::read_summary(&loaded, &state).expect("verified tip");
        assert_eq!(summary.witness, WitnessStatus::Matches);
        assert_eq!(summary.tally.entries, 1);
    }

    #[test]
    fn guarded_matching_bounds_details_and_counts_every_unguarded_duplicate() {
        let (_dir, path, state) = setup();
        let count = super::super::evidence::DETAIL_LIMIT + 1;
        let source =
            crate::pass::tests::GOOD.replace("calls = 6", &format!("calls = {}", count + 1));
        fs::write(&path, source).expect("pass");
        let charges = [Charge {
            counter: "calls",
            amount: 1,
        }];
        let mut request = SpendChargesRequest::new(&charges);
        request.caller_ref = Some("correlation-only");
        for seq in 1..=count as u64 {
            assert_eq!(
                spend_charges_in(&path, &request, NOW, &state)
                    .expect("committed")
                    .seq,
                Some(seq)
            );
        }
        request.require_new_ref = true;
        let reply = spend_charges_in(&path, &request, NOW, &state).expect("duplicate");
        assert_eq!(reply.seq, None);
        assert_eq!(
            reply.refusal.expect("refused").code,
            RefusalCode::DuplicateReference
        );
        let evidence = reply.reference_evidence.expect("evidence");
        assert_eq!(evidence.match_count, count as u64);
        assert_eq!(evidence.sequences, (1..count as u64).collect::<Vec<_>>());
        assert!(evidence.truncated);
    }

    #[test]
    fn overlapping_concurrent_debits_replay_against_serial_model() {
        let (_dir, path, state) = setup();
        let pass = fs::read_to_string(&path)
            .expect("read")
            .replace("requests = 1", "requests = 8");
        fs::write(&path, pass).expect("write");
        let start = std::sync::Barrier::new(9);
        let outcomes = std::thread::scope(|scope| {
            let workers = [9, 40, 11, 22, 6, 80, 12, 5, 32].map(|bytes| {
                let (path, state, start) = (&path, &state, &start);
                scope.spawn(move || {
                    let charges = costs(bytes);
                    start.wait();
                    spend_charges_in(path, &SpendChargesRequest::new(&charges), NOW, state)
                        .expect("decision")
                })
            });
            workers.map(|worker| worker.join().expect("worker"))
        });
        let view = read_ledger(&load(&path).expect("pass"), &state).expect("view");
        let mut reference = std::collections::BTreeMap::new();
        for (idx, event) in view.debits.iter().enumerate() {
            assert_eq!(event.seq, (idx + 1) as u64);
            let committed = outcomes
                .iter()
                .find(|o| o.seq == Some(event.seq))
                .expect("commit");
            for charge in &event.charges {
                let total = reference.entry(charge.counter.clone()).or_insert(0);
                *total += charge.amount;
                let balance = committed
                    .charges
                    .iter()
                    .find(|c| c.counter == charge.counter)
                    .expect("balance");
                assert_eq!(balance.spent, *total);
                assert!(*total <= balance.total.expect("ceiling"));
            }
        }
        assert_eq!(view.tally.spent, reference);
        assert_eq!(view.witness, WitnessStatus::Matches);
        assert!(outcomes.iter().any(|o| o.refusal.is_some()));
        for refusal in outcomes.iter().filter(|o| o.refusal.is_some()) {
            assert!(refusal.seq.is_none());
            assert!(
                refusal
                    .charges
                    .iter()
                    .any(|c| c.amount + reference[&c.counter] > c.total.expect("ceiling"))
            );
        }
    }

    proptest! {
        #[test]
        fn multi_charge_decision_matches_serial_balances(
            starting in proptest::collection::vec(0_u64..=12, 1..=4),
            amounts in proptest::collection::vec(1_u64..=12, 1..=4),
        ) {
            let (_dir, path, state) = setup();
            let names = ["a", "b", "c", "d"];
            let mut pass = fs::read_to_string(&path).expect("pass");
            for name in names { writeln!(pass, "{name} = 12").expect("format"); }
            fs::write(&path, pass).expect("pass");
            let mut initial = [0; 4];
            for (idx, n) in starting.into_iter().enumerate() {
                if n != 0 {
                    spend_in(&path, &SpendRequest::new(names[idx], n), NOW, &state).expect("starting");
                    initial[idx] = n;
                }
            }
            let charges: Vec<_> = amounts.iter().enumerate().map(|(idx, &amount)| Charge {
                counter: names[idx], amount,
            }).collect();
            let fits = amounts.iter().enumerate().all(|(idx, amount)| initial[idx] + amount <= 12);
            let result = spend_charges_in(&path, &SpendChargesRequest::new(&charges), NOW, &state).expect("decision");
            prop_assert_eq!(result.seq.is_some(), fits);
            let view = read_ledger(&load(&path).expect("pass"), &state).expect("view");
            for (idx, name) in names.into_iter().enumerate() {
                let expected = initial[idx] + if fits { amounts.get(idx).copied().unwrap_or(0) } else { 0 };
                prop_assert_eq!(view.tally.spent(name), expected);
            }
        }
    }

    // The validation that every ledger line passes has fast paths for ASCII
    // text and for debits with few charges. Each must decide exactly as the
    // definition it replaced, which these copies keep.

    fn defined_valid_text(text: &str, max: usize) -> bool {
        !text.trim().is_empty()
            && text.chars().count() <= max
            && !text
                .chars()
                .any(|c| c.is_control() || is_line_or_bidi_control(c))
    }

    /// A new reference: a recorded one without surrounding spaces or any
    /// disguising character.
    fn defined_new_reference(text: &str) -> bool {
        defined_valid_text(text, MAX_CALLER_REF)
            && text.trim() == text
            && !text.chars().any(is_disguising)
    }

    fn defined_note(note: &str) -> bool {
        !note.chars().any(char::is_control) && note.chars().count() <= crate::MAX_NOTE
    }

    fn defined_charges(charges: &[(String, u64)]) -> Result<(), &'static str> {
        if !(1..=MAX_COUNTERS).contains(&charges.len()) {
            return Err("a debit needs between 1 and MAX_COUNTERS charges");
        }
        let mut seen = BTreeSet::new();
        for (counter, amount) in charges {
            if !is_counter_name(counter) || !(1..=MAX_CEILING).contains(amount) {
                return Err("a charge counter or amount is invalid");
            }
            if !seen.insert(counter) {
                return Err("a debit cannot charge a counter more than once");
            }
        }
        Ok(())
    }

    fn defined_add(
        totals: &mut std::collections::BTreeMap<String, u64>,
        counter: &str,
        n: u64,
    ) -> Option<()> {
        if !totals.contains_key(counter) {
            totals.insert(counter.to_owned(), 0);
        }
        let total = totals.get_mut(counter)?;
        *total = total.checked_add(n).filter(|t| *t <= MAX_CEILING)?;
        Some(())
    }

    /// Text near the edge of every check: ASCII and its controls, the C1
    /// controls, the disguising characters, other non-ASCII text and blanks.
    fn edge_text() -> BoxedStrategy<String> {
        prop_oneof![
            "[ -~]{0,12}",
            "[\\x00-\\x7f]{0,12}",
            "[ a\\t\\x00\\x1f\\x7f\\x{80}\\x{85}\\x{9f}\\x{a0}\\x{ad}\\x{34f}\\x{61c}\\x{2003}\\x{200b}\\x{200e}\\x{2028}\\x{2029}\\x{202e}\\x{2066}\\x{2069}\\x{3000}\\x{3164}\\x{fe0f}\\x{feff}\\x{e0065}\\x{e0100}é]{0,12}",
            any::<String>(),
        ]
        .boxed()
    }

    /// Long notes around [`crate::MAX_NOTE`] characters, in one- and
    /// multi-byte characters.
    fn long_note() -> impl Strategy<Value = String> {
        (
            proptest::sample::select(vec!['a', 'é', '✓', '\u{1f600}']),
            proptest::sample::select(vec!['a', 'é', '\u{85}', '\n']),
            490_usize..510,
            0_usize..510,
        )
            .prop_map(|(fill, other, len, at)| {
                (0..len)
                    .map(|i| if i == at { other } else { fill })
                    .collect()
            })
    }

    fn charge_list() -> impl Strategy<Value = Vec<(String, u64)>> {
        let counter = prop_oneof![
            8 => "[a-l]",
            1 => "[a-z][a-z0-9]{0,2}",
            1 => Just("Bad".to_owned()),
            1 => Just(String::new()),
        ];
        let amount = prop_oneof![
            8 => 1_u64..1000,
            1 => Just(0),
            1 => Just(MAX_CEILING),
            1 => Just(MAX_CEILING + 1),
        ];
        prop_oneof![
            4 => proptest::collection::vec((counter.clone(), amount.clone()), 0..=12),
            1 => proptest::collection::vec((counter, amount), 60..=70),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn text_checks_decide_as_defined(text in edge_text(), max in 0_usize..16) {
            prop_assert_eq!(valid_text(&text, max), defined_valid_text(&text, max));
            prop_assert_eq!(check_new_reference(&text).is_ok(), defined_new_reference(&text));
            prop_assert_eq!(has_control(&text), text.chars().any(char::is_control));
            prop_assert_eq!(longer_than(&text, max), text.chars().count() > max);
            prop_assert_eq!(check_note(&text).is_ok(), defined_note(&text));
        }

        #[test]
        fn long_notes_decide_as_defined(note in long_note()) {
            prop_assert_eq!(check_note(&note).is_ok(), defined_note(&note));
        }

        #[test]
        fn charge_checks_decide_as_defined(charges in charge_list()) {
            let borrowed = charges.iter().map(|(c, n)| (c.as_str(), *n));
            prop_assert_eq!(check_charges(charges.len(), borrowed), defined_charges(&charges));
        }

        #[test]
        fn totals_add_as_defined(
            steps in proptest::collection::vec(
                ("[a-c]", prop_oneof![0_u64..5, Just(MAX_CEILING), Just(MAX_CEILING + 1), Just(u64::MAX)]),
                0..12,
            )
        ) {
            let (mut fast, mut defined) = (std::collections::BTreeMap::new(), std::collections::BTreeMap::new());
            for (counter, n) in steps {
                prop_assert_eq!(add(&mut fast, &counter, n), defined_add(&mut defined, &counter, n));
                prop_assert_eq!(&fast, &defined);
            }
        }
    }
}
