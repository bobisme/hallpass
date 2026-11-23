//! Bounded, local manifests reconciled against a single verified history scan.
use super::evidence::DETAIL_LIMIT;
use super::{VerifiedEvent, debit, display_safe, visit_view};
use crate::{Digest, Error, HostName, LoadedPass, StateDir, Target};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

pub const MAX_MANIFEST_BYTES: u64 = 1_048_576;
pub const MAX_MANIFEST_ROWS: usize = 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    pass_id: String,
    units: Vec<Unit>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unit {
    caller_ref: String,
    digest: String,
    charges: Vec<debit::DebitCharge>,
    targets: Option<Vec<ExpectedTarget>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedTarget {
    target: String,
    #[serde(default)]
    name: Option<String>,
}
#[derive(Serialize)]
pub struct ReconcileRow {
    pub caller_ref: String,
    pub result: &'static str,
    pub candidate_count: u64,
    pub sequences: Vec<u64>,
    pub truncated: bool,
    /// What differs between the manifest unit and each recorded candidate.
    /// Empty when nothing differs or nothing was recorded.
    pub differences: Vec<ReconcileDifference>,
    /// The first 64 sequences of reference reconciliations that list the
    /// reference: the operator recorded that its debit may be in lines an
    /// adoption lost.
    pub reconciled_at: Vec<u64>,
}
/// One field of a manifest unit that differs from a recorded debit.
#[derive(Serialize)]
pub struct ReconcileDifference {
    /// The ledger sequence of the candidate debit that the difference describes.
    pub sequence: u64,
    /// `digest`, `charge.<counter>`, `charges.count`, `target[<n>]`, `name[<n>]` or `targets.count`.
    pub field: String,
    /// The manifest value, or null when the manifest has none.
    ///
    /// The natural JSON type of the field: a number for `charge.<counter>`
    /// and `targets.count`, a string for the others.
    pub expected: Option<serde_json::Value>,
    /// The ledger value, or null when the ledger has none.
    pub recorded: Option<serde_json::Value>,
}
fn diff(
    out: &mut Vec<ReconcileDifference>,
    sequence: u64,
    field: String,
    expected: Option<serde_json::Value>,
    recorded: Option<serde_json::Value>,
) {
    if expected != recorded {
        out.push(ReconcileDifference {
            sequence,
            field,
            expected,
            recorded,
        });
    }
}
/// Compare one manifest unit with one recorded debit. Targets are compared only when both sides have them.
fn differences(
    unit: &Unit,
    seq: u64,
    digest: &Digest,
    charges: &[debit::DebitCharge],
    receipt: &debit::DebitReceipt,
) -> Vec<ReconcileDifference> {
    let mut out = Vec::new();
    diff(
        &mut out,
        seq,
        "digest".into(),
        Some(unit.digest.clone().into()),
        Some(digest.to_string().into()),
    );
    let expected: BTreeMap<_, _> = unit
        .charges
        .iter()
        .map(|c| (&c.counter, c.amount))
        .collect();
    let actual: BTreeMap<_, _> = charges.iter().map(|c| (&c.counter, c.amount)).collect();
    let counters: BTreeSet<_> = expected.keys().chain(actual.keys()).copied().collect();
    for counter in counters {
        diff(
            &mut out,
            seq,
            format!("charge.{counter}"),
            expected.get(counter).map(|n| (*n).into()),
            actual.get(counter).map(|n| (*n).into()),
        );
    }
    if let Some(targets) = unit
        .targets
        .as_ref()
        .filter(|_| !receipt.targets.is_empty())
    {
        diff(
            &mut out,
            seq,
            "targets.count".into(),
            Some(targets.len().into()),
            Some(receipt.targets.len().into()),
        );
        for (i, (a, b)) in targets.iter().zip(&receipt.targets).enumerate() {
            diff(
                &mut out,
                seq,
                format!("target[{}]", i + 1),
                Some(a.target.clone().into()),
                Some(b.target.clone().into()),
            );
            diff(
                &mut out,
                seq,
                format!("name[{}]", i + 1),
                a.name.clone().map(Into::into),
                b.name.clone().map(Into::into),
            );
        }
    }
    out
}
#[derive(Serialize)]
pub struct Reconciliation {
    pub pass_id: String,
    pub result: &'static str,
    pub rows: Vec<ReconcileRow>,
    pub witness: &'static str,
    pub adoption_count: u64,
    pub warnings: Vec<String>,
}

fn read_manifest(path: &Path, id: &str) -> Result<Manifest, Error> {
    let file = crate::files::open_no_follow(path, std::fs::OpenOptions::new().read(true))?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(path, &e))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::Usage("manifest exceeds byte limit".into()));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Usage(format!("invalid manifest: {e}")))?;
    if manifest.version != 1 {
        return Err(Error::Usage(format!(
            "manifest field version is {}; it must be 1. Set \"version\": 1 and run reconcile again",
            manifest.version
        )));
    }
    if manifest.pass_id != id {
        return Err(Error::Usage(format!(
            "manifest field pass_id is \"{}\" but this pass is \"{}\"; reconcile needs the manifest written for this pass. Use the pass it names, or a manifest for \"{}\"",
            display_safe(&manifest.pass_id),
            display_safe(id),
            display_safe(id)
        )));
    }
    if !(1..=MAX_MANIFEST_ROWS).contains(&manifest.units.len()) {
        return Err(Error::Usage(format!(
            "manifest has {} rows; it must have 1 to {MAX_MANIFEST_ROWS}. Split a larger set into several manifests and reconcile each",
            manifest.units.len()
        )));
    }
    let mut refs: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, unit) in manifest.units.iter().enumerate() {
        validate_row(unit, i + 1, &mut refs)?;
    }
    Ok(manifest)
}

/// A validation error for one manifest row. It names the row (counted from
/// 1 in file order), the caller reference, the field, the escaped value and
/// what to do.
fn row_error(
    row: usize,
    caller_ref: &str,
    field: &str,
    value: &str,
    problem: &str,
    fix: &str,
) -> Error {
    Error::Usage(format!(
        "manifest row {row} (caller_ref \"{}\"): {field} {problem}: \"{}\"; {fix}",
        display_safe(caller_ref),
        display_safe(value)
    ))
}

/// Check one row, in the order a reader would fix them: reference, digest,
/// charges, then destinations.
fn validate_row<'a>(
    unit: &'a Unit,
    row: usize,
    refs: &mut BTreeMap<&'a str, usize>,
) -> Result<(), Error> {
    let r = unit.caller_ref.as_str();
    let fix_ref = format!(
        "give the row a caller_ref of 1 to {} characters with no control or disguising characters, then run reconcile again",
        crate::MAX_CALLER_REF
    );
    if !debit::valid_text(r, crate::MAX_CALLER_REF) {
        return Err(row_error(
            row,
            r,
            "caller_ref",
            r,
            "is empty, too long, or has control or disguising characters",
            &fix_ref,
        ));
    }
    if let Some(first) = refs.insert(r, row) {
        return Err(row_error(
            row,
            r,
            "caller_ref",
            r,
            &format!("repeats the caller_ref of row {first}"),
            "give each row its own caller_ref, since a ledger debit is matched to one row by it; then run reconcile again",
        ));
    }
    if unit.digest.parse::<Digest>().is_err() {
        return Err(row_error(
            row,
            r,
            "digest",
            &unit.digest,
            "is not a digest",
            "copy the digest printed for this debit: sha256: and 64 lower-case hex digits; then run reconcile again",
        ));
    }
    if let Err(problem) = debit::check_charges(
        unit.charges.len(),
        unit.charges.iter().map(|c| (c.counter.as_str(), c.amount)),
    ) {
        let shown = serde_json::to_string(&unit.charges).unwrap_or_default();
        return Err(row_error(
            row,
            r,
            "charges",
            &shown,
            &format!("is invalid ({problem})"),
            "list each counter once, named as the pass's ceilings name it, with a whole amount of at least 1; then run reconcile again",
        ));
    }
    let Some(targets) = &unit.targets else {
        return Ok(());
    };
    validate_targets(row, r, targets)
}

/// Check the destinations of one row: their count, then each address and name.
fn validate_targets(row: usize, r: &str, targets: &[ExpectedTarget]) -> Result<(), Error> {
    if targets.is_empty() || targets.len() > crate::MAX_TARGETS {
        return Err(row_error(
            row,
            r,
            "targets",
            &targets.len().to_string(),
            &format!(
                "lists {} destinations; it must list 1 to {}",
                targets.len(),
                crate::MAX_TARGETS
            ),
            &format!(
                "leave targets out, or list 1 to {} destinations; then run reconcile again",
                crate::MAX_TARGETS
            ),
        ));
    }
    for (j, t) in targets.iter().enumerate() {
        let field = format!("targets[{}].target", j + 1);
        match t.target.parse::<Target>() {
            Ok(v) if v.to_string() == t.target => {}
            Ok(v) => {
                return Err(row_error(
                    row,
                    r,
                    &field,
                    &t.target,
                    "is not canonical",
                    &format!("write `{v}` in its place, then run reconcile again"),
                ));
            }
            Err(_) => {
                return Err(row_error(
                    row,
                    r,
                    &field,
                    &t.target,
                    "is not a destination",
                    "write ADDR:PORT/PROTO, for example `192.0.2.10:443/tcp`, then run reconcile again",
                ));
            }
        }
        let Some(name) = &t.name else { continue };
        let field = format!("targets[{}].name", j + 1);
        match name.parse::<HostName>() {
            Ok(v) if v.as_str() == name => {}
            Ok(v) => {
                return Err(row_error(
                    row,
                    r,
                    &field,
                    name,
                    "is not canonical",
                    &format!(
                        "write `{v}` (lower case, no trailing dot) in its place, then run reconcile again"
                    ),
                ));
            }
            Err(reason) => {
                return Err(row_error(
                    row,
                    r,
                    &field,
                    name,
                    "is not a host name",
                    &format!("correct it, then run reconcile again; reason: {reason}"),
                ));
            }
        }
    }
    Ok(())
}
/// Reconcile one bounded manifest against verified available ledger history.
///
/// # Errors
/// Returns an error for malformed input, unverified history, or unavailable witness.
pub fn reconcile(
    loaded: &LoadedPass,
    state: &StateDir,
    path: &Path,
) -> Result<Reconciliation, Error> {
    let manifest = read_manifest(path, &loaded.pass.id)?;
    let index: BTreeMap<_, _> = manifest
        .units
        .iter()
        .enumerate()
        .map(|(i, u)| (u.caller_ref.as_str(), i))
        .collect();
    let mut rows: Vec<_> = manifest
        .units
        .iter()
        .map(|u| ReconcileRow {
            caller_ref: u.caller_ref.clone(),
            result: "absent",
            candidate_count: 0,
            sequences: Vec::new(),
            truncated: false,
            differences: Vec::new(),
            reconciled_at: Vec::new(),
        })
        .collect();
    let mut reconciled_rows = 0_usize;
    let view = visit_view(loaded, state, false, &mut |event| {
        if let VerifiedEvent::Reconcile(r) = event {
            for listed in &r.references {
                if let Some(row) = index.get(listed.as_str()).map(|i| &mut rows[*i]) {
                    if row.reconciled_at.is_empty() {
                        reconciled_rows += 1;
                    }
                    if row.reconciled_at.len() < DETAIL_LIMIT {
                        row.reconciled_at.push(r.seq);
                    }
                }
            }
        }
        let VerifiedEvent::Debit(d) = event else {
            return Ok(());
        };
        let Some(receipt) = &d.receipt else {
            return Ok(());
        };
        let Some(i) = receipt
            .caller_ref
            .as_deref()
            .and_then(|r| index.get(r))
            .copied()
        else {
            return Ok(());
        };
        let unit = &manifest.units[i];
        let row = &mut rows[i];
        row.candidate_count += 1;
        if row.sequences.len() < DETAIL_LIMIT {
            row.sequences.push(d.seq);
        } else {
            row.truncated = true;
        }
        let found = differences(unit, d.seq, &d.digest, &d.charges, receipt);
        if row.candidate_count > 1 {
            row.result = "ambiguous";
        } else if !found.is_empty() {
            row.result = "mismatch";
        } else if unit.targets.is_some() && receipt.targets.is_empty() {
            row.result = "incomplete";
        } else {
            row.result = "match";
        }
        if row.sequences.last() == Some(&d.seq) {
            row.differences.extend(found);
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
    let result = if rows.iter().all(|r| r.result == "match") {
        "match"
    } else {
        "discrepancy"
    };
    let mut warnings = view.warnings;
    if view.adoption_count > 0 {
        warnings.push("The available history includes adoption. Carried totals can survive even when individual receipts are missing.".into());
    }
    if reconciled_rows > 0 {
        warnings.push(format!(
            "{reconciled_rows} row(s) name a reference that a reference reconciliation lists (see reconciled_at): the operator recorded that its debit may be in lines lost before an adoption, so an absent row may still have been debited."
        ));
    }
    Ok(Reconciliation {
        pass_id: loaded.pass.id.clone(),
        result,
        rows,
        witness: view.witness.as_str(),
        adoption_count: view.adoption_count,
        warnings,
    })
}
