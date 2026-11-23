//! Bounded, local manifests reconciled against a single verified history scan.
use super::evidence::DETAIL_LIMIT;
use super::{VerifiedEvent, debit, visit_view};
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
}
/// One field of a manifest unit that differs from a recorded debit.
#[derive(Serialize)]
pub struct ReconcileDifference {
    /// The ledger sequence of the candidate debit that the difference describes.
    pub sequence: u64,
    /// `digest`, `charge.<counter>`, `charges.count`, `target[<n>]`, `name[<n>]` or `targets.count`.
    pub field: String,
    /// The manifest value, or null when the manifest has none.
    pub expected: Option<String>,
    /// The ledger value, or null when the ledger has none.
    pub recorded: Option<String>,
}
fn diff(
    out: &mut Vec<ReconcileDifference>,
    sequence: u64,
    field: String,
    expected: Option<String>,
    recorded: Option<String>,
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
        Some(unit.digest.clone()),
        Some(digest.to_string()),
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
            expected.get(counter).map(u64::to_string),
            actual.get(counter).map(u64::to_string),
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
            Some(targets.len().to_string()),
            Some(receipt.targets.len().to_string()),
        );
        for (i, (a, b)) in targets.iter().zip(&receipt.targets).enumerate() {
            diff(
                &mut out,
                seq,
                format!("target[{}]", i + 1),
                Some(a.target.clone()),
                Some(b.target.clone()),
            );
            diff(
                &mut out,
                seq,
                format!("name[{}]", i + 1),
                a.name.clone(),
                b.name.clone(),
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
    if manifest.version != 1
        || manifest.pass_id != id
        || !(1..=MAX_MANIFEST_ROWS).contains(&manifest.units.len())
    {
        return Err(Error::Usage(
            "manifest version, pass ID, or row count is invalid".into(),
        ));
    }
    let mut refs = BTreeSet::new();
    for unit in &manifest.units {
        if !debit::valid_text(&unit.caller_ref, crate::MAX_CALLER_REF)
            || !refs.insert(&unit.caller_ref)
            || unit.digest.parse::<Digest>().is_err()
        {
            return Err(Error::Usage(
                "manifest reference or digest is invalid or duplicated".into(),
            ));
        }
        debit::check_charges(
            unit.charges.len(),
            unit.charges.iter().map(|c| (c.counter.as_str(), c.amount)),
        )
        .map_err(|e| Error::Usage(e.into()))?;
        if let Some(targets) = &unit.targets {
            if targets.is_empty() || targets.len() > crate::MAX_TARGETS {
                return Err(Error::Usage("invalid manifest target count".into()));
            }
            for t in targets {
                if !t
                    .target
                    .parse::<Target>()
                    .is_ok_and(|v| v.to_string() == t.target)
                    || t.name.as_deref().is_some_and(|name| {
                        !HostName::canonical(name).is_ok_and(|v| v.to_string() == name)
                    })
                {
                    return Err(Error::Usage(
                        "manifest target or name is not canonical".into(),
                    ));
                }
            }
        }
    }
    Ok(manifest)
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
        })
        .collect();
    let view = visit_view(loaded, state, false, &mut |event| {
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
    Ok(Reconciliation {
        pass_id: loaded.pass.id.clone(),
        result,
        rows,
        witness: view.witness.as_str(),
        adoption_count: view.adoption_count,
        warnings,
    })
}
