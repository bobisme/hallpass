//! Optional ledger projection for an approval revision review.
use super::{Output, REFUSED};
use hallpass::{Error, LoadedPass, StateDir, WitnessStatus, read_summary};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt::Write as _;

pub(super) fn budget(
    old: &LoadedPass,
    proposed: &LoadedPass,
    out: &mut Output,
) -> Result<(), Error> {
    if old.pass.id != proposed.pass.id {
        out.code = REFUSED;
        out.json["result"] = json!("inapplicable");
        out.json["budget_impact"] = json!({"result":"inapplicable","reason":"different-pass-id"});
        out.text
            .push_str("Budget projection requires the same approval ID.\n");
        return Ok(());
    }
    let state = StateDir::from_env();
    let view = read_summary(old, &state)?;
    if let WitnessStatus::NotChecked { reason } = view.witness {
        return Err(Error::WitnessUnavailable {
            pass_id: old.pass.id.clone(),
            dir: state.path().ok().map(ToOwned::to_owned),
            detail: reason,
        });
    }
    let names: BTreeSet<_> = old
        .pass
        .ceilings
        .keys()
        .chain(proposed.pass.ceilings.keys())
        .chain(view.tally.spent.keys())
        .collect();
    let mut rows = Vec::with_capacity(names.len());
    for name in names {
        let old_limit = old.pass.ceilings.get(name);
        let proposed_limit = proposed.pass.ceilings.get(name);
        let spent = view.tally.spent(name);
        let remaining = proposed_limit.map(|n| n.saturating_sub(spent));
        let over = proposed_limit.map(|n| spent.saturating_sub(*n));
        let old_required = old.pass.required_counters.contains(name);
        let proposed_required = proposed.pass.required_counters.contains(name);
        let _ = writeln!(
            out.text,
            "{name}: {spent} spent. Ceiling {} -> {}. Remaining {} -> {}. Over proposed: {}. Required {} -> {}.",
            amount(old_limit.copied()),
            amount(proposed_limit.copied()),
            amount(old_limit.map(|n| n.saturating_sub(spent))),
            amount(remaining),
            amount(over),
            old_required,
            proposed_required
        );
        rows.push(json!({"counter":name, "spent":spent, "old_ceiling":old_limit, "proposed_ceiling":proposed_limit,
            "old_remaining":old_limit.map(|n| n.saturating_sub(spent)), "proposed_remaining":remaining,
            "over_proposed":over, "old_required":old_required,"proposed_required":proposed_required}));
    }
    let _ = writeln!(
        out.text,
        "Current ledger witness: {}.",
        view.witness.as_str()
    );
    if let Some(tip) = &view.tip {
        let _ = writeln!(
            out.text,
            "Verified through sequence {} ({}).",
            tip.seq, tip.hash
        );
    }
    for warning in &view.warnings {
        let _ = writeln!(out.text, "WARNING: {}", super::safe(warning));
    }
    out.json["budget_impact"] = json!({"result":"projected", "tip":view.tip, "witness":view.witness.as_str(),
        "warnings":view.warnings, "counters":rows});
    Ok(())
}

fn amount(value: Option<u64>) -> String {
    value.map_or_else(|| "absent".to_owned(), |n| n.to_string())
}
