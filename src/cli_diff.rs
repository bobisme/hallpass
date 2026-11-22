//! Optional ledger projection for an approval revision review.
use super::{DiffArgs, OK, Output, REFUSED, error_output, safe};
use hallpass::time::OffsetDateTime;
use hallpass::{Error, LoadedPass, StateDir, WitnessStatus, read_summary};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt::Write as _;

fn budget(old: &LoadedPass, proposed: &LoadedPass, out: &mut Output) -> Result<(), Error> {
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

fn render_containment(
    old: &LoadedPass,
    new: &LoadedPass,
    at: hallpass::time::OffsetDateTime,
    out: &mut Output,
) {
    let report = hallpass::review::endpoint_containment(&old.pass, &new.pass, at);
    let _ = writeln!(
        out.text,
        "Endpoint scope at {}: {} ({}). Compared {} rule pairs.",
        report.at, report.result, report.reason, report.compared_pairs
    );
    if let Some(row) = &report.example {
        let _ = writeln!(
            out.text,
            "{} ({}): {} -> {}",
            row.target,
            row.name.as_deref().unwrap_or("unnamed"),
            row.before,
            row.after
        );
    }
    if report.result != "contained" {
        out.code = REFUSED;
    }
    out.json["result"] = json!(report.result);
    out.json["containment"] = json!(report);
}

pub fn review_diff(args: &DiffArgs) -> Output {
    let DiffArgs {
        old,
        new,
        at,
        examples,
        budget_impact,
        containment,
    } = args;
    if at.is_some() && !*examples && !*containment {
        return error_output(
            "diff",
            None,
            &Error::Usage("--at requires --examples or --containment".to_owned()),
        );
    }
    let review_at = match at
        .as_deref()
        .map(|s| OffsetDateTime::parse(s, &hallpass::time::format_description::well_known::Rfc3339))
        .transpose()
    {
        Ok(instant) => instant,
        Err(e) => {
            return error_output(
                "diff",
                None,
                &Error::Usage(format!(
                    "supply --at as an RFC 3339 timestamp with an offset ({e})"
                )),
            );
        }
    };
    let a = match hallpass::load(old) {
        Ok(v) => v,
        Err(e) => return error_output("diff", Some(old), &e),
    };
    let b = match hallpass::load(new) {
        Ok(v) => v,
        Err(e) => return error_output("diff", Some(new), &e),
    };
    let mut output = field_output(&a, &b);
    if *budget_impact && let Err(error) = budget(&a, &b, &mut output) {
        return error_output("diff", Some(old), &error);
    }
    if let Some(instant) = review_at
        && *containment
    {
        render_containment(&a, &b, instant, &mut output);
    }
    if let Some(instant) = review_at
        && *examples
    {
        let sample = hallpass::review::decision_examples(&a.pass, &b.pass, instant);
        let _ = writeln!(
            output.text,
            "Sampled {} distinct requests at {}. The sample cannot establish policy equivalence.",
            sample.evaluated, sample.at
        );
        for row in &sample.rows {
            let _ = writeln!(
                output.text,
                "{} ({}): {} -> {}",
                row.target,
                row.name.as_deref().unwrap_or("unnamed"),
                row.before,
                row.after
            );
        }
        if sample.truncated {
            output
                .text
                .push_str("Sampling limit reached. Additional candidates were omitted.\n");
        }
        output.json["examples"] = json!(sample);
    } else if !*budget_impact && !*containment {
        output
            .text
            .push_str("This is a declared-field diff only; it never authorizes a spend.\n");
    }
    output
}

fn field_output(a: &LoadedPass, b: &LoadedPass) -> Output {
    let old = &a.path;
    let new = &b.path;
    let report = hallpass::review::diff(a, b);
    let mut text = format!(
        "OLD pass {} digest: {}\nNEW pass {} digest: {}\n",
        report.old_pass_id, report.old_digest, report.new_pass_id, report.new_digest
    );
    if report.approval_changed {
        text.push_str("APPROVAL ID CHANGED: treat as a different ledger identity.\n");
    }
    for c in &report.changes {
        let _ = writeln!(
            text,
            "{}: {} -> {}{}",
            c.field,
            safe(&c.before),
            safe(&c.after),
            if c.review_required {
                " [review required]"
            } else {
                ""
            }
        );
    }
    for l in &report.introduced {
        let _ = writeln!(text, "introduced destination: {l}");
    }
    for l in &report.removed {
        let _ = writeln!(text, "removed destination: {l}");
    }
    if report.order_changed {
        text.push_str("WARNING: common destination order changed; returned label may change.\n");
    }
    Output {
        code: OK,
        json: json!({"command":"diff","result":"ok","old":old.display().to_string(),"new":new.display().to_string(),"old_pass_id":report.old_pass_id,"new_pass_id":report.new_pass_id,"old_digest":report.old_digest.clone(),"new_digest":report.new_digest.clone(),"approval_id_changed":report.approval_changed,"changes":report.changes,"introduced":report.introduced,"removed":report.removed,"order_changed":report.order_changed,"review_required":report.review_required,"warnings":[]}),
        text,
    }
}
