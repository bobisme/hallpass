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
    // NEW is the live pass in the documented retrieve-then-diff flow, and OLD
    // an archived copy with no ledger. Read the ledger beside NEW; fall back
    // to the one beside OLD only when NEW has none.
    let (source, ledger_of) = if hallpass::ledger_path(&proposed.path).exists() {
        ("new", proposed)
    } else if hallpass::ledger_path(&old.path).exists() {
        ("old", old)
    } else {
        ("none", proposed)
    };
    let ledger = hallpass::ledger_path(&ledger_of.path);
    let view = read_summary(ledger_of, &state)?;
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
        "Ledger used: {} ({}).",
        safe(&ledger.display().to_string()),
        match source {
            "new" => "beside NEW",
            "old" => "beside OLD; NEW has none",
            _ => "neither OLD nor NEW has one yet",
        }
    );
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
        let _ = writeln!(out.text, "WARNING: {}", super::safe_message(warning));
    }
    out.json["budget_impact"] = json!({"result":"projected", "ledger":ledger.display().to_string(), "ledger_source":source, "tip":view.tip, "witness":view.witness.as_str(),
        "warnings":view.warnings, "counters":rows});
    Ok(())
}

/// Warn when NEW replaces ceilings with new ones: spend on a dropped counter
/// does not count against a counter new to the pass.
fn flag_substitution(old: &LoadedPass, proposed: &LoadedPass, out: &mut Output) {
    let found = hallpass::review::counter_substitution(&old.pass, &proposed.pass);
    if let Some(s) = &found {
        let _ = writeln!(
            out.text,
            "WARNING: NEW drops the ceiling on {} and adds {}. A new counter starts with nothing spent, so spend on a dropped counter does not count against it. diff --containment lists this as a counter-substitution loosening; ask the owner whether the counter was renamed, and keep its name if so.",
            quoted_names(&s.dropped),
            quoted_names(&s.added)
        );
    }
    out.json["budget_impact"]["counter_substitution"] = json!(found);
}

/// Counter names as quoted values joined by `, `.
fn quoted_names(names: &[String]) -> String {
    names
        .iter()
        .map(|n| super::quoted(n))
        .collect::<Vec<_>>()
        .join(", ")
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
    let report = hallpass::review::endpoint_containment(&old.pass, &new.pass, at)
        .with_loosenings(hallpass::review::non_endpoint_loosenings(old, new));
    let _ = writeln!(
        out.text,
        "Endpoint scope at every instant: {} ({}). Compared {} rule pairs.",
        report.endpoint_result, report.reason, report.compared_pairs
    );
    if let Some(replayed) = report
        .replayed_at
        .as_ref()
        .filter(|r| !report.counterexamples.is_empty() && **r != report.at)
    {
        let _ = writeln!(
            out.text,
            "NEW's window does not hold {}, so these requests were tried at {replayed}, the start of NEW's window:",
            report.at
        );
    }
    for row in &report.counterexamples {
        let _ = writeln!(out.text, "{}", row_line(row));
    }
    if report.more_counterexamples {
        out.text
            .push_str("More new allowances may exist than the counterexamples listed above.\n");
    }
    for l in &report.loosenings {
        let _ = write!(
            out.text,
            "Loosened: {}: {} -> {}",
            l.field,
            plain(&l.before),
            plain(&l.after)
        );
        if let Some(code) = l.code {
            let _ = write!(
                out.text,
                ", renamed or replaced by {} ({code}): a new counter starts with nothing spent",
                quoted_names(&l.replaced_by)
            );
        }
        out.text.push('\n');
    }
    let why = if report.result == "contained" && report.reason == "new-admits-nothing" {
        "NEW is revoked, so it admits nothing at any instant, and no other term loosens"
    } else {
        "Contained means the endpoints and every other term only narrow"
    };
    let _ = writeln!(out.text, "Overall verdict: {}. {why}.", report.result);
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
        refusal_changes,
        ..
    } = args;
    if at.is_some() && !*examples && !*containment {
        return error_output(
            "diff",
            None,
            &Error::Usage("--at requires --examples or --containment".to_owned()),
        );
    }
    if at.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("now")) {
        return error_output(
            "diff",
            None,
            &Error::Usage(
                "--at does not accept `now`; supply an RFC 3339 timestamp with an offset"
                    .to_owned(),
            ),
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
    let (a, a_bytes) = match hallpass::load_with_bytes(old) {
        Ok(v) => v,
        Err(e) => return error_output("diff", Some(old), &e),
    };
    let (b, b_bytes) = match hallpass::load_with_bytes(new) {
        Ok(v) => v,
        Err(e) => return error_output("diff", Some(new), &e),
    };
    let mut output = field_output(&a, &b, [&a_bytes, &b_bytes]);
    // NEW's window: the length needs no clock; ended or far-future windows are
    // judged at --at, the only instant diff knows.
    let window = hallpass::review::window_warnings(&b.pass, review_at);
    output.json["new_window_warnings"] = json!(window);
    if let Some(list) = output.json["warnings"].as_array_mut() {
        list.extend(
            window
                .iter()
                .map(|w| json!(format!("NEW revision: {}", w.message))),
        );
    }
    if *budget_impact && let Err(error) = budget(&a, &b, &mut output) {
        return error_output("diff", Some(old), &error);
    }
    if *budget_impact && a.pass.id == b.pass.id {
        flag_substitution(&a, &b, &mut output);
    }
    if let Some(instant) = review_at
        && *containment
    {
        render_containment(&a, &b, instant, &mut output);
    }
    if let Some(instant) = review_at
        && *examples
    {
        render_examples(&a, &b, instant, *refusal_changes, &mut output);
    } else if !*budget_impact && !*containment {
        output
            .text
            .push_str("This is a declared-field diff only; it never authorizes a spend.\n");
    }
    output
}

fn render_examples(
    old: &LoadedPass,
    new: &LoadedPass,
    instant: OffsetDateTime,
    list_refusal_codes: bool,
    out: &mut Output,
) {
    let sample =
        hallpass::review::decision_examples_with(&old.pass, &new.pass, instant, list_refusal_codes);
    let _ = writeln!(
        out.text,
        "Sampled {} distinct requests at {}. The sample cannot establish policy equivalence.",
        sample.evaluated, sample.at
    );
    let mut heading = "";
    for row in &sample.rows {
        let title = match row.change {
            "newly-allowed" => "Newly allowed:",
            "changed" => "Other changes:",
            _ => "Refusal code changed only:",
        };
        if title != heading {
            heading = title;
            let _ = writeln!(out.text, "{title}");
        }
        let _ = writeln!(out.text, "{}", row_line(row));
    }
    if sample.refusal_code_changes > 0 && !sample.refusal_code_changes_listed {
        let _ = writeln!(
            out.text,
            "{} refused-to-refused change(s) where only the refusal code changed are not listed; add --refusal-changes to list them.",
            sample.refusal_code_changes
        );
    }
    if sample.truncated {
        out.text
            .push_str("Sampling limit reached. Additional candidates were omitted.\n");
    }
    out.json["examples"] = json!(sample);
}

/// One sampled request: `TARGET (NAME or unnamed): BEFORE -> AFTER`, and
/// the destination whose names list NEW's allowance bypasses.
fn row_line(row: &hallpass::review::DecisionExample) -> String {
    let mut line = format!(
        "{} ({}): {} -> {}",
        row.target,
        row.name.as_deref().unwrap_or("unnamed"),
        row.before,
        row.after
    );
    if let Some(label) = &row.bypasses_names_of {
        let _ = write!(line, ", bypassing the names list of {label}");
    }
    line
}

/// A changed value as plain text: null and empty read `none`.
fn plain(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "none".to_owned(),
        serde_json::Value::String(text) if text.is_empty() => "none".to_owned(),
        serde_json::Value::String(text) => safe(text).into_owned(),
        other => other.to_string(),
    }
}

/// The kinds of `text_changes` as one phrase: `comments (...) and layout (...)`.
fn text_change_kinds(kinds: &[&str]) -> String {
    let phrases: Vec<&str> = kinds
        .iter()
        .map(|kind| match *kind {
            "comments" => "comments (added, removed, changed or moved)",
            "layout" => {
                "whitespace or layout (spacing, line breaks, key order, or the form of a table or list)"
            }
            _ => {
                "values written another way (such as a time with another offset, or a list in another order)"
            }
        })
        .collect();
    match phrases.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{}, and {last}", rest.join(", ")),
        _ => phrases.concat(),
    }
}

fn field_output(a: &LoadedPass, b: &LoadedPass, bytes: [&[u8]; 2]) -> Output {
    let old = &a.path;
    let new = &b.path;
    let report = hallpass::review::diff(a, b);
    let same_fields = report.same_declared_fields();
    let changes = if same_fields && report.old_digest != report.new_digest {
        let [a_text, b_text] = bytes.map(|b| std::str::from_utf8(b).unwrap_or_default());
        hallpass::review::text_changes(a_text, b_text)
    } else {
        hallpass::review::TextChanges::default()
    };
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
            plain(&c.before),
            plain(&c.after),
            if c.review_required {
                " [review required]"
            } else {
                ""
            }
        );
    }
    for (kind, grants) in [
        ("introduced", &report.introduced_grants),
        ("removed", &report.removed_grants),
    ] {
        for g in grants {
            let names = if g.names.is_empty() {
                "any name".to_owned()
            } else {
                format!("names {}", g.names.join(", "))
            };
            let _ = writeln!(
                text,
                "{kind} destination: {} grants {} {} {} ports {}, {names} [review required]",
                safe(&g.label),
                g.scope,
                g.network,
                g.protocol,
                g.ports
            );
        }
    }
    for w in &report.name_overlap_warnings {
        let _ = writeln!(text, "WARNING: {}", super::safe_message(&w.message));
    }
    if report.order_changed {
        text.push_str("WARNING: common destination order changed; returned label may change.\n");
    }
    if !changes.kinds.is_empty() {
        let _ = writeln!(
            text,
            "The digests differ, but no declared field does: the files differ only in {}.",
            text_change_kinds(&changes.kinds)
        );
    }
    for c in &changes.comments {
        let _ = writeln!(
            text,
            "Comment {} ({} line {}): {}",
            c.change,
            if c.change == "removed" { "OLD" } else { "NEW" },
            c.line,
            super::quoted(&c.text)
        );
    }
    Output {
        code: OK,
        json: json!({"command":"diff","result":"ok","old":old.display().to_string(),"new":new.display().to_string(),"old_pass_id":report.old_pass_id,"new_pass_id":report.new_pass_id,"old_digest":report.old_digest.clone(),"new_digest":report.new_digest.clone(),"approval_id_changed":report.approval_changed,"changes":report.changes,"introduced":report.introduced,"removed":report.removed,"introduced_grants":report.introduced_grants,"removed_grants":report.removed_grants,"name_restriction_overlaps":report.name_overlap_warnings,"order_changed":report.order_changed,"review_required":report.review_required,"same_declared_fields":same_fields,"text_changes":changes.kinds,"comment_changes":changes.comments,"warnings":report.name_overlap_warnings.iter().map(|w| w.message.as_str()).collect::<Vec<_>>()}),
        text,
    }
}
