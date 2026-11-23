//! Read-only evidence commands.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hallpass::{StateDir, evidence};
use serde_json::{Value, json};

use super::{ERROR, OK, Output, REFUSED, error_output, safe};

fn output(cmd: &str, file: &Path, code: u8, mut value: Value, text: String) -> Output {
    value["command"] = json!(cmd);
    value["file"] = json!(file.display().to_string());
    Output {
        code,
        json: value,
        text,
    }
}

pub fn receipt(file: &Path, reference: &str) -> Output {
    let report = match hallpass::load(file)
        .and_then(|p| evidence::lookup_receipt(&p, &StateDir::from_env(), reference))
    {
        Ok(report) => report,
        Err(e) => return error_output("receipt", Some(file), &e),
    };
    let mut text = format!(
        "Receipt {} for {:?}. {} matches. Witness {}. Adoptions {}.\n",
        report.result,
        safe(reference),
        report.match_count,
        report.witness,
        report.adoption_count
    );
    if !report.reconciled_at.is_empty() {
        let _ = writeln!(
            text,
            "  Listed in the reference reconciliation(s) at sequence {}.",
            report
                .reconciled_at
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for row in &report.matches {
        let _ = writeln!(
            text,
            "  #{} {} {}  charges={} targets={}",
            row.seq,
            text_time(&row.time),
            row.digest,
            json!(row.charges),
            json!(row.targets)
        );
    }
    if report.truncated {
        text.push_str("  Additional matches omitted.\n");
    }
    output(
        "receipt",
        file,
        if report.result == "found" {
            OK
        } else {
            REFUSED
        },
        json!(report),
        text,
    )
}

/// Text shows times to the whole second, as `ledger` does; JSON keeps the
/// exact recorded instant. A value that is not RFC 3339 is shown as recorded.
fn text_time(recorded: &str) -> String {
    hallpass::time::OffsetDateTime::parse(
        recorded,
        &hallpass::time::format_description::well_known::Rfc3339,
    )
    .map_or_else(|_| recorded.to_owned(), hallpass::stamp)
}

fn endpoint_text(row: &evidence::AuditEndpoint) -> String {
    let name = row
        .recorded
        .name
        .as_deref()
        .map_or_else(String::new, |n| format!(" name {}", safe(n)));
    let verdict = match (&row.matched_label, row.refusal_code) {
        // Only a revision a verified signature approved can confirm.
        (Some(label), _) if *label == row.recorded.label && row.provenance == SIGNED => {
            format!("recorded label {} confirmed", safe(label))
        }
        (Some(label), _) if *label == row.recorded.label => format!(
            "recorded label {} matches the archived revision, which no verified signature approved",
            safe(label)
        ),
        (Some(label), _) => format!(
            "recorded label {} but the revision matches label {}",
            safe(&row.recorded.label),
            safe(label)
        ),
        (None, Some(code)) => format!(
            "recorded label {} but the revision refuses it ({code})",
            safe(&row.recorded.label)
        ),
        (None, None) => format!("recorded label {}", safe(&row.recorded.label)),
    };
    format!(
        "#{} target {} at {} {}{name}: {verdict}",
        row.seq,
        row.index,
        text_time(&row.time),
        safe(&row.recorded.target)
    )
}

const SIGNED: &str = "signature-verified";

/// What a gap reason means, and what would close it next time.
fn gap_meaning(reason: &str) -> &'static str {
    match reason {
        "adoption-carry" => "an adoption carried totals, which are not original debits",
        "approval-unverified" => {
            "decided under a revision that no verified signature approved in this archive; if the owner signed it, record the signature with verify-approval --archive"
        }
        "archive-missing" => {
            "the revision is not in the archive; archive each revision before spending under it"
        }
        "targets-unrecorded" => {
            "the line keeps no target; spend with --to and --record-target to keep endpoint evidence"
        }
        _ => "",
    }
}

fn omitted(truncated: bool, what: &str) -> String {
    if truncated {
        format!(" (additional {what} omitted)")
    } else {
        String::new()
    }
}

fn gaps_text(
    text: &mut String,
    gaps: &std::collections::BTreeMap<&'static str, evidence::EvidenceGap>,
) {
    for (reason, gap) in gaps {
        let _ = writeln!(
            text,
            "Gap {reason} {}: {}. Sequences {:?}{}",
            gap.count,
            gap_meaning(reason),
            gap.sequences,
            omitted(gap.truncated, "sequences")
        );
        for row in &gap.digests {
            let _ = writeln!(
                text,
                "  {} {} line(s). Sequences {:?}{}",
                row.digest,
                row.count,
                row.sequences,
                omitted(row.truncated, "sequences")
            );
        }
        if gap.digests_truncated {
            text.push_str("  Additional digests omitted.\n");
        }
    }
}

fn revisions_text(text: &mut String, revisions: &evidence::RevisionGroup) {
    let _ = writeln!(
        text,
        "Revisions used {}, {} without a verified signature",
        revisions.count, revisions.unverified
    );
    for row in &revisions.details {
        let how = row.approval.as_ref().map_or_else(
            || match row.provenance {
                "unsigned" => "archived with no signature record".to_owned(),
                _ => "not in the archive".to_owned(),
            },
            |a| {
                format!(
                    "signature-verified for principal {} with trusted signers {}",
                    safe(&format!("{:?}", a.principal)),
                    a.allowed_signers
                )
            },
        );
        let _ = writeln!(
            text,
            "  {} sequences {} to {}, {} line(s): {how}",
            row.digest, row.first_seq, row.last_seq, row.lines
        );
    }
    if revisions.truncated {
        text.push_str("  Additional revisions omitted.\n");
    }
}

fn tip_text(tip: &hallpass::Checkpoint) -> String {
    format!(
        "sequence {} hash {} (pass {})",
        tip.seq,
        safe(&tip.hash),
        safe(&tip.pass_id)
    )
}

pub fn audit(file: &Path, directory: &Path) -> Output {
    let report = match hallpass::load(file)
        .and_then(|p| evidence::audit_receipts(&p, &StateDir::from_env(), directory))
    {
        Ok(report) => report,
        Err(e) => return error_output("audit-receipts", Some(file), &e),
    };
    let mut text = format!(
        "Receipt audit {}. Witness {}.\n",
        report.result, report.witness
    );
    for (name, group) in [
        ("corroborated", &report.corroborated),
        ("mismatches", &report.mismatches),
    ] {
        let _ = writeln!(text, "{name} {}", group.count);
        for row in &group.details {
            let _ = writeln!(text, "  {}", endpoint_text(row));
        }
        if group.truncated {
            text.push_str("  Additional endpoint details omitted.\n");
        }
    }
    gaps_text(&mut text, &report.gaps);
    revisions_text(&mut text, &report.revisions);
    output(
        "audit-receipts",
        file,
        if report.result == "complete" {
            OK
        } else {
            REFUSED
        },
        json!(report),
        text,
    )
}

pub fn backups(file: &Path, candidates: &[PathBuf], ancestry: bool) -> Output {
    let report = match hallpass::load(file).and_then(|p| {
        evidence::compare_backups_with_ancestry(&p, &StateDir::from_env(), candidates, ancestry)
    }) {
        Ok(report) => report,
        Err(e) => return error_output("compare-backups", Some(file), &e),
    };
    let mut text = format!("Backup assessment {}.\n", report.assessment);
    match &report.anchor {
        Some(anchor) => {
            let _ = writeln!(text, "Captured witness: {}", tip_text(anchor));
        }
        None => text.push_str("Captured witness: none\n"),
    }
    if let Some(ancestry) = &report.ancestry {
        ancestry_text(&mut text, ancestry);
    }
    for (i, row) in report.candidates.iter().enumerate() {
        let detail = match (&row.tip, &row.error) {
            (Some(tip), _) => format!(
                "{} (tip group {})",
                tip_text(tip),
                row.tip_group.unwrap_or(i + 1)
            ),
            (None, Some(e)) => format!("error {}: {}", e.code, safe(&e.message)),
            (None, None) => String::new(),
        };
        let _ = writeln!(
            text,
            "  {:>2}  {:<10} {}  {detail}",
            i + 1,
            row.relation,
            safe(&row.path)
        );
    }
    for warning in &report.warnings {
        let _ = writeln!(text, "Warning: {}", safe(warning));
    }
    let mut value = json!(report);
    let (result, code) = if report.errors > 0 {
        ("partial-error", ERROR)
    } else if report.assessment == "preserved" {
        (report.assessment, OK)
    } else {
        (report.assessment, REFUSED)
    };
    value["result"] = json!(result);
    output("compare-backups", file, code, value, text)
}

fn ancestry_text(text: &mut String, ancestry: &evidence::BackupAncestry) {
    text.push_str("Ancestry of the extended candidates (by tip group):\n");
    if ancestry.prefix_links.is_empty() {
        text.push_str(
            "  No tip group is a prefix of another. This is not a finding of unrelated\n  backups: only candidates that extend the witness are compared, so candidates\n  that are prefixes of the witness (exact or shorter) never appear here.\n",
        );
    }
    for (from, to) in &ancestry.prefix_links {
        let _ = writeln!(text, "  group {from} is a prefix of group {to}");
    }
    let groups = ancestry
        .maximal_groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if ancestry.maximal_groups.is_empty() {
        text.push_str("  No extended candidate, so there is no maximal group.\n");
    } else {
        let _ = writeln!(
            text,
            "  Maximal groups (not a prefix of any other): {groups}"
        );
    }
}

pub fn audit_charges(file: &Path, directory: &Path) -> Output {
    let report = match hallpass::load(file)
        .and_then(|p| evidence::audit_charges(&p, &StateDir::from_env(), directory))
    {
        Ok(report) => report,
        Err(e) => return error_output("audit-charges", Some(file), &e),
    };
    let mut text = format!(
        "Charge audit {}. Witness {}. Checked debits {}.\nMismatches {}\n",
        report.result, report.witness, report.checked_debits, report.mismatches.count
    );
    for row in &report.mismatches.details {
        let _ = writeln!(
            text,
            "  #{} counter {}: {}",
            row.seq,
            safe(&row.counter),
            row.reason
        );
    }
    if report.mismatches.truncated {
        text.push_str("  Additional mismatches omitted.\n");
    }
    if report.gaps.is_empty() {
        text.push_str("Gaps none\n");
    }
    gaps_text(&mut text, &report.gaps);
    revisions_text(&mut text, &report.revisions);
    for warning in &report.warnings {
        let _ = writeln!(text, "Warning: {}", safe(warning));
    }
    output(
        "audit-charges",
        file,
        if report.result == "complete" {
            OK
        } else {
            REFUSED
        },
        json!(report),
        text,
    )
}

pub fn reconcile(file: &Path, manifest: &Path) -> Output {
    let report = match hallpass::load(file)
        .and_then(|p| evidence::reconcile(&p, &StateDir::from_env(), manifest))
    {
        Ok(report) => report,
        Err(e) => return error_output("reconcile", Some(file), &e),
    };
    let mut text = format!(
        "Reconciliation {}. Witness {}.\n",
        report.result, report.witness
    );
    for row in &report.rows {
        let _ = writeln!(
            text,
            "  {:<12} {}{}",
            row.result,
            safe(&row.caller_ref),
            match row.candidate_count {
                0 => String::new(),
                1 => format!(
                    " (ledger sequence {})",
                    row.sequences.first().copied().unwrap_or(0)
                ),
                n => format!(
                    " ({n} candidates, sequences {:?}{})",
                    row.sequences,
                    if row.truncated { ", more omitted" } else { "" }
                ),
            }
        );
        if !row.reconciled_at.is_empty() {
            let _ = writeln!(
                text,
                "      listed in the reference reconciliation(s) at sequence {}",
                row.reconciled_at
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        for d in &row.differences {
            let show = |v: &Option<serde_json::Value>| match v {
                None => "absent".to_owned(),
                Some(serde_json::Value::String(v)) => safe(v).into_owned(),
                Some(other) => other.to_string(),
            };
            let _ = writeln!(
                text,
                "      sequence {}: {} differs: expected {}, recorded {}",
                d.sequence,
                d.field,
                show(&d.expected),
                show(&d.recorded)
            );
        }
    }
    for warning in &report.warnings {
        let _ = writeln!(text, "Warning: {}", safe(warning));
    }
    output(
        "reconcile",
        file,
        if report.result == "match" {
            OK
        } else {
            REFUSED
        },
        json!(report),
        text,
    )
}
