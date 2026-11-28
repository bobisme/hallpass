//! Read-only evidence commands.
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use hallpass::{StateDir, evidence};
use serde_json::{Value, json};

use super::cli_verify::{SignatureArgs, audit_advice};
use super::{ERROR, OK, Output, REFUSED, error_output, quoted, safe};

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
        "Receipt {} for {}. {} matches. Witness {}. Adoptions {}.\n",
        report.result,
        quoted(reference),
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
            "  #{} {} {}  charges={} targets={}{}",
            row.seq,
            text_time(&row.time),
            row.digest,
            json!(row.charges),
            json!(row.targets),
            if row.test_clock { "  TEST CLOCK" } else { "" }
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

/// `pinned` when the auditor named the principals that may approve.
fn endpoint_text(row: &evidence::AuditEndpoint, pinned: bool) -> String {
    let name = row
        .recorded
        .name
        .as_deref()
        .map_or_else(String::new, |n| format!(" name {}", safe(n)));
    let verdict = match (&row.matched_label, row.refusal_code) {
        // Only a revision that a signature verified for a principal the
        // auditor named approved can confirm.
        (Some(label), _)
            if *label == row.recorded.label
                && row.provenance == SIGNED
                && pinned
                && !row.signer_matched_by_pattern =>
        {
            format!("recorded label {} confirmed", safe(label))
        }
        (Some(label), _) if *label == row.recorded.label && row.provenance == SIGNED && pinned => {
            format!(
                "recorded label {} matches the archived revision, whose signature verified only through a pattern principal in the trusted signers file",
                safe(label)
            )
        }
        (Some(label), _) if *label == row.recorded.label => format!(
            "recorded label {} matches the archived revision, {}",
            safe(label),
            match row.provenance {
                SIGNED => {
                    "whose signature verified for the principal its record names, not for one named with --principal"
                }
                "signature-recorded" => "which has a signature record (not re-verified)",
                "signature-rejected" => "whose recorded signature failed re-verification",
                _ => "which no verified signature approved",
            }
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

/// Only a signature this audit verified again (with `--allowed-signers`).
const SIGNED: &str = "signature-verified";

/// What a gap reason means, and what would close it next time.
fn gap_meaning(reason: &str) -> &'static str {
    match reason {
        "adoption-carry" => "an adoption carried totals, which are not original debits",
        "approval-unverified" => {
            "decided under a revision that no verified signature approved in this archive; if the owner signed it, record the signature with verify-approval --archive"
        }
        "signature-not-reverified" => {
            "decided under a revision with a signature record that this audit did not check; anyone who can write the archive can write a record, so run the audit with --allowed-signers and your own trusted signers file"
        }
        "signature-rejected" => {
            "decided under a revision whose recorded signature failed re-verification with the trusted signers file you supplied, so the archive does not show that the owner approved those bytes"
        }
        "signer-not-pinned" => {
            "decided under a revision whose signature verified for the principal its record names, and whoever writes the archive chose that principal; the trusted signers file decides whose keys count, and --principal decides who must have approved, so name the owner with --principal"
        }
        "signer-matched-by-pattern" => {
            "decided under a revision whose signature verified for a principal named with --principal, but the trusted signers file holds its key for that principal only on a line whose principals use a pattern (`*`, `?` or `!`), so it does not say that the key is theirs; give each owner key a line that names its principal, or pass --allow-pattern-principals to accept pattern lines"
        }
        "archive-missing" => {
            "the revision is not in the archive; archive each revision before spending under it"
        }
        "revision-unparsable" => {
            "decided under a revision that was archived before a pass rule it breaks, so this hallpass cannot replay it; never edit archived bytes, which record what the work was decided under: re-run the audit with the hallpass version that recorded the work, or accept the gap"
        }
        "targets-unrecorded" => {
            "the line keeps no target; spend with --to and --record-target to keep endpoint evidence"
        }
        "test-clock-entry" => {
            "the line was recorded under a test clock (HALLPASS_UNSAFE_TEST_CLOCK), so it is a rehearsal and its time is not the real time; record live work with a release build, in a ledger of its own"
        }
        "entry-in-future" => {
            "the line records a time later than this audit's clock, so the clock that recorded it was set ahead (or this one is behind); check both clocks, and do not take the time as when the work happened"
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
            let why = row.reason.map_or_else(String::new, |code| {
                format!(". Reason {code}: {}", audit_advice(code))
            });
            let why = row.principal.as_ref().map_or(why, |principal| {
                format!(". Verified for principal {}", quoted(principal))
            });
            let why = match &row.signer_key {
                Some(key) => format!("{why} by key {key}"),
                None => why,
            };
            let _ = writeln!(
                text,
                "  {} {} line(s). Sequences {:?}{}{why}",
                row.digest,
                row.count,
                row.sequences,
                omitted(row.truncated, "sequences")
            );
            problems_text(text, row);
        }
        if gap.digests_truncated {
            text.push_str("  Additional digests omitted.\n");
        }
    }
}

/// The pass rules of this version that a `revision-unparsable` digest breaks.
fn problems_text(text: &mut String, row: &evidence::GapDigest) {
    let (Some(problems), Some(count)) = (&row.problems, row.problem_count) else {
        return;
    };
    let _ = writeln!(text, "    This hallpass finds {count} problem(s) in it:");
    for problem in problems {
        let _ = writeln!(text, "    - {}", super::safe_message(&problem.to_string()));
    }
    if count > problems.len() {
        text.push_str("    Additional problems omitted.\n");
    }
}

/// The principals a signature had to verify for: those the auditor named,
/// else the one its record names.
fn checked_for(signatures: &evidence::SignatureCheck, record: &str) -> String {
    match signatures.principals.as_slice() {
        [] => format!("principal {}", quoted(record)),
        [one] => format!("principal {}", quoted(one)),
        many => format!("principals {}", quoted_list(many)),
    }
}

fn quoted_list(principals: &[String]) -> String {
    principals
        .iter()
        .map(|p| quoted(p))
        .collect::<Vec<_>>()
        .join(", ")
}

fn revisions_text(
    text: &mut String,
    revisions: &evidence::RevisionGroup,
    signatures: &evidence::SignatureCheck,
) {
    // Without --principal, a verified signature is still not pinned.
    let unpinned = if signatures.principals.is_empty() {
        revisions.count
    } else {
        revisions.unverified
    };
    let _ = writeln!(
        text,
        "Revisions used {}, {} without a verified signature{}",
        revisions.count,
        revisions.unverified,
        if unpinned == revisions.unverified {
            String::new()
        } else {
            format!(", {unpinned} not verified for a principal named with --principal")
        }
    );
    for row in &revisions.details {
        let how = row.approval.as_ref().map_or_else(
            || match row.provenance {
                "unsigned" => "archived with no signature record".to_owned(),
                _ => "not in the archive".to_owned(),
            },
            |a| {
                let at = row
                    .verify_time
                    .as_deref()
                    .map_or_else(String::new, |t| format!(" as of {}", text_time(t)));
                match (row.provenance, row.reason) {
                    (SIGNED, _) => format!(
                        "signature re-verified for principal {}{at} with the trusted signers you supplied, by {}{}",
                        quoted(row.verified_for.as_ref().unwrap_or(&a.principal)),
                        match (&row.signer_key, row.principal_match) {
                            (Some(key), Some("certificate")) => format!("certificate key {key}"),
                            (Some(key), _) => format!("key {key}"),
                            (None, _) => "a key that ssh-keygen did not name".to_owned(),
                        },
                        if row.principal_match == Some("pattern") {
                            ", only through a pattern principal"
                        } else {
                            ""
                        }
                    ),
                    ("signature-rejected", Some(code)) => format!(
                        "recorded signature failed re-verification for {}{at} ({code}): {}",
                        checked_for(signatures, &a.principal),
                        audit_advice(code)
                    ),
                    _ => format!(
                        "signature record present (not re-verified) for principal {}, recorded with trusted signers {} and {}",
                        quoted(&a.principal),
                        a.allowed_signers,
                        a.key.as_ref().map_or_else(
                            || "an unknown key".to_owned(),
                            |key| format!("key {}", safe(key))
                        )
                    ),
                }
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
    if let Some(trust) = &signatures.allowed_signers {
        let as_of = match signatures.as_of.as_deref() {
            None | Some("first-use") => "as of each revision's first use".to_owned(),
            Some(instant) => format!("as of {}", text_time(instant)),
        };
        let _ = writeln!(
            text,
            "Recorded signatures checked with ssh-keygen against trusted signers {trust}, {as_of}, {}.",
            match signatures.principals.as_slice() {
                [] => "each for the principal its record names, as no --principal named the owner"
                    .to_owned(),
                [one] => format!("for principal {}", quoted(one)),
                many => format!("each for any of principals {}", quoted_list(many)),
            }
        );
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

pub fn audit(file: &Path, directory: &Path, signatures: &SignatureArgs) -> Output {
    let report = match hallpass::load(file).and_then(|p| {
        signatures.reverifying(|reverify| {
            evidence::audit_receipts_with(&p, &StateDir::from_env(), directory, reverify)
        })
    }) {
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
        let pinned = !report.signatures.principals.is_empty();
        for row in &group.details {
            let _ = writeln!(text, "  {}", endpoint_text(row, pinned));
        }
        if group.truncated {
            text.push_str("  Additional endpoint details omitted.\n");
        }
    }
    gaps_text(&mut text, &report.gaps);
    revisions_text(&mut text, &report.revisions, &report.signatures);
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
    let mut text = if report.errors > 0 {
        // The result is `partial-error` and the exit status 1, so say so
        // first; the assessment covers only the candidates that could be read.
        format!(
            "Partial error: {} unreadable; assessment of the rest: {}.\n",
            if report.errors == 1 {
                "1 candidate".to_owned()
            } else {
                format!("{} candidates", report.errors)
            },
            report.assessment
        )
    } else {
        format!("Backup assessment {}.\n", report.assessment)
    };
    match &report.anchor {
        Some(anchor) => {
            let _ = writeln!(text, "Captured witness: {}", tip_text(anchor));
        }
        None => text.push_str("Captured witness: none\n"),
    }
    if let Some(ancestry) = &report.ancestry {
        ancestry_text(&mut text, ancestry, &report.candidates);
    }
    for (i, row) in report.candidates.iter().enumerate() {
        let detail = match (&row.tip, &row.error) {
            (Some(tip), _) => format!(
                "{} (tip group {})",
                tip_text(tip),
                row.tip_group.unwrap_or(i + 1)
            ),
            (None, Some(e)) => format!("error {}: {}", e.code, super::safe_message(&e.message)),
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
        let _ = writeln!(text, "Warning: {}", super::safe_message(warning));
    }
    let mut value = json!(report);
    if let Some(advice) = super::cli_doctor::last_resort(file, &report)
        .or_else(|| super::cli_doctor::restore_exact(file, &report))
    {
        let _ = writeln!(text, "{}", advice["message"].as_str().unwrap_or_default());
        value["advice"] = json!([advice]);
    }
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

fn ancestry_text(
    text: &mut String,
    ancestry: &evidence::BackupAncestry,
    candidates: &[evidence::BackupCandidate],
) {
    let behind = candidates.iter().any(|c| c.relation == "shorter");
    if behind {
        text.push_str(
            "Ancestry of the candidates at, ahead of or behind the witness (by tip group):\n",
        );
    } else {
        text.push_str("Ancestry of the extended candidates (by tip group):\n");
    }
    let groups = ancestry
        .maximal_groups
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    // Lead with the conclusion. Only candidates that extend the witness are
    // compared here; one at or behind the witness (exact or shorter) is
    // judged by its own row.
    if ancestry.prefix_links.is_empty() && behind {
        match ancestry.maximal_groups.len() {
            0 => {}
            1 => {
                let _ = writeln!(
                    text,
                    "  Nothing to compare: only tip group {groups} is at, ahead of or behind the witness."
                );
            }
            _ => {
                let _ = writeln!(
                    text,
                    "  The tip groups {groups} are on separate branches: none is a prefix of\n  another, so at most one of them lies on the line hallpass wrote."
                );
            }
        }
    } else if ancestry.prefix_links.is_empty() {
        match ancestry.maximal_groups.len() {
            0 => text.push_str(
                "  Nothing to compare: no candidate extends the witness. Candidates at or\n  behind the witness (exact or shorter) are not compared here; see their rows.\n",
            ),
            1 => {
                let _ = writeln!(
                    text,
                    "  Nothing to compare: only tip group {groups} extends the witness."
                );
            }
            _ => {
                let _ = writeln!(
                    text,
                    "  The extended tip groups {groups} split after the witness: none is a\n  prefix of another, so at most one of them is the ledger hallpass wrote."
                );
            }
        }
    }
    for (from, to) in &ancestry.prefix_links {
        let _ = writeln!(text, "  group {from} is a prefix of group {to}");
    }
    if !ancestry.maximal_groups.is_empty() {
        let label = if behind {
            "Newest copy on each branch (not a prefix of any other)"
        } else {
            "Maximal groups (not a prefix of any other)"
        };
        let _ = writeln!(text, "  {label}: {groups}");
    }
}

pub fn audit_charges(file: &Path, directory: &Path, signatures: &SignatureArgs) -> Output {
    let report = match hallpass::load(file).and_then(|p| {
        signatures.reverifying(|reverify| {
            evidence::audit_charges_with(&p, &StateDir::from_env(), directory, reverify)
        })
    }) {
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
    revisions_text(&mut text, &report.revisions, &report.signatures);
    for warning in &report.warnings {
        let _ = writeln!(text, "Warning: {}", super::safe_message(warning));
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
            quoted(&row.caller_ref),
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
        if let Some(reason) = row.reason {
            let _ = writeln!(
                text,
                "      reason {reason}: the manifest lists targets, but the debit was spent without --record-target; remove the targets from the unit to skip endpoint evidence"
            );
        }
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
                Some(serde_json::Value::String(v)) => quoted(v),
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
        let _ = writeln!(text, "Warning: {}", super::safe_message(warning));
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
