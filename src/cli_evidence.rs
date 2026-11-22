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
    for row in &report.matches {
        let _ = writeln!(
            text,
            "  #{} {} {}  charges={} targets={}",
            row.seq,
            row.time,
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
            let _ = writeln!(text, "  {}", safe(&json!(row).to_string()));
        }
        if group.truncated {
            text.push_str("  Additional endpoint details omitted.\n");
        }
    }
    for (reason, gap) in &report.gaps {
        let _ = writeln!(
            text,
            "Gap {reason} {}. Sequences {:?}{}",
            gap.count,
            gap.sequences,
            if gap.truncated {
                " (additional sequences omitted)"
            } else {
                ""
            }
        );
    }
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
    let mut text = format!(
        "Backup assessment {}. Captured witness {}.\n",
        report.assessment,
        json!(report.anchor)
    );
    if let Some(ancestry) = &report.ancestry {
        let _ = writeln!(text, "Ancestry {}", json!(ancestry));
    }
    for row in &report.candidates {
        let _ = writeln!(text, "  {}", safe(&json!(row).to_string()));
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

pub fn audit_charges(file: &Path, directory: &Path) -> Output {
    let report = match hallpass::load(file)
        .and_then(|p| evidence::audit_charges(&p, &StateDir::from_env(), directory))
    {
        Ok(report) => report,
        Err(e) => return error_output("audit-charges", Some(file), &e),
    };
    let text = format!(
        "Charge audit {}. Witness {}. Checked debits {}.\nMismatches {}\nGaps {}\n",
        report.result,
        report.witness,
        report.checked_debits,
        safe(&json!(report.mismatches).to_string()),
        safe(&json!(report.gaps).to_string())
    );
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
