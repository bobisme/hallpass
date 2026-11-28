//! A counter substitution is a loosening: NEW drops an OLD ceiling and adds a
//! ceiling under a name OLD did not have. The ledger counts spend by counter
//! name, so the new counter starts from zero mid-engagement.
#![cfg(feature = "cli")]

use hallpass::{
    SpendRequest, StateDir, spend_in,
    time::{OffsetDateTime, format_description::well_known::Rfc3339},
};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/review-approval.toml");
const AT: &str = "2026-11-20T10:00:00Z";

/// A pass with these ceiling lines and, when not empty, these required counters.
fn pass(ceilings: &str, required: &[&str]) -> String {
    let head = if required.is_empty() {
        BASE.to_owned()
    } else {
        let list: Vec<String> = required.iter().map(|c| format!("\"{c}\"")).collect();
        BASE.replacen(
            "format = 1\n",
            &format!("format = 1\nrequired_counters_v1 = [{}]\n", list.join(", ")),
            1,
        )
    };
    format!("{head}\n[ceilings]\n{ceilings}\n")
}

fn write(dir: &Path, file: &str, body: &str) {
    let path = dir.join(file);
    fs::write(&path, body).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn hallpass(dir: &Path, json: bool, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
    if json {
        cmd.arg("--json");
    }
    let out = cmd
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("HALLPASS_UNSAFE_TEST_CLOCK", AT)
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run");
    let mut text = String::from_utf8(out.stdout).expect("utf8");
    text.push_str(&String::from_utf8(out.stderr).expect("utf8"));
    (out.status.code().expect("exit"), text)
}

/// `diff --containment` from OLD to NEW: exit code, JSON and text.
fn containment(old: &str, new: &str) -> (i32, Value, String) {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old", old);
    write(tmp.path(), "new", new);
    let args = ["diff", "old", "new", "--containment", "--at", AT];
    let (code, json) = hallpass(tmp.path(), true, &args);
    let (text_code, text) = hallpass(tmp.path(), false, &args);
    assert_eq!(code, text_code, "{text}");
    (code, serde_json::from_str(&json).expect("json"), text)
}

fn loosened_fields(json: &Value) -> Vec<String> {
    json["containment"]["loosenings"]
        .as_array()
        .expect("list")
        .iter()
        .map(|l| l["field"].as_str().expect("field").to_owned())
        .collect()
}

fn substitution<'a>(json: &'a Value, field: &str) -> &'a Value {
    json["containment"]["loosenings"]
        .as_array()
        .expect("list")
        .iter()
        .find(|l| l["field"] == field)
        .unwrap_or_else(|| panic!("no loosening {field}: {json}"))
}

fn assert_widened(code: i32, json: &Value, text: &str) {
    assert_eq!(code, 2, "{text}");
    assert_eq!(json["result"], "widened", "{json}");
    assert_eq!(json["containment"]["endpoint_result"], "contained");
    assert!(text.contains("Overall verdict: widened."), "{text}");
}

#[test]
fn a_rename_to_a_required_counter_is_widened() {
    // The evaluation's repro: the gate passed this and 6 units went out
    // against an approval of 3.
    let (code, json, text) =
        containment(&pass("requests = 3", &[]), &pass("calls = 3", &["calls"]));
    assert_widened(code, &json, &text);
    let l = substitution(&json, "ceilings.requests");
    assert_eq!(l["code"], "counter-substitution");
    assert_eq!(l["replaced_by"], json!(["calls"]));
    assert_eq!(l["before"], 3);
    assert!(l["after"].is_null());
    assert!(
        text.contains(
            "Loosened: ceilings.requests: 3 -> none, renamed or replaced by \"calls\" (counter-substitution)"
        ),
        "{text}"
    );
}

#[test]
fn a_rename_to_an_optional_counter_lists_both_loosenings() {
    let (code, json, text) = containment(&pass("requests = 3", &[]), &pass("calls = 3", &[]));
    assert_widened(code, &json, &text);
    assert_eq!(
        loosened_fields(&json),
        ["ceilings.calls", "ceilings.requests"]
    );
    // The new ceiling is an ordinary loosening, without a code.
    assert!(substitution(&json, "ceilings.calls").get("code").is_none());
}

#[test]
fn a_rename_that_lowers_the_amount_is_still_widened() {
    let (code, json, text) =
        containment(&pass("requests = 3", &[]), &pass("calls = 1", &["calls"]));
    assert_widened(code, &json, &text);
    assert_eq!(
        substitution(&json, "ceilings.requests")["code"],
        "counter-substitution"
    );
}

#[test]
fn a_split_ceiling_is_one_substitution_with_both_new_names() {
    let (code, json, text) = containment(
        &pass("requests = 6", &["requests"]),
        &pass("reads = 3\nwrites = 3", &["reads", "writes"]),
    );
    assert_widened(code, &json, &text);
    let l = substitution(&json, "ceilings.requests");
    assert_eq!(l["replaced_by"], json!(["reads", "writes"]));
    assert!(text.contains("\"reads\", \"writes\""), "{text}");
}

#[test]
fn merged_ceilings_are_each_a_substitution() {
    let (code, json, text) = containment(
        &pass("reads = 3\nwrites = 3", &[]),
        &pass("requests = 6", &["requests"]),
    );
    assert_widened(code, &json, &text);
    for field in ["ceilings.reads", "ceilings.writes"] {
        assert_eq!(
            substitution(&json, field)["replaced_by"],
            json!(["requests"])
        );
    }
}

#[test]
fn a_substitution_beside_a_kept_required_counter_is_widened() {
    // Every debit still charges `bytes`, but work that OLD charged to
    // `requests` is now counted from zero under `calls`.
    let (code, json, text) = containment(
        &pass("bytes = 100\nrequests = 3", &["bytes"]),
        &pass("bytes = 100\ncalls = 3", &["bytes", "calls"]),
    );
    assert_widened(code, &json, &text);
    assert_eq!(loosened_fields(&json), ["ceilings.requests"]);
}

#[test]
fn a_removed_ceiling_alone_still_narrows() {
    let (code, json, text) = containment(
        &pass("bytes = 100\nrequests = 3", &[]),
        &pass("bytes = 100", &[]),
    );
    assert_eq!(code, 0, "{text}");
    assert_eq!(json["result"], "contained");
    assert_eq!(json["containment"]["loosenings"], json!([]));
}

#[test]
fn a_new_required_counter_beside_a_kept_required_one_narrows() {
    // Every debit still charges `requests` and its spend so far.
    let (code, json, text) = containment(
        &pass("requests = 3", &["requests"]),
        &pass("calls = 3\nrequests = 3", &["calls", "requests"]),
    );
    assert_eq!(code, 0, "{text}");
    assert_eq!(json["result"], "contained");
}

#[test]
fn a_new_counter_only_new_requires_is_widened() {
    // NEW keeps `requests` but does not require it: a debit can charge
    // `calls` alone, counted from zero outside OLD's ceiling.
    let (code, json, text) = containment(
        &pass("requests = 3", &[]),
        &pass("calls = 3\nrequests = 3", &["calls"]),
    );
    assert_widened(code, &json, &text);
    assert_eq!(loosened_fields(&json), ["ceilings.calls"]);
    assert!(substitution(&json, "ceilings.calls").get("code").is_none());
}

#[test]
fn a_required_ceiling_added_to_a_pass_without_ceilings_is_widened() {
    // OLD could not be spent at all.
    let (code, json, text) = containment(&format!("{BASE}\n"), &pass("calls = 3", &["calls"]));
    assert_widened(code, &json, &text);
    assert_eq!(loosened_fields(&json), ["ceilings.calls"]);
}

#[test]
fn a_new_counter_only_new_requires_does_spend_past_the_old_ceiling() {
    // The reason for the rule above, shown on a ledger.
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    let now = OffsetDateTime::parse(AT, &Rfc3339).expect("instant");
    let state = StateDir::new(dir.join("state/hallpass"));
    let live = dir.join("live");
    write(dir, "live", &pass("requests = 3", &[]));
    let spend = |counter, amount| {
        spend_in(&live, &SpendRequest::new(counter, amount), now, &state).expect("spend")
    };
    assert!(spend("requests", 3).refusal.is_none());
    assert!(spend("requests", 1).refusal.is_some());
    write(dir, "live", &pass("calls = 3\nrequests = 3", &["calls"]));
    assert!(spend("calls", 3).refusal.is_none(), "a fresh count");
}

#[test]
fn budget_impact_flags_a_substitution() {
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    write(dir, "old", &pass("requests = 3", &[]));
    write(dir, "new", &pass("calls = 3", &["calls"]));
    let args = ["diff", "old", "new", "--budget-impact"];
    let (code, text) = hallpass(dir, false, &args);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("WARNING: NEW drops the ceiling on \"requests\" and adds \"calls\"."),
        "{text}"
    );
    assert!(text.contains("counter-substitution"), "{text}");
    let (code, out) = hallpass(dir, true, &args);
    assert_eq!(code, 0, "{out}");
    let value: Value = serde_json::from_str(&out).expect("json");
    assert_eq!(
        value["budget_impact"]["counter_substitution"],
        json!({"dropped": ["requests"], "added": ["calls"]})
    );
    // No substitution: the key is null and nothing is printed.
    write(dir, "new", &pass("requests = 2", &[]));
    let (_, text) = hallpass(dir, false, &args);
    assert!(!text.contains("counter-substitution"), "{text}");
    let (_, out) = hallpass(dir, true, &args);
    let value: Value = serde_json::from_str(&out).expect("json");
    assert!(
        value["budget_impact"]["counter_substitution"].is_null(),
        "{value}"
    );
}
