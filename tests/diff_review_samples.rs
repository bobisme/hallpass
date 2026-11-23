//! `diff --containment` counterexamples and the order of `diff --examples` rows.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/review-approval.toml");
const AT: &str = "2026-11-20T10:00:00Z";

fn head() -> &'static str {
    BASE.split("[[destination]]").next().expect("header")
}

fn write_pass(dir: &Path, file: &str, destinations: &str) {
    let path = dir.join(file);
    fs::write(&path, format!("{}{destinations}", head())).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn diff(dir: &Path, extra: &[&str], exit: i32) -> (Value, String) {
    let run = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .args(["diff", "old", "new", "--at", AT])
            .args(extra)
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_STATE_HOME", dir.join("state"))
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(exit));
        String::from_utf8(out.stdout).expect("utf8")
    };
    (serde_json::from_str(&run(true)).expect("json"), run(false))
}

fn web(ports: &str, protocol: &str) -> String {
    format!(
        "[[destination]]\nlabel = \"web\"\naddress = \"192.0.2.10\"\nprotocol = \"{protocol}\"\nports = {ports}\n"
    )
}

#[test]
fn a_widening_across_two_port_ranges_gives_two_counterexamples() {
    let tmp = tempfile::tempdir().expect("dir");
    write_pass(tmp.path(), "old", &web("443", "tcp"));
    write_pass(
        tmp.path(),
        "new",
        &web("[443, \"8000-8010\", \"9000-9010\"]", "tcp"),
    );
    let (json, text) = diff(tmp.path(), &["--containment"], 2);
    let c = &json["containment"];
    assert_eq!(c["result"], "expanded");
    let rows = c["counterexamples"].as_array().expect("list");
    assert_eq!(rows.len(), 2, "{c}");
    assert!(rows[0]["target"].as_str().expect("t").contains(":8000/"));
    assert!(rows[1]["target"].as_str().expect("t").contains(":9000/"));
    assert_eq!(c["example"], rows[0], "the first stays in `example`");
    assert_eq!(c["more_counterexamples"], false);
    assert_eq!(
        text.matches("refused (port-not-listed) -> allowed").count(),
        2,
        "{text}"
    );
}

#[test]
fn counterexamples_are_bounded_and_say_when_more_exist() {
    let tmp = tempfile::tempdir().expect("dir");
    write_pass(tmp.path(), "old", &web("443", "tcp"));
    let ranges: Vec<String> = (0..12)
        .map(|i| format!("\"{}-{}\"", 2000 + i * 100, 2010 + i * 100))
        .collect();
    write_pass(
        tmp.path(),
        "new",
        &web(&format!("[{}]", ranges.join(",")), "tcp"),
    );
    let (json, text) = diff(tmp.path(), &["--containment"], 2);
    let c = &json["containment"];
    assert_eq!(c["counterexamples"].as_array().expect("list").len(), 8);
    assert_eq!(c["more_counterexamples"], true);
    assert!(text.contains("More new allowances may exist"), "{text}");
}

#[test]
fn examples_list_new_allowances_first_and_count_refusal_code_changes() {
    let tmp = tempfile::tempdir().expect("dir");
    write_pass(tmp.path(), "old", &web("443", "tcp"));
    // Moving the address changes the refusal code of the neighbouring ports.
    write_pass(
        tmp.path(),
        "new",
        &web("443", "tcp").replace("192.0.2.10", "192.0.2.11"),
    );

    let (json, text) = diff(tmp.path(), &["--examples"], 0);
    let ex = &json["examples"];
    let kinds: Vec<_> = ex["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r["change"].as_str().expect("change").to_owned())
        .collect();
    assert_eq!(kinds.first().map(String::as_str), Some("newly-allowed"));
    assert!(!kinds.iter().any(|k| k == "refusal-code-only"), "{kinds:?}");
    assert!(
        ex["refusal_code_changes"].as_u64().expect("count") > 0,
        "{ex}"
    );
    assert_eq!(ex["refusal_code_changes_listed"], false);
    assert!(
        text.contains("only the refusal code changed are not listed"),
        "{text}"
    );
    assert!(
        text.find("Newly allowed:") < text.find("Other changes:"),
        "{text}"
    );

    let (json, text) = diff(tmp.path(), &["--examples", "--refusal-changes"], 0);
    let rows = json["examples"]["rows"].as_array().expect("rows");
    let rank = |r: &Value| match r["change"].as_str().expect("change") {
        "newly-allowed" => 0,
        "changed" => 1,
        _ => 2,
    };
    assert!(
        rows.windows(2).all(|w| rank(&w[0]) <= rank(&w[1])),
        "{rows:?}"
    );
    assert_eq!(rank(rows.last().expect("row")), 2);
    assert_eq!(json["examples"]["refusal_code_changes_listed"], true);
    assert!(
        text.find("Newly allowed:") < text.find("Refusal code changed only:"),
        "{text}"
    );
}
