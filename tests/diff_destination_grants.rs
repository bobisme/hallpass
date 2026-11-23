//! `diff` shows what an introduced or removed destination grants.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/review-approval.toml");

const WEB: &str = "[[destination]]\nlabel = \"cdn-web\"\naddress = \"203.0.113.20\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"cdn.example\"]\n";
const ANY: &str = "[[destination]]\nlabel = \"cdn-any\"\nnetwork = \"203.0.113.20/32\"\nprotocol = \"tcp\"\nports = 443\n";

fn write_pass(dir: &Path, file: &str, destinations: &str) {
    let head = BASE.split("[[destination]]").next().expect("header");
    let path = dir.join(file);
    fs::write(&path, format!("{head}{destinations}")).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn run(dir: &Path, json: bool) -> (String, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
    if json {
        cmd.arg("--json");
    }
    let out = cmd
        .args(["diff", "old", "new"])
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).expect("utf8");
    let value = if json {
        serde_json::from_str(&text).expect("json")
    } else {
        Value::Null
    };
    (text, value)
}

fn setup(old: &str, new: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "old", old);
    write_pass(dir.path(), "new", new);
    dir
}

#[test]
fn an_introduced_destination_prints_its_grant_and_the_overlap() {
    let dir = setup(WEB, &format!("{WEB}{ANY}"));
    let (text, _) = run(dir.path(), false);
    assert!(
        text.contains("introduced destination: cdn-any grants address 203.0.113.20 tcp ports 443, any name [review required]"),
        "{text}"
    );
    assert!(
        text.contains("WARNING: destination `cdn-web` restricts names"),
        "{text}"
    );
    let (_, json) = run(dir.path(), true);
    assert_eq!(json["review_required"], true);
    let g = &json["introduced_grants"][0];
    assert_eq!(g["label"], "cdn-any");
    assert_eq!(g["scope"], "address");
    assert_eq!(g["network"], "203.0.113.20");
    assert_eq!(g["protocol"], "tcp");
    assert_eq!(g["ports"], "443");
    assert_eq!(g["names"], serde_json::json!([]));
    assert_eq!(json["removed_grants"], serde_json::json!([]));
    let w = &json["name_restriction_overlaps"][0];
    assert_eq!(w["named_label"], "cdn-web");
    assert_eq!(w["unnamed_label"], "cdn-any");
}

#[test]
fn a_removed_destination_prints_what_it_granted() {
    let dir = setup(&format!("{WEB}{ANY}"), WEB);
    let (text, _) = run(dir.path(), false);
    assert!(
        text.contains("removed destination: cdn-any grants address 203.0.113.20 tcp ports 443, any name [review required]"),
        "{text}"
    );
    assert!(!text.contains("WARNING"), "{text}");
    let (_, json) = run(dir.path(), true);
    assert_eq!(json["removed_grants"][0]["label"], "cdn-any");
    assert_eq!(json["introduced_grants"], serde_json::json!([]));
    assert_eq!(json["name_restriction_overlaps"], serde_json::json!([]));
}

#[test]
fn a_named_introduced_destination_lists_its_names_without_a_warning() {
    let dir = setup(
        WEB,
        &format!(
            "{WEB}{}",
            ANY.replace(
                "ports = 443\n",
                "ports = 443\nnames = [\"b.example\", \"a.example\"]\n"
            )
        ),
    );
    let (text, _) = run(dir.path(), false);
    let (_, json) = run(dir.path(), true);
    assert!(
        text.contains("names a.example, b.example [review required]"),
        "{text}"
    );
    assert_eq!(json["name_restriction_overlaps"], serde_json::json!([]));
    assert_eq!(
        json["introduced_grants"][0]["names"],
        serde_json::json!(["a.example", "b.example"])
    );
}
