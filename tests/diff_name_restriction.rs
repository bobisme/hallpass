//! `diff --examples` and `diff --containment` show an address that a
//! destination restricts to names when a nameless NEW destination opens it.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

const BASE: &str = include_str!("../docs/review-approval.toml");
const AT: &str = "2026-11-20T10:00:00Z";

const APP: &str = "[[destination]]\nlabel = \"app\"\naddress = \"203.0.113.50\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"app.example.com\", \"api.example.com\"]\n";
const WEB: &str = "[[destination]]\nlabel = \"web\"\nnetwork = \"203.0.113.0/28\"\nprotocol = \"tcp\"\nports = 443\n";

fn dmz(network: &str, protocol: &str, ports: &str) -> String {
    format!(
        "[[destination]]\nlabel = \"dmz\"\nnetwork = \"{network}\"\nprotocol = \"{protocol}\"\nports = {ports}\n"
    )
}

fn write_pass(dir: &Path, file: &str, destinations: &str) {
    let head = BASE.split("[[destination]]").next().expect("header");
    let path = dir.join(file);
    fs::write(&path, format!("{head}{destinations}")).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    // A pass written less than 250 ms ago is read again; backdate it.
    fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|f| f.set_modified(SystemTime::now() - Duration::from_secs(60)))
        .expect("backdate");
}

/// `diff old new --at AT MODE`, as JSON and as text.
fn diff(old: &str, new: &str, mode: &str, exit: i32) -> (Value, String) {
    let dir = tempfile::tempdir().expect("dir");
    write_pass(dir.path(), "old", old);
    write_pass(dir.path(), "new", new);
    let run = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .args(["diff", "old", "new", "--at", AT, mode])
            .current_dir(dir.path())
            .env("HOME", dir.path())
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(exit), "{out:?}");
        String::from_utf8(out.stdout).expect("utf8")
    };
    (serde_json::from_str(&run(true)).expect("json"), run(false))
}

fn list(value: &Value) -> Vec<Value> {
    value.as_array().expect("rows").clone()
}

/// The two rows that show `app`'s names list bypassed at 203.0.113.50:443.
fn assert_bypass_rows(rows: &[Value]) {
    let first = &rows[0];
    assert_eq!(first["target"], "203.0.113.50:443/tcp", "{rows:?}");
    assert!(first["name"].is_null(), "{rows:?}");
    assert_eq!(first["before"]["code"], "name-required", "{rows:?}");
    assert_eq!(first["after"]["label"], "dmz", "{rows:?}");
    assert_eq!(first["bypasses_names_of"], "app", "{rows:?}");
    let second = &rows[1];
    assert_eq!(second["target"], "203.0.113.50:443/tcp", "{rows:?}");
    let name = second["name"].as_str().expect("a name");
    assert!(name.ends_with(".example.net"), "{rows:?}");
    assert_eq!(second["before"]["code"], "name-not-listed", "{rows:?}");
    assert_eq!(second["after"]["label"], "dmz", "{rows:?}");
    assert_eq!(second["bypasses_names_of"], "app", "{rows:?}");
}

/// The line of `text` that holds `needle`.
fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no {needle:?} in\n{text}"))
}

#[test]
fn an_added_network_over_a_named_address_shows_it_first() {
    let old = format!("{WEB}{APP}");
    let new = format!("{old}{}", dmz("203.0.113.48/29", "tcp", "[22, 443]"));

    let (json, text) = diff(&old, &new, "--examples", 0);
    let rows = list(&json["examples"]["rows"]);
    assert_bypass_rows(&rows);
    assert!(
        rows[2..].iter().all(|r| r["bypasses_names_of"].is_null()),
        "{rows:?}"
    );
    assert!(
        rows.iter()
            .any(|r| r["target"] == "203.0.113.49:22/tcp" && r["change"] == "newly-allowed"),
        "{rows:?}"
    );
    let bypass = line_of(
        &text,
        "203.0.113.50:443/tcp (unnamed): refused (name-required) -> allowed by dmz, bypassing the names list of app",
    );
    let unlisted = line_of(
        &text,
        "example.net): refused (name-not-listed) -> allowed by dmz, bypassing the names list of app",
    );
    assert!(bypass < unlisted, "{text}");
    assert!(unlisted < line_of(&text, "203.0.113.49:"), "{text}");
    assert!(line_of(&text, "Newly allowed:") < bypass, "{text}");

    let (json, text) = diff(&old, &new, "--containment", 2);
    let c = &json["containment"];
    assert_eq!(c["endpoint_result"], "expanded", "{c}");
    let counter = list(&c["counterexamples"]);
    assert_bypass_rows(&counter);
    assert_eq!(counter[2]["target"], "203.0.113.49:22/tcp", "{c}");
    assert_eq!(counter.len(), 3, "one per widened class: {c}");
    assert_eq!(c["example"], counter[0], "{c}");
    assert_eq!(c["more_counterexamples"], false, "{c}");
    assert!(
        line_of(&text, "bypassing the names list of app") < line_of(&text, "203.0.113.49:"),
        "{text}"
    );
    assert!(!text.contains("More new allowances may exist"), "{text}");
}

#[test]
fn a_destination_that_grows_over_a_named_address_shows_it_first() {
    let old = format!("{WEB}{APP}{}", dmz("203.0.113.56/29", "tcp", "[22, 443]"));
    let new = format!("{WEB}{APP}{}", dmz("203.0.113.48/28", "tcp", "[22, 443]"));
    let (json, _) = diff(&old, &new, "--examples", 0);
    let rows = list(&json["examples"]["rows"]);
    assert_bypass_rows(&rows);
    let (json, _) = diff(&old, &new, "--containment", 2);
    assert_bypass_rows(&list(&json["containment"]["counterexamples"]));
}

#[test]
fn a_destination_that_overlaps_no_named_one_leaves_the_examples_unchanged() {
    // Each new rule misses `app` by address, protocol or port.
    let added = [
        dmz("198.51.100.0/29", "tcp", "443"),
        dmz("203.0.113.48/29", "udp", "443"),
        dmz("203.0.113.48/29", "tcp", "22"),
    ];
    for rule in added {
        let with_app = diff(
            &format!("{WEB}{APP}"),
            &format!("{WEB}{APP}{rule}"),
            "--examples",
            0,
        );
        let without = diff(WEB, &format!("{WEB}{rule}"), "--examples", 0);
        let (a, b) = (&with_app.0["examples"], &without.0["examples"]);
        assert_eq!(a["rows"], b["rows"], "{rule}");
        assert_eq!(a["candidates"], b["candidates"], "{rule}");
        assert_eq!(a["evaluated"], b["evaluated"], "{rule}");
        assert!(!list(&a["rows"]).is_empty(), "{rule}");
        assert!(
            list(&a["rows"])
                .iter()
                .all(|r| r["bypasses_names_of"].is_null()),
            "{rule}"
        );
        assert!(!with_app.1.contains("bypassing"), "{}", with_app.1);
    }
}

#[test]
fn a_range_two_old_rules_cover_together_is_not_a_widened_class() {
    // OLD allows 443 and 444 through two rules, so NEW's single 443-444 rule
    // allows nothing new there. The union proof shows that (bn-1ixb: before
    // it, no one OLD rule covered the range, and the class stayed open with
    // more_counterexamples true). Port 8000 is new.
    let old = "[[destination]]\nlabel = \"a\"\naddress = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\n[[destination]]\nlabel = \"b\"\naddress = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 444\n";
    let new = "[[destination]]\nlabel = \"a\"\naddress = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = [443, 444, 8000]\n";
    let (json, text) = diff(old, new, "--containment", 2);
    let c = &json["containment"];
    assert_eq!(c["endpoint_result"], "expanded", "{c}");
    let counter = list(&c["counterexamples"]);
    assert_eq!(counter.len(), 1, "{c}");
    assert_eq!(counter[0]["target"], "192.0.2.10:8000/tcp", "{c}");
    assert_eq!(c["more_counterexamples"], false, "{c}");
    assert!(!text.contains("More new allowances may exist"), "{text}");
}
