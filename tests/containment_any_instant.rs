//! `diff --containment` judges the endpoints at every instant, not only at
//! `--at` (bn-3js): a widening revision reviewed outside its window is not
//! contained.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const OLD: &str = r#"format = 1
id = "cont-1"
name = "Containment"

[approval]
owner = "Pat Owner"
reference = "email"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
network = "192.0.2.0/28"
protocol = "tcp"
ports = [443, 8443]
names = ["app.example.org"]

[ceilings]
calls = 6
"#;

/// Before, inside and after the window both revisions share.
const INSTANTS: [&str; 3] = [
    "2026-11-19T20:00:00Z",
    "2026-11-20T09:00:00Z",
    "2026-11-21T09:00:00Z",
];

fn write(dir: &Path, file: &str, body: &str) {
    let path = dir.join(file);
    fs::write(&path, body).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    let earlier = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|f| f.set_modified(earlier))
        .expect("date back");
}

/// Exit code, JSON and text of `diff --containment --at AT` for OLD and `new`.
fn run(new: &str, at: &str) -> (i32, Value, String) {
    let tmp = tempfile::tempdir().expect("dir");
    write(tmp.path(), "old.toml", OLD);
    write(tmp.path(), "new.toml", new);
    let go = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        cmd.args(["diff", "--containment", "--at", at, "old.toml", "new.toml"])
            .current_dir(tmp.path())
            .env("HOME", tmp.path())
            .env("XDG_STATE_HOME", tmp.path().join("state"))
            .output()
            .expect("run")
    };
    let (j, t) = (go(true), go(false));
    assert_eq!(j.status.code(), t.status.code());
    (
        j.status.code().expect("code"),
        serde_json::from_slice(&j.stdout).expect("json"),
        String::from_utf8(t.stdout).expect("utf8"),
    )
}

/// The evaluator's revision: every port on `web`, no names list, and a new
/// UDP network.
fn widening() -> String {
    format!(
        "{}\n[[destination]]\nlabel = \"extra\"\nnetwork = \"198.51.100.0/24\"\nprotocol = \"udp\"\nports = \"1-65535\"\n",
        OLD.replace("ports = [443, 8443]", "ports = \"1-65535\"")
            .replace("names = [\"app.example.org\"]\n", "")
    )
}

#[test]
fn a_widening_is_expanded_before_inside_and_after_the_window() {
    for at in INSTANTS {
        let (code, json, text) = run(&widening(), at);
        assert_eq!(code, 2, "{at}: {text}");
        assert_eq!(json["result"], "expanded", "{at}");
        let c = &json["containment"];
        assert_eq!(c["endpoint_result"], "expanded", "{at}");
        assert_eq!(c["reason"], "replayed-new-allowance", "{at}");
        let rows = c["counterexamples"].as_array().expect("rows");
        let after: Vec<_> = rows
            .iter()
            .map(|r| r["after"]["label"].as_str().expect("allowed"))
            .collect();
        assert!(
            after.contains(&"extra") && after.contains(&"web"),
            "{at}: {text}"
        );
        let inside = at == INSTANTS[1];
        let replayed = if inside { at } else { "2026-11-20T08:00:00Z" };
        assert_eq!(c["replayed_at"], replayed, "{at}");
        assert!(rows.iter().all(|r| r["at"] == replayed), "{at}");
        assert_eq!(
            text.contains("NEW's window does not hold"),
            !inside,
            "{at}: {text}"
        );
        assert!(text.contains("allowed by extra"), "{at}: {text}");
        assert!(text.contains("Overall verdict: expanded."), "{at}: {text}");
    }
}

#[test]
fn a_narrowing_is_contained_at_every_instant() {
    let new = OLD
        .replace("network = \"192.0.2.0/28\"", "address = \"192.0.2.10\"")
        .replace("ports = [443, 8443]", "ports = 443")
        .replace("calls = 6", "calls = 3");
    for at in INSTANTS {
        let (code, json, text) = run(&new, at);
        assert_eq!(code, 0, "{at}: {text}");
        assert_eq!(json["result"], "contained", "{at}");
        let c = &json["containment"];
        assert_eq!(c["reason"], "rules-and-ipv4-edges-covered", "{at}");
        assert!(c["replayed_at"].is_null(), "{at}");
        assert!(
            text.contains("Endpoint scope at every instant: contained"),
            "{text}"
        );
        assert!(
            text.contains("Contained means the endpoints and every other term only narrow."),
            "{text}"
        );
    }
}

#[test]
fn a_narrower_window_alone_is_contained_at_every_instant() {
    let new = OLD
        .replace("08:00:00Z", "10:00:00Z")
        .replace("17:00:00Z", "12:00:00Z");
    for at in INSTANTS {
        let (code, json, text) = run(&new, at);
        assert_eq!(code, 0, "{at}: {text}");
        assert_eq!(json["result"], "contained", "{at}");
        assert_eq!(
            json["containment"]["reason"],
            "rules-and-ipv4-edges-covered"
        );
    }
}

#[test]
fn a_moved_window_with_the_same_rules_is_widened_not_contained() {
    // The window moves a day later: the later end is the loosening, at any --at.
    let new = OLD.replace("2026-11-20", "2026-11-21");
    for at in INSTANTS {
        let (code, json, text) = run(&new, at);
        assert_eq!(code, 2, "{at}: {text}");
        assert_eq!(json["result"], "widened", "{at}");
        assert_eq!(json["containment"]["endpoint_result"], "contained");
        assert_eq!(
            json["containment"]["loosenings"][0]["field"],
            "approval.valid_until"
        );
    }
}

#[test]
fn a_revoked_widening_admits_nothing_and_is_contained() {
    let new = widening().replace("revoked = false", "revoked = true");
    for at in INSTANTS {
        let (code, json, text) = run(&new, at);
        assert_eq!(code, 0, "{at}: {text}");
        assert_eq!(json["result"], "contained", "{at}");
        let c = &json["containment"];
        assert_eq!(c["reason"], "new-admits-nothing", "{at}");
        assert_eq!(c["compared_pairs"], 0);
        assert!(
            text.contains(
                "Overall verdict: contained. NEW is revoked, so it admits nothing at any instant, and no other term loosens."
            ),
            "{text}"
        );
        assert!(!text.contains("Contained means"), "{text}");
    }
}
