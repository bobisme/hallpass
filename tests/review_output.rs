//! Plain values in `diff`, and the name-overlap warning in `check` and `status`.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const HEAD: &str = "format = 1\nid = \"p\"\nname = \"n\"\n[approval]\nowner = \"O\"\nreference = \"R\"\noperator = \"Op\"\nvalid_from = 2026-11-20T08:00:00Z\nvalid_until = 2026-11-20T17:00:00Z\nrevoked = false\n";

struct Case {
    dir: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }
    fn pass(&self, name: &str, body: &str) -> String {
        let path = self.dir.path().join(name);
        fs::write(&path, format!("{HEAD}{body}")).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        path.to_str().expect("utf8").to_owned()
    }
    fn run(&self, json: bool, args: &[&str]) -> (i32, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .args(args)
            .env("HALLPASS_UNSAFE_TEST_CLOCK", "2026-11-20T09:00:00Z")
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .output()
            .expect("run");
        (
            out.status.code().expect("exit"),
            String::from_utf8(out.stdout).expect("utf8"),
        )
    }
}

const WEB: &str =
    "[[destination]]\nlabel = \"web\"\naddress = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\n";

fn changes(case: &Case, old: &str, new: &str) -> (Vec<Value>, String) {
    let (_, text) = case.run(false, &["diff", old, new]);
    let (_, json) = case.run(true, &["diff", old, new]);
    let value: Value = serde_json::from_str(&json).expect("json");
    (value["changes"].as_array().expect("changes").clone(), text)
}

fn find<'a>(rows: &'a [Value], field: &str) -> &'a Value {
    rows.iter()
        .find(|c| c["field"] == field)
        .unwrap_or_else(|| panic!("no {field}: {rows:?}"))
}

#[test]
fn diff_shows_plain_values_and_real_field_names() {
    let case = Case::new();
    let base = format!("{WEB}hostname = \"sip.acme.example\"\n[ceilings]\ncalls = 5\n");
    let old = case.pass("old.toml", &base);

    // Added ceiling, removed ceiling.
    let added = case.pass("added.toml", &format!("{base}bytes = 7\n"));
    let (rows, text) = changes(&case, &old, &added);
    let row = find(&rows, "ceilings.bytes");
    assert_eq!(row["before"], Value::Null);
    assert_eq!(row["after"], 7);
    assert!(
        text.contains("ceilings.bytes: none -> 7 [review required]"),
        "{text}"
    );
    let (rows, text) = changes(&case, &added, &old);
    let row = find(&rows, "ceilings.bytes");
    assert_eq!(
        (row["before"].clone(), row["after"].clone()),
        (7.into(), Value::Null)
    );
    assert!(text.contains("ceilings.bytes: 7 -> none"), "{text}");

    // Hostname change.
    let renamed = case.pass("renamed.toml", &base.replace("sip.acme", "sip2.acme"));
    let (rows, text) = changes(&case, &old, &renamed);
    let row = find(&rows, "destination[web].hostname");
    assert_eq!(row["before"], "sip.acme.example");
    assert_eq!(row["after"], "sip2.acme.example");
    assert!(
        text.contains("sip.acme.example -> sip2.acme.example"),
        "{text}"
    );

    // Hostname added: absent before.
    let no_host = case.pass(
        "no_host.toml",
        &base.replace("hostname = \"sip.acme.example\"\n", ""),
    );
    let (rows, _) = changes(&case, &no_host, &old);
    assert_eq!(
        find(&rows, "destination[web].hostname")["before"],
        Value::Null
    );

    // Port list change prints like status.
    let ports = case.pass(
        "ports.toml",
        &base.replace("ports = 443", "ports = [443, 8443, \"9000-9010\"]"),
    );
    let (rows, text) = changes(&case, &old, &ports);
    let row = find(&rows, "destination[web].ports");
    assert_eq!(row["before"], "443");
    assert_eq!(row["after"], "443, 8443, 9000-9010");
    assert!(text.contains("443 -> 443, 8443, 9000-9010"), "{text}");

    // Address stays `address`; a network change is named `network`.
    let moved = case.pass("moved.toml", &base.replace("192.0.2.10", "192.0.2.11"));
    let (rows, _) = changes(&case, &old, &moved);
    assert_eq!(
        find(&rows, "destination[web].address")["after"],
        "192.0.2.11"
    );
    let net_old = case.pass(
        "net-old.toml",
        &WEB.replace("address = \"192.0.2.10\"", "network = \"192.0.2.0/28\""),
    );
    let net_new = case.pass(
        "net-new.toml",
        &WEB.replace("address = \"192.0.2.10\"", "network = \"192.0.2.16/28\""),
    );
    let (rows, text) = changes(&case, &net_old, &net_new);
    let row = find(&rows, "destination[web].network");
    assert_eq!(row["before"], "192.0.2.0/28");
    assert!(
        text.contains("destination[web].network: 192.0.2.0/28 -> 192.0.2.16/28"),
        "{text}"
    );
    let (rows, _) = changes(&case, &old, &net_new);
    assert_eq!(
        find(&rows, "destination[web].network")["before"],
        "192.0.2.10"
    );

    // Names change.
    let named = case.pass(
        "named.toml",
        &format!("{WEB}names = [\"app.example.com\"]\n"),
    );
    let plain = case.pass("plain.toml", WEB);
    let (rows, text) = changes(&case, &plain, &named);
    assert_eq!(
        find(&rows, "destination[web].names")["after"],
        "app.example.com"
    );
    assert!(text.contains("names: none -> app.example.com"), "{text}");

    // Revoked reason.
    let revoked = case.pass("revoked.toml", WEB);
    let revoked_text = fs::read_to_string(&revoked).expect("read").replace(
        "revoked = false",
        "revoked = true\nrevoked_reason = \"done\"",
    );
    fs::write(&revoked, revoked_text).expect("write");
    let (rows, _) = changes(&case, &plain, &revoked);
    assert_eq!(find(&rows, "approval.revoked_reason")["after"], "done");

    for (_, text) in [changes(&case, &old, &added), changes(&case, &old, &ports)] {
        assert!(!text.contains("Some(") && !text.contains("None"), "{text}");
    }
}

const OVERLAP: &str = "[[destination]]\nlabel = \"wide\"\nnetwork = \"198.51.100.0/24\"\nprotocol = \"tcp\"\nports = \"1-1024\"\n[[destination]]\nlabel = \"app\"\naddress = \"198.51.100.20\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"app.example.com\"]\n";
const DISJOINT: &str = "[[destination]]\nlabel = \"wide\"\nnetwork = \"198.51.100.0/24\"\nprotocol = \"tcp\"\nports = \"1-1024\"\n[[destination]]\nlabel = \"app\"\naddress = \"203.0.113.20\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"app.example.com\"]\n";

#[test]
fn check_and_status_warn_when_another_destination_defeats_names() {
    let case = Case::new();
    let overlap = case.pass("overlap.toml", OVERLAP);
    let disjoint = case.pass("disjoint.toml", DISJOINT);
    for command in ["check", "status"] {
        let (code, text) = case.run(false, &[command, &overlap]);
        assert_eq!(code, 0, "{text}");
        assert!(
            text.contains("WARNING: destination `app` restricts names"),
            "{text}"
        );
        assert!(
            text.contains("`wide`") && text.contains("hallpass lint"),
            "{text}"
        );
        let (code, json) = case.run(true, &[command, &overlap]);
        assert_eq!(code, 0, "{json}");
        let value: Value = serde_json::from_str(&json).expect("json");
        let found = value["name_restriction_overlaps"]
            .as_array()
            .expect("array");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["named_label"], "app");
        assert_eq!(found[0]["unnamed_label"], "wide");
        assert_eq!(found[0]["code"], "name-restriction-overlap");
        assert!(
            value["warnings"]
                .as_array()
                .expect("warnings")
                .iter()
                .any(|w| w.as_str().is_some_and(|w| w.contains("`wide`")))
        );

        let (code, text) = case.run(false, &[command, &disjoint]);
        assert_eq!(code, 0);
        assert!(!text.contains("restricts names"), "{text}");
        let (_, json) = case.run(true, &[command, &disjoint]);
        let value: Value = serde_json::from_str(&json).expect("json");
        assert_eq!(
            value["name_restriction_overlaps"]
                .as_array()
                .expect("array")
                .len(),
            0
        );
    }
    // lint output is unchanged by the new advice.
    let (_, json) = case.run(true, &["lint", &overlap]);
    let value: Value = serde_json::from_str(&json).expect("json");
    assert_eq!(value["findings"][0]["code"], "name-restriction-overlap");
}
