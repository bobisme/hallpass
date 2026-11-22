#![cfg(feature = "cli")]
use hallpass::{
    Decision, HostName, Pass, Target,
    time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339},
};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

const BASE: &str = include_str!("../docs/review-approval.toml");
const AT: &str = "2026-11-20T10:00:00.123456789+01:00";

fn write_pass(dir: &Path, file: &str, pass: &str) {
    let path = dir.join(file);
    fs::write(&path, pass).expect("pass");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn command(dir: &Path, args: &[&str], exit: i32) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .arg("--json")
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .output()
        .expect("run hallpass");
    assert_eq!(
        out.status.code(),
        Some(exit),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).expect("single JSON document")
}

fn diff(dir: &Path, old: &str, new: &str, at: &str) -> Value {
    write_pass(dir, "old", old);
    write_pass(dir, "new", new);
    let args = ["diff", "old", "new", "--examples", "--at", at];
    let result = command(dir, &args, 0);
    let old = Pass::parse(old).expect("old pass");
    let new = Pass::parse(new).expect("new pass");
    let sample = &result["examples"];
    assert_eq!(sample["sampled"], true);
    assert_eq!(sample["at"], at);
    let now = OffsetDateTime::parse(at, &Rfc3339).expect("offset instant");
    for row in sample["rows"].as_array().expect("rows") {
        assert_eq!(&row["at"], at);
        let target: Target = row["target"]
            .as_str()
            .expect("target")
            .parse()
            .expect("literal");
        let name = row["name"]
            .as_str()
            .map(HostName::canonical)
            .transpose()
            .expect("name");
        for (side, pass) in [("before", &old), ("after", &new)] {
            let expected = match pass.permits_named(&target, name.as_ref(), now, Duration::ZERO) {
                Decision::Allowed { label } => json!({"result":"allowed","label":label}),
                Decision::Refused(r) => json!({"result":"refused","code":r.code.as_str()}),
            };
            assert_eq!(row[side], expected, "{row}");
        }
        assert_ne!(row["before"], row["after"]);
    }
    assert!(!dir.join("state").exists());
    result
}

fn rows(report: &Value) -> &[Value] {
    report["examples"]["rows"].as_array().expect("rows")
}

#[test]
fn decision_changes_replay_with_exact_instant_and_both_address_families() {
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    let ports = BASE.replace("ports = 443", "ports = \"443-445\"");
    let expanded = diff(dir, BASE, &ports, AT);
    assert!(
        rows(&expanded)
            .iter()
            .any(|r| r["before"]["code"] == "port-not-listed" && r["after"]["label"] == "web")
    );
    assert_eq!(expanded["review_required"], true);
    let unnamed = BASE.replace("names = [\"app.example.com\"]", "");
    let relaxed = diff(dir, BASE, &unnamed, AT);
    assert!(rows(&relaxed).iter().any(|r| r["name"].is_null()
        && r["before"]["code"] == "name-required"
        && r["after"]["label"] == "web"));
    let (head, first) = BASE.split_once("[[destination]]").expect("rule");
    let other = first.replace("label = \"web\"", "label = \"second\"");
    let reorder = |a: &str, b: &str| format!("{head}[[destination]]{a}[[destination]]{b}");
    let reordered = diff(dir, &reorder(first, &other), &reorder(&other, first), AT);
    assert!(
        rows(&reordered)
            .iter()
            .any(|r| r["before"]["label"] == "web" && r["after"]["label"] == "second")
    );
    let comment = diff(dir, BASE, &format!("{BASE}# reviewed\n"), AT);
    assert_eq!(comment["examples"]["rows"], json!([]));
    assert_eq!(comment["examples"]["candidates"], 0);
    let v4 = BASE.replace("address = \"192.0.2.10\"", "network = \"192.0.2.8/30\"");
    let edge = diff(dir, &v4, &BASE.replace("192.0.2.10", "192.0.2.11"), AT);
    assert!(
        rows(&edge)
            .iter()
            .any(|r| r["target"] == "192.0.2.11:443/tcp"
                && r["before"]["code"] == "network-or-broadcast"
                && r["after"]["label"] == "web")
    );
    let v6 = BASE.replace("address = \"192.0.2.10\"", "network = \"2001:db8::/124\"");
    let narrowed = diff(dir, &v6, &v6.replace("/124", "/125"), AT);
    assert!(
        rows(&narrowed)
            .iter()
            .any(|r| r["target"] == "[2001:db8::f]:443/tcp"
                && r["before"]["label"] == "web"
                && r["after"]["code"] == "address-not-listed")
    );
    let inactive = diff(dir, BASE, &ports, "2026-11-20T17:00:00Z");
    assert_eq!(inactive["examples"]["rows"], json!([]));
    assert_eq!(inactive["review_required"], true);
    for args in [
        &["diff", "old", "new", "--examples"][..],
        &["diff", "old", "new", "--at", AT],
        &["diff", "old", "new", "--examples", "--at", "noon"],
    ] {
        assert_eq!(command(dir, args, 1)["error"]["code"], "usage");
    }
}

#[test]
fn candidate_work_and_changed_rows_have_independent_limits() {
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    let names = (0..64)
        .map(|n| format!("\"n{n}.example.org\""))
        .collect::<Vec<_>>()
        .join(",");
    let old = BASE
        .replace("\"app.example.com\"", &names)
        .replace("address = \"192.0.2.10\"", "network = \"192.0.2.8/30\"");
    let new = old.replace("ports = 443", "ports = 444");
    let capped = diff(dir, &old, &new, "2026-11-21T09:00:00Z");
    assert_eq!(capped["examples"]["candidates"], 512);
    assert_eq!(capped["examples"]["truncated"], true);
    assert_eq!(capped["examples"]["rows"], json!([]));
    assert_eq!(capped["review_required"], true);
    let changed = diff(dir, &old, &new, AT);
    assert_eq!(rows(&changed).len(), 64);
    assert_eq!(changed["examples"]["truncated"], true);
    assert_eq!(changed["review_required"], true);
}

#[test]
fn coverage_compares_each_enforced_requirement_and_rejects_bad_declarations() {
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    let pass = format!("{BASE}\n[ceilings]\nrequests=10\nbytes=20\ncalls=30\n");
    write_pass(dir, "pass", &pass);
    let gaps = command(
        dir,
        &[
            "consumer-coverage",
            "pass",
            "--can",
            "endpoints",
            "--can",
            "charge:calls",
        ],
        2,
    );
    assert_eq!(gaps["result"], "gaps");
    assert_eq!(
        gaps["digest"],
        hallpass::Digest::of(pass.as_bytes()).to_string()
    );
    assert_eq!(
        gaps["findings"],
        json!([{"code":"missing-live-window"},{"code":"missing-names","label":"web"},{"code":"missing-counter","counter":"bytes"},{"code":"missing-counter","counter":"requests"}])
    );
    let all = command(
        dir,
        &[
            "consumer-coverage",
            "pass",
            "--can",
            "endpoints",
            "--can",
            "live-window",
            "--can",
            "names",
            "--can",
            "charge:calls",
            "--can",
            "charge:bytes",
            "--can",
            "charge:requests",
        ],
        0,
    );
    assert_eq!(all["result"], "covered");
    assert_eq!(all["findings"], json!([]));
    let literal = BASE.replace(
        "names = [\"app.example.com\"]",
        "hostname = \"service.example.org\"",
    );
    write_pass(dir, "pass", &literal);
    assert_eq!(
        command(
            dir,
            &[
                "consumer-coverage",
                "pass",
                "--can",
                "endpoints",
                "--can",
                "live-window"
            ],
            0
        )["result"],
        "covered"
    );
    assert_eq!(
        command(dir, &["consumer-coverage", "pass", "--can", "none"], 2)["findings"],
        json!([{"code":"missing-live-window"},{"code":"missing-endpoints","label":"web"}])
    );
    for args in [
        &[][..],
        &["--can", "packets"],
        &["--can", "charge:"],
        &["--can", "charge:No"],
        &["--can", "none", "--can", "names"],
        &["--can", "names", "--can", "names"],
    ] {
        let mut argv = vec!["consumer-coverage", "pass"];
        argv.extend(args);
        assert_eq!(command(dir, &argv, 1)["error"]["code"], "usage");
    }
    assert!(!dir.join("state").exists());
    assert!(!dir.join("pass.ledger").exists());
}

#[test]
fn amendment_projects_only_current_history_including_adoption() {
    use hallpass::{SpendRequest, StateDir, adopt, spend_in};
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    let old = format!("{BASE}\n[ceilings]\ncalls = 10\n");
    let args = ["diff", "old", "new", "--budget-impact"];
    write_pass(dir, "old", &old);
    write_pass(
        dir,
        "new",
        &old.replace("calls = 10", "calls = 6\nbytes = 100"),
    );
    write_pass(dir, "new.ledger", "corrupt decoy");
    let fresh = command(dir, &args, 0);
    assert!(fresh["budget_impact"]["tip"].is_null());
    assert!(!dir.join("state").exists());
    let now = OffsetDateTime::parse(AT, &Rfc3339).expect("instant");
    let state = StateDir::new(dir.join("state/hallpass"));
    let path = dir.join("old");
    let ledger = dir.join("old.ledger");
    spend_in(&path, &SpendRequest::new("calls", 8), now, &state).expect("spend");
    fs::remove_file(&ledger).expect("simulate loss");
    assert_eq!(command(dir, &args, 1)["error"]["code"], "ledger-missing");
    adopt(&path, "restore balances", now, &state).expect("carry");
    let saved = fs::read(&ledger).expect("snapshot");
    let witness = state.witness_path("review-example").expect("path");
    let witness_before = fs::read(&witness).expect("witness");
    for (limit, remaining, over) in [(6, 0, 2), (8, 0, 0), (12, 4, 0)] {
        write_pass(
            dir,
            "new",
            &old.replace("calls = 10", &format!("calls = {limit}\nbytes = 100")),
        );
        let projection = &command(dir, &args, 0)["budget_impact"];
        assert_eq!(projection["witness"], "matches");
        assert_eq!(projection["tip"]["seq"], 1);
        assert_eq!(projection["counters"][0]["spent"], 0);
        let row = &projection["counters"][1];
        assert_eq!(row["spent"], 8);
        assert_eq!(row["old_remaining"], 2);
        assert_eq!(row["proposed_remaining"], remaining);
        assert_eq!(row["over_proposed"], over);
    }
    write_pass(dir, "new", BASE);
    assert!(command(dir, &args, 0)["budget_impact"]["counters"][0]["proposed_ceiling"].is_null());
    write_pass(dir, "old", BASE);
    write_pass(
        dir,
        "new",
        &old.replace(
            "[approval]",
            "required_counters_v1 = [\"calls\"]\n[approval]",
        ),
    );
    let row = &command(dir, &args, 0)["budget_impact"]["counters"][0];
    assert!(row["old_ceiling"].is_null());
    assert_eq!(row["proposed_remaining"], 2);
    assert_eq!(row["proposed_required"], true);
    assert_eq!(fs::read(&ledger).expect("snapshot"), saved);
    assert_eq!(fs::read(witness).expect("witness"), witness_before);
    write_pass(dir, "new", &old.replace("review-example", "other-id"));
    assert_eq!(
        command(dir, &args, 2)["budget_impact"]["reason"],
        "different-pass-id"
    );
    write_pass(dir, "new", &old);
    write_pass(dir, "old.ledger", "broken");
    assert_eq!(command(dir, &args, 1)["error"]["code"], "ledger-corrupt");
    assert_eq!(command(dir, &["diff", "old", "new"], 0)["result"], "ok");
}

#[test]
fn containment_cli_requires_open_windows_and_replays_expanded_edges() {
    let tmp = tempfile::tempdir().expect("dir");
    let dir = tmp.path();
    let args = ["diff", "old", "new", "--containment", "--at", AT];
    let old = BASE.replace("address = \"192.0.2.10\"", "network = \"192.0.2.8/30\"");
    write_pass(dir, "old", &old);
    write_pass(dir, "new", &BASE.replace("192.0.2.10", "192.0.2.11"));
    let expanded = command(dir, &args, 2);
    let evidence = &expanded["containment"]["example"];
    assert_eq!(expanded["result"], "expanded");
    assert_eq!(evidence["before"]["code"], "network-or-broadcast");
    assert_eq!(evidence["after"]["label"], "web");
    write_pass(
        dir,
        "old",
        &BASE
            .replace("address = \"192.0.2.10\"", "network = \"2001:db8::/124\"")
            .replace("ports = 443", "ports = [443, 444]")
            .replace("names = [\"app.example.com\"]", ""),
    );
    write_pass(
        dir,
        "new",
        &BASE
            .replace("192.0.2.10", "2001:db8::1")
            .replace("label = \"web\"", "label = \"site\""),
    );
    assert_eq!(command(dir, &args, 0)["containment"]["result"], "contained");
    write_pass(dir, "new", &BASE.replace("review-example", "other-id"));
    assert_eq!(
        command(dir, &args, 2)["containment"]["reason"],
        "different-pass-id"
    );
    write_pass(dir, "new", &BASE.replace("2026-11-20", "2026-11-21"));
    assert_eq!(
        command(dir, &args, 2)["containment"]["reason"],
        "both-windows-must-be-open"
    );
    assert!(!dir.join("state").exists());
}

#[test]
fn every_small_containment_certificate_agrees_with_exhaustive_endpoint_decisions() {
    use hallpass::review::endpoint_containment;
    let now = OffsetDateTime::parse(AT, &Rfc3339).expect("time");
    let mut policies = vec![];
    for cidr in ["192.0.2.8/30", "192.0.2.10/31", "192.0.2.11/32"] {
        for ports in ["443", "[443,444]"] {
            for names in ["", "names = [\"app.example.com\"]"] {
                let text = BASE
                    .replace("address = \"192.0.2.10\"", &format!("network = \"{cidr}\""))
                    .replace("ports = 443", &format!("ports = {ports}"))
                    .replace("names = [\"app.example.com\"]", names);
                for extra in [
                    "",
                    "\n[[destination]]\nlabel = \"other\"\naddress = \"192.0.2.11\"\nports = 444\nprotocol = \"udp\"\n",
                ] {
                    policies.push(Pass::parse(&format!("{text}{extra}")).expect("pass"));
                }
            }
        }
    }
    let app = HostName::canonical("app.example.com").expect("app");
    let other = HostName::canonical("other.example.com").expect("other");
    let requests: Vec<_> = (7..=12)
        .flat_map(|last| {
            (442..=445).flat_map(move |port| {
                ["tcp", "udp"].into_iter().map(move |proto| {
                    format!("192.0.2.{last}:{port}/{proto}")
                        .parse::<Target>()
                        .expect("target")
                })
            })
        })
        .collect();
    for old in &policies {
        for new in &policies {
            if endpoint_containment(old, new, now).result != "contained" {
                continue;
            }
            for target in &requests {
                for name in [None, Some(&app), Some(&other)] {
                    if matches!(
                        new.permits_named(target, name, now, Duration::ZERO),
                        Decision::Allowed { .. }
                    ) {
                        assert!(matches!(
                            old.permits_named(target, name, now, Duration::ZERO),
                            Decision::Allowed { .. }
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn pair_limit_and_union_proofs_remain_inconclusive() {
    use hallpass::review::endpoint_containment;
    let now = OffsetDateTime::parse(AT, &Rfc3339).expect("time");
    let (head, _) = BASE.split_once("[[destination]]").expect("head");
    let mut many = head.to_string();
    for port in 1..=190 {
        use std::fmt::Write as _;
        writeln!(many, "[[destination]]\nlabel = \"r{port}\"\naddress = \"192.0.2.10\"\nports = {port}\nprotocol = \"tcp\"").expect("row");
    }
    let pass = Pass::parse(&many).expect("pass");
    let capped = endpoint_containment(&pass, &pass, now);
    assert_eq!(capped.result, "inconclusive");
    assert_eq!(capped.reason, "pair-limit");
    let split = format!(
        "{BASE}\n[[destination]]\nlabel = \"other\"\naddress = \"192.0.2.10\"\nports = 444\nprotocol = \"tcp\"\nnames = [\"app.example.com\"]\n"
    );
    let proposed = BASE.replace("ports = 443", "ports = [443,444]");
    let union = endpoint_containment(
        &Pass::parse(&split).expect("pass"),
        &Pass::parse(&proposed).expect("pass"),
        now,
    );
    assert_eq!(union.result, "inconclusive");
    assert_eq!(union.reason, "single-rule-coverage-unproved");
}
