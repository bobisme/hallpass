#![cfg(feature = "cli")]

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use serde_json::Value;

const PASS: &str = include_str!("../docs/review-approval.toml");
const WEAK: &str = include_str!("../docs/review-suite-weak.toml");
const STRONG: &str = include_str!("../docs/review-suite-strong.toml");

fn pass_file(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("approval.toml");
    fs::write(&path, contents).expect("pass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private pass");
    path
}

#[test]
fn weak_and_strong_suites_report_the_first_distinguishing_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = pass_file(dir.path(), PASS);
    let before = fs::read(&path).expect("original bytes");
    let loaded = hallpass::load(&path).expect("valid pass");
    let weak = hallpass::review::mutation_strength(&loaded.pass, WEAK).expect("weak analysis");
    assert_eq!(weak["result"], "surviving-mutations");
    let weak_names = weak["mutations"]
        .as_array()
        .expect("mutations")
        .iter()
        .find(|mutation| {
            mutation["changed_term"]
                .as_str()
                .unwrap_or("")
                .contains(".names:")
        })
        .expect("name mutation");
    assert_eq!(weak_names["status"], "survived");
    assert_eq!(
        weak,
        hallpass::review::mutation_strength(&loaded.pass, WEAK).expect("repeat")
    );

    let strong =
        hallpass::review::mutation_strength(&loaded.pass, STRONG).expect("strong analysis");
    assert_eq!(strong["result"], "complete");
    let mutations = strong["mutations"].as_array().expect("mutations");
    let names = mutations
        .iter()
        .find(|mutation| {
            mutation["changed_term"]
                .as_str()
                .unwrap_or("")
                .contains(".names:")
        })
        .expect("name mutation");
    assert_eq!(names["status"], "distinguished");
    assert_eq!(
        names["first_distinguishing_case"]["id"],
        "wrong-name-refusal"
    );
    let upper = mutations
        .iter()
        .find(|mutation| {
            mutation["changed_term"]
                .as_str()
                .unwrap_or("")
                .contains("upper endpoint")
        })
        .expect("upper port edit");
    assert_eq!(upper["status"], "distinguished");
    assert_eq!(
        upper["first_distinguishing_case"]["id"],
        "adjacent-port-refusal"
    );
    let lower = mutations
        .iter()
        .find(|mutation| {
            mutation["changed_term"]
                .as_str()
                .unwrap_or("")
                .contains("lower endpoint")
        })
        .expect("lower port edit");
    assert_eq!(
        lower["first_distinguishing_case"]["id"],
        "lower-adjacent-port-refusal"
    );
    assert_eq!(fs::read(path).expect("pass unchanged"), before);
}

#[test]
fn shadowed_rule_name_edit_survives_and_port_endpoints_never_wrap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut shadowed = PASS.to_owned();
    shadowed.push_str("\n[[destination]]\nlabel = \"overlap\"\naddress = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\n");
    let path = pass_file(dir.path(), &shadowed);
    let loaded = hallpass::load(&path).expect("shadowed pass");
    let report = hallpass::review::mutation_strength(&loaded.pass, WEAK).expect("analysis");
    assert!(
        report["mutations"]
            .as_array()
            .expect("mutations")
            .iter()
            .any(|m| {
                m["changed_term"].as_str().unwrap_or("").contains(".names:")
                    && m["status"] == "survived"
            })
    );

    for port in [1, 65_535] {
        let contents = PASS.replace("ports = 443", &format!("ports = {port}"));
        let pass = hallpass::Pass::parse(&contents).expect("endpoint pass");
        let suite = format!(
            "version = 1\n[[case]]\nid = \"endpoint\"\nat = \"2026-11-20T09:00:00Z\"\nto = \"192.0.2.10:{port}/tcp\"\nname = \"app.example.com\"\nexpected = \"allowed\"\n"
        );
        let report = hallpass::review::mutation_strength(&pass, &suite).expect("endpoint analysis");
        for mutation in report["mutations"].as_array().expect("mutations") {
            let term = mutation["changed_term"].as_str().unwrap_or("");
            assert!(!(port == 1 && term.contains("lower endpoint")));
            assert!(!(port == 65_535 && term.contains("upper endpoint")));
        }
    }
}

#[test]
fn shared_missing_port_between_ranges_is_mutated_once_with_compact_terms() {
    let pass = PASS.replace("ports = 443", "ports = [443, 445]");
    let pass = hallpass::Pass::parse(&pass).expect("pass with a one-port gap");
    let report = hallpass::review::mutation_strength(&pass, WEAK).expect("analysis");
    let added_444 = report["mutations"]
        .as_array()
        .expect("mutations")
        .iter()
        .filter(|mutation| {
            mutation["changed_term"]
                .as_str()
                .is_some_and(|term| term.contains("add adjacent port 444"))
        })
        .count();
    assert_eq!(added_444, 1);
    for mutation in report["mutations"].as_array().expect("mutations") {
        assert!(mutation["changed_term"].as_str().expect("term").len() < 128);
    }
}

#[test]
fn baseline_failure_and_both_work_limits_are_explicit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = pass_file(dir.path(), PASS);
    let loaded = hallpass::load(&path).expect("valid pass");
    let failing = WEAK.replace("expected = \"allowed\"", "expected = \"expired\"");
    let failed =
        hallpass::review::mutation_strength(&loaded.pass, &failing).expect("failed baseline");
    assert_eq!(failed["result"], "baseline-failed");
    assert_eq!(failed["mutations_tested"], 0);

    let mut many = loaded.pass.clone();
    for n in 0..30 {
        let mut destination = many.destinations[0].clone();
        destination.label = format!("copy-{n}");
        many.destinations.push(destination);
    }
    let capped = hallpass::review::mutation_strength(&many, WEAK).expect("mutation cap");
    assert_eq!(capped["result"], "partial");
    assert_eq!(capped["mutations_tested"], 64);
    assert_eq!(capped["truncated"], true);

    let mut suite = "version = 1\n".to_owned();
    for n in 0..1024 {
        let _ = write!(
            suite,
            "\n[[case]]\nid = \"case-{n}\"\nat = \"2026-11-20T09:00:00Z\"\nto = \"192.0.2.10:443/tcp\"\nname = \"app.example.com\"\nexpected = \"allowed\"\n"
        );
    }
    let mut many_eval = loaded.pass;
    for n in 0..3 {
        let mut destination = many_eval.destinations[0].clone();
        destination.label = format!("eval-copy-{n}");
        many_eval.destinations.push(destination);
    }
    let capped = hallpass::review::mutation_strength(&many_eval, &suite).expect("evaluation cap");
    assert_eq!(capped["result"], "partial");
    assert_eq!(capped["evaluations"], 4_096);
    assert_eq!(capped["mutations_tested"], 3);
    assert_eq!(capped["truncated"], true);
}

#[test]
fn strength_is_opt_in_and_non_complete_results_exit_two() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pass = pass_file(dir.path(), PASS);
    let suite = dir.path().join("suite.toml");
    fs::write(&suite, WEAK).expect("suite");
    let run = |strength: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hallpass"));
        cmd.current_dir(dir.path()).arg("--json").args([
            "test-pass",
            pass.to_str().expect("path"),
            suite.to_str().expect("path"),
        ]);
        if strength {
            cmd.arg("--strength");
        }
        cmd.output().expect("hallpass")
    };
    let ordinary = run(false);
    assert_eq!(ordinary.status.code(), Some(0));
    let ordinary_json: Value = serde_json::from_slice(&ordinary.stdout).expect("json");
    assert_eq!(ordinary_json["result"], "ok");
    assert!(ordinary_json.get("mutation_strength").is_none());
    let strength = run(true);
    assert_eq!(strength.status.code(), Some(2));
    let strength_json: Value = serde_json::from_slice(&strength.stdout).expect("json");
    assert_eq!(strength_json["result"], "surviving-mutations");
    assert!(strength_json["mutation_strength"].is_object());
    fs::write(&suite, STRONG).expect("strong suite");
    let complete = run(true);
    assert_eq!(complete.status.code(), Some(0));
    let complete_json: Value = serde_json::from_slice(&complete.stdout).expect("json");
    assert_eq!(complete_json["result"], "complete");
}
