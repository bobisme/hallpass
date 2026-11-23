//! Loosening mutations in `test-pass --strength`: networks, protocols,
//! windows and the ceilings that a case cannot observe.
#![cfg(feature = "cli")]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const PASS: &str = include_str!("../docs/review-approval.toml");
const WEAK: &str = include_str!("../docs/review-suite-weak.toml");
const STRONG: &str = include_str!("../docs/review-suite-strong.toml");

fn analyze(pass: &str, suite: &str) -> Value {
    let pass = hallpass::Pass::parse(pass).expect("pass");
    hallpass::review::mutation_strength(&pass, suite).expect("analysis")
}

fn find<'a>(report: &'a Value, term: &str) -> &'a Value {
    report["mutations"]
        .as_array()
        .expect("mutations")
        .iter()
        .find(|m| m["changed_term"].as_str().is_some_and(|t| t.contains(term)))
        .unwrap_or_else(|| panic!("no mutation {term}: {report}"))
}

fn suite_for(to: &str) -> String {
    format!(
        "version = 1\n[[case]]\nid = \"in\"\nat = \"2026-11-20T09:00:00Z\"\nto = \"{to}\"\nname = \"app.example.com\"\nexpected = \"allowed\"\n"
    )
}

const KINDS: [(&str, &str); 4] = [
    (".address: widen", "neighbor-address-refusal"),
    (".protocol: also allow udp", "other-transport-refusal"),
    ("valid_from: one second earlier", "before-window-refusal"),
    ("valid_until: one second later", "window-end-refusal"),
];

#[test]
fn strong_suite_kills_every_new_mutation_and_weak_suite_does_not() {
    let strong = analyze(PASS, STRONG);
    assert_eq!(strong["result"], "complete");
    assert_eq!(strong["mutations_skipped"], 0);
    let weak = analyze(PASS, WEAK);
    for (term, case) in KINDS {
        let row = find(&strong, term);
        assert_eq!(row["status"], "distinguished", "{term}");
        assert_eq!(row["first_distinguishing_case"]["id"], case);
        assert_eq!(find(&weak, term)["status"], "survived", "{term}");
    }
}

#[test]
fn a_network_widens_by_one_bit_and_a_breadth_cap_skips_it() {
    let pass = PASS.replace("address = \"192.0.2.10\"", "network = \"192.0.2.16/28\"");
    let row = analyze(&pass, &suite_for("192.0.2.17:443/tcp"));
    let row = find(&row, ".network: widen 192.0.2.16/28 to 192.0.2.0/27");
    assert_eq!(row["status"], "survived");
    // A /24 is at the cap: a /23 needs approval, so the mutation is skipped.
    let pass = PASS.replace("address = \"192.0.2.10\"", "network = \"192.0.2.0/24\"");
    let report = analyze(&pass, WEAK);
    let row = find(&report, ".network: widen");
    assert_eq!(row["status"], "skipped");
    assert!(
        row["reason"]
            .as_str()
            .expect("reason")
            .contains("breadth cap")
    );
    // With approval the /23 is tested.
    let approved = pass.replace("ports = 443", "ports = 443\nwhole_network_approved = true");
    assert_eq!(
        find(&analyze(&approved, WEAK), ".network: widen")["status"],
        "survived"
    );
    // A /31 would become a /30, which excludes edge addresses: skipped.
    let pass = PASS.replace("address = \"192.0.2.10\"", "network = \"192.0.2.10/31\"");
    let report = analyze(&pass, WEAK);
    let row = find(&report, ".network: widen");
    assert_eq!(row["status"], "skipped");
    assert_eq!(report["mutations_skipped"], 1);
}

#[test]
fn ipv6_host_widens_to_a_slash_127() {
    let pass = PASS.replace("address = \"192.0.2.10\"", "address = \"2001:db8::10\"");
    let row = analyze(&pass, &suite_for("[2001:db8::10]:443/tcp"));
    assert_eq!(
        find(&row, ".address: widen 2001:db8::10 to 2001:db8::10/127")["status"],
        "survived"
    );
}

#[test]
fn ceilings_are_skipped_with_a_reason_not_reported_as_survived() {
    let pass = format!("{PASS}[ceilings]\ncalls = 5\n");
    let report = analyze(&pass, WEAK);
    let row = find(&report, "ceilings.calls");
    assert_eq!(row["status"], "skipped");
    assert!(
        row["reason"]
            .as_str()
            .expect("reason")
            .contains("cannot spend")
    );
    assert_eq!(report["mutations_skipped"], 1);
    let survivors = report["mutations"]
        .as_array()
        .expect("mutations")
        .iter()
        .filter(|m| m["status"] == "survived")
        .count();
    assert_eq!(report["mutations_survived"], survivors);
    assert_eq!(
        report["mutations_tested"],
        report["mutations"].as_array().expect("m").len() - 1
    );
}

#[test]
fn text_output_is_one_readable_line_per_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pass = dir.path().join("p.toml");
    fs::write(&pass, format!("{PASS}[ceilings]\ncalls = 5\n")).expect("pass");
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).expect("mode");
    let suite = dir.path().join("s.toml");
    fs::write(&suite, STRONG).expect("suite");
    let out = Command::new(env!("CARGO_BIN_EXE_hallpass"))
        .current_dir(dir.path())
        .args(["test-pass", "p.toml", "s.toml", "--strength"])
        .output()
        .expect("run");
    let text = String::from_utf8(out.stdout).expect("utf8");
    assert!(!text.contains("{\"") && !text.contains("\"web\""), "{text}");
    assert!(text.contains("mutation(s) tested"), "{text}");
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with("distinguished")
                && l.contains("(case wrong-name-refusal: name-not-listed -> allowed)")),
        "{text}"
    );
    assert!(
        text.lines().any(|l| l.trim_start().starts_with("skipped")
            && l.contains("ceilings.calls: raise")
            && l.contains("cannot spend")),
        "{text}"
    );
}
