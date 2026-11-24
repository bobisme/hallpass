use hallpass::{Pass, review};
use proptest::prelude::*;
use std::fmt::Write as _;

const PASS: &str = r#"
format = 1
id = "review-1"
name = "review"
[approval]
owner = "owner"
reference = "approval #1"
operator = "operator"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false
[[destination]]
label = "named"
address = "192.0.2.10"
protocol = "tcp"
ports = [443, "1000-1100"]
names = ["app.example.com"]
[[destination]]
label = "open"
network = "192.0.2.0/28"
protocol = "tcp"
ports = ["1050-1200"]
[ceilings]
calls = 2
"#;

#[test]
fn breadth_and_overlap_are_exact_and_replayable() {
    let pass = Pass::parse(PASS).expect("fixture");
    let b = review::breadth(&pass);
    assert_eq!(b.ipv4, "16");
    assert_eq!(b.ipv6, "0");
    let findings = review::lint(
        &pass,
        time::OffsetDateTime::parse(
            "2026-11-20T09:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("time"),
    );
    let findings = findings.findings;
    assert_eq!(findings.len(), 1);
    assert_eq!((findings[0].port, findings[0].port_end), (1050, 1100));
    assert!(findings[0].effective);
}

#[test]
fn cases_are_strict_and_report_stable_codes() {
    let pass = Pass::parse(PASS).expect("fixture");
    let suite = r#"version = 1
[[case]]
id = "allow"
at = "2026-11-20T09:00:00Z"
to = "192.0.2.10:443/tcp"
name = "app.example.com"
duration = 60
expected = "allowed"
[[case]]
id = "refuse"
at = "2026-11-20T09:00:00Z"
to = "192.0.2.10:443/tcp"
expected = "name-required"
"#;
    let result = review::cases(&pass, suite).expect("suite");
    assert_eq!(result[0]["actual"], "allowed");
    assert_eq!(result[1]["actual"], "name-required");
    assert!(review::cases(&pass, "").is_err());
    assert!(review::cases(&pass, "version = 1\n").is_err());
    assert!(review::cases(&pass, "[[case]]\nid=\"x\"\nat=\"2026-11-20T09:00:00Z\"\nto=\"192.0.2.10:443/tcp\"\nexpected=\"allowed\"\nextra=true\n").is_err());
}

#[test]
fn approval_id_is_stable_and_namespaced() {
    let id = |owner, reference| review::approval_id(owner, reference).expect("an id");
    let a = id("owner", "approval #1");
    assert_eq!(a, id("owner", "approval #1"));
    assert_ne!(a, id("other", "approval #1"));
    assert!(a.starts_with("hp1-"));
}

proptest! {
    #[test]
    fn normalized_port_sets_ignore_order_and_adjacent_ranges(a in 1u16..=65534, b in 1u16..=65535) {
        let lo = a.min(b); let hi = a.max(b);
        let left = hallpass::PortSet::from_ranges(vec![(lo, hi)]).expect("range");
        let right = hallpass::PortSet::from_ranges(vec![(hi, hi), (lo, hi)]).expect("range");
        prop_assert_eq!(left.normalized_ranges(), right.normalized_ranges());
    }
}

#[test]
fn breadth_handles_max_destinations_and_large_ipv6_without_enumeration() {
    let mut text = String::from(
        "format = 1\nid = \"many\"\nname = \"many\"\n[approval]\nowner=\"o\"\nreference=\"r\"\noperator=\"x\"\nvalid_from=2026-11-20T00:00:00Z\nvalid_until=2026-11-21T00:00:00Z\nrevoked=false\n",
    );
    for i in 0..1024 {
        let address = if i == 0 {
            "2001:db8::".to_owned()
        } else {
            format!("2001:db8::{i:x}")
        };
        let _ = writeln!(
            text,
            "[[destination]]\nlabel=\"d{i}\"\nnetwork=\"{address}/128\"\nprotocol=\"tcp\"\nports=443"
        );
    }
    let pass = Pass::parse(&text).expect("1024 destinations");
    assert_eq!(pass.destinations.len(), 1024);
    assert_eq!(review::breadth(&pass).ipv6, "1024");
}
