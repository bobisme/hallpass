use hallpass::{
    Decision, Pass, PortSet, Target, load, review,
    time::{Duration, macros::datetime},
};
use proptest::prelude::*;

const NOW: hallpass::time::OffsetDateTime = datetime!(2026-11-20 09:00 UTC);
const HEADER: &str = "format=1\nid='fixture'\nname='Fixture'\n[approval]\nowner='A'\noperator='B'\nreference='R'\nvalid_from=2026-11-20T08:00:00Z\nvalid_until=2026-11-20T17:00:00Z\nrevoked=false\n";
fn rule(label: &str, scope: &str, ports: &str, names: &str) -> String {
    format!("[[destination]]\nlabel='{label}'\n{scope}\nprotocol='tcp'\nports={ports}\n{names}\n")
}

proptest! {
    #[test]
    fn every_reported_unnamed_example_lies_in_both_rules(subnet in 0u8..16, port in 1000u16..2000, disjoint in any::<bool>()) {
        let base=subnet*16;
        let addr=if disjoint {"198.51.100.0/24".to_owned()} else {format!("192.0.2.{base}/28")};
        let restricted=rule("named","network='192.0.2.0/24'",&format!("['{}-{}',443,65535]", port,port+5),"names=['approved.example']");
        let open=rule("open",&format!("network='{addr}'"),&format!("['{}-{}',443,65535]", port+2,port+8),"");
        let pass=Pass::parse(&format!("{HEADER}{restricted}{open}")).expect("fixture");
        let rev=Pass::parse(&format!("{HEADER}{open}{restricted}")).expect("reversed");
        let result=review::lint(&pass,NOW);
        let again=review::lint(&rev,NOW);
        prop_assert_eq!(serde_json::to_value(&result).expect("json"),serde_json::to_value(&again).expect("json"));
        prop_assert_eq!(result.findings.len(),if disjoint {0}else{3});
        for row in &result.findings {
            let target=Target{ip:row.address.parse().expect("IP"),port:row.port,protocol:hallpass::Protocol::Tcp};
            prop_assert!(row.effective);
            prop_assert!(pass.destinations.iter().all(|d|d.network.contains(target.ip) && d.ports.contains(row.port) && d.ports.contains(row.port_end)));
            prop_assert!(matches!(pass.permits(&target,NOW,Duration::ZERO),Decision::Allowed{..}),"actual policy refused {}",target);
        }
    }

    #[test]
    fn normalized_port_sets_preserve_membership(mut ranges in prop::collection::vec((1u16..=65535, 1u16..=65535),1..20),query in 1u16..=65535) {
        for (a,b) in &mut ranges { if *a>*b {std::mem::swap(a,b);} }
        let ports=PortSet::from_ranges(ranges.clone()).expect("ports");
        ranges.reverse();ranges.push((65535,65535));
        let expanded=PortSet::from_ranges(ranges).expect("expanded");
        let canon=PortSet::from_ranges(ports.normalized_ranges()).expect("canon");
        prop_assert_eq!(ports.contains(query),canon.contains(query));
        prop_assert_eq!(expanded.contains(query),canon.contains(query)||query==65535);
    }
}

#[test]
fn explicit_host_at_network_edge_is_the_exact_overlap_example() {
    let a = rule(
        "named",
        "network='192.0.2.0/28'",
        "443",
        "names=['one.example']",
    );
    let b = rule("open", "address='192.0.2.15'", "443", "");
    let pass = Pass::parse(&format!("{HEADER}{a}{b}")).expect("valid");
    let row = review::lint(&pass, NOW).findings.remove(0);
    assert!(row.effective);
    assert_eq!(row.address, "192.0.2.15");
    let revoked =
        Pass::parse(&format!("{}{a}{b}", HEADER.replace("false", "true"))).expect("valid");
    assert_eq!(
        review::lint(&revoked, NOW).findings[0]
            .inactive_reason
            .as_deref(),
        Some("revoked")
    );
}

#[test]
fn truncation_requires_an_actual_extra_intersection() {
    let mut text = HEADER.to_owned();
    for i in 0..32 {
        text += &rule(
            &format!("rule-{i}"),
            "address='192.0.2.1'",
            "443",
            if i < 16 { "names=['one.example']" } else { "" },
        );
    }
    let report = review::lint(&Pass::parse(&text).expect("256 pairs"), NOW);
    assert_eq!(report.findings.len(), 256);
    assert!(!report.truncated);
    text += &rule("extra", "address='192.0.2.1'", "443", "");
    assert!(review::lint(&Pass::parse(&text).expect("more pairs"), NOW).truncated);
}

#[test]
fn diff_preserves_identity_and_detects_common_order_even_with_a_new_label() {
    let a = rule(
        "named",
        "address='192.0.2.10'",
        "[443,65535]",
        "names=['a.example','b.example']",
    );
    let b = rule("open", "network='192.0.2.0/28'", "443", "");
    let c = rule("other", "address='198.51.100.7'", "443", "");
    let dir = tempfile::tempdir().expect("temp");
    let file = dir.path().join("approval");
    let snapshot = |text: &str| {
        std::fs::write(&file, text).expect("write");
        load(&file).expect("load")
    };
    let old = snapshot(&format!("{HEADER}{a}{b}"));
    let equiv = snapshot(
        &format!("{HEADER}{a}{b}# comment\n")
            .replace("443,65535", "65535,443")
            .replace("'a.example','b.example'", "'b.example','a.example'"),
    );
    let same = review::diff(&old, &equiv);
    assert!(!same.review_required);
    assert_ne!(same.old_digest, same.new_digest);
    assert_eq!(same.changes.len(), 0);
    let changed = snapshot(&format!("{HEADER}{b}{c}{a}").replace("id='fixture'", "id='changed'"));
    let diff = review::diff(&old, &changed);
    assert!(diff.order_changed && diff.approval_changed && diff.review_required);
    assert_eq!(diff.introduced, ["other"]);
}

proptest! {
    #[test]
    fn ipv4_breadth_counts_the_union_once(entries in prop::collection::vec((0u8..=255,0u8..=4),1..18)) {
        let mut members=[false;256];
        let mut text=HEADER.to_owned();
        for (i,(position,host_bits)) in entries.iter().enumerate() {
            let size=1u16<<host_bits;
            let start=u16::from(*position)/size*size;
            for host in &mut members[usize::from(start)..usize::from(start+size)] {*host=true;}
            text+=&rule(&format!("n{i}"),&format!("network='192.0.2.{start}/{}'",32-host_bits),"443","");
        }
        let pass=Pass::parse(&text).expect("valid");
        let count=members.into_iter().filter(|v|*v).count().to_string();
        prop_assert_eq!(review::breadth(&pass).ipv4,count);
    }
}

#[test]
fn broad_ipv6_totals_remain_exact_above_machine_integer_precision() {
    let scope = rule(
        "wide",
        "network='2001:db8::/32'\nwhole_network_approved=true",
        "443",
        "",
    );
    let pass = Pass::parse(&format!("{HEADER}{scope}")).expect("valid");
    let total = review::breadth(&pass);
    assert_eq!(total.ipv6, (1u128 << 96).to_string());
    assert_eq!(review::breadth_warnings(&total).len(), 1);
}

#[test]
fn duration_and_expiry_in_documented_suite_are_executable() {
    let pass = Pass::parse(include_str!("../docs/review-approval.toml")).expect("documented pass");
    let fixture = include_str!("../docs/review-suite.toml");
    let rows = review::cases(&pass, fixture).expect("documented suite");
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|row| row["match"] == true));
    for invalid in [
        fixture.replace("version = 1", "version = 2"),
        fixture.replace("duration = 60", "duration = -1"),
        fixture.replace("name = \"app.example.com\"", "name = 7"),
        fixture.replace("name-refusal", "named-allowance"),
        format!("unknown = 1\n{fixture}"),
    ] {
        assert!(review::cases(&pass, &invalid).is_err());
    }
}
