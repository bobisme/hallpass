//! A table of nasty inputs for every path that can answer "allowed", and a
//! property that checks each "allowed" against an independent reading of
//! the pass. Library only: nothing here touches a file, a clock or the
//! network.

use std::net::IpAddr;

use hallpass::time::macros::datetime;
use hallpass::time::{Duration, OffsetDateTime};
use hallpass::{Decision, HostName, Pass, Protocol, RefusalCode, Target};
use proptest::prelude::*;

const PASS: &str = r#"
format = 1
id = "nasty-2026-11"
name = "Nasty inputs"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = [5060, "10000-10100"]

[[destination]]
label = "lan"
network = "198.51.100.0/24"
protocol = "tcp"
ports = 443

[[destination]]
label = "v6"
network = "2001:db8::/64"
protocol = "tcp"
ports = 443

[[destination]]
label = "named"
address = "203.0.113.7"
protocol = "tcp"
ports = 443
names = ["app.example.com", "xn--bcher-kva.example"]

[[destination]]
label = "loop"
address = "::1"
protocol = "tcp"
ports = 8080
"#;

const NOW: OffsetDateTime = datetime!(2026-11-20 09:00 UTC);

fn pass() -> Pass {
    Pass::parse(PASS).expect("the test pass is valid")
}

/// `Ok(label)` or `Err(code)` for one question.
fn ask(pass: &Pass, to: &str, name: Option<&str>, now: OffsetDateTime) -> Result<String, String> {
    let target: Target = to.parse().unwrap_or_else(|e| panic!("{to}: {e}"));
    let name: Option<HostName> = name.map(|n| n.parse().unwrap_or_else(|e| panic!("{n}: {e}")));
    match pass.permits_named(&target, name.as_ref(), now, Duration::ZERO) {
        Decision::Allowed { label } => Ok(label),
        Decision::Refused(r) => {
            assert_ne!(r.message, "", "a refusal says why and what to do");
            Err(r.code.as_str().to_owned())
        }
    }
}

#[test]
fn targets_table() {
    let p = pass();
    let allowed = |label: &str| Ok(label.to_owned());
    let refused = |code: &str| Err(code.to_owned());
    for (to, want) in [
        // The listed address, its ports and its neighbours.
        ("192.0.2.10:5060/udp", allowed("sip-edge")),
        ("192.0.2.10:10000/udp", allowed("sip-edge")),
        ("192.0.2.10:10100/udp", allowed("sip-edge")),
        ("192.0.2.10:10101/udp", refused("port-not-listed")),
        ("192.0.2.10:9999/udp", refused("port-not-listed")),
        ("192.0.2.10:5061/udp", refused("port-not-listed")),
        ("192.0.2.10:5060/tcp", refused("port-not-listed")),
        ("192.0.2.10:1/udp", refused("port-not-listed")),
        ("192.0.2.10:65535/udp", refused("port-not-listed")),
        ("192.0.2.9:5060/udp", refused("address-not-listed")),
        ("192.0.2.11:5060/udp", refused("address-not-listed")),
        ("192.0.2.100:5060/udp", refused("address-not-listed")),
        // The edges of a listed network are not hosts; its neighbours are
        // not listed.
        ("198.51.100.0:443/tcp", refused("network-or-broadcast")),
        ("198.51.100.255:443/tcp", refused("network-or-broadcast")),
        ("198.51.100.255:80/tcp", refused("network-or-broadcast")),
        ("198.51.100.1:443/tcp", allowed("lan")),
        ("198.51.100.254:443/tcp", allowed("lan")),
        ("198.51.100.1:443/udp", refused("port-not-listed")),
        ("198.51.99.255:443/tcp", refused("address-not-listed")),
        ("198.51.101.0:443/tcp", refused("address-not-listed")),
        // IPv6: any spelling of a listed address, never a form that
        // carries IPv4, even inside the listed network.
        ("[2001:db8::1]:443/tcp", allowed("v6")),
        ("[2001:DB8:0:0::1]:443/tcp", allowed("v6")),
        (
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:443/tcp",
            allowed("v6"),
        ),
        ("[2001:db8::ffff:ffff:ffff:ffff]:443/tcp", allowed("v6")),
        ("[2001:db8:0:1::1]:443/tcp", refused("address-not-listed")),
        ("[2001:db9::1]:443/tcp", refused("address-not-listed")),
        ("[2001:db8::1]:8443/tcp", refused("port-not-listed")),
        (
            "[2001:db8::5efe:c000:20a]:443/tcp",
            refused("embedded-ipv4"),
        ),
        (
            "[2001:db8::200:5efe:c633:6401]:443/tcp",
            refused("embedded-ipv4"),
        ),
        ("[2001:db8::0.0.0.1]:443/tcp", allowed("v6")),
        ("[::ffff:192.0.2.10]:5060/udp", refused("embedded-ipv4")),
        ("[::ffff:c000:20a]:5060/udp", refused("embedded-ipv4")),
        (
            "[0:0:0:0:0:ffff:192.0.2.10]:5060/udp",
            refused("embedded-ipv4"),
        ),
        ("[::192.0.2.10]:5060/udp", refused("embedded-ipv4")),
        ("[::ffff:0:192.0.2.10]:5060/udp", refused("embedded-ipv4")),
        ("[64:ff9b::192.0.2.10]:5060/udp", refused("embedded-ipv4")),
        ("[64:ff9b:1::c000:20a]:5060/udp", refused("embedded-ipv4")),
        ("[2002:c000:20a::1]:5060/udp", refused("embedded-ipv4")),
        ("[2001:0:c000:20a::1]:5060/udp", refused("embedded-ipv4")),
        // Loopback only as listed; "any", broadcast, multicast and
        // link-local are never listed.
        ("[::1]:8080/tcp", allowed("loop")),
        ("[::1]:8081/tcp", refused("port-not-listed")),
        ("127.0.0.1:8080/tcp", refused("address-not-listed")),
        ("[::]:8080/tcp", refused("address-not-listed")),
        ("0.0.0.0:5060/udp", refused("address-not-listed")),
        ("255.255.255.255:5060/udp", refused("address-not-listed")),
        ("224.0.0.1:5060/udp", refused("address-not-listed")),
        ("169.254.169.254:443/tcp", refused("address-not-listed")),
        ("[fe80::1]:443/tcp", refused("address-not-listed")),
        ("[ff02::1]:443/tcp", refused("address-not-listed")),
        // A destination with names answers no unnamed question.
        ("203.0.113.7:443/tcp", refused("name-required")),
        ("203.0.113.7:80/tcp", refused("port-not-listed")),
    ] {
        assert_eq!(ask(&p, to, None, NOW), want, "{to}");
    }
}

#[test]
fn targets_that_are_not_one_address_are_not_questions() {
    for bad in [
        "",
        "192.0.2.10",
        "192.0.2.10:5060",
        "192.0.2.10/udp",
        "192.0.2.10:/udp",
        "192.0.2.10:0/udp",
        "192.0.2.10:65536/udp",
        "192.0.2.10:05060/udp",
        "192.0.2.10:+5060/udp",
        "192.0.2.10:-1/udp",
        "192.0.2.10:5060-5061/udp",
        "192.0.2.10:5060/UDP",
        "192.0.2.10:5060/udp ",
        " 192.0.2.10:5060/udp",
        "192.0.2.10:5060/udp\n",
        "192.0.2.10:5060/udp\0",
        "192.0.2.10:5060/udp/tcp",
        "192.0.2.10:5060/icmp",
        "192.0.2.10:5060/",
        "192.0.2.10.:5060/udp",
        "192.0.2:5060/udp",
        "192.0.2.010:5060/udp",
        "0300.0.2.10:5060/udp",
        "0xc0.0.2.10:5060/udp",
        "3221225994:5060/udp",
        "192.0.2.256:5060/udp",
        "192.0.2.10.1:5060/udp",
        "192.0.2.0/24:5060/udp",
        "１９２.0.2.10:5060/udp",
        "192.0.2.10:５０６０/udp",
        "sip.example.net:5060/udp",
        "localhost:5060/udp",
        "[192.0.2.10]:5060/udp",
        "2001:db8::1:443/tcp",
        "[2001:db8::1]/tcp",
        "[2001:db8::1]443/tcp",
        "[2001:db8::1]:443:1/tcp",
        "[2001:db8::1:443/tcp",
        "[[2001:db8::1]]:443/tcp",
        "[2001:db8::1%eth0]:443/tcp",
        "[2001:db8::1%25eth0]:443/tcp",
        "[fe80::1%1]:443/tcp",
        "[2001:db8::/64]:443/tcp",
        "[2001:db8::g]:443/tcp",
        "[2001:db8:::1]:443/tcp",
        "[12345::1]:443/tcp",
        "[::ffff:192.0.2.010]:443/tcp",
    ] {
        assert!(
            bad.parse::<Target>().is_err(),
            "{bad:?} was read as a target"
        );
    }
}

#[test]
fn names_table() {
    let p = pass();
    let to = "203.0.113.7:443/tcp";
    for (name, want) in [
        ("app.example.com", Ok("named")),
        ("APP.Example.COM", Ok("named")),
        ("app.example.com.", Ok("named")),
        ("xn--bcher-kva.example", Ok("named")),
        ("XN--BCHER-KVA.EXAMPLE.", Ok("named")),
        ("app.example.com.evil.example", Err("name-not-listed")),
        ("evilapp.example.com", Err("name-not-listed")),
        ("evil.app.example.com", Err("name-not-listed")),
        ("example.com", Err("name-not-listed")),
        ("app.example.co", Err("name-not-listed")),
        ("app-example.com", Err("name-not-listed")),
        ("app_example.com", Err("name-not-listed")),
        ("com", Err("name-not-listed")),
        ("xn--bcher-kvb.example", Err("name-not-listed")),
    ] {
        assert_eq!(
            ask(&p, to, Some(name), NOW),
            want.map(str::to_owned).map_err(str::to_owned),
            "{name}"
        );
    }
    // A listed name grants nothing on another address, port or protocol.
    for (to, want) in [
        ("203.0.113.8:443/tcp", "address-not-listed"),
        ("203.0.113.7:8443/tcp", "port-not-listed"),
        ("203.0.113.7:443/udp", "port-not-listed"),
        ("[::ffff:203.0.113.7]:443/tcp", "embedded-ipv4"),
    ] {
        assert_eq!(
            ask(&p, to, Some("app.example.com"), NOW),
            Err(want.to_owned()),
            "{to}"
        );
    }
}

#[test]
fn names_that_are_not_one_host_name_are_not_questions() {
    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = format!("{}example", "a.".repeat(124));
    for bad in [
        "",
        ".",
        "..",
        "app..example.com",
        ".app.example.com",
        "app.example.com..",
        "*.example.com",
        "*",
        "app.*.com",
        "bücher.example",
        "app.example.com:443",
        "app.example.com/",
        "https://app.example.com",
        "app.example.com ",
        " app.example.com",
        "app.example.com\n",
        "app.example.com\0",
        "app example.com",
        "-app.example.com",
        "app-.example.com",
        "user@app.example.com",
        "app.example.com?x",
        "app.example.com#x",
        "[::1]",
        "::1",
        "192.0.2.10",
        "192.0.2.10.",
        "192.0.2",
        "010.0.0.1",
        "3221225994",
        "0xc000020a",
        "app.example.123",
        long_label.as_str(),
        long_name.as_str(),
    ] {
        assert!(
            bad.parse::<HostName>().is_err(),
            "{bad:?} was read as a name"
        );
        assert!(HostName::canonical(bad).is_err(), "{bad:?}");
    }
    assert!(long_name.len() > 253);
}

#[test]
fn window_boundaries() {
    let p = pass();
    let to = "192.0.2.10:5060/udp";
    let tick = Duration::nanoseconds(1);
    let from = datetime!(2026-11-20 08:00 UTC);
    let until = datetime!(2026-11-20 17:00 UTC);
    let decide = |now: OffsetDateTime, needed: Duration| {
        let target: Target = to.parse().expect("target");
        match p.permits(&target, now, needed) {
            Decision::Allowed { .. } => None,
            Decision::Refused(r) => Some(r.code),
        }
    };
    assert_eq!(
        decide(from - tick, Duration::ZERO),
        Some(RefusalCode::NotYetValid)
    );
    assert_eq!(
        decide(from, Duration::ZERO),
        None,
        "valid_from is inclusive"
    );
    assert_eq!(decide(until - tick, Duration::ZERO), None);
    assert_eq!(
        decide(until, Duration::ZERO),
        Some(RefusalCode::Expired),
        "valid_until is exclusive"
    );
    assert_eq!(
        decide(until + tick, Duration::ZERO),
        Some(RefusalCode::Expired)
    );
    // The same instants written with other offsets.
    assert_eq!(decide(datetime!(2026-11-20 09:00 +1), Duration::ZERO), None);
    assert_eq!(
        decide(datetime!(2026-11-20 08:59:59 +1), Duration::ZERO),
        Some(RefusalCode::NotYetValid)
    );
    assert_eq!(
        decide(datetime!(2026-11-20 12:00 -5), Duration::ZERO),
        Some(RefusalCode::Expired)
    );
    assert_eq!(
        decide(datetime!(2026-11-20 11:59:59 -5), Duration::ZERO),
        None
    );
    // Work that could run to the end of the window, or past it.
    let hour = Duration::hours(1);
    assert_eq!(
        decide(until - hour, hour),
        Some(RefusalCode::WindowTooShort)
    );
    assert_eq!(decide(until - hour, hour - tick), None);
    assert_eq!(
        decide(until - hour, hour + tick),
        Some(RefusalCode::WindowTooShort)
    );
    assert_eq!(
        decide(from, Duration::MAX),
        Some(RefusalCode::WindowTooShort)
    );
    // Revocation wins at every instant.
    let revoked = Pass::parse(&PASS.replace("revoked = false", "revoked = true")).expect("valid");
    let target: Target = to.parse().expect("target");
    for now in [from - hour, from, NOW, until, until + hour] {
        assert!(matches!(
            revoked.permits(&target, now, Duration::ZERO),
            Decision::Refused(r) if r.code == RefusalCode::Revoked
        ));
    }
}

/// An independent, deliberately plain reading of the test pass: what is
/// listed, by hand, without the library's parsers.
fn oracle(ip: IpAddr, port: u16, protocol: Protocol, name: Option<&str>) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => oracle_v4(v4.octets(), port, protocol, name),
        IpAddr::V6(v6) => oracle_v6(v6.segments(), port, protocol),
    }
}

fn oracle_v4(
    o: [u8; 4],
    port: u16,
    protocol: Protocol,
    name: Option<&str>,
) -> Option<&'static str> {
    let tcp_443 = protocol == Protocol::Tcp && port == 443;
    if o == [192, 0, 2, 10]
        && protocol == Protocol::Udp
        && (port == 5060 || (10000..=10100).contains(&port))
    {
        Some("sip-edge")
    } else if o[..3] == [198, 51, 100] && o[3] != 0 && o[3] != 255 && tcp_443 {
        Some("lan")
    } else if o == [203, 0, 113, 7]
        && tcp_443
        && matches!(name, Some("app.example.com" | "xn--bcher-kva.example"))
    {
        Some("named")
    } else {
        None
    }
}

fn oracle_v6(s: [u16; 8], port: u16, protocol: Protocol) -> Option<&'static str> {
    let tcp = protocol == Protocol::Tcp;
    // An ISATAP interface identifier carries an IPv4 address.
    let isatap = matches!(s[4], 0 | 0x100 | 0x200 | 0x300) && s[5] == 0x5efe;
    if s == [0, 0, 0, 0, 0, 0, 0, 1] && tcp && port == 8080 {
        Some("loop")
    } else if s[..4] == [0x2001, 0xdb8, 0, 0] && !isatap && tcp && port == 443 {
        Some("v6")
    } else {
        None
    }
}

fn near_ipv4() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        Just(IpAddr::from([192, 0, 2, 10])),
        Just(IpAddr::from([203, 0, 113, 7])),
        (0u8..=255).prop_map(|d| IpAddr::from([192, 0, 2, d])),
        (99u8..=101, 0u8..=255).prop_map(|(c, d)| IpAddr::from([198, 51, c, d])),
        (0u8..=255).prop_map(|d| IpAddr::from([203, 0, 113, d])),
        any::<u32>().prop_map(|bits| IpAddr::from(bits.to_be_bytes())),
    ]
}

fn near_ipv6() -> impl Strategy<Value = IpAddr> {
    let low = prop_oneof![
        any::<u64>(),
        (0u16..4, any::<u32>())
            .prop_map(|(ul, v4)| u64::from(ul) << 56 | 0x5efe_u64 << 32 | u64::from(v4)),
        0u64..4,
    ];
    let high = prop_oneof![
        Just(0x2001_0db8_0000_0000_u64),
        Just(0x2001_0db8_0000_0001_u64),
        Just(0u64),
        Just(0x2002_c000_020a_0000_u64),
        Just(0x0064_ff9b_0000_0000_u64),
        any::<u64>(),
    ];
    (high, low).prop_map(|(h, l)| IpAddr::from((u128::from(h) << 64 | u128::from(l)).to_be_bytes()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Whatever is asked, "allowed" is only ever said for what the plain
    /// reading lists, inside the window, and names the right destination.
    #[test]
    fn allowed_only_for_what_is_listed(
        ip in prop_oneof![near_ipv4(), near_ipv6()],
        port in prop_oneof![Just(443u16), Just(5060u16), Just(8080u16), 9990u16..10110, any::<u16>()],
        udp: bool,
        name in prop_oneof![
            Just(None),
            Just(Some("app.example.com")),
            Just(Some("xn--bcher-kva.example")),
            Just(Some("other.example.org")),
        ],
        offset_seconds in -3600i64..(10 * 3600),
        needed_seconds in 0i64..7200,
    ) {
        let p = pass();
        let protocol = if udp { Protocol::Udp } else { Protocol::Tcp };
        let target = Target { ip, port, protocol };
        let host: Option<HostName> = name.map(|n| n.parse().expect("name"));
        let now = datetime!(2026-11-20 08:00 UTC) + Duration::seconds(offset_seconds);
        let needed = Duration::seconds(needed_seconds);
        let in_window = (0..9 * 3600).contains(&offset_seconds)
            && (needed_seconds == 0 || 9 * 3600 - offset_seconds > needed_seconds);
        let listed = oracle(ip, port, protocol, name);
        match p.permits_named(&target, host.as_ref(), now, needed) {
            Decision::Allowed { label } => {
                prop_assert!(in_window, "allowed outside the window: {target} at {now}");
                prop_assert_eq!(Some(label.as_str()), listed, "{}", target);
            }
            Decision::Refused(refusal) => {
                prop_assert!(
                    !(in_window && listed.is_some()),
                    "refused though listed and in the window: {} ({})", target, refusal.message
                );
                prop_assert_ne!(refusal.message, "");
            }
        }
        // A question round-trips through its text form unchanged.
        prop_assert_eq!(target.to_string().parse::<Target>(), Ok(target));
    }
}
