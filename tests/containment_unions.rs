//! `diff --containment` proves coverage against the union of OLD's rules
//! (bn-1ixb): consolidations are `contained`, near misses are `expanded`
//! with a counterexample, and a brute-force enumeration over a small address
//! and port space agrees with every verdict.
use std::fmt::Write as _;

use hallpass::review::{Containment, endpoint_containment};
use hallpass::{
    Decision, HostName, Pass, Target,
    time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339},
};

const AT: &str = "2026-11-20T10:00:00Z";
const HEAD: &str = "format = 1\nid = \"u-1\"\nname = \"Union\"\n\n[approval]\nowner = \"Pat Owner\"\nreference = \"email\"\noperator = \"Sam\"\nvalid_from = 2026-11-20T08:00:00Z\nvalid_until = 2026-11-20T17:00:00Z\nrevoked = false\n";

fn now() -> OffsetDateTime {
    OffsetDateTime::parse(AT, &Rfc3339).expect("instant")
}

/// A pass with one destination per body, labelled d1, d2, ...
fn pass(prefix: &str, bodies: &[&str]) -> Pass {
    let mut text = HEAD.to_owned();
    for (i, body) in bodies.iter().enumerate() {
        write!(text, "\n[[destination]]\nlabel = \"{prefix}{i}\"\n{body}\n").expect("write");
    }
    Pass::parse(&text).unwrap_or_else(|e| panic!("{e:?}\n{text}"))
}

fn contain(old: &[&str], new: &[&str]) -> Containment {
    endpoint_containment(&pass("o", old), &pass("n", new), now())
}

fn allows(pass: &Pass, target: &Target, name: Option<&HostName>) -> bool {
    matches!(
        pass.permits_named(target, name, now(), Duration::ZERO),
        Decision::Allowed { .. }
    )
}

/// Every counterexample is allowed by NEW and refused by OLD.
fn check_counterexamples(old: &Pass, new: &Pass, report: &Containment) {
    assert!(!report.counterexamples.is_empty(), "{report:?}");
    for row in &report.counterexamples {
        let target: Target = row.target.parse().expect("target");
        let name = row
            .name
            .as_deref()
            .map(|n| HostName::canonical(n).expect("name"));
        assert!(allows(new, &target, name.as_ref()), "{row:?}");
        assert!(!allows(old, &target, name.as_ref()), "{row:?}");
    }
}

fn expanded(old: &[&str], new: &[&str]) -> Vec<(String, Option<String>)> {
    let (old, new) = (pass("o", old), pass("n", new));
    let report = endpoint_containment(&old, &new, now());
    assert_eq!(report.endpoint_result, "expanded", "{report:?}");
    assert_eq!(report.reason, "replayed-new-allowance");
    check_counterexamples(&old, &new, &report);
    report
        .counterexamples
        .iter()
        .map(|row| (row.target.clone(), row.name.clone()))
        .collect()
}

fn contained(old: &[&str], new: &[&str]) {
    let report = contain(old, new);
    assert_eq!(report.endpoint_result, "contained", "{report:?}");
    assert_eq!(report.reason, "rules-and-ipv4-edges-covered");
}

#[test]
fn consolidations_are_contained() {
    // Two port ranges merged into one.
    contained(
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = \"1-100\"",
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = \"101-200\"",
        ],
        &["address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = \"50-150\""],
    );
    // Two /29s and their inner edges, listed as hosts, merged into a /28.
    contained(
        &[
            "network = \"192.0.2.0/29\"\nprotocol = \"tcp\"\nports = 443",
            "network = \"192.0.2.8/29\"\nprotocol = \"tcp\"\nports = 443",
            "address = \"192.0.2.7\"\nprotocol = \"tcp\"\nports = 443",
            "address = \"192.0.2.8\"\nprotocol = \"tcp\"\nports = 443",
        ],
        &["network = \"192.0.2.0/28\"\nprotocol = \"tcp\"\nports = 443"],
    );
    // A names list that two OLD rules give together.
    contained(
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = [443, 8443]\nnames = [\"a.example.com\"]",
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"b.example.com\"]",
        ],
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"a.example.com\", \"b.example.com\"]",
        ],
    );
    // Hosts that fill a /29 between its excluded edges.
    let hosts: Vec<String> = (1..=6)
        .map(|h| format!("address = \"192.0.2.{h}\"\nprotocol = \"udp\"\nports = 53"))
        .collect();
    let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
    contained(
        &hosts,
        &["network = \"192.0.2.0/29\"\nprotocol = \"udp\"\nports = 53"],
    );
    // IPv6 halves into the whole, and a named rule beside a nameless one.
    contained(
        &[
            "network = \"2001:db8::/65\"\nprotocol = \"tcp\"\nports = \"1-1000\"",
            "network = \"2001:db8:0:0:8000::/65\"\nprotocol = \"tcp\"\nports = \"500-2000\"\nnames = [\"a.example.com\"]",
            "network = \"2001:db8:0:0:8000::/65\"\nprotocol = \"tcp\"\nports = \"1-499\"",
        ],
        &[
            "network = \"2001:db8::/64\"\nprotocol = \"tcp\"\nports = \"1-1000\"\nnames = [\"a.example.com\"]",
        ],
    );
}

#[test]
fn near_misses_are_expanded_with_the_uncovered_request() {
    // One port between the two OLD ranges.
    let rows = expanded(
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = \"1-100\"",
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = \"102-200\"",
        ],
        &["address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = \"50-150\""],
    );
    assert!(
        rows.contains(&("192.0.2.10:101/tcp".into(), None)),
        "{rows:?}"
    );
    // One host missing from the middle of a /29.
    let hosts: Vec<String> = [1, 2, 3, 5, 6]
        .iter()
        .map(|h| format!("address = \"192.0.2.{h}\"\nprotocol = \"udp\"\nports = 53"))
        .collect();
    let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
    let rows = expanded(
        &hosts,
        &["network = \"192.0.2.0/29\"\nprotocol = \"udp\"\nports = 53"],
    );
    assert_eq!(rows, [("192.0.2.4:53/udp".to_owned(), None)]);
    // One inner edge not listed as a host: OLD excludes it, NEW does not.
    let rows = expanded(
        &[
            "network = \"192.0.2.0/29\"\nprotocol = \"tcp\"\nports = 443",
            "network = \"192.0.2.8/29\"\nprotocol = \"tcp\"\nports = 443",
            "address = \"192.0.2.7\"\nprotocol = \"tcp\"\nports = 443",
        ],
        &["network = \"192.0.2.0/28\"\nprotocol = \"tcp\"\nports = 443"],
    );
    assert_eq!(rows, [("192.0.2.8:443/tcp".to_owned(), None)]);
    // One name that OLD did not allow on one port.
    let rows = expanded(
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = [443, 8443]\nnames = [\"a.example.com\"]",
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"b.example.com\"]",
        ],
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 8443\nnames = [\"a.example.com\", \"b.example.com\"]",
        ],
    );
    assert_eq!(
        rows,
        [(
            "192.0.2.10:8443/tcp".to_owned(),
            Some("b.example.com".to_owned())
        )]
    );
    // A nameless NEW rule needs nameless OLD rules: names do not add up to
    // every name.
    let rows = expanded(
        &[
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"a.example.com\"]",
            "address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443\nnames = [\"b.example.com\"]",
        ],
        &["address = \"192.0.2.10\"\nprotocol = \"tcp\"\nports = 443"],
    );
    assert!(
        rows.contains(&("192.0.2.10:443/tcp".into(), None)),
        "{rows:?}"
    );
}

#[test]
fn past_the_work_limit_the_proof_is_inconclusive() {
    // 512 OLD rules each give one port of a /112, and 512 hosts cut it into
    // 513 pieces: each NEW rule costs about 800,000 units.
    let mut old = Vec::new();
    for port in 1..=512 {
        old.push(format!(
            "network = \"2001:db8::/112\"\nprotocol = \"tcp\"\nports = {port}"
        ));
    }
    for host in 1..=512 {
        old.push(format!(
            "address = \"2001:db8::{host:x}\"\nprotocol = \"tcp\"\nports = 1"
        ));
    }
    let old: Vec<&str> = old.iter().map(String::as_str).collect();
    let rule = "network = \"2001:db8::/112\"\nprotocol = \"tcp\"\nports = \"1-512\"";
    contained(&old, &[rule]);
    let report = contain(&old, &[rule; 8]);
    assert_eq!(report.endpoint_result, "inconclusive", "{report:?}");
    assert_eq!(report.reason, "work-limit");
}

/// A small deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) % n
    }
}

/// A random rule in 192.0.2.0/28, ports 1-6, inside `within` when given.
fn random_rule(rng: &mut Rng, within: Option<(u8, u8, u8, u8, u64, bool)>) -> String {
    let (prefix, base, lo, hi, names, udp) = match within {
        None => {
            let prefix = 28 + u8::try_from(rng.below(5)).expect("prefix");
            let size = 1u8 << (32 - prefix);
            let base = u8::try_from(rng.below(16)).expect("base") / size * size;
            let lo = 1 + u8::try_from(rng.below(6)).expect("lo");
            let hi = lo + u8::try_from(rng.below(u64::from(7 - lo))).expect("hi");
            (prefix, base, lo, hi, rng.below(4), rng.below(4) == 0)
        }
        Some((prefix, base, lo, hi, names, udp)) => {
            // Narrow the OLD rule: a longer prefix, a shorter port range,
            // sometimes a widened names list or a nudged range.
            let sub = prefix + u8::try_from(rng.below(u64::from(33 - prefix))).expect("sub");
            let size = 1u8 << (32 - sub);
            let span = 1u8 << (32 - prefix);
            let base = base + u8::try_from(rng.below(u64::from(span / size))).expect("off") * size;
            let lo2 = lo + u8::try_from(rng.below(u64::from(hi - lo + 1))).expect("lo");
            let hi2 = (lo2 + u8::try_from(rng.below(3)).expect("hi")).min(6);
            let names = if rng.below(3) == 0 {
                rng.below(4)
            } else {
                names
            };
            (sub, base, lo2, hi2, names, udp)
        }
    };
    let names = match names {
        1 => "\nnames = [\"a.example.com\"]",
        2 => "\nnames = [\"b.example.com\"]",
        3 => "\nnames = [\"a.example.com\", \"b.example.com\"]",
        _ => "",
    };
    let protocol = if udp { "udp" } else { "tcp" };
    format!(
        "network = \"192.0.2.{base}/{prefix}\"\nprotocol = \"{protocol}\"\nports = \"{lo}-{hi}\"{names}"
    )
}

/// Parse back the fields `random_rule` wrote, to narrow it.
fn fields(rule: &str) -> (u8, u8, u8, u8, u64, bool) {
    let net = rule.split('"').nth(1).expect("network");
    let (addr, prefix) = net.split_once('/').expect("prefix");
    let base = addr
        .rsplit('.')
        .next()
        .expect("octet")
        .parse()
        .expect("base");
    let ports = rule.split('"').nth(5).expect("ports");
    let (lo, hi) = ports.split_once('-').expect("range");
    let names = match (rule.contains("a.example"), rule.contains("b.example")) {
        (true, true) => 3,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 0,
    };
    (
        prefix.parse().expect("prefix"),
        base,
        lo.parse().expect("lo"),
        hi.parse().expect("hi"),
        names,
        rule.contains("udp"),
    )
}

#[test]
fn union_cover_agrees_with_brute_force_enumeration() {
    let names: Vec<Option<HostName>> = [None, Some("a.example.com"), Some("b.example.com")]
        .into_iter()
        .chain([Some("c.example.com")])
        .map(|n| n.map(|n| HostName::canonical(n).expect("name")))
        .collect();
    let requests: Vec<Target> = (0..16)
        .flat_map(|host| {
            (1..=7).flat_map(move |port| {
                ["tcp", "udp"].into_iter().map(move |proto| {
                    format!("192.0.2.{host}:{port}/{proto}")
                        .parse()
                        .expect("target")
                })
            })
        })
        .collect();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut proved, mut refuted) = (0, 0);
    for _ in 0..3000 {
        let old: Vec<String> = (0..=rng.below(4))
            .map(|_| random_rule(&mut rng, None))
            .collect();
        let new: Vec<String> = (0..=rng.below(3))
            .map(|_| {
                if rng.below(5) == 0 {
                    random_rule(&mut rng, None)
                } else {
                    let i = usize::try_from(rng.below(old.len() as u64)).expect("index");
                    random_rule(&mut rng, Some(fields(&old[i])))
                }
            })
            .collect();
        let old = pass("o", &old.iter().map(String::as_str).collect::<Vec<_>>());
        let new = pass("n", &new.iter().map(String::as_str).collect::<Vec<_>>());
        let truth = requests.iter().all(|target| {
            names.iter().all(|name| {
                !allows(&new, target, name.as_ref()) || allows(&old, target, name.as_ref())
            })
        });
        let report = endpoint_containment(&old, &new, now());
        if truth {
            proved += 1;
            assert_eq!(
                report.endpoint_result, "contained",
                "{old:?}\n{new:?}\n{report:?}"
            );
        } else {
            refuted += 1;
            assert_eq!(
                report.endpoint_result, "expanded",
                "{old:?}\n{new:?}\n{report:?}"
            );
            check_counterexamples(&old, &new, &report);
        }
    }
    // Both verdicts are well represented.
    assert!(proved > 500 && refuted > 500, "{proved} {refuted}");
}
