//! Sample changed destination decisions through the ordinary pure evaluator.
use crate::{Decision, Destination, HostName, Network, Pass, Target};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use time::{Duration, OffsetDateTime};

const MAX_CANDIDATES: usize = 512;
const MAX_ROWS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ExampleDecision {
    Allowed { label: String },
    Refused { code: &'static str },
}

impl From<Decision> for ExampleDecision {
    fn from(value: Decision) -> Self {
        match value {
            Decision::Allowed { label } => Self::Allowed { label },
            Decision::Refused(r) => Self::Refused {
                code: r.code.as_str(),
            },
        }
    }
}

impl std::fmt::Display for ExampleDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed { label } => write!(f, "allowed by {label}"),
            Self::Refused { code } => write!(f, "refused ({code})"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DecisionExample {
    pub target: String,
    pub name: Option<String>,
    pub at: String,
    pub before: ExampleDecision,
    pub after: ExampleDecision,
}

/// Candidate count includes duplicate requests encountered during sampling.
#[derive(Clone, Debug, Serialize)]
pub struct ExampleReport {
    pub sampled: bool,
    pub at: String,
    pub candidates: usize,
    pub evaluated: usize,
    pub truncated: bool,
    pub rows: Vec<DecisionExample>,
}

fn boundary_addresses(network: Network) -> Vec<IpAddr> {
    let first = network.addr();
    if network.is_host() {
        return vec![first];
    }
    let prefix = network.prefix();
    match first {
        IpAddr::V4(address) => {
            let start = u32::from(address);
            let end = start | (u32::MAX >> prefix);
            [start, start + 1, end - 1, end]
                .map(Ipv4Addr::from)
                .map(IpAddr::from)
                .into()
        }
        IpAddr::V6(address) => {
            let start = u128::from(address);
            let end = start | (u128::MAX >> prefix);
            [start, start + 1, end - 1, end]
                .map(Ipv6Addr::from)
                .map(IpAddr::from)
                .into()
        }
    }
}

fn candidates(rule: &Destination) -> impl Iterator<Item = (Target, Option<&HostName>)> {
    let addresses = boundary_addresses(rule.network);
    rule.ports
        .normalized_ranges()
        .into_iter()
        .flat_map(move |(lo, hi)| {
            let addresses = addresses.clone();
            [
                Some(lo),
                (hi != lo).then_some(hi),
                lo.checked_sub(1).filter(|p| *p > 0),
                hi.checked_add(1),
            ]
            .into_iter()
            .flatten()
            .flat_map(move |port| {
                // At most four addresses; copied into the lazy iterator.
                addresses.clone().into_iter().flat_map(move |ip| {
                    let target = Target {
                        ip,
                        port,
                        protocol: rule.protocol,
                    };
                    std::iter::once(None)
                        .chain(rule.names.iter().map(Some))
                        .map(move |name| (target, name))
                })
            })
        })
}

/// Evaluate deterministic boundary requests from edited or reordered destinations.
/// Both the number of visited candidates and the number of reported changes are bounded.
#[must_use]
pub fn decision_examples(old: &Pass, new: &Pass, now: OffsetDateTime) -> ExampleReport {
    let mut report = ExampleReport {
        sampled: true,
        at: super::exact_stamp(now),
        candidates: 0,
        evaluated: 0,
        truncated: false,
        rows: Vec::new(),
    };
    let mut by_label = BTreeMap::<_, [Option<&Destination>; 2]>::new();
    for (side, pass) in [old, new].into_iter().enumerate() {
        for rule in &pass.destinations {
            by_label.entry(rule.label.as_str()).or_default()[side] = Some(rule);
        }
    }
    // Insertion alone shifts numeric positions while preserving common rule order.
    let common = |rule: &&Destination| by_label[rule.label.as_str()].iter().all(Option::is_some);
    let moved: BTreeSet<_> = old
        .destinations
        .iter()
        .filter(common)
        .zip(new.destinations.iter().filter(common))
        .filter(|(a, b)| a.label != b.label)
        .map(|(a, _)| a.label.as_str())
        .collect();
    let mut visited = HashSet::new();
    for (label, sides) in by_label {
        if let [Some(a), Some(b)] = sides
            && !moved.contains(label)
            && a.network == b.network
            && a.protocol == b.protocol
            && a.ports == b.ports
            && a.names == b.names
        {
            continue;
        }
        let mut streams = sides.map(|s| s.map(candidates));
        // Alternate revisions so either side can contribute early boundary cases.
        loop {
            let mut advanced = false;
            for stream in streams.iter_mut().flatten() {
                let Some((target, name)) = stream.next() else {
                    continue;
                };
                if report.candidates == MAX_CANDIDATES || report.rows.len() == MAX_ROWS {
                    report.truncated = true;
                    return report;
                }
                advanced = true;
                report.candidates += 1;
                if !visited.insert((target, name)) {
                    continue;
                }
                report.evaluated += 1;
                let decide = |pass: &Pass| {
                    ExampleDecision::from(pass.permits_named(&target, name, now, Duration::ZERO))
                };
                let before = decide(old);
                let after = decide(new);
                if before != after {
                    report.rows.push(DecisionExample {
                        target: target.to_string(),
                        name: name.map(ToString::to_string),
                        at: report.at.clone(),
                        before,
                        after,
                    });
                }
            }
            if !advanced {
                break;
            }
        }
    }
    report
}
