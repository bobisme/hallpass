//! Sufficient proof of zero-duration endpoint containment between two open approvals.
use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::{Destination, Pass};
use serde::Serialize;
use time::OffsetDateTime;

use super::{DecisionExample, ExampleDecision, decision_examples, exact_stamp};

const MAX_PAIRS: usize = 16_384;

/// Evidence about the endpoint admission relation at a single instant.
#[derive(Debug, Serialize)]
pub struct Containment {
    pub result: &'static str,
    pub at: String,
    pub reason: &'static str,
    pub compared_pairs: usize,
    pub example: Option<DecisionExample>,
}

// The policy first rejects both IPv4 edges globally, unless any destination
// lists that address as a single host (independently of protocol or port).
fn blocked_edges(pass: &Pass) -> BTreeSet<u32> {
    let mut hosts = BTreeSet::new();
    let mut edges = BTreeSet::new();
    for dest in &pass.destinations {
        if let IpAddr::V4(ip) = dest.network.addr() {
            let addr = u32::from(ip);
            match dest.network.prefix() {
                32 => {
                    hosts.insert(addr);
                }
                prefix @ 0..=30 => {
                    edges.extend([addr, addr | (u32::MAX >> prefix)]);
                }
                _ => {}
            }
        }
    }
    edges.retain(|addr| !hosts.contains(addr));
    edges
}

struct Rule<'a> {
    dest: &'a Destination,
    ports: Vec<(u16, u16)>,
}

impl<'a> From<&'a Destination> for Rule<'a> {
    fn from(dest: &'a Destination) -> Self {
        Self {
            dest,
            ports: dest.ports.normalized_ranges(),
        }
    }
}

impl Rule<'_> {
    fn covers(&self, proposed: &Self) -> bool {
        let a = self.dest;
        let b = proposed.dest;
        a.protocol == b.protocol
            && a.network.prefix() <= b.network.prefix()
            && a.network.contains(b.network.addr())
            && (a.names.is_empty()
                || (!b.names.is_empty() && b.names.iter().all(|name| a.names.contains(name))))
            && proposed.ports.iter().all(|&(lo, hi)| {
                let i = self.ports.partition_point(|&(_, end)| end < lo);
                self.ports
                    .get(i)
                    .is_some_and(|&(start, end)| start <= lo && end >= hi)
            })
    }
}

/// Prove coverage of every proposed rule, or supply the reason a proof is unavailable.
/// An expansion requires a witness from the normal decision procedure.
#[must_use]
pub fn endpoint_containment(old: &Pass, new: &Pass, at: OffsetDateTime) -> Containment {
    let mut report = Containment {
        result: "inconclusive",
        at: exact_stamp(at),
        reason: "different-pass-id",
        compared_pairs: 0,
        example: None,
    };
    if old.id != new.id {
        return report;
    }
    if !old.window_at(at).is_valid() || !new.window_at(at).is_valid() {
        report.reason = "both-windows-must-be-open";
        return report;
    }
    let original: Vec<_> = old.destinations.iter().map(Rule::from).collect();
    let mut reason = None;
    'rules: for dest in &new.destinations {
        let proposed = Rule::from(dest);
        for prior in &original {
            if report.compared_pairs == MAX_PAIRS {
                reason = Some("pair-limit");
                break 'rules;
            }
            report.compared_pairs += 1;
            if prior.covers(&proposed) {
                continue 'rules;
            }
        }
        reason = Some("single-rule-coverage-unproved");
        break;
    }
    if reason.is_none() && !blocked_edges(old).is_subset(&blocked_edges(new)) {
        reason = Some("ipv4-edge-coverage-unproved");
    }
    if let Some(reason) = reason {
        report.reason = reason;
        report.example = decision_examples(old, new, at)
            .rows
            .into_iter()
            .find(|row| {
                matches!(row.before, ExampleDecision::Refused { .. })
                    && matches!(row.after, ExampleDecision::Allowed { .. })
            });
        if report.example.is_some() {
            report.result = "expanded";
            report.reason = "replayed-new-allowance";
        }
    } else {
        report.result = "contained";
        report.reason = "rules-and-ipv4-edges-covered";
    }
    report
}
