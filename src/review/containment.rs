//! Sufficient proof of zero-duration endpoint containment at an instant.
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::{Destination, Pass};
use serde::Serialize;
use time::OffsetDateTime;

use super::{DecisionExample, ExampleDecision, decision_examples, exact_stamp};

const MAX_PAIRS: usize = 16_384;
/// The most counterexamples reported: one per widened destination or port range.
const MAX_COUNTEREXAMPLES: usize = 8;

/// Evidence about the endpoint admission relation at a single instant.
#[derive(Debug, Serialize)]
pub struct Containment {
    /// The overall verdict: `contained` only when the endpoints are contained
    /// and nothing else loosens; `widened` when only non-endpoint terms loosen.
    pub result: &'static str,
    /// The endpoint-only verdict (`contained`, `expanded` or `inconclusive`).
    pub endpoint_result: &'static str,
    /// Non-endpoint loosenings: window, ceilings, requirements, revocation, approver.
    pub loosenings: Vec<super::Loosening>,
    pub at: String,
    pub reason: &'static str,
    pub compared_pairs: usize,
    /// The first counterexample, kept for older readers.
    pub example: Option<DecisionExample>,
    /// Up to eight new allowances, at most one per destination rule and port range.
    pub counterexamples: Vec<DecisionExample>,
    /// More new allowances may exist than `counterexamples` lists.
    pub more_counterexamples: bool,
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

fn old_edges_stay_excluded(old: &Pass, new: &Pass) -> bool {
    let old_edges = blocked_edges(old);
    let new_edges = blocked_edges(new);
    let freed: BTreeSet<_> = old_edges.difference(&new_edges).copied().collect();
    new.destinations
        .iter()
        .all(|rule| match rule.network.addr() {
            IpAddr::V6(_) => true,
            IpAddr::V4(ip) => {
                let first = u32::from(ip);
                let last = first
                    | u32::MAX
                        .checked_shr(u32::from(rule.network.prefix()))
                        .unwrap_or(0);
                freed.range(first..=last).next().is_none()
            }
        })
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

impl Containment {
    /// Fold the non-endpoint loosenings into the overall verdict.
    #[must_use]
    pub fn with_loosenings(mut self, loosenings: Vec<super::Loosening>) -> Self {
        if !loosenings.is_empty() && self.result != "expanded" {
            self.result = "widened";
        }
        self.loosenings = loosenings;
        self
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

/// The new rule and port range that admit a counterexample.
fn widened_range(new: &Pass, row: &DecisionExample) -> (String, u16, u16) {
    let ExampleDecision::Allowed { label } = &row.after else {
        return (String::new(), 0, 0);
    };
    let (lo, hi) = new
        .destinations
        .iter()
        .find(|d| d.label == *label)
        .and_then(|d| {
            d.ports
                .normalized_ranges()
                .into_iter()
                .find(|&(lo, hi)| (lo..=hi).contains(&row.port))
        })
        .unwrap_or((row.port, row.port));
    (label.clone(), lo, hi)
}

/// Prove coverage of every proposed rule, or supply the reason a proof is unavailable.
/// An expansion requires a witness from the normal decision procedure.
#[must_use]
pub fn endpoint_containment(old: &Pass, new: &Pass, at: OffsetDateTime) -> Containment {
    let mut report = Containment {
        result: "inconclusive",
        endpoint_result: "inconclusive",
        loosenings: Vec::new(),
        at: exact_stamp(at),
        reason: "different-pass-id",
        compared_pairs: 0,
        example: None,
        counterexamples: Vec::new(),
        more_counterexamples: false,
    };
    if old.id != new.id {
        return report;
    }
    if !new.window_at(at).is_valid() {
        // NEW admits nothing at this instant, so every endpoint it admits (none)
        // is admitted by OLD, whether or not OLD is open.
        report.result = "contained";
        report.endpoint_result = "contained";
        report.reason = "new-admits-nothing";
        return report;
    }
    if !old.window_at(at).is_valid() {
        report.reason = "old-closed-new-open";
        return report;
    }
    let original: BTreeMap<_, _> = old
        .destinations
        .iter()
        .map(|d| (d.label.as_str(), Rule::from(d)))
        .collect();
    let mut reason = None;
    'rules: for dest in &new.destinations {
        let proposed = Rule::from(dest);
        let label = dest.label.as_str();
        let candidates = original.get(label).into_iter().chain(
            original
                .iter()
                .filter(|(name, _)| **name != label)
                .map(|(_, rule)| rule),
        );
        for prior in candidates {
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
    if reason.is_none() && !old_edges_stay_excluded(old, new) {
        reason = Some("ipv4-edge-coverage-unproved");
    }
    if let Some(reason) = reason {
        report.reason = reason;
        let sample = decision_examples(old, new, at);
        let mut seen = BTreeSet::new();
        for row in sample.rows.into_iter().filter(|row| {
            matches!(row.before, ExampleDecision::Refused { .. })
                && matches!(row.after, ExampleDecision::Allowed { .. })
        }) {
            if !seen.insert(widened_range(new, &row)) {
                continue;
            }
            if report.counterexamples.len() == MAX_COUNTEREXAMPLES {
                report.more_counterexamples = true;
                break;
            }
            report.counterexamples.push(row);
        }
        report.more_counterexamples |= sample.truncated && !report.counterexamples.is_empty();
        report.example = report.counterexamples.first().cloned();
        if report.example.is_some() {
            report.result = "expanded";
            report.reason = "replayed-new-allowance";
        }
    } else {
        report.result = "contained";
        report.reason = "rules-and-ipv4-edges-covered";
    }
    report.endpoint_result = report.result;
    report
}
