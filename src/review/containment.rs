//! Sufficient proof of zero-duration endpoint containment at an instant.
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::{Destination, Pass};
use serde::Serialize;
use time::OffsetDateTime;

use super::examples::restriction_probes;
use super::{DecisionExample, ExampleDecision, decision_examples, exact_stamp};

const MAX_PAIRS: usize = 16_384;
/// The most counterexamples reported, each in a widened class no earlier one is in.
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
    /// Up to eight new allowances. Each lies in a widened class that no
    /// earlier one lies in: a NEW destination and port range that no single
    /// OLD destination covers, an IPv4 network or broadcast address that NEW
    /// no longer excludes, or an address and port that a nameless NEW
    /// destination opens although another destination restricts it to
    /// names (once without a name and once with an unlisted one). Rows of
    /// that last class come first.
    pub counterexamples: Vec<DecisionExample>,
    /// The list is not empty and some widened class has no counterexample
    /// in it (or a work limit left the classes unknown), so more new
    /// allowances may exist. False means each widened class has one.
    pub more_counterexamples: bool,
}

// The policy first rejects both IPv4 edges globally, unless any destination
// lists that address as a single host (independently of protocol or port).
pub(super) fn blocked_edges(pass: &Pass) -> BTreeSet<u32> {
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

/// The IPv4 edges OLD excludes and NEW no longer does, within a NEW destination.
fn freed_edges(old: &Pass, new: &Pass) -> BTreeSet<u32> {
    let new_edges = blocked_edges(new);
    let mut freed = blocked_edges(old);
    freed.retain(|edge| {
        !new_edges.contains(edge)
            && new
                .destinations
                .iter()
                .any(|rule| match rule.network.addr() {
                    IpAddr::V6(_) => false,
                    IpAddr::V4(ip) => {
                        let first = u32::from(ip);
                        let last = first
                            | u32::MAX
                                .checked_shr(u32::from(rule.network.prefix()))
                                .unwrap_or(0);
                        (first..=last).contains(edge)
                    }
                })
    });
    freed
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

/// One part of the endpoints in which NEW may allow what OLD refuses.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    /// A NEW destination and port range that no single OLD destination covers.
    Range(String, u16, u16),
    /// An IPv4 network or broadcast address that OLD excludes and NEW does not.
    Edge(u32),
    /// A request where a nameless NEW destination opens an address and port
    /// that another destination restricts to names: the target, and whether
    /// the request carries a name.
    Names(String, bool),
}

/// Every class in which NEW may allow what OLD refuses, or None when a
/// work limit leaves some unknown. A class may hold no new allowance.
fn widened_classes(old: &Pass, new: &Pass) -> Option<BTreeSet<Class>> {
    let original: Vec<Rule> = old.destinations.iter().map(Rule::from).collect();
    let mut pairs = 0;
    let mut classes = BTreeSet::new();
    for dest in &new.destinations {
        for (lo, hi) in dest.ports.normalized_ranges() {
            let proposed = Rule {
                dest,
                ports: vec![(lo, hi)],
            };
            let mut covered = false;
            for prior in &original {
                pairs += 1;
                if pairs > MAX_PAIRS {
                    return None;
                }
                if prior.covers(&proposed) {
                    covered = true;
                    break;
                }
            }
            if !covered {
                classes.insert(Class::Range(dest.label.clone(), lo, hi));
            }
        }
    }
    classes.extend(freed_edges(old, new).into_iter().map(Class::Edge));
    let (probes, cut) = restriction_probes(old, new);
    if cut {
        return None;
    }
    for probe in probes {
        let (label, lo, hi) = probe.opener;
        // A covered opener range was open without names in OLD already.
        if classes.contains(&Class::Range(label, lo, hi)) {
            classes.insert(Class::Names(probe.target.to_string(), probe.name.is_some()));
        }
    }
    Some(classes)
}

/// The classes a newly allowed request lies in.
fn classes_of(new: &Pass, row: &DecisionExample, freed: &BTreeSet<u32>) -> Vec<Class> {
    let request = row.request;
    let mut out = Vec::new();
    if row.bypasses_names_of.is_some() {
        out.push(Class::Names(row.target.clone(), row.name.is_some()));
    }
    if let IpAddr::V4(ip) = request.ip
        && freed.contains(&u32::from(ip))
    {
        out.push(Class::Edge(u32::from(ip)));
    }
    for dest in &new.destinations {
        let named = dest.names.is_empty()
            || row
                .host
                .as_ref()
                .is_some_and(|name| dest.names.contains(name));
        if !named || dest.protocol != request.protocol || !dest.network.contains(request.ip) {
            continue;
        }
        if let Some((lo, hi)) = dest
            .ports
            .normalized_ranges()
            .into_iter()
            .find(|&(lo, hi)| (lo..=hi).contains(&request.port))
        {
            out.push(Class::Range(dest.label.clone(), lo, hi));
        }
    }
    out
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
    if reason.is_none() && !freed_edges(old, new).is_empty() {
        reason = Some("ipv4-edge-coverage-unproved");
    }
    if let Some(reason) = reason {
        report.reason = reason;
        let sample = decision_examples(old, new, at);
        let widened = widened_classes(old, new);
        let freed = freed_edges(old, new);
        let mut shown = BTreeSet::new();
        for row in sample.rows.into_iter().filter(|row| {
            matches!(row.before, ExampleDecision::Refused { .. })
                && matches!(row.after, ExampleDecision::Allowed { .. })
        }) {
            let classes = classes_of(new, &row, &freed);
            // Weigh the classes the proof could not cover, when they are known.
            let mut counted = classes
                .iter()
                .filter(|class| widened.as_ref().is_none_or(|w| w.contains(*class)))
                .peekable();
            let fresh = if counted.peek().is_some() {
                counted.any(|class| !shown.contains(class))
            } else {
                classes.iter().any(|class| !shown.contains(class))
            };
            if !fresh {
                continue;
            }
            if report.counterexamples.len() == MAX_COUNTEREXAMPLES {
                report.more_counterexamples = true;
                break;
            }
            shown.extend(classes);
            report.counterexamples.push(row);
        }
        report.more_counterexamples |= !report.counterexamples.is_empty()
            && widened.is_none_or(|widened| !widened.is_subset(&shown));
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
