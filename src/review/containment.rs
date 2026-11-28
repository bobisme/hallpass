//! Sufficient proof of zero-duration endpoint containment at every instant.
//!
//! A request is admitted when the window is open and not revoked, and a
//! destination rule matches it. The rule match does not depend on the
//! instant, so the proof compares the destination rules alone; the window
//! and revocation are their own terms, judged as loosenings.
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::{Destination, HostName, Network, Pass, Target};
use serde::Serialize;
use time::OffsetDateTime;

use super::examples::{replayed_new_allowance, restriction_probes};
use super::{DecisionExample, ExampleDecision, decision_examples, exact_stamp};

/// The most work the union proof spends, and separately the search for
/// widened classes: one unit per rule pair compared, per address interval
/// and per port range merged. Past it the proof is `inconclusive`.
const MAX_WORK: usize = 1 << 22;
/// The most counterexamples reported, each in a widened class no earlier one is in.
const MAX_COUNTEREXAMPLES: usize = 8;

/// Evidence about the endpoint admission relation, independent of the instant.
#[derive(Debug, Serialize)]
pub struct Containment {
    /// The overall verdict: `contained` only when the endpoints are contained
    /// and nothing else loosens; `widened` when only non-endpoint terms loosen.
    pub result: &'static str,
    /// The endpoint-only verdict (`contained`, `expanded` or `inconclusive`).
    pub endpoint_result: &'static str,
    /// Non-endpoint loosenings: window, ceilings, requirements, revocation, approver.
    pub loosenings: Vec<super::Loosening>,
    /// The `--at` instant as given.
    pub at: String,
    /// The instant the counterexample search replayed requests at: `at` when
    /// NEW's window holds it, otherwise the start of NEW's window. Null when
    /// no search ran.
    pub replayed_at: Option<String>,
    pub reason: &'static str,
    pub compared_pairs: usize,
    /// The first counterexample, kept for older readers.
    pub example: Option<DecisionExample>,
    /// Up to eight new allowances. Each lies in a widened class that no
    /// earlier one lies in: a NEW destination and port range that OLD's
    /// destinations together do not cover, an IPv4 network or broadcast address that NEW
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

/// The work limit was reached.
struct Exhausted;

/// Work left before the proof gives up.
struct Budget(usize);

impl Budget {
    fn spend(&mut self, units: usize) -> Result<(), Exhausted> {
        self.0 = self.0.checked_sub(units).ok_or(Exhausted)?;
        Ok(())
    }
}

/// A network as its family (true for IPv6) and its inclusive address interval.
fn span(network: Network) -> (bool, u128, u128) {
    let prefix = u32::from(network.prefix());
    match network.addr() {
        IpAddr::V4(ip) => {
            let first = u32::from(ip);
            let last = first | u32::MAX.checked_shr(prefix).unwrap_or(0);
            (false, first.into(), last.into())
        }
        IpAddr::V6(ip) => {
            let first = u128::from(ip);
            (
                true,
                first,
                first | u128::MAX.checked_shr(prefix).unwrap_or(0),
            )
        }
    }
}

fn address(v6: bool, n: u128) -> IpAddr {
    if v6 {
        IpAddr::V6(n.into())
    } else {
        IpAddr::V4(u32::try_from(n).unwrap_or(u32::MAX).into())
    }
}

/// True when two sorted, disjoint port lists share a port.
fn ports_overlap(a: &[(u16, u16)], b: &[(u16, u16)]) -> bool {
    let (mut i, mut j) = (0, 0);
    while let (Some(&(a_lo, a_hi)), Some(&(b_lo, b_hi))) = (a.get(i), b.get(j)) {
        if a_lo.max(b_lo) <= a_hi.min(b_hi) {
            return true;
        }
        if a_hi <= b_hi {
            i += 1;
        } else {
            j += 1;
        }
    }
    false
}

/// The first port of the sorted, disjoint `need` that no range in `held` holds.
fn first_missing_port(need: &[(u16, u16)], mut held: Vec<(u16, u16)>) -> Option<u16> {
    held.sort_unstable();
    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(held.len());
    for (start, end) in held {
        if let Some((_, last_end)) = merged.last_mut()
            && u32::from(start) <= u32::from(*last_end) + 1
        {
            *last_end = (*last_end).max(end);
        } else {
            merged.push((start, end));
        }
    }
    // The merged ranges neither overlap nor touch, so the port after the end
    // of the one holding `lo` is held by none.
    for &(lo, hi) in need {
        let i = merged.partition_point(|&(_, end)| end < lo);
        match merged.get(i) {
            Some(&(start, end)) if start <= lo => {
                if end < hi {
                    return Some(end + 1);
                }
            }
            _ => return Some(lo),
        }
    }
    None
}

/// A request inside a NEW rule that no OLD rule matches.
struct Gap {
    target: Target,
    name: Option<HostName>,
}

/// The first address and port in `first..=last` × `ports`, other than the
/// sorted `excluded` addresses, that no rule in `admitting` holds.
///
/// The interval is cut at every start of an admitting rule and after every
/// end, and around each excluded address. No rule begins or ends inside a
/// piece, so a rule holds all of a piece or none of it, and testing the
/// first address of each piece decides the whole piece.
fn sweep(
    admitting: &[&Rule],
    (v6, first, last): (bool, u128, u128),
    excluded: &[u128],
    ports: &[(u16, u16)],
    budget: &mut Budget,
) -> Result<Option<(IpAddr, u16)>, Exhausted> {
    let spans: Vec<(u128, u128)> = admitting
        .iter()
        .map(|prior| {
            let (_, lo, hi) = span(prior.dest.network);
            (lo, hi)
        })
        .collect();
    let mut cuts = BTreeSet::from([first]);
    for &(lo, hi) in &spans {
        cuts.insert(lo.max(first));
        if hi < last {
            cuts.insert(hi + 1);
        }
    }
    for &p in excluded {
        cuts.insert(p);
        if p < last {
            cuts.insert(p + 1);
        }
    }
    cuts.retain(|&cut| (first..=last).contains(&cut));
    for cut in cuts {
        if excluded.binary_search(&cut).is_ok() {
            continue;
        }
        budget.spend(1 + spans.len())?;
        let mut held = Vec::new();
        for (prior, &(lo, hi)) in admitting.iter().zip(&spans) {
            if (lo..=hi).contains(&cut) {
                held.extend_from_slice(&prior.ports);
            }
        }
        budget.spend(held.len())?;
        if let Some(port) = first_missing_port(ports, held) {
            return Ok(Some((address(v6, cut), port)));
        }
    }
    Ok(None)
}

/// The first request that `rule` admits on `ports` and no OLD rule matches,
/// or None when the union of OLD's rules holds every one.
///
/// The addresses NEW excludes as IPv4 network or broadcast edges
/// (`excluded`) are left out: NEW refuses them whatever its rules say. A
/// nameless rule admits every name and none, and a name no OLD rule lists
/// exists, so only nameless OLD rules count for it and the request has no
/// name. A named rule is tried with each of its names, against the OLD
/// rules that are nameless or list that name.
fn first_gap(
    original: &[Rule],
    rule: &Destination,
    ports: &[(u16, u16)],
    excluded: &BTreeSet<u32>,
    budget: &mut Budget,
    pairs: &mut usize,
) -> Result<Option<Gap>, Exhausted> {
    let whole @ (v6, first, last) = span(rule.network);
    let mut near = Vec::new();
    for (i, prior) in original.iter().enumerate() {
        budget.spend(1 + prior.ports.len() + ports.len())?;
        *pairs += 1;
        let (family, lo, hi) = span(prior.dest.network);
        if prior.dest.protocol == rule.protocol
            && family == v6
            && lo <= last
            && hi >= first
            && ports_overlap(&prior.ports, ports)
        {
            near.push(i);
        }
    }
    let skip: Vec<u128> = if v6 {
        Vec::new()
    } else {
        let lo = u32::try_from(first).unwrap_or(u32::MAX);
        let hi = u32::try_from(last).unwrap_or(u32::MAX);
        excluded.range(lo..=hi).map(|&p| u128::from(p)).collect()
    };
    let names: Vec<Option<&HostName>> = if rule.names.is_empty() {
        vec![None]
    } else {
        rule.names.iter().map(Some).collect()
    };
    // Names that the same OLD rules admit get the same answer.
    let mut tried = BTreeSet::new();
    for name in names {
        budget.spend(1 + near.len())?;
        let admitting: Vec<usize> = near
            .iter()
            .copied()
            .filter(|&i| {
                let names = &original[i].dest.names;
                names.is_empty() || name.is_some_and(|n| names.contains(n))
            })
            .collect();
        if !tried.insert(admitting.clone()) {
            continue;
        }
        let admitting: Vec<&Rule> = admitting.into_iter().map(|i| &original[i]).collect();
        if let Some((ip, port)) = sweep(&admitting, whole, &skip, ports, budget)? {
            return Ok(Some(Gap {
                target: Target {
                    ip,
                    port,
                    protocol: rule.protocol,
                },
                name: name.cloned(),
            }));
        }
    }
    Ok(None)
}

/// One part of the endpoints in which NEW may allow what OLD refuses.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    /// A NEW destination and port range that OLD's destinations together do
    /// not cover.
    Range(String, u16, u16),
    /// An IPv4 network or broadcast address that OLD excludes and NEW does not.
    Edge(u32),
    /// A request where a nameless NEW destination opens an address and port
    /// that another destination restricts to names: the target, and whether
    /// the request carries a name.
    Names(String, bool),
}

/// Every class in which NEW may allow what OLD refuses, or None when a
/// work limit leaves some unknown. A class may hold no new allowance. Also
/// a request in each NEW destination and port range that OLD's rules do
/// not cover, found so far, for replay.
fn widened_classes(old: &Pass, new: &Pass) -> (Option<BTreeSet<Class>>, Vec<Gap>) {
    let original: Vec<Rule> = old.destinations.iter().map(Rule::from).collect();
    let excluded = blocked_edges(new);
    let mut budget = Budget(MAX_WORK);
    let mut pairs = 0;
    let mut classes = BTreeSet::new();
    let mut gaps = Vec::new();
    for dest in &new.destinations {
        for (lo, hi) in dest.ports.normalized_ranges() {
            match first_gap(
                &original,
                dest,
                &[(lo, hi)],
                &excluded,
                &mut budget,
                &mut pairs,
            ) {
                Err(Exhausted) => return (None, gaps),
                Ok(Some(gap)) => {
                    classes.insert(Class::Range(dest.label.clone(), lo, hi));
                    gaps.push(gap);
                }
                Ok(None) => {}
            }
        }
    }
    // NEW allows a freed edge through any NEW destination that holds it,
    // while OLD refuses it whatever the request.
    for edge in freed_edges(old, new) {
        let ip = IpAddr::V4(edge.into());
        gaps.extend(
            new.destinations
                .iter()
                .find(|dest| dest.network.contains(ip))
                .and_then(|dest| {
                    let (port, _) = dest.ports.normalized_ranges().first().copied()?;
                    Some(Gap {
                        target: Target {
                            ip,
                            port,
                            protocol: dest.protocol,
                        },
                        name: dest.names.first().cloned(),
                    })
                }),
        );
        classes.insert(Class::Edge(edge));
    }
    let (probes, cut) = restriction_probes(old, new);
    if cut {
        return (None, gaps);
    }
    for probe in probes {
        let (label, lo, hi) = probe.opener;
        // A covered opener range was open without names in OLD already.
        if classes.contains(&Class::Range(label, lo, hi)) {
            classes.insert(Class::Names(probe.target.to_string(), probe.name.is_some()));
        }
    }
    (Some(classes), gaps)
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

/// Why OLD's rules together are not shown to cover NEW's, or None when they
/// are. `pairs` counts the rule pairs compared.
fn rules_coverage(old: &Pass, new: &Pass, pairs: &mut usize) -> Option<&'static str> {
    let original: Vec<Rule> = old.destinations.iter().map(Rule::from).collect();
    let by_label: BTreeMap<_, _> = original
        .iter()
        .map(|rule| (rule.dest.label.as_str(), rule))
        .collect();
    let excluded = blocked_edges(new);
    let mut budget = Budget(MAX_WORK);
    for dest in &new.destinations {
        let proposed = Rule::from(dest);
        // The same label usually covers on its own; then one pair is enough.
        if let Some(prior) = by_label.get(dest.label.as_str()) {
            *pairs += 1;
            if budget.spend(1).is_err() {
                return Some("work-limit");
            }
            if prior.covers(&proposed) {
                continue;
            }
        }
        match first_gap(
            &original,
            dest,
            &proposed.ports,
            &excluded,
            &mut budget,
            pairs,
        ) {
            Ok(None) => {}
            Ok(Some(_)) => return Some("union-coverage-unproved"),
            Err(Exhausted) => return Some("work-limit"),
        }
    }
    None
}

/// OLD's rules under NEW's window and revocation state, and an instant inside
/// NEW's window (`at` when the window holds it, else its start), so a replayed
/// request's decisions differ only by the destination rules.
fn replay_setting(old: &Pass, new: &Pass, at: OffsetDateTime) -> (Pass, OffsetDateTime) {
    let replay_at = if new.window_at(at).is_valid() {
        at
    } else {
        new.approval.valid_from
    };
    let mut old_rules = old.clone();
    old_rules.approval = new.approval.clone();
    (old_rules, replay_at)
}

/// Prove coverage of every proposed rule, or supply the reason a proof is unavailable.
/// An expansion requires a witness from the normal decision procedure.
///
/// A proposed rule is covered when the union of OLD's rules holds every
/// request it admits, apart from the IPv4 edges NEW excludes: for each of
/// its names (or, for a nameless rule, for every name and none), each
/// address and port is in some OLD rule with that protocol and name. The
/// check is exact; past a work limit the result is `inconclusive`.
///
/// The verdict holds for every instant: the rules are compared without a
/// window. Only a revoked NEW admits nothing at any instant (the window is
/// never empty), so only then is the result `new-admits-nothing`. `at` only
/// chooses the instant the counterexample search replays requests at.
#[must_use]
pub fn endpoint_containment(old: &Pass, new: &Pass, at: OffsetDateTime) -> Containment {
    let mut report = Containment {
        result: "inconclusive",
        endpoint_result: "inconclusive",
        loosenings: Vec::new(),
        at: exact_stamp(at),
        replayed_at: None,
        reason: "different-pass-id",
        compared_pairs: 0,
        example: None,
        counterexamples: Vec::new(),
        more_counterexamples: false,
    };
    if old.id != new.id {
        return report;
    }
    if new.approval.revoked {
        // NEW admits nothing at any instant, so every endpoint it admits
        // (none) is admitted by OLD.
        report.result = "contained";
        report.endpoint_result = "contained";
        report.reason = "new-admits-nothing";
        return report;
    }
    let mut reason = rules_coverage(old, new, &mut report.compared_pairs);
    if reason.is_none() && !freed_edges(old, new).is_empty() {
        reason = Some("ipv4-edge-coverage-unproved");
    }
    if let Some(reason) = reason {
        report.reason = reason;
        let (old_rules, replay_at) = replay_setting(old, new, at);
        report.replayed_at = Some(exact_stamp(replay_at));
        let sample = decision_examples(&old_rules, new, replay_at);
        let (widened, gaps) = widened_classes(old, new);
        let freed = freed_edges(old, new);
        let mut rows: Vec<DecisionExample> = sample
            .rows
            .into_iter()
            .filter(|row| {
                matches!(row.before, ExampleDecision::Refused { .. })
                    && matches!(row.after, ExampleDecision::Allowed { .. })
            })
            .collect();
        // Then the requests the union proof found uncovered, replayed
        // through the same decision procedure.
        for gap in gaps {
            if rows
                .iter()
                .any(|row| row.request == gap.target && row.host == gap.name)
            {
                continue;
            }
            rows.extend(replayed_new_allowance(
                &old_rules,
                new,
                replay_at,
                gap.target,
                gap.name.as_ref(),
            ));
        }
        let mut shown = BTreeSet::new();
        for row in rows {
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
