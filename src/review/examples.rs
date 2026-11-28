//! Sample changed destination decisions through the ordinary pure evaluator.
use crate::{Decision, Destination, HostName, MAX_NAMES, Network, Pass, Target};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use time::{Duration, OffsetDateTime};

const MAX_CANDIDATES: usize = 512;
const MAX_ROWS: usize = 64;
/// The most requests tried where a nameless NEW destination opens what
/// another destination restricts to names: 32 overlaps, two requests each.
const MAX_RESTRICTION_PROBES: usize = 64;

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
    /// `newly-allowed`, `changed` or `refusal-code-only`.
    pub change: &'static str,
    /// The destination that restricts this address and port to names, when
    /// NEW allows the request without one of them through a nameless
    /// destination; null otherwise.
    pub bypasses_names_of: Option<String>,
    #[serde(skip)]
    pub(crate) request: Target,
    #[serde(skip)]
    pub(crate) host: Option<HostName>,
}

const NEWLY_ALLOWED: &str = "newly-allowed";
const CHANGED: &str = "changed";
const REFUSAL_CODE_ONLY: &str = "refusal-code-only";

const fn classify(before: &ExampleDecision, after: &ExampleDecision) -> &'static str {
    match (before, after) {
        (ExampleDecision::Refused { .. }, ExampleDecision::Allowed { .. }) => NEWLY_ALLOWED,
        (ExampleDecision::Refused { .. }, ExampleDecision::Refused { .. }) => REFUSAL_CODE_ONLY,
        _ => CHANGED,
    }
}

/// Candidate count includes duplicate requests encountered during sampling.
#[derive(Clone, Debug, Serialize)]
pub struct ExampleReport {
    pub sampled: bool,
    pub at: String,
    pub candidates: usize,
    pub evaluated: usize,
    pub truncated: bool,
    /// Refused-to-refused changes where only the refusal code differs.
    pub refusal_code_changes: usize,
    /// Whether those changes are listed in `rows` (after every other row).
    pub refusal_code_changes_listed: bool,
    /// Newly allowed rows first, then other changes, then refusal-code-only rows.
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
    decision_examples_with(old, new, now, false)
}

/// One label's destination in OLD and in NEW.
type Sides<'a> = [Option<&'a Destination>; 2];

/// The destinations, by label, that NEW adds, removes, edits or moves.
fn changed_rules<'a>(old: &'a Pass, new: &'a Pass) -> BTreeMap<&'a str, Sides<'a>> {
    let mut by_label = BTreeMap::<_, Sides<'a>>::new();
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
    by_label.retain(|label, sides| match sides {
        [Some(a), Some(b)] => {
            moved.contains(label)
                || a.network != b.network
                || a.protocol != b.protocol
                || a.ports != b.ports
                || a.names != b.names
        }
        _ => true,
    });
    by_label
}

/// A request in the addresses and ports that one destination restricts to
/// names, which a nameless destination of NEW also matches.
pub(super) struct Probe {
    pub(super) target: Target,
    /// No name, or a name the restricting destination does not list.
    pub(super) name: Option<HostName>,
    /// The destination that restricts names.
    pub(super) restricted: String,
    /// The nameless NEW destination, and its port range that holds the port.
    pub(super) opener: (String, u16, u16),
}

/// The first port of each range that both sorted, disjoint lists hold, with
/// the range of `b` it lies in.
fn common_ports(a: &[(u16, u16)], b: &[(u16, u16)]) -> Vec<(u16, (u16, u16))> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while let (Some(&(a_lo, a_hi)), Some(&(b_lo, b_hi))) = (a.get(i), b.get(j)) {
        if a_lo.max(b_lo) <= a_hi.min(b_hi) {
            out.push((a_lo.max(b_lo), (b_lo, b_hi)));
        }
        if a_hi <= b_hi {
            i += 1;
        }
        if b_hi <= a_hi {
            j += 1;
        }
    }
    out
}

/// A name `rule` does not list: `unlisted.example.net`, or a numbered one
/// when the rule lists that. A rule lists at most `MAX_NAMES` names.
fn unlisted_name(rule: &Destination) -> Option<HostName> {
    std::iter::once("unlisted.example.net".to_owned())
        .chain((2..=MAX_NAMES + 1).map(|n| format!("unlisted-{n}.example.net")))
        .filter_map(|text| HostName::canonical(&text).ok())
        .find(|name| !rule.names.contains(name))
}

/// Requests where a nameless destination that NEW adds or changes opens an
/// address and port that another destination, in OLD or NEW, restricts to
/// names. One address per pair and one port per shared port range, each
/// tried without a name and with a name the restricting destination does
/// not list. The flag is true when the list stopped at its limit.
pub(super) fn restriction_probes(old: &Pass, new: &Pass) -> (Vec<Probe>, bool) {
    let changed = changed_rules(old, new);
    let excluded = super::containment::blocked_edges(new);
    let restricted: Vec<&Destination> = new
        .destinations
        .iter()
        .chain(
            old.destinations
                .iter()
                .filter(|d| changed.contains_key(d.label.as_str())),
        )
        .filter(|d| !d.names.is_empty())
        .collect();
    let openers = new
        .destinations
        .iter()
        .filter(|d| d.names.is_empty() && changed.contains_key(d.label.as_str()));
    let mut probes = Vec::new();
    for opener in openers {
        let open = opener.ports.normalized_ranges();
        for rule in &restricted {
            if rule.label == opener.label
                || rule.protocol != opener.protocol
                || !rule.network.overlaps(&opener.network)
            {
                continue;
            }
            // Two overlapping networks nest: the longer prefix lies in both.
            let shared = if rule.network.prefix() >= opener.network.prefix() {
                rule.network
            } else {
                opener.network
            };
            let ip = super::overlap_example(shared, &excluded);
            for (port, (lo, hi)) in common_ports(&rule.ports.normalized_ranges(), &open) {
                for name in std::iter::once(None).chain(unlisted_name(rule).map(Some)) {
                    if probes.len() == MAX_RESTRICTION_PROBES {
                        return (probes, true);
                    }
                    probes.push(Probe {
                        target: Target {
                            ip,
                            port,
                            protocol: opener.protocol,
                        },
                        name,
                        restricted: rule.label.clone(),
                        opener: (opener.label.clone(), lo, hi),
                    });
                }
            }
        }
    }
    (probes, false)
}

/// Visits candidate requests once each, within the limits.
struct Sampler<'a> {
    old: &'a Pass,
    new: &'a Pass,
    now: OffsetDateTime,
    list_refusal_codes: bool,
    visited: HashSet<(Target, Option<&'a HostName>)>,
    report: ExampleReport,
}

impl<'a> Sampler<'a> {
    /// Evaluate one candidate under both revisions and keep a changed
    /// decision. False when a limit is reached: the report is truncated.
    fn visit(
        &mut self,
        target: Target,
        name: Option<&'a HostName>,
        restricted: Option<&str>,
    ) -> bool {
        let report = &mut self.report;
        if report.candidates == MAX_CANDIDATES || report.rows.len() == MAX_ROWS {
            report.truncated = true;
            return false;
        }
        report.candidates += 1;
        if !self.visited.insert((target, name)) {
            return true;
        }
        report.evaluated += 1;
        let decide = |pass: &Pass| {
            ExampleDecision::from(pass.permits_named(&target, name, self.now, Duration::ZERO))
        };
        let before = decide(self.old);
        let after = decide(self.new);
        if before == after {
            return true;
        }
        let change = classify(&before, &after);
        if change == REFUSAL_CODE_ONLY {
            report.refusal_code_changes += 1;
            if !self.list_refusal_codes {
                return true;
            }
        }
        let bypasses_names_of = restricted
            .filter(|_| matches!(after, ExampleDecision::Allowed { .. }))
            .map(ToOwned::to_owned);
        report.rows.push(DecisionExample {
            target: target.to_string(),
            name: name.map(ToString::to_string),
            at: report.at.clone(),
            before,
            after,
            change,
            bypasses_names_of,
            request: target,
            host: name.cloned(),
        });
        true
    }
}

/// One request replayed through the ordinary decision procedure under both
/// revisions, kept only when OLD refuses it and NEW allows it.
pub(super) fn replayed_new_allowance(
    old: &Pass,
    new: &Pass,
    now: OffsetDateTime,
    target: Target,
    name: Option<&HostName>,
) -> Option<DecisionExample> {
    let decide =
        |pass: &Pass| ExampleDecision::from(pass.permits_named(&target, name, now, Duration::ZERO));
    let before = decide(old);
    let after = decide(new);
    (classify(&before, &after) == NEWLY_ALLOWED).then(|| DecisionExample {
        target: target.to_string(),
        name: name.map(ToString::to_string),
        at: super::exact_stamp(now),
        before,
        after,
        change: NEWLY_ALLOWED,
        bypasses_names_of: None,
        request: target,
        host: name.cloned(),
    })
}

/// Like [`decision_examples`]. Refused-to-refused changes in which only the
/// code differs are counted, and listed (last) only when `list_refusal_codes`.
///
/// The requests tried first are those where a nameless destination that NEW
/// adds or changes opens an address and port that another destination
/// restricts to names: without a name, and with a name that destination
/// does not list. Their rows name it in `bypasses_names_of` when NEW allows them.
#[must_use]
pub fn decision_examples_with(
    old: &Pass,
    new: &Pass,
    now: OffsetDateTime,
    list_refusal_codes: bool,
) -> ExampleReport {
    let (probes, probes_cut) = restriction_probes(old, new);
    let mut sampler = Sampler {
        old,
        new,
        now,
        list_refusal_codes,
        visited: HashSet::new(),
        report: ExampleReport {
            sampled: true,
            at: super::exact_stamp(now),
            candidates: 0,
            evaluated: 0,
            truncated: probes_cut,
            refusal_code_changes: 0,
            refusal_code_changes_listed: list_refusal_codes,
            rows: Vec::new(),
        },
    };
    // A names list losing its effect shows more than added scope does.
    for probe in &probes {
        if !sampler.visit(probe.target, probe.name.as_ref(), Some(&probe.restricted)) {
            return finish(sampler.report);
        }
    }
    for sides in changed_rules(old, new).into_values() {
        let mut streams = sides.map(|s| s.map(candidates));
        // Alternate revisions so either side can contribute early boundary cases.
        loop {
            let mut advanced = false;
            for stream in streams.iter_mut().flatten() {
                let Some((target, name)) = stream.next() else {
                    continue;
                };
                advanced = true;
                if !sampler.visit(target, name, None) {
                    return finish(sampler.report);
                }
            }
            if !advanced {
                break;
            }
        }
    }
    finish(sampler.report)
}

/// Newly allowed rows first; the sort is stable, so discovery order holds within a kind.
fn finish(mut report: ExampleReport) -> ExampleReport {
    let rank = |row: &DecisionExample| match row.change {
        NEWLY_ALLOWED => 0,
        CHANGED => 1,
        _ => 2,
    };
    report.rows.sort_by_key(rank);
    report
}
