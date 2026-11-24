//! Read-only approval review helpers. These intentionally make no ledger or
//! authorization changes: review output is evidence for an owner, never a
//! permission to spend.
use crate::{Decision, HostName, LoadedPass, Pass, Problem, Target, stamp};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use toml::Value;

mod containment;
pub use containment::{Containment, endpoint_containment};
mod examples;
pub use examples::{
    DecisionExample, ExampleDecision, ExampleReport, decision_examples, decision_examples_with,
};
mod coverage;
pub use coverage::{Capabilities, CoverageFinding, CoverageReport, consumer_coverage};

#[derive(Clone, Debug, Serialize)]
pub struct FieldChange {
    pub field: String,
    /// A JSON string, number or null (absent).
    pub before: serde_json::Value,
    /// A JSON string, number or null (absent).
    pub after: serde_json::Value,
    pub review_required: bool,
}

/// A change outside the endpoint rules that gives the pass more authority.
#[derive(Clone, Debug, Serialize)]
pub struct Loosening {
    /// The field, named as in `changes`.
    pub field: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}

/// A ceiling change loosens when the limit is raised, or when a new counter
/// becomes spendable without NEW requiring every debit to charge it. A counter
/// with no ceiling cannot be spent at all (`unknown-counter`), so removing a
/// ceiling narrows. Any other field here is the approver or operator:
/// authority passes to someone else.
fn ceiling_loosens(a: &Pass, b: &Pass, field: &str) -> bool {
    let Some(name) = field.strip_prefix("ceilings.") else {
        return true;
    };
    match (a.ceilings.get(name), b.ceilings.get(name)) {
        (None, Some(_)) => !b.required_counters.iter().any(|c| c == name),
        (Some(x), Some(y)) => y > x,
        _ => false,
    }
}

/// The non-endpoint changes that loosen the pass.
///
/// Each is a change diff marks `[review required]`, other than the destination
/// rules (which the endpoint proof judges): a longer
/// window, a higher or new ceiling, a dropped requirement, an un-revoke, or a
/// different approver or operator. A change that only narrows is not listed.
#[must_use]
pub fn non_endpoint_loosenings(old: &LoadedPass, new: &LoadedPass) -> Vec<Loosening> {
    let (a, b) = (&old.pass, &new.pass);
    diff(old, new)
        .changes
        .into_iter()
        .filter(|c| c.review_required && !c.field.starts_with("destination["))
        .filter(|c| match c.field.as_str() {
            "approval.valid_from" => b.approval.valid_from < a.approval.valid_from,
            "approval.valid_until" => b.approval.valid_until > a.approval.valid_until,
            "approval.revoked" => a.approval.revoked && !b.approval.revoked,
            "approval.revoked_reason" => false,
            "require_target_v1" => a.require_target && !b.require_target,
            "required_counters_v1" => a
                .required_counters
                .iter()
                .any(|name| !b.required_counters.contains(name)),
            field => ceiling_loosens(a, b, field),
        })
        .map(|c| Loosening {
            field: c.field,
            before: c.before,
            after: c.after,
        })
        .collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffReport {
    pub old_pass_id: String,
    pub new_pass_id: String,
    pub old_digest: String,
    pub new_digest: String,
    pub approval_changed: bool,
    pub changes: Vec<FieldChange>,
    pub introduced: Vec<String>,
    pub removed: Vec<String>,
    /// What each introduced destination grants, in label order.
    pub introduced_grants: Vec<DestinationGrant>,
    /// What each removed destination granted, in label order.
    pub removed_grants: Vec<DestinationGrant>,
    /// Name-restriction overlaps in the new pass that involve an introduced
    /// destination and were not already in the old pass.
    pub name_overlap_warnings: Vec<NameOverlapWarning>,
    pub order_changed: bool,
    pub review_required: bool,
}

/// The full grant of one destination, as plain values.
#[derive(Clone, Debug, Serialize)]
pub struct DestinationGrant {
    pub label: String,
    /// `address` for a single host, `network` otherwise.
    pub scope: &'static str,
    /// The literal address or the CIDR network.
    pub network: String,
    pub protocol: String,
    /// Normalized ranges, such as `443, 8000-8010`.
    pub ports: String,
    /// The approved host names; empty means any name.
    pub names: Vec<String>,
    pub hostname: Option<String>,
    pub whole_network_approved: bool,
    /// Labels whose overlap with this destination's names the owner accepted.
    pub overlap_acknowledged: Vec<String>,
}

fn grant(d: &crate::Destination) -> DestinationGrant {
    let mut names = d
        .names
        .iter()
        .map(|n| n.as_str().to_owned())
        .collect::<Vec<_>>();
    names.sort_unstable();
    DestinationGrant {
        label: d.label.clone(),
        scope: if d.network.is_host() {
            "address"
        } else {
            "network"
        },
        network: d.network.to_string(),
        protocol: d.protocol.to_string(),
        ports: ports_text(&d.ports.normalized_ranges()),
        names,
        hostname: d.hostname.clone(),
        whole_network_approved: d.whole_network_approved,
        overlap_acknowledged: {
            let mut labels = d.overlap_acknowledged.clone();
            labels.sort_unstable();
            labels
        },
    }
}

#[allow(clippy::needless_pass_by_value)]
fn change(
    out: &mut Vec<FieldChange>,
    field: impl Into<String>,
    before: impl ToString,
    after: impl ToString,
    review: bool,
) {
    let (before, after) = (
        serde_json::Value::String(before.to_string()),
        serde_json::Value::String(after.to_string()),
    );
    change_value(out, field, before, after, review);
}

fn change_value(
    out: &mut Vec<FieldChange>,
    field: impl Into<String>,
    before: serde_json::Value,
    after: serde_json::Value,
    review: bool,
) {
    if before != after {
        out.push(FieldChange {
            field: field.into(),
            before,
            after,
            review_required: review,
        });
    }
}

/// Ports as `status` prints them: `443, 8443` and `10000-10100`.
fn ports_text(ranges: &[(u16, u16)]) -> String {
    ranges
        .iter()
        .map(|&(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn exact_stamp(instant: OffsetDateTime) -> String {
    instant.format(&Rfc3339).unwrap_or_else(|_| stamp(instant))
}

/// Compare declared pass fields; this deliberately does not claim arbitrary
/// policy equivalence.
#[allow(clippy::too_many_lines)]
pub fn diff(old: &LoadedPass, new: &LoadedPass) -> DiffReport {
    let a = &old.pass;
    let b = &new.pass;
    let mut changes = Vec::new();
    change(
        &mut changes,
        "approval.owner",
        &a.approval.owner,
        &b.approval.owner,
        true,
    );
    change(
        &mut changes,
        "approval.reference",
        &a.approval.reference,
        &b.approval.reference,
        false,
    );
    change(
        &mut changes,
        "approval.operator",
        &a.approval.operator,
        &b.approval.operator,
        true,
    );
    change(
        &mut changes,
        "approval.valid_from",
        exact_stamp(a.approval.valid_from),
        exact_stamp(b.approval.valid_from),
        true,
    );
    change(
        &mut changes,
        "approval.valid_until",
        exact_stamp(a.approval.valid_until),
        exact_stamp(b.approval.valid_until),
        true,
    );
    change(
        &mut changes,
        "approval.revoked",
        a.approval.revoked,
        b.approval.revoked,
        true,
    );
    change_value(
        &mut changes,
        "approval.revoked_reason",
        serde_json::json!(a.approval.revoked_reason),
        serde_json::json!(b.approval.revoked_reason),
        true,
    );
    change(&mut changes, "name", &a.name, &b.name, false);
    let old_labels: BTreeSet<_> = a.destinations.iter().map(|d| d.label.clone()).collect();
    let new_labels: BTreeSet<_> = b.destinations.iter().map(|d| d.label.clone()).collect();
    let introduced = new_labels
        .difference(&old_labels)
        .cloned()
        .collect::<Vec<_>>();
    let removed = old_labels
        .difference(&new_labels)
        .cloned()
        .collect::<Vec<_>>();
    for label in old_labels.intersection(&new_labels) {
        let Some(x) = a.destinations.iter().find(|d| d.label == *label) else {
            continue;
        };
        let Some(y) = b.destinations.iter().find(|d| d.label == *label) else {
            continue;
        };
        let field = if x.network.is_host() && y.network.is_host() {
            "address"
        } else {
            "network"
        };
        change(
            &mut changes,
            format!("destination[{label}].{field}"),
            x.network,
            y.network,
            true,
        );
        change(
            &mut changes,
            format!("destination[{label}].protocol"),
            x.protocol,
            y.protocol,
            true,
        );
        change(
            &mut changes,
            format!("destination[{label}].ports"),
            ports_text(&x.ports.normalized_ranges()),
            ports_text(&y.ports.normalized_ranges()),
            true,
        );
        change_value(
            &mut changes,
            format!("destination[{label}].hostname"),
            serde_json::json!(x.hostname),
            serde_json::json!(y.hostname),
            false,
        );
        let mut old_names = x.names.iter().map(HostName::as_str).collect::<Vec<_>>();
        old_names.sort_unstable();
        let mut new_names = y.names.iter().map(HostName::as_str).collect::<Vec<_>>();
        new_names.sort_unstable();
        change(
            &mut changes,
            format!("destination[{label}].names"),
            old_names.join(","),
            new_names.join(","),
            true,
        );
        let sorted = |d: &crate::Destination| {
            let mut labels = d.overlap_acknowledged.clone();
            labels.sort_unstable();
            labels.join(",")
        };
        change(
            &mut changes,
            format!("destination[{label}].overlap_acknowledged"),
            sorted(x),
            sorted(y),
            true,
        );
        change(
            &mut changes,
            format!("destination[{label}].whole_network_approved"),
            x.whole_network_approved,
            y.whole_network_approved,
            true,
        );
    }
    change(
        &mut changes,
        "require_target_v1",
        a.require_target,
        b.require_target,
        true,
    );
    change(
        &mut changes,
        "required_counters_v1",
        a.required_counters.join(","),
        b.required_counters.join(","),
        true,
    );
    let counters: BTreeSet<_> = a.ceilings.keys().chain(b.ceilings.keys()).collect();
    for counter in counters {
        change_value(
            &mut changes,
            format!("ceilings.{counter}"),
            serde_json::json!(a.ceilings.get(counter)),
            serde_json::json!(b.ceilings.get(counter)),
            true,
        );
    }
    let order_changed = a
        .destinations
        .iter()
        .map(|d| &d.label)
        .filter(|l| new_labels.contains(*l))
        .ne(b
            .destinations
            .iter()
            .map(|d| &d.label)
            .filter(|l| old_labels.contains(*l)));
    let grants = |pass: &Pass, labels: &[String]| {
        labels
            .iter()
            .filter_map(|l| pass.destinations.iter().find(|d| d.label == *l))
            .map(grant)
            .collect::<Vec<_>>()
    };
    let introduced_grants = grants(b, &introduced);
    let removed_grants = grants(a, &removed);
    let old_overlaps = name_overlap_warnings(a)
        .into_iter()
        .map(|w| (w.named_label, w.unnamed_label))
        .collect::<BTreeSet<_>>();
    let name_overlap_warnings = name_overlap_warnings(b)
        .into_iter()
        .filter(|w| {
            (introduced.contains(&w.named_label) || introduced.contains(&w.unnamed_label))
                && !old_overlaps.contains(&(w.named_label.clone(), w.unnamed_label.clone()))
        })
        .collect();
    let approval_changed = a.id != b.id;
    let review_required = approval_changed
        || order_changed
        || !introduced.is_empty()
        || !removed.is_empty()
        || changes.iter().any(|c| c.review_required);
    DiffReport {
        old_pass_id: a.id.clone(),
        new_pass_id: b.id.clone(),
        old_digest: old.digest.to_string(),
        new_digest: new.digest.to_string(),
        approval_changed,
        changes,
        introduced,
        removed,
        introduced_grants,
        removed_grants,
        name_overlap_warnings,
        order_changed,
        review_required,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OverlapFinding {
    pub code: &'static str,
    pub named_label: String,
    pub unnamed_label: String,
    pub address: String,
    pub network: String,
    pub protocol: String,
    pub port: u16,
    pub port_end: u16,
    pub effective: bool,
    pub inactive_reason: Option<String>,
    /// The owner acknowledged this pair in `overlap_acknowledged`.
    pub acknowledged: bool,
}

/// One row per contiguous interval of common ports. Both lists are bounded.
#[derive(Clone, Debug, Serialize)]
pub struct LintReport {
    pub findings: Vec<OverlapFinding>,
    pub truncated: bool,
}

fn overlap_example(net: crate::Network, excluded: &BTreeSet<u32>) -> IpAddr {
    match net.addr() {
        IpAddr::V4(address) => {
            let mut candidate = u32::from(address);
            while excluded.contains(&candidate) {
                let Some(successor) = candidate.checked_add(1) else {
                    return net.addr();
                };
                if !net.contains(IpAddr::V4(successor.into())) {
                    return net.addr();
                }
                candidate = successor;
            }
            IpAddr::V4(candidate.into())
        }
        // An accepted prefix can begin inside an ISATAP interval. Skip its
        // variable low 32 bits rather than enumerating hosts.
        IpAddr::V6(address) if crate::ipv6_transition(address).is_some() => {
            let after = (u128::from(address) | u128::from(u32::MAX))
                .checked_add(1)
                .map(|n| IpAddr::V6(n.into()))
                .filter(|ip| net.contains(*ip));
            after.unwrap_or_else(|| net.addr())
        }
        address @ IpAddr::V6(_) => address,
    }
}

/// Find a concrete unnamed request in each shared network and port interval.
#[must_use]
pub fn lint(pass: &Pass, now: OffsetDateTime) -> LintReport {
    const LIMIT: usize = 256;
    let mut excluded = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    let mut rules = Vec::with_capacity(pass.destinations.len());
    for d in &pass.destinations {
        if let IpAddr::V4(addr) = d.network.addr() {
            let addr = u32::from(addr);
            let prefix = d.network.prefix();
            if prefix <= 30 {
                excluded.insert(addr);
                excluded.insert(addr | (u32::MAX >> prefix));
            } else if prefix == 32 {
                hosts.insert(addr);
            }
        }
        rules.push((d, d.ports.normalized_ranges()));
    }
    excluded.retain(|ip| !hosts.contains(ip));
    rules.sort_unstable_by(|(a, _), (b, _)| a.label.cmp(&b.label));
    let mut report = LintReport {
        findings: vec![],
        truncated: false,
    };
    for (named, left) in rules.iter().filter(|(d, _)| !d.names.is_empty()) {
        for (unnamed, right) in rules.iter().filter(|(d, _)| d.names.is_empty()) {
            if named.protocol != unnamed.protocol || !named.network.overlaps(&unnamed.network) {
                continue;
            }
            let net = if named.network.prefix() >= unnamed.network.prefix() {
                named.network
            } else {
                unnamed.network
            };
            let ip = overlap_example(net, &excluded);
            let (mut i, mut j) = (0, 0);
            while let (Some(&(a, b)), Some(&(c, d))) = (left.get(i), right.get(j)) {
                let (start, end) = (a.max(c), b.min(d));
                if start <= end {
                    if report.findings.len() == LIMIT {
                        report.truncated = true;
                        return report;
                    }
                    let target = Target {
                        ip,
                        port: start,
                        protocol: named.protocol,
                    };
                    let (effective, inactive_reason) =
                        match pass.permits(&target, now, Duration::ZERO) {
                            Decision::Allowed { .. } => (true, None),
                            Decision::Refused(reason) => {
                                (false, Some(reason.code.as_str().to_owned()))
                            }
                        };
                    report.findings.push(OverlapFinding {
                        code: "name-restriction-overlap",
                        named_label: named.label.clone(),
                        unnamed_label: unnamed.label.clone(),
                        address: ip.to_string(),
                        network: net.to_string(),
                        protocol: named.protocol.to_string(),
                        port: start,
                        port_end: end,
                        effective,
                        inactive_reason,
                        acknowledged: named.overlap_acknowledged.contains(&unnamed.label),
                    });
                }
                if b <= d {
                    i += 1;
                }
                if d <= b {
                    j += 1;
                }
            }
        }
    }
    report
}

/// The longest approval window that raises no warning: 90 days.
///
/// A written
/// authorization for a security test normally covers an engagement of days or
/// weeks; a quarter is the longest ordinary engagement, and a longer window is
/// more often a typo (`2062` for `2026`) than a plan. The owner may still
/// approve one.
pub const LONG_WINDOW_DAYS: i64 = 90;
/// How far ahead of the instant a window may open without a warning: 30 days.
pub const FAR_START_DAYS: i64 = 30;

/// A warning about an implausible approval window. Advice only: the window is
/// the owner's decision, so none of these refuses anything.
#[derive(Clone, Debug, Serialize)]
pub struct WindowWarning {
    /// `window-too-long`, `window-ended` or `window-starts-far-ahead`.
    pub code: &'static str,
    pub message: String,
}

/// Warnings about the approval window of `pass`, judged at `now` when given.
///
/// `window-too-long` needs no clock. `window-ended` and
/// `window-starts-far-ahead` need `now` and are skipped for a revoked pass,
/// which is already refused by name.
#[must_use]
pub fn window_warnings(pass: &Pass, now: Option<OffsetDateTime>) -> Vec<WindowWarning> {
    let a = &pass.approval;
    let mut out = Vec::new();
    let length = a.valid_until - a.valid_from;
    if length > Duration::days(LONG_WINDOW_DAYS) {
        out.push(WindowWarning {
            code: "window-too-long",
            message: format!(
                "the approval window is {} days long, more than the {LONG_WINDOW_DAYS} days that raise no warning; check valid_from and valid_until against the owner's written approval for a typo",
                length.whole_days()
            ),
        });
    }
    if let Some(now) = now.filter(|_| !a.revoked) {
        if now >= a.valid_until {
            out.push(WindowWarning {
                code: "window-ended",
                message: format!(
                    "the approval window ended at {} and every request is refused as expired; check valid_until, or get a new written approval",
                    exact_stamp(a.valid_until)
                ),
            });
        } else if a.valid_from - now > Duration::days(FAR_START_DAYS) {
            out.push(WindowWarning {
                code: "window-starts-far-ahead",
                message: format!(
                    "the approval window opens at {}, {} days after now, more than the {FAR_START_DAYS} days that raise no warning; check valid_from for a typo",
                    exact_stamp(a.valid_from),
                    (a.valid_from - now).whole_days()
                ),
            });
        }
    }
    out
}

/// One pair of destinations where a nameless rule defeats a `names` list.
#[derive(Clone, Debug, Serialize)]
pub struct NameOverlapWarning {
    /// `name-restriction-overlap`, or `overlap-acknowledgement-unmatched`
    /// for an acknowledgement in the pass that names no overlap.
    pub code: &'static str,
    pub named_label: String,
    pub unnamed_label: String,
    /// The owner wrote this pair in `overlap_acknowledged`. Advice only: the
    /// overlap still exists and decisions are unchanged.
    pub acknowledged: bool,
    pub message: String,
}

/// Advice for `check`, `status` and `diff` about name-restriction overlaps.
///
/// One entry per pair that `lint` reports as `name-restriction-overlap`, and
/// one for each acknowledgement (`overlap_acknowledged`) whose pair does not
/// overlap. The pass stays valid; the names list may have no effect for the shared addresses. An
/// acknowledged pair is still listed, marked `acknowledged`, so a command can
/// show it as a note and `check` and `lint` can keep showing it in full.
#[must_use]
pub fn name_overlap_warnings(pass: &Pass) -> Vec<NameOverlapWarning> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let report = lint(pass, pass.approval.valid_from);
    for f in report.findings {
        if !seen.insert((f.named_label.clone(), f.unnamed_label.clone())) {
            continue;
        }
        let acknowledged = f.acknowledged;
        let mut message = format!(
            "destination `{}` restricts names, but destination `{}` allows the same addresses and ports without names, so the names list may have no effect there; run `hallpass lint` for details",
            f.named_label, f.unnamed_label
        );
        if acknowledged {
            message.push_str(
                "; the owner acknowledged this overlap in the pass (`overlap_acknowledged`), and it still applies",
            );
        }
        out.push(NameOverlapWarning {
            code: f.code,
            named_label: f.named_label,
            unnamed_label: f.unnamed_label,
            acknowledged,
            message,
        });
    }
    // With the list cut short, a missing pair proves nothing.
    if !report.truncated {
        for d in &pass.destinations {
            for label in &d.overlap_acknowledged {
                if seen.contains(&(d.label.clone(), label.clone())) {
                    continue;
                }
                out.push(NameOverlapWarning {
                    code: "overlap-acknowledgement-unmatched",
                    named_label: d.label.clone(),
                    unnamed_label: label.clone(),
                    acknowledged: false,
                    message: format!(
                        "destination `{}` acknowledges an overlap with `{label}`, but the two share no address, protocol and port, so the acknowledgement covers nothing; remove it from `overlap_acknowledged`",
                        d.label
                    ),
                });
            }
        }
    }
    out
}

#[derive(Clone, Debug, Serialize)]
pub struct Breadth {
    pub ipv4: String,
    pub ipv6: String,
}

/// Derive the stable format-1 approval identifier from its written identity.
///
/// `owner` and `reference` are checked first, as `approval.owner` and
/// `approval.reference` of a pass are checked when it loads, so an id is
/// only given for an owner and reference that a pass can hold.
///
/// # Errors
///
/// Every problem with `owner` or `reference`, with its field
/// (`approval.owner` or `approval.reference`) and the message
/// [`Pass::parse`] gives for it: empty, longer than 200 characters, leading
/// or trailing spaces, a control character, or a character that can make
/// text display as something else (a line separator, a Unicode format
/// character, another invisible character or a space other than the ASCII
/// space), named with its code point.
pub fn approval_id(owner: &str, reference: &str) -> Result<String, Vec<Problem>> {
    let problems = crate::pass::approval_identity_problems(owner, reference);
    if !problems.is_empty() {
        return Err(problems);
    }
    let mut h = Sha256::new();
    h.update(b"hallpass/approval/v1\0");
    h.update(owner.as_bytes());
    h.update([0]);
    h.update(reference.as_bytes());
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(format!("hp1-{}", &hex[..52]))
}
#[must_use]
pub fn breadth(pass: &Pass) -> Breadth {
    fn total(pass: &Pass, v6: bool) -> u128 {
        let mut ranges: Vec<(u128, u128)> = pass
            .destinations
            .iter()
            .filter(|d| d.network.addr().is_ipv6() == v6)
            .map(|d| {
                let n = d.network;
                let width = if v6 { 128 } else { 32 };
                let start = match n.addr() {
                    IpAddr::V4(a) => u128::from(u32::from(a)),
                    IpAddr::V6(a) => u128::from(a),
                };
                let size = 1u128 << (width - u32::from(n.prefix()));
                (start, start + size - 1)
            })
            .collect();
        ranges.sort_unstable();
        let mut sum = 0;
        let mut current: Option<(u128, u128)> = None;
        for (a, b) in ranges {
            if let Some((x, y)) = current {
                if a <= y + 1 {
                    current = Some((x, y.max(b)));
                } else {
                    sum += y - x + 1;
                    current = Some((a, b));
                }
            } else {
                current = Some((a, b));
            }
        }
        if let Some((a, b)) = current {
            sum += b - a + 1;
        }
        sum
    }
    Breadth {
        ipv4: total(pass, false).to_string(),
        ipv6: total(pass, true).to_string(),
    }
}

#[must_use]
pub fn breadth_warnings(b: &Breadth) -> Vec<String> {
    let mut out = Vec::new();
    if b.ipv4.parse::<u128>().map_or(true, |n| n > (1u128 << 24)) {
        out.push("declared IPv4 breadth exceeds the one /8 consumer comparison point".to_owned());
    }
    if b.ipv6.parse::<u128>().map_or(true, |n| n > (1u128 << 64)) {
        out.push("declared IPv6 breadth exceeds the one /64 consumer comparison point".to_owned());
    }
    out
}

/// Small, strict case-suite parser used by the CLI.
/// # Errors
///
/// Returns an error for malformed TOML, unknown fields, duplicate IDs, or an
/// invalid target, timestamp, duration, or expected decision code.
#[derive(Clone)]
struct ReviewCase {
    id: String,
    expected: String,
    target: Target,
    name: Option<HostName>,
    now: OffsetDateTime,
    duration: u32,
}

fn parse_cases(text: &str) -> Result<Vec<ReviewCase>, String> {
    const CODES: &[&str] = &[
        "allowed",
        "not-yet-valid",
        "expired",
        "revoked",
        "window-too-short",
        "embedded-ipv4",
        "network-or-broadcast",
        "address-not-listed",
        "port-not-listed",
        "name-required",
        "name-not-listed",
        "unknown-counter",
        "ceiling-reached",
        "pass-changed",
    ];
    if text.len() > 256 * 1024 {
        return Err("case suite exceeds 256 KiB".into());
    }
    let root: toml::Table = text.parse().map_err(|e: toml::de::Error| e.to_string())?;
    match root.get("version") {
        Some(Value::Integer(1)) => {}
        Some(_) => return Err("suite.version must be integer 1".into()),
        None => return Err("suite.version missing; write version = 1".into()),
    }
    for key in root.keys() {
        if key != "version" && key != "case" {
            return Err(format!("unknown suite key `{key}`"));
        }
    }
    let arr = root
        .get("case")
        .and_then(Value::as_array)
        .ok_or("missing [[case]]")?;
    if arr.is_empty() || arr.len() > 1024 {
        return Err("case suite must contain 1..1024 cases".into());
    }
    let mut ids = BTreeSet::new();
    let mut out = Vec::new();
    for item in arr {
        let t = item.as_table().ok_or("case must be a table")?;
        for key in t.keys() {
            if !["id", "at", "to", "name", "duration", "expected"].contains(&key.as_str()) {
                return Err(format!("unknown case key `{key}`"));
            }
        }
        let id = t
            .get("id")
            .and_then(Value::as_str)
            .ok_or("case.id missing")?;
        if id.trim().is_empty() || id.chars().any(char::is_control) {
            return Err("case.id must be non-empty printable text".into());
        }
        if !ids.insert(id) {
            return Err(format!("duplicate case id `{id}`"));
        }
        let to = t
            .get("to")
            .and_then(Value::as_str)
            .ok_or("case.to missing")?;
        let target: Target = to.parse()?;
        let name = match t.get("name") {
            None => None,
            Some(Value::String(s)) => Some(s.parse()?),
            Some(_) => return Err("case.name must be a string".into()),
        };
        let at = t
            .get("at")
            .and_then(Value::as_str)
            .ok_or("case.at missing")?;
        let now = OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
            .map_err(|e| e.to_string())?;
        let duration = t.get("duration").map_or(Ok(0i64), |v| {
            v.as_integer().ok_or("case.duration must be an integer")
        })?;
        if duration < 0 {
            return Err("case.duration must be non-negative".into());
        }
        let duration = u32::try_from(duration).map_err(|_| "case.duration is too large")?;
        let expected = t
            .get("expected")
            .and_then(Value::as_str)
            .ok_or("case.expected missing")?;
        if !CODES.contains(&expected) {
            return Err(format!(
                "case.expected `{expected}` is not a stable decision code"
            ));
        }
        out.push(ReviewCase {
            id: id.to_owned(),
            expected: expected.to_owned(),
            target,
            name,
            now,
            duration,
        });
    }
    Ok(out)
}

fn evaluate_cases(pass: &Pass, cases: &[ReviewCase]) -> Vec<serde_json::Value> {
    cases
        .iter()
        .map(|case| {
            let actual = match pass.permits_named(
                &case.target,
                case.name.as_ref(),
                case.now,
                Duration::seconds(i64::from(case.duration)),
            ) {
            Decision::Allowed { .. } => "allowed".to_owned(),
            Decision::Refused(r) => r.code.as_str().to_owned(),
            };
            serde_json::json!({"id":case.id,"expected":case.expected,"actual":actual,"duration":case.duration,"match":case.expected==actual})
        })
        .collect()
}

/// Evaluate a validated suite against one pass using the ordinary decision
/// engine.
///
/// # Errors
///
/// If the suite is malformed or contains invalid cases.
pub fn cases(pass: &Pass, text: &str) -> Result<Vec<serde_json::Value>, String> {
    Ok(evaluate_cases(pass, &parse_cases(text)?))
}

/// Run an owner's suite against the real pass and bounded in-memory policy
/// mutations. Survivors identify changes the suite did not distinguish.
///
/// # Errors
///
/// If the suite is malformed or contains invalid cases.
pub fn mutation_strength(pass: &Pass, text: &str) -> Result<serde_json::Value, String> {
    cases_with_strength(pass, text).map(|(_, report)| report)
}

/// Return the ordinary case results and strength report from one suite evaluation.
///
/// # Errors
/// Returns a diagnostic for invalid suite input.
pub fn cases_with_strength(
    pass: &Pass,
    text: &str,
) -> Result<(Vec<serde_json::Value>, serde_json::Value), String> {
    let parsed = parse_cases(text)?;
    let baseline = evaluate_cases(pass, &parsed);
    let report = strength_report(pass, &parsed, &baseline)?;
    Ok((baseline, report))
}

/// The network one bit wider, when that change only loosens the pass and
/// still validates. The error says why the mutation was skipped.
fn widened(destination: &crate::Destination) -> Result<crate::Network, String> {
    let net = destination.network;
    let Some(prefix) = net.prefix().checked_sub(1) else {
        return Err("the network already covers every address".to_owned());
    };
    let (cap, floor) = match net.addr() {
        IpAddr::V4(_) => (crate::pass::IPV4_CAP, crate::pass::IPV4_FLOOR),
        IpAddr::V6(_) => (crate::pass::IPV6_CAP, crate::pass::IPV6_FLOOR),
    };
    if prefix < floor {
        return Err(format!(
            "/{prefix} is broader than /{floor}, the widest network a pass accepts"
        ));
    }
    if prefix < cap && !destination.whole_network_approved {
        return Err(format!(
            "/{prefix} is broader than the /{cap} breadth cap and the destination has no whole_network_approved"
        ));
    }
    if net.addr().is_ipv4() && net.prefix() == 31 {
        return Err("a /30 does not treat its first and last addresses as hosts, so it would not only loosen".to_owned());
    }
    let base = match net.addr() {
        IpAddr::V4(a) => {
            let mask = u32::MAX << (32 - u32::from(prefix));
            IpAddr::V4((u32::from(a) & mask).into())
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX << (128 - u32::from(prefix));
            IpAddr::V6((u128::from(a) & mask).into())
        }
    };
    crate::address::parse_network(&format!("{base}/{prefix}")).map_err(|e| e.to_string())
}

#[allow(clippy::too_many_lines)]
fn strength_report(
    pass: &Pass,
    parsed: &[ReviewCase],
    baseline: &[serde_json::Value],
) -> Result<serde_json::Value, String> {
    const MAX_MUTATIONS: usize = 64;
    const MAX_EVALUATIONS: usize = 4_096;

    #[derive(Clone)]
    enum Edit {
        RemoveNames {
            index: usize,
        },
        AddPort {
            index: usize,
            port: u16,
        },
        Widen {
            index: usize,
            network: crate::Network,
        },
        OtherTransport {
            index: usize,
            label: String,
        },
        ValidFrom(OffsetDateTime),
        ValidUntil(OffsetDateTime),
    }
    struct Candidate {
        label: String,
        changed_term: String,
        edit: Edit,
    }
    fn push_candidate(candidates: &mut Vec<Candidate>, candidate: Candidate, limit: usize) -> bool {
        if candidates.len() == limit {
            true
        } else {
            candidates.push(candidate);
            false
        }
    }
    let baseline_failed = baseline.iter().any(|row| row["match"] != true);
    if baseline_failed {
        return Ok(serde_json::json!({
            "result": "baseline-failed",
            "baseline": "failed",
            "baseline_cases": baseline.len(),
            "baseline_mismatches": baseline.iter().filter(|row| row["match"] != true).count(),
            "mutations_tested": 0,
            "mutations_survived": 0,
            "evaluations": baseline.len(),
            "truncated": false,
            "mutations": [],
            "note": "Mutation analysis requires a passing baseline suite."
        }));
    }
    let mut candidates = Vec::new();
    // Mutations that cannot be run: (label, changed term, reason). Reported as
    // skipped, never as survived.
    let mut skipped: Vec<(String, String, String)> = Vec::new();
    let mut candidate_overflow = false;
    for (index, destination) in pass.destinations.iter().enumerate() {
        if !destination.names.is_empty() {
            let before = destination
                .names
                .iter()
                .map(HostName::as_str)
                .collect::<Vec<_>>()
                .join(",");
            candidate_overflow = push_candidate(
                &mut candidates,
                Candidate {
                    label: destination.label.clone(),
                    changed_term: format!(
                        "destination[{}].names: [{before}] -> []",
                        destination.label
                    ),
                    edit: Edit::RemoveNames { index },
                },
                MAX_MUTATIONS,
            );
            if candidate_overflow {
                break;
            }
        }
        let ranges = destination.ports.normalized_ranges();
        let mut adjacent_ports = BTreeSet::new();
        for &(start, end) in &ranges {
            for (port, side) in [
                (start.checked_sub(1).filter(|port| *port > 0), "lower"),
                (end.checked_add(1), "upper"),
            ] {
                let Some(port) = port else { continue };
                if !adjacent_ports.insert(port) {
                    continue;
                }
                candidate_overflow = push_candidate(
                    &mut candidates,
                    Candidate {
                        label: destination.label.clone(),
                        changed_term: format!(
                            "destination[{}].ports: add adjacent port {port} ({side} endpoint)",
                            destination.label
                        ),
                        edit: Edit::AddPort { index, port },
                    },
                    MAX_MUTATIONS,
                );
                if candidate_overflow {
                    break;
                }
            }
            if candidate_overflow {
                break;
            }
        }
        if candidate_overflow {
            break;
        }
        let kind = if destination.network.is_host() {
            "address"
        } else {
            "network"
        };
        match widened(destination) {
            Ok(network) => {
                candidate_overflow = push_candidate(
                    &mut candidates,
                    Candidate {
                        label: destination.label.clone(),
                        changed_term: format!(
                            "destination[{}].{kind}: widen {} to {network}",
                            destination.label, destination.network
                        ),
                        edit: Edit::Widen { index, network },
                    },
                    MAX_MUTATIONS,
                );
            }
            Err(reason) => skipped.push((
                destination.label.clone(),
                format!(
                    "destination[{}].{kind}: widen by one bit",
                    destination.label
                ),
                reason,
            )),
        }
        if candidate_overflow {
            break;
        }
        let other = match destination.protocol {
            crate::Protocol::Tcp => crate::Protocol::Udp,
            crate::Protocol::Udp => crate::Protocol::Tcp,
        };
        let extra = format!("{}-{other}", destination.label);
        if pass.destinations.iter().any(|d| d.label == extra) {
            skipped.push((
                destination.label.clone(),
                format!(
                    "destination[{}].protocol: also allow {other}",
                    destination.label
                ),
                format!("the added destination label `{extra}` is already used"),
            ));
        } else {
            candidate_overflow = push_candidate(
                &mut candidates,
                Candidate {
                    label: destination.label.clone(),
                    changed_term: format!(
                        "destination[{}].protocol: also allow {other}",
                        destination.label
                    ),
                    edit: Edit::OtherTransport {
                        index,
                        label: extra,
                    },
                },
                MAX_MUTATIONS,
            );
        }
        if candidate_overflow {
            break;
        }
    }
    if !candidate_overflow {
        let step = Duration::SECOND;
        let window = [
            (
                "approval.valid_from: one second earlier",
                pass.approval.valid_from.checked_sub(step),
                true,
            ),
            (
                "approval.valid_until: one second later",
                pass.approval.valid_until.checked_add(step),
                false,
            ),
        ];
        for (term, moved, from) in window {
            match moved.and_then(crate::decision::in_utc) {
                Some(instant) => {
                    candidate_overflow = push_candidate(
                        &mut candidates,
                        Candidate {
                            label: "approval".to_owned(),
                            changed_term: term.to_owned(),
                            edit: if from {
                                Edit::ValidFrom(instant)
                            } else {
                                Edit::ValidUntil(instant)
                            },
                        },
                        MAX_MUTATIONS,
                    );
                }
                None => skipped.push((
                    "approval".to_owned(),
                    term.to_owned(),
                    "the moved instant is outside the years 0001 to 9999 in UTC".to_owned(),
                )),
            }
            if candidate_overflow {
                break;
            }
        }
    }
    for name in pass.ceilings.keys() {
        skipped.push((
            "ceilings".to_owned(),
            format!("ceilings.{name}: raise"),
            "a case cannot spend, so a ceiling change cannot change any case result".to_owned(),
        ));
    }
    let mut evaluations = baseline.len();
    let mut reports = Vec::new();
    for candidate in &candidates {
        if evaluations.saturating_add(parsed.len()) > MAX_EVALUATIONS {
            candidate_overflow = true;
            break;
        }
        let mut mutated = pass.clone();
        match &candidate.edit {
            Edit::RemoveNames { index } => mutated.destinations[*index].names.clear(),
            Edit::AddPort { index, port } => {
                let mut ranges = mutated.destinations[*index].ports.normalized_ranges();
                ranges.push((*port, *port));
                mutated.destinations[*index].ports = crate::PortSet::from_ranges(ranges)
                    .map_err(|error| format!("cannot apply adjacent port mutation: {error}"))?;
            }
            Edit::Widen { index, network } => mutated.destinations[*index].network = *network,
            Edit::OtherTransport { index, label } => {
                let mut extra = mutated.destinations[*index].clone();
                extra.protocol = match extra.protocol {
                    crate::Protocol::Tcp => crate::Protocol::Udp,
                    crate::Protocol::Udp => crate::Protocol::Tcp,
                };
                extra.label.clone_from(label);
                mutated.destinations.push(extra);
            }
            Edit::ValidFrom(instant) => mutated.approval.valid_from = *instant,
            Edit::ValidUntil(instant) => mutated.approval.valid_until = *instant,
        }
        let changed = evaluate_cases(&mutated, parsed);
        evaluations += changed.len();
        let first = baseline.iter().zip(&changed).find_map(|(before, after)| {
            (before["actual"] != after["actual"]).then(|| {
                serde_json::json!({"id":before["id"],"baseline":before["actual"],"mutated":after["actual"]})
            })
        });
        reports.push(serde_json::json!({
            "label": candidate.label,
            "changed_term": candidate.changed_term,
            "status": if first.is_some() { "distinguished" } else { "survived" },
            "first_distinguishing_case": first,
        }));
    }
    let tested = reports.len();
    let truncated = candidate_overflow || tested < candidates.len();
    for (label, changed_term, reason) in &skipped {
        reports.push(serde_json::json!({
            "label": label,
            "changed_term": changed_term,
            "status": "skipped",
            "reason": reason,
            "first_distinguishing_case": null,
        }));
    }
    let survivors = reports
        .iter()
        .filter(|row| row["status"] == "survived")
        .count();
    let status = if truncated {
        "partial"
    } else if survivors > 0 {
        "surviving-mutations"
    } else {
        "complete"
    };
    Ok(serde_json::json!({
        "result": status,
        "baseline": if baseline_failed { "failed" } else { "passed" },
        "baseline_cases": baseline.len(),
        "baseline_mismatches": baseline.iter().filter(|row| row["match"] != true).count(),
        "mutations_tested": tested,
        "mutations_survived": survivors,
        "mutations_skipped": skipped.len(),
        "evaluations": evaluations,
        "truncated": truncated,
        "mutations": reports,
        "note": "A surviving mutation is a review prompt; never alter the approval to make a suite pass."
    }))
}
