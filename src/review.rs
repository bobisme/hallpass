//! Read-only approval review helpers. These intentionally make no ledger or
//! authorization changes: review output is evidence for an owner, never a
//! permission to spend.
use crate::{Decision, HostName, LoadedPass, Pass, Target, stamp};
use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use toml::Value;

#[derive(Clone, Debug, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub before: String,
    pub after: String,
    pub review_required: bool,
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
    pub order_changed: bool,
    pub review_required: bool,
}

#[allow(clippy::needless_pass_by_value)]
fn change(
    out: &mut Vec<FieldChange>,
    field: impl Into<String>,
    before: impl ToString,
    after: impl ToString,
    review: bool,
) {
    let (before, after) = (before.to_string(), after.to_string());
    if before != after {
        out.push(FieldChange {
            field: field.into(),
            before,
            after,
            review_required: review,
        });
    }
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
    change(
        &mut changes,
        "approval.revoked_reason",
        format!("{:?}", a.approval.revoked_reason),
        format!("{:?}", b.approval.revoked_reason),
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
        change(
            &mut changes,
            format!("destination[{label}].address"),
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
            x.ports
                .normalized_ranges()
                .iter()
                .map(|r| format!("{}-{}", r.0, r.1))
                .collect::<Vec<_>>()
                .join(","),
            y.ports
                .normalized_ranges()
                .iter()
                .map(|r| format!("{}-{}", r.0, r.1))
                .collect::<Vec<_>>()
                .join(","),
            true,
        );
        change(
            &mut changes,
            format!("destination[{label}].hostname"),
            format!("{:?}", x.hostname),
            format!("{:?}", y.hostname),
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
        change(
            &mut changes,
            format!("destination[{label}].whole_network_approved"),
            x.whole_network_approved,
            y.whole_network_approved,
            true,
        );
    }
    let counters: BTreeSet<_> = a.ceilings.keys().chain(b.ceilings.keys()).collect();
    for counter in counters {
        change(
            &mut changes,
            format!("ceilings.{counter}"),
            format!("{:?}", a.ceilings.get(counter)),
            format!("{:?}", b.ceilings.get(counter)),
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

#[derive(Clone, Debug, Serialize)]
pub struct Breadth {
    pub ipv4: String,
    pub ipv6: String,
}

/// Derive the stable format-1 approval identifier from its written identity.
#[must_use]
pub fn approval_id(owner: &str, reference: &str) -> String {
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
    format!("hp1-{}", &hex[..52])
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
pub fn cases(pass: &Pass, text: &str) -> Result<Vec<serde_json::Value>, String> {
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
        let actual = match pass.permits_named(
            &target,
            name.as_ref(),
            now,
            Duration::seconds(i64::from(duration)),
        ) {
            Decision::Allowed { .. } => "allowed".to_owned(),
            Decision::Refused(r) => r.code.as_str().to_owned(),
        };
        out.push(serde_json::json!({"id":id,"expected":expected,"actual":actual,"duration":duration,"match":expected==actual}));
    }
    Ok(out)
}
