//! The pass file: parsing and validation.
//!
//! [`Pass::parse`] reads the TOML text and checks every rule in
//! `docs/PASS-FORMAT.md`. It reports every problem it finds, each with the
//! field path and what to do, rather than stopping at the first.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
use toml::{Table, Value};

use crate::address::{Network, Protocol, parse_address, parse_network};
use crate::ports::PortSet;

/// The one pass format version this library reads.
pub const FORMAT_VERSION: i64 = 1;

/// The breadth cap for IPv4: a network with a shorter prefix (more
/// addresses than a /24) needs `whole_network_approved = true`.
pub const IPV4_CAP: u8 = 24;
/// The breadth cap for IPv6: a network broader than one /64 subnet needs
/// `whole_network_approved = true`.
pub const IPV6_CAP: u8 = 64;
/// No IPv4 network broader than a /8 is accepted, even when approved.
pub const IPV4_FLOOR: u8 = 8;
/// No IPv6 network broader than a /32 is accepted, even when approved.
pub const IPV6_FLOOR: u8 = 32;
/// The largest ceiling total (10^12), so totals and sums stay exact.
pub const MAX_CEILING: u64 = 1_000_000_000_000;
/// The most counters one pass may define.
pub const MAX_COUNTERS: usize = 64;
/// The most destinations one pass may list.
pub const MAX_DESTINATIONS: usize = 1024;

/// One thing wrong with a pass file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Problem {
    /// Where: a dotted path such as `approval.valid_until` or
    /// `destination[2].address` (destinations count from 1).
    pub field: String,
    /// What is wrong and what to do about it.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Who approved the test, the written reference, and the window.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Approval {
    /// Who approved (the owner of the destinations).
    pub owner: String,
    /// Where the written approval is (free text, such as "email of DATE").
    pub reference: String,
    /// Who runs the test.
    pub operator: String,
    /// The first instant the pass is valid (inclusive).
    pub valid_from: OffsetDateTime,
    /// The instant the pass stops being valid (exclusive).
    pub valid_until: OffsetDateTime,
    /// True when the owner withdrew the approval.
    pub revoked: bool,
    /// Why, when the pass is revoked and the reason was recorded.
    pub revoked_reason: Option<String>,
}

/// One allowed destination: a literal address or network, a protocol and
/// ports.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Destination {
    /// A short unique label, named in every decision.
    pub label: String,
    /// The literal address (a single-host network) or the CIDR network.
    pub network: Network,
    /// The transport protocol.
    pub protocol: Protocol,
    /// The allowed ports.
    pub ports: PortSet,
    /// What the owner calls it. Informational only: it grants nothing.
    pub hostname: Option<String>,
    /// The owner approved the whole network beyond the breadth cap.
    pub whole_network_approved: bool,
}

/// A validated pass.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pass {
    /// The pass id; the ledger belongs to it.
    pub id: String,
    /// A short human name.
    pub name: String,
    /// The approval and its window.
    pub approval: Approval,
    /// The allowed destinations, in file order.
    pub destinations: Vec<Destination>,
    /// Named ceilings: counter name to total.
    pub ceilings: BTreeMap<String, u64>,
}

struct Walker {
    problems: Vec<Problem>,
}

impl Walker {
    fn problem(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem {
            field: field.into(),
            message: message.into(),
        });
    }

    fn unknown_keys(&mut self, table: &Table, prefix: &str, allowed: &[&str]) {
        for key in table.keys() {
            if !allowed.contains(&key.as_str()) {
                self.problem(
                    join(prefix, key),
                    format!(
                        "unknown key `{key}`; a typo could drop a restriction, so unknown keys are refused. Allowed here: {}",
                        allowed.join(", ")
                    ),
                );
            }
        }
    }

    fn text(&mut self, table: &Table, prefix: &str, key: &str, max: usize) -> Option<String> {
        let field = join(prefix, key);
        let Some(value) = table.get(key) else {
            self.problem(field, format!("missing; add `{key} = \"...\"`"));
            return None;
        };
        self.text_value(value, &field, max)
    }

    fn text_value(&mut self, value: &Value, field: &str, max: usize) -> Option<String> {
        let Some(text) = value.as_str() else {
            self.problem(
                field,
                format!("must be a quoted string, not {}", kind(value)),
            );
            return None;
        };
        match check_text(text, max) {
            Ok(()) => Some(text.to_owned()),
            Err(message) => {
                self.problem(field, message);
                None
            }
        }
    }

    fn instant(&mut self, table: &Table, prefix: &str, key: &str) -> Option<OffsetDateTime> {
        let field = join(prefix, key);
        let example = "for example 2026-11-20T08:00:00Z or 2026-11-20T09:00:00+01:00";
        let Some(value) = table.get(key) else {
            self.problem(field, format!("missing; add `{key} = ...`, {example}"));
            return None;
        };
        let parsed = match value {
            Value::Datetime(dt) => from_toml_datetime(dt),
            Value::String(text) if text.is_empty() => Err(format!(
                "is empty; write the timestamp from the written approval, {example}"
            )),
            Value::String(text) => OffsetDateTime::parse(text, &Rfc3339).map_err(|_| {
                format!("`{text}` is not an RFC 3339 timestamp with an explicit offset ({example})")
            }),
            other => Err(format!(
                "must be a timestamp ({example}), not {}",
                kind(other)
            )),
        };
        match parsed {
            Ok(instant) => Some(instant),
            Err(message) => {
                self.problem(field, message);
                None
            }
        }
    }
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

const fn kind(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "a string",
        Value::Integer(_) => "an integer",
        Value::Float(_) => "a number with a fraction",
        Value::Boolean(_) => "true/false",
        Value::Datetime(_) => "a date/time",
        Value::Array(_) => "a list",
        Value::Table(_) => "a table",
    }
}

/// Free text: printable, no surrounding spaces, 1 to `max` characters.
fn check_text(text: &str, max: usize) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("is empty; fill it in".to_owned());
    }
    if text.chars().any(char::is_control) {
        return Err(
            "contains a control character (such as a newline or tab); write one plain line"
                .to_owned(),
        );
    }
    if text.trim() != text {
        return Err("has leading or trailing spaces; remove them".to_owned());
    }
    if text.chars().count() > max {
        return Err(format!("is longer than {max} characters; shorten it"));
    }
    Ok(())
}

/// An identifier: `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && text.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A counter name: `[a-z][a-z0-9_-]{0,31}`.
#[must_use]
pub fn is_counter_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && text.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

fn from_toml_datetime(dt: &toml::value::Datetime) -> Result<OffsetDateTime, String> {
    let (Some(d), Some(t)) = (dt.date, dt.time) else {
        return Err(format!(
            "`{dt}` is not a full date and time; write for example 2026-11-20T08:00:00Z"
        ));
    };
    let Some(offset) = dt.offset else {
        return Err(format!(
            "`{dt}` has no offset, so its instant depends on the reader's time zone; add one, for example {dt}Z or {dt}+01:00"
        ));
    };
    let bad = || format!("`{dt}` is not a valid date and time");
    let month = Month::try_from(d.month).map_err(|_| bad())?;
    let date = Date::from_calendar_date(i32::from(d.year), month, d.day).map_err(|_| bad())?;
    let time = Time::from_hms_nano(
        t.hour,
        t.minute,
        t.second.unwrap_or(0),
        t.nanosecond.unwrap_or(0),
    )
    .map_err(|_| bad())?;
    let offset = match offset {
        toml::value::Offset::Z => UtcOffset::UTC,
        toml::value::Offset::Custom { minutes } => {
            UtcOffset::from_whole_seconds(i32::from(minutes) * 60).map_err(|_| bad())?
        }
    };
    Ok(PrimitiveDateTime::new(date, time).assume_offset(offset))
}

impl Pass {
    /// Parse and validate a pass from its TOML text.
    ///
    /// # Errors
    ///
    /// Every problem found, each with its field path. A TOML syntax error is
    /// reported alone, since nothing else can be read.
    pub fn parse(text: &str) -> Result<Self, Vec<Problem>> {
        let table: Table = text.parse().map_err(|e: toml::de::Error| {
            vec![Problem {
                field: "(file)".to_owned(),
                message: format!(
                    "the file is not valid TOML: {}; fix the syntax",
                    e.message().trim()
                ),
            }]
        })?;
        let mut w = Walker {
            problems: Vec::new(),
        };
        w.unknown_keys(
            &table,
            "",
            &[
                "format",
                "id",
                "name",
                "approval",
                "destination",
                "ceilings",
            ],
        );
        match table.get("format") {
            None => w.problem("format", format!("missing; add `format = {FORMAT_VERSION}`")),
            Some(Value::Integer(FORMAT_VERSION)) => {}
            Some(other) => w.problem(
                "format",
                format!(
                    "is {other}, but this hallpass reads format {FORMAT_VERSION}; write `format = {FORMAT_VERSION}` or use a hallpass that reads this format"
                ),
            ),
        }
        let id = w.text(&table, "", "id", 64);
        if let Some(id_text) = &id
            && !is_identifier(id_text)
        {
            w.problem(
                "id",
                "must be 1-64 letters, digits, `.`, `_` or `-`, starting with a letter or digit",
            );
        }
        let name = w.text(&table, "", "name", 80);
        let approval = parse_approval(&mut w, &table);
        let destinations = parse_destinations(&mut w, &table);
        let ceilings = parse_ceilings(&mut w, &table);
        if !w.problems.is_empty() {
            return Err(w.problems);
        }
        match (id, name, approval, destinations, ceilings) {
            (Some(id), Some(name), Some(approval), Some(destinations), Some(ceilings)) => {
                Ok(Self {
                    id,
                    name,
                    approval,
                    destinations,
                    ceilings,
                })
            }
            _ => Err(vec![Problem {
                field: "(file)".to_owned(),
                message: "the pass is incomplete".to_owned(),
            }]),
        }
    }

    /// The first destination entry that allows `ip`, `port` and `protocol`.
    #[must_use]
    pub fn destination_for(
        &self,
        ip: IpAddr,
        port: u16,
        protocol: Protocol,
    ) -> Option<&Destination> {
        self.destinations
            .iter()
            .find(|d| d.network.contains(ip) && d.protocol == protocol && d.ports.contains(port))
    }
}

fn sub_table<'a>(w: &mut Walker, table: &'a Table, key: &str, example: &str) -> Option<&'a Table> {
    match table.get(key) {
        None => {
            w.problem(key, format!("missing; add a `[{key}]` section{example}"));
            None
        }
        Some(Value::Table(t)) => Some(t),
        Some(other) => {
            w.problem(
                key,
                format!("must be a `[{key}]` section, not {}", kind(other)),
            );
            None
        }
    }
}

fn parse_approval(w: &mut Walker, table: &Table) -> Option<Approval> {
    let t = sub_table(w, table, "approval", "")?;
    let p = "approval";
    w.unknown_keys(
        t,
        p,
        &[
            "owner",
            "reference",
            "operator",
            "valid_from",
            "valid_until",
            "revoked",
            "revoked_reason",
        ],
    );
    let owner = w.text(t, p, "owner", 200);
    let reference = w.text(t, p, "reference", 200);
    let operator = w.text(t, p, "operator", 200);
    let valid_from = w.instant(t, p, "valid_from");
    let valid_until = w.instant(t, p, "valid_until");
    if let (Some(from), Some(until)) = (valid_from, valid_until)
        && from >= until
    {
        w.problem(
            "approval.valid_until",
            "is not later than valid_from; the window must start before it ends: check both against the written approval",
        );
    }
    let revoked = match t.get("revoked") {
        Some(Value::Boolean(b)) => Some(*b),
        None => {
            w.problem(
                "approval.revoked",
                "missing; write `revoked = false` (or `true` when the owner has withdrawn the approval)",
            );
            None
        }
        Some(other) => {
            w.problem(
                "approval.revoked",
                format!("must be true or false, not {}", kind(other)),
            );
            None
        }
    };
    let revoked_reason = t.get("revoked_reason").and_then(|value| {
        let reason = w.text_value(value, "approval.revoked_reason", 500);
        if revoked == Some(false) {
            w.problem(
                "approval.revoked_reason",
                "is set but revoked = false; set `revoked = true` to revoke, or remove the reason",
            );
        }
        reason
    });
    Some(Approval {
        owner: owner?,
        reference: reference?,
        operator: operator?,
        valid_from: valid_from?,
        valid_until: valid_until?,
        revoked: revoked?,
        revoked_reason,
    })
}

fn parse_destinations(w: &mut Walker, table: &Table) -> Option<Vec<Destination>> {
    let entries = match table.get("destination") {
        None => {
            w.problem(
                "destination",
                "no destinations; add one `[[destination]]` section for each literal address or network the owner approved",
            );
            return None;
        }
        Some(Value::Array(items)) => items,
        Some(other) => {
            w.problem(
                "destination",
                format!(
                    "must be a list of `[[destination]]` sections, not {}",
                    kind(other)
                ),
            );
            return None;
        }
    };
    if entries.is_empty() {
        w.problem(
            "destination",
            "the list is empty; add at least one `[[destination]]`",
        );
        return None;
    }
    if entries.len() > MAX_DESTINATIONS {
        w.problem(
            "destination",
            format!("more than {MAX_DESTINATIONS} entries; use networks or split the pass"),
        );
        return None;
    }
    let mut out = Vec::new();
    let mut complete = true;
    let mut labels: BTreeMap<String, usize> = BTreeMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let prefix = format!("destination[{}]", i + 1);
        let Value::Table(t) = entry else {
            w.problem(&prefix, "must be a `[[destination]]` section");
            complete = false;
            continue;
        };
        match parse_destination(w, t, &prefix) {
            Some(d) => {
                if let Some(first) = labels.insert(d.label.clone(), i + 1) {
                    w.problem(
                        format!("{prefix}.label"),
                        format!(
                            "`{}` is also the label of destination[{first}]; labels must be unique",
                            d.label
                        ),
                    );
                }
                out.push(d);
            }
            None => complete = false,
        }
    }
    complete.then_some(out)
}

fn parse_destination(w: &mut Walker, t: &Table, p: &str) -> Option<Destination> {
    w.unknown_keys(
        t,
        p,
        &[
            "label",
            "address",
            "network",
            "protocol",
            "ports",
            "hostname",
            "whole_network_approved",
        ],
    );
    let label = w.text(t, p, "label", 64);
    if let Some(l) = &label
        && !is_identifier(l)
    {
        w.problem(
            join(p, "label"),
            "must be 1-64 letters, digits, `.`, `_` or `-`, starting with a letter or digit",
        );
    }
    let whole = match t.get("whole_network_approved") {
        None => Some(false),
        Some(Value::Boolean(b)) => Some(*b),
        Some(other) => {
            w.problem(
                join(p, "whole_network_approved"),
                format!("must be true or false, not {}", kind(other)),
            );
            None
        }
    };
    let network = parse_target_field(w, t, p, whole.unwrap_or(false));
    let protocol = match t.get("protocol") {
        None => {
            w.problem(
                join(p, "protocol"),
                "missing; add `protocol = \"tcp\"` or `protocol = \"udp\"`",
            );
            None
        }
        Some(Value::String(s)) => match s.parse::<Protocol>() {
            Ok(proto) => Some(proto),
            Err(message) => {
                w.problem(join(p, "protocol"), message);
                None
            }
        },
        Some(other) => {
            w.problem(
                join(p, "protocol"),
                format!("must be \"tcp\" or \"udp\", not {}", kind(other)),
            );
            None
        }
    };
    let ports = parse_ports(w, t, p);
    let hostname = t.get("hostname").and_then(|value| {
        {
            let field = join(p, "hostname");
            let name = w.text_value(value, &field, 253);
            if let Some(n) = &name {
                if n.parse::<IpAddr>().is_ok() {
                    w.problem(
                        &field,
                        "holds an address; addresses go in `address` or `network`. `hostname` is only what the owner calls it",
                    );
                } else if !n
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                {
                    w.problem(
                        &field,
                        "must be a DNS name (letters, digits, `.`, `-`, `_`); it is informational and grants nothing",
                    );
                }
            }
            name
        }
    });
    Some(Destination {
        label: label?,
        network: network?,
        protocol: protocol?,
        ports: ports?,
        hostname,
        whole_network_approved: whole?,
    })
}

fn parse_target_field(w: &mut Walker, t: &Table, p: &str, whole: bool) -> Option<Network> {
    match (t.get("address"), t.get("network")) {
        (None, None) => {
            w.problem(
                join(p, "address"),
                "missing; add `address = \"192.0.2.10\"` (one literal IP) or `network = \"192.0.2.0/28\"` (a CIDR)",
            );
            None
        }
        (Some(_), Some(_)) => {
            w.problem(
                p,
                "has both `address` and `network`; write one of them per destination",
            );
            None
        }
        (Some(value), None) => {
            let field = join(p, "address");
            let Some(text) = value.as_str() else {
                w.problem(
                    field,
                    format!("must be a quoted literal IP address, not {}", kind(value)),
                );
                return None;
            };
            if whole {
                w.problem(
                    join(p, "whole_network_approved"),
                    "applies only to `network`; remove it from a single address",
                );
            }
            match parse_address(text) {
                Ok(ip) => Some(Network::host(ip)),
                Err(e) => {
                    w.problem(field, e.to_string());
                    None
                }
            }
        }
        (None, Some(value)) => {
            let field = join(p, "network");
            let Some(text) = value.as_str() else {
                w.problem(
                    field,
                    format!("must be a quoted CIDR network, not {}", kind(value)),
                );
                return None;
            };
            let network = match parse_network(text) {
                Ok(n) => n,
                Err(e) => {
                    w.problem(field, e.to_string());
                    return None;
                }
            };
            let (cap, floor) = match network.addr() {
                IpAddr::V4(_) => (IPV4_CAP, IPV4_FLOOR),
                IpAddr::V6(_) => (IPV6_CAP, IPV6_FLOOR),
            };
            if network.prefix() < floor {
                w.problem(
                    field,
                    format!(
                        "`{network}` is broader than /{floor}, the widest network a pass accepts even with the owner's approval; list the owner's own, narrower networks"
                    ),
                );
                return None;
            }
            if network.prefix() < cap && !whole {
                w.problem(
                    field,
                    format!(
                        "`{network}` is broader than the /{cap} breadth cap; list the narrower networks the owner approved, or, only if the written approval names this whole network, add `whole_network_approved = true` to this destination"
                    ),
                );
                return None;
            }
            Some(network)
        }
    }
}

fn parse_ports(w: &mut Walker, t: &Table, p: &str) -> Option<PortSet> {
    let field = join(p, "ports");
    let example = "write `ports = 443`, `ports = [80, 443]` or `ports = [\"8000-8100\"]`";
    let Some(value) = t.get("ports") else {
        w.problem(field, format!("missing; {example}"));
        return None;
    };
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut ranges = Vec::new();
    let mut ok = true;
    for item in items {
        let parsed = match item {
            Value::Integer(n) => match u16::try_from(*n) {
                Ok(port) if port != 0 => Ok((port, port)),
                _ => Err(format!("{n} is not a port 1-65535")),
            },
            Value::String(s) => PortSet::parse_element(s),
            other => Err(format!("{} is not a port; {example}", kind(other))),
        };
        match parsed {
            Ok(range) => ranges.push(range),
            Err(message) => {
                w.problem(&field, message);
                ok = false;
            }
        }
    }
    if !ok {
        return None;
    }
    match PortSet::from_ranges(ranges) {
        Ok(set) => Some(set),
        Err(message) => {
            w.problem(field, message);
            None
        }
    }
}

fn parse_ceilings(w: &mut Walker, table: &Table) -> Option<BTreeMap<String, u64>> {
    let t = match table.get("ceilings") {
        None => return Some(BTreeMap::new()),
        Some(Value::Table(t)) => t,
        Some(other) => {
            w.problem(
                "ceilings",
                format!("must be a `[ceilings]` section, not {}", kind(other)),
            );
            return None;
        }
    };
    if t.len() > MAX_COUNTERS {
        w.problem(
            "ceilings",
            format!("more than {MAX_COUNTERS} counters; keep the ones the owner approved"),
        );
        return None;
    }
    let mut out = BTreeMap::new();
    let mut ok = true;
    for (name, value) in t {
        let field = join("ceilings", name);
        if !is_counter_name(name) {
            w.problem(
                &field,
                "is not a valid counter name; use 1-32 lower-case letters, digits, `_` or `-`, starting with a letter",
            );
            ok = false;
        }
        match value {
            Value::Integer(n) => match u64::try_from(*n) {
                Ok(total) if total <= MAX_CEILING => {
                    out.insert(name.clone(), total);
                }
                _ => {
                    w.problem(
                        field,
                        format!("{n} is not a whole number from 0 to {MAX_CEILING}"),
                    );
                    ok = false;
                }
            },
            other => {
                w.problem(
                    field,
                    format!(
                        "must be a whole number (for example `calls = 6`), not {}",
                        kind(other)
                    ),
                );
                ok = false;
            }
        }
    }
    ok.then_some(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const GOOD: &str = r#"
format = 1
id = "acme-2026-11"
name = "Example voice edge"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = "2026-11-20T18:00:00+01:00"
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = [5060, "10000-10100"]
hostname = "sip.example.net"

[[destination]]
label = "web"
network = "2001:db8::/120"
protocol = "tcp"
ports = 443

[ceilings]
calls = 6
requests = 500
"#;

    fn problems(text: &str) -> Vec<Problem> {
        match Pass::parse(text) {
            Ok(_) => panic!("accepted"),
            Err(p) => p,
        }
    }

    fn fields(text: &str) -> Vec<String> {
        problems(text).into_iter().map(|p| p.field).collect()
    }

    #[test]
    fn good_pass() {
        let pass = Pass::parse(GOOD).expect("valid");
        assert_eq!(pass.id, "acme-2026-11");
        assert_eq!(pass.destinations.len(), 2);
        assert_eq!(pass.ceilings.get("calls"), Some(&6));
        assert_eq!(
            pass.approval.valid_until - pass.approval.valid_from,
            time::Duration::hours(9)
        );
        let d = pass
            .destination_for("192.0.2.10".parse().expect("ip"), 10050, Protocol::Udp)
            .expect("allowed");
        assert_eq!(d.label, "sip-edge");
        assert!(
            pass.destination_for("192.0.2.10".parse().expect("ip"), 5060, Protocol::Tcp)
                .is_none()
        );
    }

    #[test]
    fn unknown_keys_everywhere() {
        let text = GOOD
            .replace("name = ", "nmae = \"x\"\nname = ")
            .replace("revoked = false", "revoked = false\nrevokd = true")
            .replace("ports = 443", "ports = 443\nport = 80");
        let f = fields(&text);
        assert!(f.contains(&"nmae".to_owned()), "{f:?}");
        assert!(f.contains(&"approval.revokd".to_owned()), "{f:?}");
        assert!(f.contains(&"destination[2].port".to_owned()), "{f:?}");
    }

    #[test]
    fn every_problem_reported() {
        let text = GOOD
            .replace(
                "valid_from = 2026-11-20T08:00:00Z",
                "valid_from = 2026-11-20T08:00:00",
            )
            .replace("address = \"192.0.2.10\"", "address = \"sip.example.net\"")
            .replace("calls = 6", "calls = -1")
            .replace("format = 1", "format = 2");
        let f = fields(&text);
        for want in [
            "format",
            "approval.valid_from",
            "destination[1].address",
            "ceilings.calls",
        ] {
            assert!(f.contains(&want.to_owned()), "{want} missing from {f:?}");
        }
    }

    #[test]
    fn window_rules() {
        let text = GOOD.replace(
            "valid_until = \"2026-11-20T18:00:00+01:00\"",
            "valid_until = 2026-11-20T08:00:00Z",
        );
        assert_eq!(fields(&text), vec!["approval.valid_until"]);
        let text = GOOD.replace("2026-11-20T18:00:00+01:00", "2026-11-20 18:00");
        assert_eq!(fields(&text), vec!["approval.valid_until"]);
        let text = GOOD.replace(
            "valid_from = 2026-11-20T08:00:00Z",
            "valid_from = 2026-11-20",
        );
        assert_eq!(fields(&text), vec!["approval.valid_from"]);
        let text = GOOD.replace("revoked = false", "revoked = false\nrevoked_reason = \"x\"");
        assert_eq!(fields(&text), vec!["approval.revoked_reason"]);
        let text = GOOD.replace("revoked = false\n", "");
        assert_eq!(fields(&text), vec!["approval.revoked"]);
    }

    #[test]
    fn breadth_cap() {
        let wide = GOOD.replace(
            "network = \"2001:db8::/120\"",
            "network = \"2001:db8::/48\"",
        );
        let p = problems(&wide);
        assert_eq!(p.len(), 1);
        assert!(p[0].message.contains("breadth cap"), "{p:?}");
        let approved = wide.replace("ports = 443", "ports = 443\nwhole_network_approved = true");
        assert!(Pass::parse(&approved).is_ok());
        let too_wide = approved.replace("2001:db8::/48", "2001:d00::/24");
        assert!(problems(&too_wide)[0].message.contains("widest"));
        let v4 = GOOD.replace("network = \"2001:db8::/120\"", "network = \"10.0.0.0/16\"");
        assert!(problems(&v4)[0].message.contains("/24 breadth cap"));
        let v4_ok = GOOD.replace("network = \"2001:db8::/120\"", "network = \"10.0.0.0/24\"");
        assert!(Pass::parse(&v4_ok).is_ok());
        let on_address = GOOD.replace(
            "hostname = \"sip.example.net\"",
            "whole_network_approved = true",
        );
        assert_eq!(
            fields(&on_address),
            vec!["destination[1].whole_network_approved"]
        );
    }

    #[test]
    fn destination_rules() {
        let both = GOOD.replace(
            "address = \"192.0.2.10\"",
            "address = \"192.0.2.10\"\nnetwork = \"192.0.2.0/28\"",
        );
        assert_eq!(fields(&both), vec!["destination[1]"]);
        let dup = GOOD.replace("label = \"web\"", "label = \"sip-edge\"");
        assert_eq!(fields(&dup), vec!["destination[2].label"]);
        let proto = GOOD.replace("protocol = \"tcp\"", "protocol = \"icmp\"");
        assert_eq!(fields(&proto), vec!["destination[2].protocol"]);
        let ports = GOOD.replace("ports = 443", "ports = [0, \"9-3\", 1.5]");
        assert_eq!(problems(&ports).len(), 3);
        let host = GOOD.replace("sip.example.net", "192.0.2.10");
        assert_eq!(fields(&host), vec!["destination[1].hostname"]);
        let none = GOOD
            .split("[[destination]]")
            .next()
            .expect("head")
            .to_owned()
            + "[ceilings]\ncalls = 1\n";
        assert_eq!(fields(&none), vec!["destination"]);
        let int_addr = GOOD.replace("address = \"192.0.2.10\"", "address = 3221225994");
        assert_eq!(fields(&int_addr), vec!["destination[1].address"]);
    }

    #[test]
    fn ceiling_rules() {
        for bad in [
            "calls = 1.5",
            "calls = \"6\"",
            "Calls = 6",
            "calls = 1000000000001",
        ] {
            let text = GOOD.replace("calls = 6", bad);
            assert_eq!(problems(&text).len(), 1, "{bad}");
        }
        let zero = GOOD.replace("calls = 6", "calls = 0");
        assert!(Pass::parse(&zero).is_ok());
        let none = GOOD.split("[ceilings]").next().expect("head").to_owned();
        assert!(
            Pass::parse(&none)
                .expect("no ceilings is fine")
                .ceilings
                .is_empty()
        );
    }

    #[test]
    fn text_rules() {
        let text = GOOD.replace("Sam Tester", " Sam");
        assert_eq!(fields(&text), vec!["approval.operator"]);
        let text = GOOD.replace("Sam Tester", "Sam\\nTester");
        assert_eq!(fields(&text), vec!["approval.operator"]);
        let text = GOOD.replace("acme-2026-11", "acme 2026");
        assert_eq!(fields(&text), vec!["id"]);
        let text = GOOD.replace("format = 1", "format = 1\nformat = 1");
        assert_eq!(fields(&text), vec!["(file)"]);
    }
}
