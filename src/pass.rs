//! The pass file: parsing and validation.
//!
//! [`Pass::parse`] reads the TOML text and checks every rule in
//! `docs/PASS-FORMAT.md`. It reports every problem it finds, each with the
//! field path and what to do, rather than stopping at the first.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
use toml::{Table, Value};

use crate::address::{AddressError, Network, Protocol, parse_address, parse_network};
use crate::name::{HostName, MAX_NAMES};
use crate::ports::PortSet;

mod marks;
mod oversized;

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
    /// The only host names this destination is approved for. Empty: no
    /// name restriction. A name narrows and never grants.
    pub names: Vec<HostName>,
    /// The owner approved the whole network beyond the breadth cap.
    pub whole_network_approved: bool,
    /// Labels of the nameless destinations whose overlap with this
    /// destination's `names` list the owner accepted. Advice only: it never
    /// changes a decision.
    pub overlap_acknowledged: Vec<String>,
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
    /// Counter names that every debit must charge, in sorted order.
    pub required_counters: Vec<String>,
    /// Whether every debit must check at least one destination.
    pub require_target: bool,
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
                let hint = if !prefix.is_empty() && TOP_LEVEL_KEYS.contains(&key.as_str()) {
                    format!(" `{key}` is a top-level key: {}.", top_level_move(key))
                } else {
                    String::new()
                };
                self.problem(
                    join(prefix, key),
                    format!(
                        "unknown key `{key}`; a typo could drop a restriction, so unknown keys are refused.{hint} Allowed here: {}",
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
        // Kept in UTC. A timestamp that has no UTC form in the years 0001
        // to 9999 (9999-12-31T23:59:59-01:00) cannot be compared or shown.
        let parsed = parsed.and_then(|instant| {
            crate::decision::in_utc(instant).ok_or_else(|| {
                format!(
                    "`{}` is outside the years 0001 to 9999 in UTC; copy the timestamp from the written approval ({example})",
                    crate::decision::stamp(instant)
                )
            })
        });
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

/// The most characters `approval.owner` and `approval.reference` may hold.
const MAX_APPROVAL_TEXT: usize = 200;

/// Every problem `owner` and `reference` would have as `approval.owner` and
/// `approval.reference` of a pass, with those fields, as [`Pass::parse`]
/// reports them. Empty when a pass can hold both. `approval-id` checks its
/// input with this, so it never gives an id for an owner or reference that
/// no pass can hold.
pub fn approval_identity_problems(owner: &str, reference: &str) -> Vec<Problem> {
    [("approval.owner", owner), ("approval.reference", reference)]
        .into_iter()
        .filter_map(|(field, text)| {
            check_text(text, MAX_APPROVAL_TEXT)
                .err()
                .map(|message| Problem {
                    field: field.to_owned(),
                    message,
                })
        })
        .collect()
}

/// Advice about `owner` and `reference` as `approval.owner` and
/// `approval.reference`, with those fields.
///
/// It is for text a pass can hold whose approval id still depends on how it
/// was typed. A combining mark (general category Mn, Mc or Me) means the
/// same text can often be written in other characters that look the same
/// (`é` as one character, or `e` and U+0301), and a run of spaces is easily
/// copied as one; either copy gives another id. Advice only: nothing is
/// refused.
#[must_use]
pub fn approval_identity_warnings(owner: &str, reference: &str) -> Vec<Problem> {
    const SAME: &str = "The approval id depends on the exact characters, so a copy typed or pasted";
    const SHARE: &str = "share the id itself, not a retyped copy of the text";
    let mut out = Vec::new();
    for (field, text) in [("approval.owner", owner), ("approval.reference", reference)] {
        if let Some(mark) = text.chars().find(|c| marks::is_combining_mark(*c)) {
            out.push(Problem {
                field: field.to_owned(),
                message: format!(
                    "holds a combining mark (U+{:04X}), so the same text can also be written in other characters that look the same (an accented letter as one character, for example). {SAME} differently gives another id; {SHARE}",
                    u32::from(mark)
                ),
            });
        }
        if text.contains("  ") {
            out.push(Problem {
                field: field.to_owned(),
                message: format!(
                    "holds two or more spaces in a row. {SAME} with one space gives another id; write one space, or {SHARE}"
                ),
            });
        }
    }
    out
}

/// Free text: printable, without line separators, Unicode format
/// characters, other invisible characters or spaces other than the ASCII
/// space ([`crate::ledger::is_disguising`]), no surrounding spaces, 1 to
/// `max` characters.
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
    if let Some(c) = text.chars().find(|c| crate::ledger::is_disguising(*c)) {
        return Err(format!(
            "contains {}, which can make it display as something else; write one plain line without it",
            crate::ledger::describe_disguising(c)
        ));
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
pub fn is_identifier(text: &str) -> bool {
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
    /// reported alone, since nothing else can be read, but for the
    /// characters that can make the file display as something else: those
    /// are reported anywhere in the file, comments included, with their
    /// line and column.
    pub fn parse(text: &str) -> Result<Self, Vec<Problem>> {
        // A character that can disguise the file is reported wherever it is,
        // comments included, and before a syntax error it may explain.
        let mut problems = crate::literal::hidden_characters(text);
        let table: Table = match text.parse() {
            Ok(table) => table,
            Err(e) => {
                let e: toml::de::Error = e;
                if let Some(problem) = e
                    .span()
                    .and_then(|span| oversized::problem(text, span.start, e.message()))
                {
                    problems.push(problem);
                    return Err(problems);
                }
                let at = e
                    .span()
                    .and_then(|span| text.get(..span.start))
                    .map_or_else(String::new, |before| {
                        let line = before.matches('\n').count() + 1;
                        let column =
                            before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                        format!(" at line {line}, column {column}")
                    });
                problems.push(Problem {
                    field: "(file)".to_owned(),
                    message: format!(
                        "the file is not valid TOML{at}: {}; fix the syntax there",
                        e.message().trim()
                    ),
                });
                return Err(problems);
            }
        };
        problems.extend(crate::literal::problems(text));
        let mut w = Walker { problems };
        w.unknown_keys(&table, "", TOP_LEVEL_KEYS);
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
        let required_counters = parse_required_counters(&mut w, &table, ceilings.as_ref());
        let require_target = match table.get("require_target_v1") {
            None => false,
            Some(Value::Boolean(true)) => true,
            Some(_) => {
                w.problem(
                    "require_target_v1",
                    "must be true when present, or omit this key",
                );
                false
            }
        };
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
                    required_counters,
                    require_target,
                })
            }
            _ => Err(vec![Problem {
                field: "(file)".to_owned(),
                message: "the pass is incomplete".to_owned(),
            }]),
        }
    }

    /// The first destination entry that lists `ip`, `port` and `protocol`.
    ///
    /// This is a lookup, not a decision: it does not look at the window,
    /// revocation, `names`, IPv6 forms that carry IPv4, or the network and
    /// broadcast addresses of a listed network. To decide whether something
    /// may be sent, use [`Pass::permits`] or [`Pass::permits_named`].
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
    let owner = w.text(t, p, "owner", MAX_APPROVAL_TEXT);
    let reference = w.text(t, p, "reference", MAX_APPROVAL_TEXT);
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
    // Labels are checked over the raw entries, so a duplicate is reported
    // even when either destination has other problems. People read, type
    // and match labels, so two that differ only in ASCII letter case are
    // refused too.
    let mut seen: BTreeMap<String, (usize, &str)> = BTreeMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let Some(label) = entry
            .as_table()
            .and_then(|t| t.get("label"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(&(first, earlier)) = seen.get(&label.to_ascii_lowercase()) else {
            seen.insert(label.to_ascii_lowercase(), (i + 1, label));
            continue;
        };
        let message = if earlier == label {
            format!(
                "{} is also the label of destination[{first}]; labels must be unique",
                crate::display_quoted(label)
            )
        } else {
            format!(
                "{} differs from {}, the label of destination[{first}], only in letter case; people read and type labels, so make the two differ in more than case",
                crate::display_quoted(label),
                crate::display_quoted(earlier)
            )
        };
        w.problem(format!("destination[{}].label", i + 1), message);
    }
    let mut out = Vec::new();
    let mut complete = true;
    for (i, entry) in entries.iter().enumerate() {
        let prefix = format!("destination[{}]", i + 1);
        let Value::Table(t) = entry else {
            w.problem(&prefix, "must be a `[[destination]]` section");
            complete = false;
            continue;
        };
        match parse_destination(w, t, &prefix) {
            Some(d) => out.push(d),
            None => complete = false,
        }
    }
    if complete {
        check_overlap_acknowledgements(w, &out);
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
            "names",
            "overlap_acknowledged",
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
                if n.parse::<IpAddr>().is_ok() || crate::name::ends_in_number(n) {
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
    let names = parse_names(w, t, p);
    let overlap_acknowledged = parse_overlap_acknowledged(w, t, p);
    Some(Destination {
        label: label?,
        network: network?,
        protocol: protocol?,
        ports: ports?,
        hostname,
        names: names?,
        whole_network_approved: whole?,
        overlap_acknowledged: overlap_acknowledged?,
    })
}

/// The optional `overlap_acknowledged` list: distinct destination labels.
/// Whether each label names a real nameless destination is checked once all
/// destinations are known ([`check_overlap_acknowledgements`]).
fn parse_overlap_acknowledged(w: &mut Walker, t: &Table, p: &str) -> Option<Vec<String>> {
    let field = join(p, "overlap_acknowledged");
    let items = match t.get("overlap_acknowledged") {
        None => return Some(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(other) => {
            w.problem(
                field,
                format!(
                    "must be a list of destination labels (for example `overlap_acknowledged = [\"wide\"]`), not {}",
                    kind(other)
                ),
            );
            return None;
        }
    };
    if items.is_empty() {
        w.problem(
            field,
            "is an empty list; list the labels of the nameless destinations whose overlap the owner accepted, or remove the key",
        );
        return None;
    }
    if items.len() > MAX_DESTINATIONS {
        w.problem(field, "lists more labels than a pass has destinations");
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    let mut complete = true;
    for (i, item) in items.iter().enumerate() {
        let at = format!("{field}[{}]", i + 1);
        match item.as_str() {
            None => {
                w.problem(
                    at,
                    format!("must be a quoted destination label, not {}", kind(item)),
                );
                complete = false;
            }
            Some(label) if out.iter().any(|l| l == label) => {
                w.problem(
                    at,
                    format!(
                        "{} is listed twice; remove one",
                        crate::display_quoted(label)
                    ),
                );
                complete = false;
            }
            Some(label) => out.push(label.to_owned()),
        }
    }
    complete.then_some(out)
}

/// Each acknowledgement names one other destination that has no `names`, and
/// sits on a destination that has them: the only pair an overlap can be
/// between. Whether the two really overlap is advice, not a pass problem (see
/// `review::name_overlap_warnings`).
fn check_overlap_acknowledgements(w: &mut Walker, destinations: &[Destination]) {
    for (i, d) in destinations.iter().enumerate() {
        if d.overlap_acknowledged.is_empty() {
            continue;
        }
        let field = format!("destination[{}].overlap_acknowledged", i + 1);
        if d.names.is_empty() {
            w.problem(
                &field,
                "is set on a destination without `names`; an overlap is a named destination whose names list another destination defeats. Put it on the destination that has `names`",
            );
            continue;
        }
        for (j, label) in d.overlap_acknowledged.iter().enumerate() {
            let at = format!("{field}[{}]", j + 1);
            match destinations.iter().find(|o| o.label == *label) {
                None => w.problem(at, format!("`{label}` is not the label of any destination")),
                Some(o) if o.label == d.label => w.problem(
                    at,
                    "names this destination itself; name the other, nameless destination",
                ),
                Some(o) if !o.names.is_empty() => w.problem(
                    at,
                    format!("destination `{label}` has `names`, so it cannot defeat another destination's names list; name a destination without `names`"),
                ),
                Some(_) => {}
            }
        }
    }
}

/// The optional `names` list: canonical host names, no duplicates.
fn parse_names(w: &mut Walker, t: &Table, p: &str) -> Option<Vec<HostName>> {
    let field = join(p, "names");
    let example = "for example `names = [\"app.example.com\"]`";
    let items = match t.get("names") {
        None => return Some(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(other) => {
            w.problem(
                field,
                format!(
                    "must be a list of host names ({example}), not {}",
                    kind(other)
                ),
            );
            return None;
        }
    };
    if items.is_empty() {
        w.problem(
            field,
            "is an empty list, which could mean \"no names\" or \"any name\"; list the approved names, or remove the key for no name restriction",
        );
        return None;
    }
    if items.len() > MAX_NAMES {
        w.problem(
            field,
            format!("lists more than {MAX_NAMES} names; split the destination"),
        );
        return None;
    }
    let mut out: Vec<HostName> = Vec::new();
    let mut complete = true;
    for (i, item) in items.iter().enumerate() {
        let at = format!("{field}[{}]", i + 1);
        let Some(text) = item.as_str() else {
            w.problem(
                at,
                format!("must be a quoted host name, not {}", kind(item)),
            );
            complete = false;
            continue;
        };
        match HostName::canonical(text) {
            Ok(name) if out.contains(&name) => {
                w.problem(at, format!("`{name}` is listed twice; remove one"));
                complete = false;
            }
            Ok(name) => out.push(name),
            Err(message) => {
                w.problem(at, message);
                complete = false;
            }
        }
    }
    complete.then_some(out)
}

/// The problem text for an address or network that a pass file refused. A
/// host name gets the pass-file advice: `names` restricts the destination,
/// while `hostname` only records what the owner calls it.
fn address_problem(e: &AddressError) -> String {
    match e {
        AddressError::Hostname(name) => format!(
            "`{name}` is a host name, and a pass grants nothing to names: write the literal IP address the owner approved in `address` or `network`. To restrict the destination to a name, add `names = [\"{name}\"]`; `hostname` only records what the owner calls it and grants nothing."
        ),
        other => other.to_string(),
    }
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
                    w.problem(field, address_problem(&e));
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
                    w.problem(field, address_problem(&e));
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
    let repeated = repeated_ports(&ranges);
    if !repeated.is_empty() {
        for message in repeated {
            w.problem(&field, message);
        }
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

/// A problem for each port that `ranges`, the elements of one `ports` list
/// in file order, lists more than once: twice the same element, or two
/// elements that overlap. Each names the first port the two share, and no
/// port is named twice.
fn repeated_ports(ranges: &[(u16, u16)]) -> Vec<String> {
    let shown = |(start, end): (u16, u16)| {
        if start == end {
            format!("`{start}`")
        } else {
            format!("`{start}-{end}`")
        }
    };
    let mut sorted: Vec<((u16, u16), usize)> = ranges.iter().copied().zip(0..).collect();
    sorted.sort_unstable();
    let mut out: Vec<String> = Vec::new();
    let mut named: BTreeSet<u16> = BTreeSet::new();
    // The element that reaches furthest so far, and where it was written.
    let mut reach: Option<((u16, u16), usize)> = None;
    for (range, at) in sorted {
        let Some((covering, written)) = reach else {
            reach = Some((range, at));
            continue;
        };
        if range.0 <= covering.1 && named.insert(range.0) {
            out.push(if range == covering {
                format!("lists {} twice; remove one", shown(range))
            } else {
                let (first, second) = if written < at {
                    (covering, range)
                } else {
                    (range, covering)
                };
                format!(
                    "lists port {} twice, in {} and in {}; list each port once",
                    range.0,
                    shown(first),
                    shown(second)
                )
            });
        }
        if range.1 > covering.1 {
            reach = Some((range, at));
        }
    }
    out
}

fn parse_required_counters(
    w: &mut Walker,
    table: &Table,
    ceilings: Option<&BTreeMap<String, u64>>,
) -> Vec<String> {
    const FIELD: &str = "required_counters_v1";
    let Some(value) = table.get(FIELD) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        w.problem(FIELD, "must be an array of names from [ceilings]");
        return Vec::new();
    };
    if !(1..=MAX_COUNTERS).contains(&items.len()) {
        w.problem(
            FIELD,
            format!("list 1 to {MAX_COUNTERS} distinct counter names, or omit this key"),
        );
        return Vec::new();
    }
    let mut names = std::collections::BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        let field = format!("{FIELD}[{}]", i + 1);
        let Some(name) = item.as_str().filter(|name| is_counter_name(name)) else {
            w.problem(field, "must be a valid quoted counter name");
            continue;
        };
        if !names.insert(name.to_owned()) {
            w.problem(&field, format!("duplicate required counter `{name}`"));
        }
        if ceilings.is_some_and(|limits| !limits.contains_key(name)) {
            w.problem(
                field,
                format!("required counter `{name}` must be declared in [ceilings]"),
            );
        }
    }
    names.into_iter().collect()
}

/// The keys a pass may have before its first `[table]` header.
const TOP_LEVEL_KEYS: &[&str] = &[
    "format",
    "id",
    "name",
    "approval",
    "destination",
    "ceilings",
    "required_counters_v1",
    "require_target_v1",
];

/// What to do about a top-level key written under a `[table]` header.
fn top_level_move(key: &str) -> String {
    format!("top-level keys must come before the first `[table]` header; move `{key}` up above it")
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
        if TOP_LEVEL_KEYS.contains(&name.as_str()) && !matches!(value, Value::Integer(_)) {
            w.problem(
                field,
                format!(
                    "`{name}` is a top-level key, but it sits under `[ceilings]`; {}",
                    top_level_move(name)
                ),
            );
            ok = false;
            continue;
        }
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
        for ambiguous in ["010.0.2.10", "192.0.2", "3221225994", "0xc000020a"] {
            let host = GOOD.replace("sip.example.net", ambiguous);
            assert_eq!(
                fields(&host),
                vec!["destination[1].hostname"],
                "{ambiguous}"
            );
        }
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
        // A syntax error says where it is.
        let p = problems("format = 1\nid = \"x\"\nname = \n");
        assert!(p[0].message.contains("line 3, column 8"), "{p:?}");
    }

    #[test]
    fn a_window_that_does_not_fit_in_utc_is_refused_not_a_panic() {
        // 9999-12-31T23:59:59-01:00 is year 10000 in UTC; every later
        // `stamp` of it used to panic (status, permits, and library users).
        for (from, to) in [
            (
                "valid_until = \"2026-11-20T18:00:00+01:00\"",
                "valid_until = 9999-12-31T23:59:59-01:00",
            ),
            (
                "valid_until = \"2026-11-20T18:00:00+01:00\"",
                "valid_until = \"9999-12-31T23:59:59-01:00\"",
            ),
        ] {
            let text = GOOD.replace(from, to);
            assert_ne!(text, GOOD);
            let p = problems(&text);
            assert_eq!(p.len(), 1, "{p:?}");
            assert_eq!(p[0].field, "approval.valid_until");
            assert!(p[0].message.contains("0001 to 9999"), "{p:?}");
        }
        // Year 0 and earlier in UTC is not a real approval either.
        let text = GOOD.replace(
            "valid_from = 2026-11-20T08:00:00Z",
            "valid_from = 0000-01-01T00:00:00+01:00",
        );
        assert_eq!(fields(&text), vec!["approval.valid_from"]);
        // The last representable second is still a timestamp.
        let text = GOOD.replace(
            "valid_until = \"2026-11-20T18:00:00+01:00\"",
            "valid_until = 9999-12-31T23:59:59Z",
        );
        let pass = Pass::parse(&text).expect("valid");
        assert_eq!(
            crate::decision::stamp(pass.approval.valid_until),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn numbers_are_written_in_plain_decimal() {
        // TOML also reads 0x10 (16), 0o17 (15), 0b110 (6), 1_0 (10) and +6.
        // A reviewer may not: one spelling per number, as for addresses.
        for (from, to, field) in [
            ("calls = 6", "calls = 0x10", "ceilings.calls"),
            ("calls = 6", "calls = 0o17", "ceilings.calls"),
            ("calls = 6", "calls = 0b110", "ceilings.calls"),
            ("calls = 6", "calls = 1_0", "ceilings.calls"),
            ("calls = 6", "calls = +6", "ceilings.calls"),
            ("ports = 443", "ports = 0x1BB", "destination[2].ports"),
            (
                "ports = [5060, \"10000-10100\"]",
                "ports = [5060, 1_0000]",
                "destination[1].ports[2]",
            ),
            ("format = 1", "format = 0x1", "format"),
        ] {
            let text = GOOD.replace(from, to);
            assert_ne!(text, GOOD, "{to}");
            let p = problems(&text);
            assert_eq!(p.len(), 1, "{to}: {p:?}");
            assert_eq!(p[0].field, field, "{to}");
            assert!(p[0].message.contains("plain decimal"), "{to}: {p:?}");
        }
        let hex = problems(&GOOD.replace("calls = 6", "calls = 0x10"));
        assert!(hex[0].message.contains("16"), "{hex:?}");
        // Still one problem, with its own message, for these.
        for (to, count) in [("calls = -1", 1), ("calls = 0", 0)] {
            let text = GOOD.replace("calls = 6", to);
            assert_eq!(
                Pass::parse(&text).err().map_or(0, |p| p.len()),
                count,
                "{to}"
            );
        }
    }

    #[test]
    fn strings_are_written_without_escapes() {
        // "192.0.2.1\u0030" is 192.0.2.10 to TOML; the reviewer must read
        // the same characters the tool uses.
        for (from, to, field) in [
            (
                "address = \"192.0.2.10\"",
                "address = \"192.0.2.1\\u0030\"",
                "destination[1].address",
            ),
            (
                "protocol = \"udp\"",
                "protocol = \"\\u0075dp\"",
                "destination[1].protocol",
            ),
            (
                "owner = \"Pat Owner, Example Corp\"",
                "owner = \"Pat \\u004fwner\"",
                "approval.owner",
            ),
            (
                "id = \"acme-2026-11\"",
                "id = \"\"\"acme-\\\n  2026-11\"\"\"",
                "id",
            ),
            ("calls = 6", "\"c\\u0061lls\" = 6", "ceilings.calls"),
        ] {
            let text = GOOD.replace(from, to);
            assert_ne!(text, GOOD, "{to}");
            let p = problems(&text);
            assert_eq!(p.len(), 1, "{to}: {p:?}");
            assert_eq!(p[0].field, field, "{to}");
            assert!(p[0].message.contains("escape"), "{to}: {p:?}");
        }
        // A quote or a backslash in free text, and literal strings, are fine.
        let text = GOOD
            .replace(
                "name = \"Example voice edge\"",
                "name = \"The \\\"voice\\\" edge, C:\\\\share\"",
            )
            .replace(
                "reference = \"email of 2026-11-18\"",
                "reference = 'email \\u0041 of 2026-11-18'",
            )
            .replace("address = \"192.0.2.10\"", "address = '192.0.2.10'");
        let pass = Pass::parse(&text).expect("valid");
        assert_eq!(pass.name, "The \"voice\" edge, C:\\share");
        assert_eq!(pass.approval.reference, "email \\u0041 of 2026-11-18");
    }

    fn with_names(value: &str) -> Result<Pass, Vec<Problem>> {
        let text = GOOD.replacen(
            "hostname = \"sip.example.net\"",
            &format!("hostname = \"sip.example.net\"\nnames = {value}"),
            1,
        );
        assert!(
            text.contains("names = "),
            "GOOD has no hostname line to anchor on"
        );
        Pass::parse(&text)
    }

    #[test]
    fn names_are_read_in_order_and_default_to_none() {
        let pass = Pass::parse(GOOD).expect("valid");
        assert!(pass.destinations.iter().all(|d| d.names.is_empty()));
        let pass = with_names("[\"app.example.com\", \"xn--bcher-kva.example\"]").expect("valid");
        let names: Vec<&str> = pass.destinations[0]
            .names
            .iter()
            .map(HostName::as_str)
            .collect();
        assert_eq!(names, vec!["app.example.com", "xn--bcher-kva.example"]);
    }

    #[test]
    fn bad_names_are_refused_with_their_position() {
        for (value, field) in [
            ("[]", "destination[1].names"),
            ("\"app.example.com\"", "destination[1].names"),
            ("[\"app.example.com\", 5]", "destination[1].names[2]"),
            ("[\"App.example.com\"]", "destination[1].names[1]"),
            ("[\"app.example.com.\"]", "destination[1].names[1]"),
            ("[\"*.example.com\"]", "destination[1].names[1]"),
            ("[\"192.0.2.10\"]", "destination[1].names[1]"),
            ("[\"a.example\", \"a.example\"]", "destination[1].names[2]"),
            ("[\"https://app.example.com\"]", "destination[1].names[1]"),
            ("[\"app.example.com:443\"]", "destination[1].names[1]"),
        ] {
            let problems = with_names(value).expect_err(value);
            let fields: Vec<&str> = problems.iter().map(|p| p.field.as_str()).collect();
            assert_eq!(fields, vec![field], "{value}: {problems:?}");
        }
        let many: Vec<String> = (0..=MAX_NAMES)
            .map(|i| format!("\"h{i}.example\""))
            .collect();
        assert!(with_names(&format!("[{}]", many.join(", "))).is_err());
    }

    #[test]
    fn a_port_listed_twice_is_named_once() {
        for (ranges, expected) in [
            (
                vec![(443, 443), (443, 443)],
                vec!["lists `443` twice; remove one"],
            ),
            (
                vec![(8000, 8100), (8000, 8100)],
                vec!["lists `8000-8100` twice; remove one"],
            ),
            (
                vec![(80, 80), (1, 1024), (80, 80)],
                vec!["lists port 80 twice, in `80` and in `1-1024`; list each port once"],
            ),
            (
                vec![(8050, 8200), (8000, 8100), (9000, 9000), (8100, 8100)],
                vec![
                    "lists port 8050 twice, in `8050-8200` and in `8000-8100`; list each port once",
                    "lists port 8100 twice, in `8050-8200` and in `8100`; list each port once",
                ],
            ),
        ] {
            assert_eq!(repeated_ports(&ranges), expected, "{ranges:?}");
        }
        for apart in [
            vec![(443, 443)],
            vec![(1, 80), (81, 100)],
            vec![(443, 443), (80, 80), (8443, 8443)],
            vec![(1, 65535)],
        ] {
            assert_eq!(repeated_ports(&apart), Vec::<String>::new(), "{apart:?}");
        }
    }
}
