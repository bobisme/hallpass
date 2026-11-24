//! Pure decisions: the window state at an instant, and whether a target is
//! permitted. Nothing here reads a clock or a file; the caller passes `now`.

use std::fmt;
use std::net::IpAddr;

use time::{Duration, OffsetDateTime};

use crate::address::{Target, embedded_ipv4, ipv6_transition};
use crate::name::HostName;
use crate::pass::{Destination, Pass};

/// Where an instant falls relative to the approval window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowState {
    /// Before `valid_from`; `opens_in` is the time until it opens.
    NotYetValid {
        /// Time until the window opens.
        opens_in: Duration,
    },
    /// Inside the window; `remaining` is the time until `valid_until`.
    Valid {
        /// Time until the window ends.
        remaining: Duration,
    },
    /// At or after `valid_until`; `ended_ago` is how long ago it ended.
    Expired {
        /// Time since the window ended.
        ended_ago: Duration,
    },
    /// The owner withdrew the approval. This wins over every other state.
    Revoked {
        /// The recorded reason, if any.
        reason: Option<String>,
    },
}

impl WindowState {
    /// The stable name used in JSON: `not-yet-valid`, `valid`, `expired`,
    /// `revoked`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotYetValid { .. } => "not-yet-valid",
            Self::Valid { .. } => "valid",
            Self::Expired { .. } => "expired",
            Self::Revoked { .. } => "revoked",
        }
    }

    /// True only inside the window of an unrevoked pass.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

/// Why something was refused, as a stable code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RefusalCode {
    /// The window has not opened.
    NotYetValid,
    /// The window has ended.
    Expired,
    /// The owner revoked the approval.
    Revoked,
    /// The window ends before the work could finish.
    WindowTooShort,
    /// An IPv6 form that carries an IPv4 address (mapped, compatible,
    /// NAT64, or a transition form: 6to4, Teredo, ISATAP, SIIT-translated).
    EmbeddedIpv4,
    /// The network address or the directed broadcast (all-ones) address of
    /// a listed IPv4 network of /30 or broader: not a host.
    NetworkOrBroadcast,
    /// No entry lists this address.
    AddressNotListed,
    /// The address is listed, but not with this protocol and port.
    PortNotListed,
    /// The destination is approved only for listed host names, and the
    /// query named none.
    NameRequired,
    /// The destination is approved only for listed host names, and the
    /// query's name is not one of them.
    NameNotListed,
    /// The counter is not one of the pass's ceilings.
    UnknownCounter,
    /// A debit omitted a counter required by the approval.
    RequiredCounterMissing,
    /// A debit omitted a destination required by the approval.
    TargetRequired,
    /// A guarded caller reference already occurs in the verified available history.
    DuplicateReference,
    /// The available history cannot establish that a guarded caller reference is new.
    ReferenceInconclusive,
    /// The spend would exceed the ceiling.
    CeilingReached,
    /// The pass on disk is not the one the caller expected.
    PassChanged,
}

impl RefusalCode {
    /// The stable spelling used in JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotYetValid => "not-yet-valid",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::WindowTooShort => "window-too-short",
            Self::EmbeddedIpv4 => "embedded-ipv4",
            Self::NetworkOrBroadcast => "network-or-broadcast",
            Self::AddressNotListed => "address-not-listed",
            Self::PortNotListed => "port-not-listed",
            Self::NameRequired => "name-required",
            Self::NameNotListed => "name-not-listed",
            Self::UnknownCounter => "unknown-counter",
            Self::RequiredCounterMissing => "required-counter-missing",
            Self::TargetRequired => "target-required",
            Self::DuplicateReference => "duplicate-reference",
            Self::ReferenceInconclusive => "reference-inconclusive",
            Self::CeilingReached => "ceiling-reached",
            Self::PassChanged => "pass-changed",
        }
    }
}

/// A refusal: a stable code and a message that says what happened and what
/// to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The stable code.
    pub code: RefusalCode,
    /// What happened and what to do, in plain words.
    pub message: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The answer to "may I touch this now?".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Allowed by the destination with this label.
    Allowed {
        /// The label of the first matching destination.
        label: String,
    },
    /// Refused, with the reason.
    Refused(Refusal),
}

/// `instant` in UTC, when its UTC form is a date this library can hold
/// (years 0001 to 9999). `9999-12-31T23:59:59-01:00` is not: it is year
/// 10000 in UTC.
pub fn in_utc(instant: OffsetDateTime) -> Option<OffsetDateTime> {
    instant
        .checked_to_offset(time::UtcOffset::UTC)
        .filter(|utc| (1..=9999).contains(&utc.year()))
}

/// `2026-11-20T08:00:00Z`: UTC, whole seconds.
///
/// An instant whose UTC form is outside the years 0001 to 9999 is written
/// with its own offset instead (a validated pass never holds one).
#[must_use]
pub fn stamp(instant: OffsetDateTime) -> String {
    let Some(utc) = in_utc(instant) else {
        let (h, m, _) = instant.offset().as_hms();
        return format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
            instant.year(),
            u8::from(instant.month()),
            instant.day(),
            instant.hour(),
            instant.minute(),
            instant.second(),
            if instant.offset().is_negative() {
                '-'
            } else {
                '+'
            },
            h.unsigned_abs(),
            m.unsigned_abs()
        );
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// A duration in words: `45 s`, `12 min`, `3 h 5 min`, `2 d 4 h`.
#[must_use]
pub fn span(duration: Duration) -> String {
    let s = duration.whole_seconds().max(0);
    if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    } else {
        format!("{} d {} h", s / 86400, s % 86400 / 3600)
    }
}

/// Time still left in an open window, for text.
///
/// Like [`span`] it rounds down, so the number never promises more time than
/// the decision allows; a part second reads `less than 1 s`, so an open
/// window never reads `0 s`.
#[must_use]
pub fn span_left(duration: Duration) -> String {
    if duration > Duration::ZERO && duration < Duration::SECOND {
        "less than 1 s".to_owned()
    } else {
        span(duration)
    }
}

/// Time until a window opens, for text. It rounds a part second up, so the
/// window is never said to open sooner than it does.
#[must_use]
pub fn span_until(duration: Duration) -> String {
    span(Duration::seconds(whole_seconds_up(duration)))
}

/// Whole seconds in `duration`, rounded up, never negative.
#[must_use]
pub fn whole_seconds_up(duration: Duration) -> i64 {
    let s = duration.whole_seconds();
    if duration.subsec_nanoseconds() > 0 {
        s.saturating_add(1).max(0)
    } else {
        s.max(0)
    }
}

impl Pass {
    /// The window state at `now`.
    #[must_use]
    pub fn window_at(&self, now: OffsetDateTime) -> WindowState {
        let a = &self.approval;
        if a.revoked {
            WindowState::Revoked {
                reason: a.revoked_reason.clone(),
            }
        } else if now < a.valid_from {
            WindowState::NotYetValid {
                opens_in: a.valid_from - now,
            }
        } else if now >= a.valid_until {
            WindowState::Expired {
                ended_ago: now - a.valid_until,
            }
        } else {
            WindowState::Valid {
                remaining: a.valid_until - now,
            }
        }
    }

    /// Refuse unless the window is valid at `now` and still open after
    /// `needed` (the longest the caller's next piece of work may take; pass
    /// [`Duration::ZERO`] for "right now"; a negative duration is read as
    /// zero here, and is a usage error in [`crate::spend`]).
    ///
    /// # Errors
    ///
    /// The refusal when the pass permits nothing in that time.
    pub fn check_window(&self, now: OffsetDateTime, needed: Duration) -> Result<(), Refusal> {
        let a = &self.approval;
        let new_window =
            "ask the owner for a new written approval and record its window in the pass";
        match self.window_at(now) {
            WindowState::Revoked { reason } => Err(Refusal {
                code: RefusalCode::Revoked,
                message: format!(
                    "the owner revoked this pass{}; stop. Nothing more is permitted under it",
                    reason
                        .map_or_else(String::new, |r| format!(" ({})", crate::display_quoted(&r)))
                ),
            }),
            WindowState::NotYetValid { opens_in } => Err(Refusal {
                code: RefusalCode::NotYetValid,
                message: format!(
                    "the approval window has not opened (valid from {}, in {}); wait for it to open",
                    stamp(a.valid_from),
                    span_until(opens_in)
                ),
            }),
            WindowState::Expired { .. } => Err(Refusal {
                code: RefusalCode::Expired,
                message: format!(
                    "the approval window has ended (valid until {}); {new_window}",
                    stamp(a.valid_until)
                ),
            }),
            WindowState::Valid { remaining } if needed > Duration::ZERO && remaining <= needed => {
                Err(Refusal {
                    code: RefusalCode::WindowTooShort,
                    message: format!(
                        "the work may take up to {} and would end at or after the window closes (valid until {}; {} remain); do less, or {new_window}",
                        span(needed),
                        stamp(a.valid_until),
                        span_left(remaining)
                    ),
                })
            }
            WindowState::Valid { .. } => Ok(()),
        }
    }

    /// Whether `target` is permitted at `now`, for work that may take up to
    /// `needed`: the window and revocation first, then the destinations.
    ///
    /// The query carries no host name, so a destination that lists `names`
    /// does not allow it: see [`Pass::permits_named`].
    #[must_use]
    pub fn permits(&self, target: &Target, now: OffsetDateTime, needed: Duration) -> Decision {
        self.permits_named(target, None, now, needed)
    }

    /// As [`Pass::permits`], for a request that will carry the host name
    /// `name` (as the TLS server name and the `Host` header, for example).
    ///
    /// A name never grants: the address, protocol and port must be listed.
    /// A destination with `names` allows only a query that carries one of
    /// them; a destination without `names` allows any name or none.
    #[must_use]
    pub fn permits_named(
        &self,
        target: &Target,
        name: Option<&HostName>,
        now: OffsetDateTime,
        needed: Duration,
    ) -> Decision {
        if let Err(refusal) = self.check_window(now, needed) {
            return Decision::Refused(refusal);
        }
        if let IpAddr::V6(v6) = target.ip
            && let Some(ipv4) = embedded_ipv4(v6)
        {
            return Decision::Refused(Refusal {
                code: RefusalCode::EmbeddedIpv4,
                message: format!(
                    "{} is an IPv6 form that carries the IPv4 address {ipv4}; ask about {ipv4} itself",
                    target.ip
                ),
            });
        }
        if let IpAddr::V6(v6) = target.ip
            && let Some((mechanism, ipv4)) = ipv6_transition(v6)
        {
            return Decision::Refused(Refusal {
                code: RefusalCode::EmbeddedIpv4,
                message: format!(
                    "{} is {} that carries the IPv4 address {ipv4}: packets to it are tunnelled or translated over IPv4. A pass names native addresses only; ask about {ipv4} or the host's native IPv6 address",
                    target.ip,
                    mechanism.name()
                ),
            });
        }
        // An address listed on its own is a host, whatever network it is
        // also in; otherwise the two edge addresses of a listed IPv4 network
        // are not hosts.
        let listed_alone = self
            .destinations
            .iter()
            .any(|d| d.network.is_host() && d.network.contains(target.ip));
        if !listed_alone
            && let Some(d) = self
                .destinations
                .iter()
                .find(|d| d.network.is_network_or_broadcast(target.ip))
        {
            let which = if target.ip == d.network.addr() {
                "the network address"
            } else {
                "the broadcast (all-ones) address"
            };
            return Decision::Refused(Refusal {
                code: RefusalCode::NetworkOrBroadcast,
                message: format!(
                    "{} is {which} of the listed network {} (destination {}), not a host: a packet to it may reach every host on that network; do not send to it. If the owner's network is larger and this is one host, the owner must list it as its own address in writing",
                    target.ip, d.network, d.label
                ),
            });
        }
        let matching: Vec<&Destination> = self
            .destinations
            .iter()
            .filter(|d| {
                d.network.contains(target.ip)
                    && d.protocol == target.protocol
                    && d.ports.contains(target.port)
            })
            .collect();
        if let Some(d) = matching
            .iter()
            .find(|d| d.names.is_empty() || name.is_some_and(|n| d.names.contains(n)))
        {
            return Decision::Allowed {
                label: d.label.clone(),
            };
        }
        if !matching.is_empty() {
            return Decision::Refused(name_refusal(target, name, &matching));
        }
        let listed: Vec<String> = self
            .destinations
            .iter()
            .filter(|d| d.network.contains(target.ip))
            .map(|d| format!("{} ({} {})", d.label, d.protocol, d.ports))
            .collect();
        if listed.is_empty() {
            Decision::Refused(Refusal {
                code: RefusalCode::AddressNotListed,
                message: format!(
                    "{} is not in any destination of this pass; do not touch it. If the owner approved it, they must add it to the pass in writing",
                    target.ip
                ),
            })
        } else {
            Decision::Refused(Refusal {
                code: RefusalCode::PortNotListed,
                message: format!(
                    "{} is listed only as {}, not for {} port {}; do not touch it. If the owner approved it, they must add it to the pass in writing",
                    target.ip,
                    listed.join(", "),
                    target.protocol,
                    target.port
                ),
            })
        }
    }
}

/// The refusal for a target whose every matching destination lists
/// `names`, none of them the query's.
fn name_refusal(target: &Target, name: Option<&HostName>, matching: &[&Destination]) -> Refusal {
    let approved = matching
        .iter()
        .map(|d| {
            let names: Vec<&str> = d.names.iter().map(HostName::as_str).collect();
            format!("{} ({})", d.label, names.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ");
    name.map_or_else(
        || Refusal {
            code: RefusalCode::NameRequired,
            message: format!(
                "{target} is approved only for named hosts: {approved}. Ask again with the host name the request will carry, and send only that name"
            ),
        },
        |n| Refusal {
            code: RefusalCode::NameNotListed,
            message: format!(
                "{target} is not approved for the name {n}, only for: {approved}. Do not send that name to it; another party may answer for it on this address. If the owner approved it, they must add it to the pass in writing"
            ),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pass::tests::GOOD;
    use time::macros::datetime;

    fn pass() -> Pass {
        Pass::parse(GOOD).expect("valid")
    }

    fn target(text: &str) -> Target {
        text.parse().expect("target")
    }

    #[test]
    fn window_states() {
        let p = pass();
        assert_eq!(
            p.window_at(datetime!(2026-11-20 07:00 UTC)),
            WindowState::NotYetValid {
                opens_in: Duration::hours(1)
            }
        );
        assert_eq!(
            p.window_at(datetime!(2026-11-20 08:00 UTC)),
            WindowState::Valid {
                remaining: Duration::hours(9)
            }
        );
        assert_eq!(
            p.window_at(datetime!(2026-11-20 17:00 UTC)),
            WindowState::Expired {
                ended_ago: Duration::ZERO
            }
        );
        let mut revoked = p;
        revoked.approval.revoked = true;
        assert!(matches!(
            revoked.window_at(datetime!(2026-11-20 09:00 UTC)),
            WindowState::Revoked { .. }
        ));
    }

    /// A pass whose one destination is `network` (whole network approved).
    fn network_pass(network: &str, extra: &str) -> Pass {
        let text = GOOD.replace(
            "network = \"2001:db8::/120\"",
            &format!("network = \"{network}\"\nwhole_network_approved = true"),
        );
        let text = format!("{text}{extra}");
        let text = text.replace("[ceilings]\ncalls = 6\nrequests = 500\n", "");
        Pass::parse(&format!("{text}\n[ceilings]\ncalls = 6\n")).expect("valid")
    }

    #[test]
    fn network_and_broadcast_addresses_are_not_hosts() {
        let now = datetime!(2026-11-20 09:00 UTC);
        let p = network_pass("198.51.100.0/24", "");
        let decide = |p: &Pass, t: &str| p.permits(&target(t), now, Duration::ZERO);
        for edge in ["198.51.100.0:443/tcp", "198.51.100.255:443/tcp"] {
            match decide(&p, edge) {
                Decision::Refused(r) => {
                    assert_eq!(r.code, RefusalCode::NetworkOrBroadcast, "{edge}");
                    assert!(r.message.contains("198.51.100.0/24"), "{}", r.message);
                    assert!(r.message.contains("not a host"), "{}", r.message);
                }
                other @ Decision::Allowed { .. } => panic!("{edge}: {other:?}"),
            }
        }
        assert!(matches!(
            decide(&p, "198.51.100.1:443/tcp"),
            Decision::Allowed { .. }
        ));
        // Listed on its own, the address is a host after all.
        let explicit = network_pass(
            "198.51.100.0/24",
            "\n[[destination]]\nlabel = \"bcast-host\"\naddress = \"198.51.100.255\"\nprotocol = \"udp\"\nports = 9\n",
        );
        assert!(matches!(
            decide(&explicit, "198.51.100.255:9/udp"),
            Decision::Allowed { .. }
        ));
        // /31 and /32 have no network or broadcast address.
        let p31 = network_pass("198.51.100.4/31", "");
        for host in ["198.51.100.4:443/tcp", "198.51.100.5:443/tcp"] {
            assert!(
                matches!(decide(&p31, host), Decision::Allowed { .. }),
                "{host}"
            );
        }
        // Transition forms are refused in a query, naming the IPv4 address.
        let p = pass();
        match decide(&p, "[2002:c000:20a::1]:5060/udp") {
            Decision::Refused(r) => {
                assert_eq!(r.code, RefusalCode::EmbeddedIpv4);
                assert!(r.message.contains("6to4") && r.message.contains("192.0.2.10"));
            }
            other @ Decision::Allowed { .. } => panic!("{other:?}"),
        }
        match decide(&p, "[2001:db8::5efe:c000:20a]:443/tcp") {
            Decision::Refused(r) => assert!(r.message.contains("ISATAP"), "{}", r.message),
            other @ Decision::Allowed { .. } => panic!("{other:?}"),
        }
    }

    proptest::proptest! {
        #[test]
        fn edges_refused_hosts_allowed(bits: u32, prefix in 8u8..=32, offset: u32) {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            // Inside 10.0.0.0/8, which has no special ranges.
            let base = (0x0a00_0000 | (bits & 0x00ff_ffff)) & mask;
            let last = base | !mask;
            let network = format!("{}/{prefix}", std::net::Ipv4Addr::from(base));
            let p = network_pass(&network, "");
            let now = datetime!(2026-11-20 09:00 UTC);
            let ask = |a: u32| p.permits(&target(&format!("{}:443/tcp", std::net::Ipv4Addr::from(a))), now, Duration::ZERO);
            for edge in [base, last] {
                match ask(edge) {
                    Decision::Refused(r) => proptest::prop_assert!(prefix <= 30 && r.code == RefusalCode::NetworkOrBroadcast),
                    Decision::Allowed { .. } => proptest::prop_assert!(prefix >= 31),
                }
            }
            let inside = base | (offset & !mask);
            if inside != base && inside != last {
                let allowed = matches!(ask(inside), Decision::Allowed { .. });
                proptest::prop_assert!(allowed, "host {} refused", std::net::Ipv4Addr::from(inside));
            }
        }
    }

    #[test]
    fn permits_paths() {
        let p = pass();
        let now = datetime!(2026-11-20 09:00 UTC);
        assert_eq!(
            p.permits(&target("192.0.2.10:5060/udp"), now, Duration::ZERO),
            Decision::Allowed {
                label: "sip-edge".to_owned()
            }
        );
        assert_eq!(
            p.permits(&target("[2001:db8::ff]:443/tcp"), now, Duration::ZERO),
            Decision::Allowed {
                label: "web".to_owned()
            }
        );
        let code = |t: &str, now, needed| match p.permits(&target(t), now, needed) {
            Decision::Refused(r) => r.code,
            Decision::Allowed { .. } => panic!("{t} allowed"),
        };
        assert_eq!(
            code("192.0.2.10:5060/tcp", now, Duration::ZERO),
            RefusalCode::PortNotListed
        );
        assert_eq!(
            code("192.0.2.11:5060/udp", now, Duration::ZERO),
            RefusalCode::AddressNotListed
        );
        assert_eq!(
            code("[2001:db8::100]:443/tcp", now, Duration::ZERO),
            RefusalCode::AddressNotListed
        );
        assert_eq!(
            code("[::ffff:192.0.2.10]:5060/udp", now, Duration::ZERO),
            RefusalCode::EmbeddedIpv4
        );
        assert_eq!(
            code(
                "192.0.2.10:5060/udp",
                datetime!(2026-11-20 07:59:59 UTC),
                Duration::ZERO
            ),
            RefusalCode::NotYetValid
        );
        assert_eq!(
            code(
                "192.0.2.10:5060/udp",
                datetime!(2026-11-21 00:00 UTC),
                Duration::ZERO
            ),
            RefusalCode::Expired
        );
        assert_eq!(
            code(
                "192.0.2.10:5060/udp",
                datetime!(2026-11-20 16:59 UTC),
                Duration::minutes(5)
            ),
            RefusalCode::WindowTooShort
        );
    }

    #[test]
    fn words() {
        assert_eq!(span(Duration::seconds(45)), "45 s");
        assert_eq!(span(Duration::minutes(12)), "12 min");
        assert_eq!(span(Duration::minutes(185)), "3 h 5 min");
        assert_eq!(span(Duration::hours(52)), "2 d 4 h");
        assert_eq!(
            stamp(datetime!(2026-11-20 09:00 +01:00)),
            "2026-11-20T08:00:00Z"
        );
    }

    #[test]
    fn stamp_never_panics() {
        // Year 10000 in UTC cannot be shown as a UTC stamp; it is shown with
        // its own offset instead of aborting the caller.
        let edge = datetime!(9999-12-31 23:59:59 -1);
        assert_eq!(stamp(edge), "9999-12-31T23:59:59-01:00");
        let low = datetime!(-9999-01-01 00:00 +1);
        assert_eq!(stamp(low), "-9999-01-01T00:00:00+01:00");
        // Deciding at such an instant does not panic either.
        let p = pass();
        assert!(matches!(p.window_at(edge), WindowState::Expired { .. }));
        assert!(p.check_window(edge, Duration::MAX).is_err());
        assert!(matches!(p.window_at(low), WindowState::NotYetValid { .. }));
    }

    const NAMED: &str = r#"
[[destination]]
label = "shared-web"
address = "198.51.100.7"
protocol = "tcp"
ports = 443
names = ["app.example.com", "admin.example.com"]

[[destination]]
label = "shared-api"
address = "198.51.100.7"
protocol = "tcp"
ports = [443, 8443]
names = ["api.example.com"]

[[destination]]
label = "plain"
address = "198.51.100.8"
protocol = "tcp"
ports = 443
"#;

    fn named_pass() -> Pass {
        let text = GOOD.replacen("[ceilings]", &format!("{NAMED}\n[ceilings]"), 1);
        assert!(
            text.contains("shared-web"),
            "GOOD has no [ceilings] to anchor on"
        );
        Pass::parse(&text).expect("valid")
    }

    fn ask(pass: &Pass, to: &str, name: Option<&str>) -> Result<String, RefusalCode> {
        let name: Option<HostName> = name.map(|n| n.parse().expect("name"));
        match pass.permits_named(
            &target(to),
            name.as_ref(),
            datetime!(2026-11-20 09:00 UTC),
            Duration::ZERO,
        ) {
            Decision::Allowed { label } => Ok(label),
            Decision::Refused(r) => Err(r.code),
        }
    }

    #[test]
    fn a_named_destination_allows_only_its_names() {
        let p = named_pass();
        let to = "198.51.100.7:443/tcp";
        assert_eq!(
            ask(&p, to, Some("app.example.com")),
            Ok("shared-web".to_owned())
        );
        assert_eq!(
            ask(&p, to, Some("ADMIN.example.com.")),
            Ok("shared-web".to_owned())
        );
        // A later destination on the same address and port may list more names.
        assert_eq!(
            ask(&p, to, Some("api.example.com")),
            Ok("shared-api".to_owned())
        );
        assert_eq!(
            ask(&p, to, Some("other.example.org")),
            Err(RefusalCode::NameNotListed)
        );
        assert_eq!(
            ask(&p, to, Some("evil-app.example.com")),
            Err(RefusalCode::NameNotListed)
        );
        assert_eq!(
            ask(&p, to, Some("example.com")),
            Err(RefusalCode::NameNotListed)
        );
        assert_eq!(ask(&p, to, None), Err(RefusalCode::NameRequired));
        // `permits` is the query without a name.
        assert!(matches!(
            p.permits(&target(to), datetime!(2026-11-20 09:00 UTC), Duration::ZERO),
            Decision::Refused(Refusal {
                code: RefusalCode::NameRequired,
                ..
            })
        ));
    }

    #[test]
    fn names_are_per_port() {
        let p = named_pass();
        let to = "198.51.100.7:8443/tcp";
        assert_eq!(
            ask(&p, to, Some("api.example.com")),
            Ok("shared-api".to_owned())
        );
        assert_eq!(
            ask(&p, to, Some("app.example.com")),
            Err(RefusalCode::NameNotListed)
        );
    }

    #[test]
    fn a_name_never_grants() {
        let p = named_pass();
        // An approved name on an address, port or protocol that is not listed.
        assert_eq!(
            ask(&p, "198.51.100.9:443/tcp", Some("app.example.com")),
            Err(RefusalCode::AddressNotListed)
        );
        assert_eq!(
            ask(&p, "198.51.100.7:80/tcp", Some("app.example.com")),
            Err(RefusalCode::PortNotListed)
        );
        assert_eq!(
            ask(&p, "198.51.100.7:443/udp", Some("app.example.com")),
            Err(RefusalCode::PortNotListed)
        );
        // Nor does it get past the window.
        let name: HostName = "app.example.com".parse().expect("name");
        assert!(matches!(
            p.permits_named(
                &target("198.51.100.7:443/tcp"),
                Some(&name),
                datetime!(2026-11-20 18:00 UTC),
                Duration::ZERO
            ),
            Decision::Refused(Refusal {
                code: RefusalCode::Expired,
                ..
            })
        ));
    }

    #[test]
    fn a_destination_without_names_takes_any_name_or_none() {
        let p = named_pass();
        let to = "198.51.100.8:443/tcp";
        assert_eq!(ask(&p, to, None), Ok("plain".to_owned()));
        assert_eq!(
            ask(&p, to, Some("anything.example.org")),
            Ok("plain".to_owned())
        );
    }

    #[test]
    fn name_refusals_list_the_approved_names() {
        let p = named_pass();
        let other: HostName = "other.example.org".parse().expect("name");
        for name in [None, Some(&other)] {
            let Decision::Refused(r) = p.permits_named(
                &target("198.51.100.7:443/tcp"),
                name,
                datetime!(2026-11-20 09:00 UTC),
                Duration::ZERO,
            ) else {
                panic!("allowed");
            };
            for expected in [
                "shared-web (app.example.com, admin.example.com)",
                "shared-api (api.example.com)",
            ] {
                assert!(r.message.contains(expected), "{}", r.message);
            }
        }
    }
}
