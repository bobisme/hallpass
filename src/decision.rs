//! Pure decisions: the window state at an instant, and whether a target is
//! permitted. Nothing here reads a clock or a file; the caller passes `now`.

use std::fmt;
use std::net::IpAddr;

use time::{Duration, OffsetDateTime};

use crate::address::{Target, embedded_ipv4, ipv6_transition};
use crate::pass::Pass;

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
    /// The counter is not one of the pass's ceilings.
    UnknownCounter,
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
            Self::UnknownCounter => "unknown-counter",
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

/// `2026-11-20T08:00:00Z`: UTC, whole seconds.
#[must_use]
pub fn stamp(instant: OffsetDateTime) -> String {
    let utc = instant.to_offset(time::UtcOffset::UTC);
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
    /// [`Duration::ZERO`] for "right now").
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
                    reason.map_or_else(String::new, |r| format!(" ({r})"))
                ),
            }),
            WindowState::NotYetValid { opens_in } => Err(Refusal {
                code: RefusalCode::NotYetValid,
                message: format!(
                    "the approval window has not opened (valid from {}, in {}); wait for it to open",
                    stamp(a.valid_from),
                    span(opens_in)
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
                        "the work may take up to {}, but only {} of the approval window remain (valid until {}); do less, or {new_window}",
                        span(needed),
                        span(remaining),
                        stamp(a.valid_until)
                    ),
                })
            }
            WindowState::Valid { .. } => Ok(()),
        }
    }

    /// Whether `target` is permitted at `now`, for work that may take up to
    /// `needed`: the window and revocation first, then the destinations.
    #[must_use]
    pub fn permits(&self, target: &Target, now: OffsetDateTime, needed: Duration) -> Decision {
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
        if let Some(d) = self.destination_for(target.ip, target.port, target.protocol) {
            return Decision::Allowed {
                label: d.label.clone(),
            };
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
}
