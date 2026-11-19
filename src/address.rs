//! Literal addresses and networks, spelled strictly.
//!
//! A pass names destinations by literal IP address or CIDR network only. The
//! parsers here accept exactly one spelling for each address (the canonical
//! one that [`std::net`] prints), so a reviewer reads the address that is
//! used. They refuse spellings that different tools read differently
//! (`010.0.0.1`, `10.1`, `2130706433`), IPv6 forms that carry an IPv4
//! address past the list (`::ffff:192.0.2.1`, NAT64 prefixes), and addresses
//! that are not one unicast host (unspecified, multicast, broadcast and the
//! reserved IPv4 block) or that are ambiguous without an interface
//! (link-local).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Why an address or network spelling was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AddressError {
    /// Nothing was written.
    #[error("the value is empty; write a literal IPv4 or IPv6 address")]
    Empty,
    /// The text looks like a host name.
    #[error(
        "`{0}` looks like a host name; a pass grants nothing to names: write the literal IP address the owner approved (a name may go in the informational `hostname` field)"
    )]
    Hostname(String),
    /// The text is not an address at all.
    #[error("`{0}` is not a literal IPv4 or IPv6 address")]
    NotAnAddress(String),
    /// An IPv4 part has a leading zero, which some tools read as octal.
    #[error(
        "`{0}` has a leading zero in an IPv4 part, which some tools read as octal; write each part without leading zeros (for example 10.0.0.1)"
    )]
    LeadingZero(String),
    /// A shortened IPv4 form such as `10.1` or a bare integer.
    #[error(
        "`{0}` is a shortened IPv4 form that tools expand differently; write all four parts (for example 10.0.0.1)"
    )]
    Shortened(String),
    /// An IPv6 interface (zone) suffix.
    #[error(
        "`{0}` carries an interface (zone) suffix; a pass cannot name an interface: write the address without `%`"
    )]
    Zone(String),
    /// An IPv6 spelling other than the canonical one.
    #[error("`{given}` is not written in canonical form; write `{canonical}`")]
    NotCanonical {
        /// What was written.
        given: String,
        /// The one accepted spelling.
        canonical: String,
    },
    /// An IPv6 address that embeds an IPv4 address.
    #[error(
        "`{given}` is an IPv6 form that carries the IPv4 address {ipv4}; name the IPv4 address itself"
    )]
    EmbedsIpv4 {
        /// What was written.
        given: String,
        /// The IPv4 address it carries.
        ipv4: Ipv4Addr,
    },
    /// The unspecified ("any") address, or a network that contains it.
    #[error("`{0}` is or contains the unspecified (any) address; name the service's own addresses")]
    Unspecified(String),
    /// A multicast address or a network that overlaps multicast space.
    #[error("`{0}` is or overlaps multicast space; a pass names unicast hosts only")]
    Multicast(String),
    /// The limited broadcast address.
    #[error("`{0}` is the broadcast address; a pass names unicast hosts only")]
    Broadcast(String),
    /// The reserved IPv4 block 240.0.0.0/4.
    #[error("`{0}` is or overlaps the reserved block 240.0.0.0/4, which is not a unicast host")]
    Reserved(String),
    /// A link-local address or network.
    #[error(
        "`{0}` is or overlaps link-local space (169.254.0.0/16, fe80::/10); link-local addresses are ambiguous without an interface and include cloud metadata endpoints, so a pass does not accept them"
    )]
    LinkLocal(String),
    /// A network spelling with a malformed prefix length.
    #[error(
        "`{0}` has a malformed prefix length; write ADDRESS/LENGTH with a decimal length without leading zeros"
    )]
    Prefix(String),
    /// A prefix length longer than the address.
    #[error("`{given}`: the prefix length {prefix} is longer than {max} bits")]
    PrefixTooLong {
        /// What was written.
        given: String,
        /// The prefix length written.
        prefix: u8,
        /// The address width.
        max: u8,
    },
    /// A CIDR whose address part has bits set below the prefix.
    #[error(
        "`{given}` has host bits set below the prefix; for the network write `{network}`, for one host use `address` instead of `network`"
    )]
    HostBits {
        /// What was written.
        given: String,
        /// The network with the host bits cleared.
        network: String,
    },
    /// A single address was given where a CIDR was expected, or the reverse.
    #[error(
        "`{0}` contains `/`; a single `address` has no prefix length: use `network` for a CIDR"
    )]
    UnexpectedPrefix(String),
}

/// An IPv4 or IPv6 network: an address and a prefix length.
///
/// A single host is a network with the full prefix length (/32 or /128).
/// Values come only from the strict parser, so the address part never has
/// host bits set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    /// The single-host network for `addr`.
    #[must_use]
    pub const fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            prefix: width(addr),
        }
    }

    /// The network address.
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// True for a single host (/32 or /128).
    #[must_use]
    pub const fn is_host(&self) -> bool {
        self.prefix == width(self.addr)
    }

    /// True when `ip` lies inside this network (same family only).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = mask32(self.prefix);
                u32::from(ip) & mask == u32::from(net) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = mask128(self.prefix);
                u128::from(ip) & mask == u128::from(net) & mask
            }
            _ => false,
        }
    }

    /// True when the two networks share at least one address.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.contains(other.addr) || other.contains(self.addr)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_host() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

const fn width(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

const fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

const fn net(addr: IpAddr, prefix: u8) -> Network {
    Network { addr, prefix }
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

const fn v6(s: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ))
}

/// Ranges that are never a destination, with the error each one gives.
#[derive(Clone, Copy)]
enum Special {
    Unspecified,
    Multicast,
    Broadcast,
    Reserved,
    LinkLocal,
}

const SPECIAL: [(Network, Special); 8] = [
    (net(v4(0, 0, 0, 0), 8), Special::Unspecified),
    (net(v4(224, 0, 0, 0), 4), Special::Multicast),
    (net(v4(255, 255, 255, 255), 32), Special::Broadcast),
    (net(v4(240, 0, 0, 0), 4), Special::Reserved),
    (net(v4(169, 254, 0, 0), 16), Special::LinkLocal),
    (net(v6([0, 0, 0, 0, 0, 0, 0, 0]), 128), Special::Unspecified),
    (
        net(v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8),
        Special::Multicast,
    ),
    (
        net(v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10),
        Special::LinkLocal,
    ),
];

fn special_error(kind: Special, text: &str) -> AddressError {
    let text = text.to_owned();
    match kind {
        Special::Unspecified => AddressError::Unspecified(text),
        Special::Multicast => AddressError::Multicast(text),
        Special::Broadcast => AddressError::Broadcast(text),
        Special::Reserved => AddressError::Reserved(text),
        Special::LinkLocal => AddressError::LinkLocal(text),
    }
}

/// The IPv4 address an IPv6 address carries, if any.
///
/// These are the ranges whose traffic reaches that IPv4 address: IPv4-mapped (`::ffff:0:0/96`),
/// IPv4-compatible (`::/96` other than `::` and `::1`), and the NAT64
/// prefixes `64:ff9b::/96` and `64:ff9b:1::/48`.
#[must_use]
pub fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return Some(mapped);
    }
    let s = ip.segments();
    let low = Ipv4Addr::from(u32::from(s[6]) << 16 | u32::from(s[7]));
    let bits = u128::from(ip);
    if s[..6] == [0; 6] && bits > 1 {
        return Some(low);
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1) {
        return Some(low);
    }
    None
}

/// The IPv6 ranges that carry IPv4 addresses (see [`embedded_ipv4`]).
const EMBEDDING: [Network; 4] = [
    net(v6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96),
    net(v6([0, 0, 0, 0, 0, 0, 0, 0]), 96),
    net(v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96),
    net(v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48),
];

/// Refuse a network (or single host) that is, contains or overlaps a range
/// that is never a destination.
fn check_special(network: &Network, text: &str) -> Result<(), AddressError> {
    // The unspecified address first: `0.0.0.0/0` should say "any".
    for (range, kind) in &SPECIAL {
        if matches!(kind, Special::Unspecified) && network.overlaps(range) {
            return Err(special_error(*kind, text));
        }
    }
    for (range, kind) in &SPECIAL {
        // A network that holds 255.255.255.255 is reported as reserved space.
        let skip = matches!(kind, Special::Broadcast) && !network.is_host();
        if !skip && network.overlaps(range) {
            return Err(special_error(*kind, text));
        }
    }
    if let IpAddr::V6(addr) = network.addr {
        let loopback = Network::host(IpAddr::V6(Ipv6Addr::LOCALHOST));
        for range in &EMBEDDING {
            if network.overlaps(range) && *network != loopback {
                let ipv4 = embedded_ipv4(addr).unwrap_or(Ipv4Addr::UNSPECIFIED);
                return Err(AddressError::EmbedsIpv4 {
                    given: text.to_owned(),
                    ipv4,
                });
            }
        }
    }
    Ok(())
}

/// Parse one address in its canonical spelling, without range checks.
fn parse_literal(text: &str) -> Result<IpAddr, AddressError> {
    if text.is_empty() {
        return Err(AddressError::Empty);
    }
    if text.contains('%') {
        return Err(AddressError::Zone(text.to_owned()));
    }
    if text.contains('/') {
        return Err(AddressError::UnexpectedPrefix(text.to_owned()));
    }
    if text.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let parts: Vec<&str> = text.split('.').collect();
        if parts.len() > 4 {
            return Err(AddressError::NotAnAddress(text.to_owned()));
        }
        if parts.len() < 4 || parts.iter().any(|p| p.is_empty()) {
            return Err(AddressError::Shortened(text.to_owned()));
        }
        if parts.iter().any(|p| p.len() > 1 && p.starts_with('0')) {
            return Err(AddressError::LeadingZero(text.to_owned()));
        }
    }
    let Ok(ip) = IpAddr::from_str(text) else {
        let alpha = text
            .bytes()
            .any(|b| b.is_ascii_alphabetic() && !b.is_ascii_hexdigit());
        let named = !text.contains(':') && text.bytes().any(|b| b.is_ascii_alphabetic());
        if alpha || named {
            return Err(AddressError::Hostname(text.to_owned()));
        }
        return Err(AddressError::NotAnAddress(text.to_owned()));
    };
    if let IpAddr::V6(addr) = ip
        && let Some(ipv4) = embedded_ipv4(addr)
    {
        return Err(AddressError::EmbedsIpv4 {
            given: text.to_owned(),
            ipv4,
        });
    }
    let canonical = ip.to_string();
    if canonical != text {
        return Err(AddressError::NotCanonical {
            given: text.to_owned(),
            canonical,
        });
    }
    Ok(ip)
}

/// Parse a single literal destination address.
///
/// # Errors
///
/// Any spelling other than the canonical one, a host name, and any address
/// that is not one ordinary unicast host (see the module notes).
pub fn parse_address(text: &str) -> Result<IpAddr, AddressError> {
    let ip = parse_literal(text)?;
    check_special(&Network::host(ip), text)?;
    Ok(ip)
}

/// Parse a CIDR network such as `192.0.2.0/24` or `2001:db8::/48`.
///
/// # Errors
///
/// As [`parse_address`] for the address part, plus a malformed or too long
/// prefix length, host bits set below the prefix, and any overlap with a
/// range that is never a destination.
pub fn parse_network(text: &str) -> Result<Network, AddressError> {
    let Some((addr_text, prefix_text)) = text.split_once('/') else {
        let ip = parse_address(text)?;
        return Ok(Network::host(ip));
    };
    let bad_prefix = prefix_text.is_empty()
        || prefix_text.len() > 3
        || !prefix_text.bytes().all(|b| b.is_ascii_digit())
        || (prefix_text.len() > 1 && prefix_text.starts_with('0'));
    if bad_prefix {
        return Err(AddressError::Prefix(text.to_owned()));
    }
    let prefix: u8 = prefix_text
        .parse()
        .map_err(|_| AddressError::Prefix(text.to_owned()))?;
    let addr = parse_literal(addr_text)?;
    let max = width(addr);
    if prefix > max {
        return Err(AddressError::PrefixTooLong {
            given: text.to_owned(),
            prefix,
            max,
        });
    }
    let network = Network { addr, prefix };
    let cleared = match addr {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(prefix))),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(prefix))),
    };
    if cleared != addr {
        return Err(AddressError::HostBits {
            given: text.to_owned(),
            network: format!("{cleared}/{prefix}"),
        });
    }
    check_special(&network, text)?;
    Ok(network)
}

/// A transport protocol a destination allows.
///
/// Only protocols with ports: every consumer's transport maps onto one of
/// them (TLS and HTTP/1-2 run over TCP; QUIC, DTLS and RTP over UDP).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// The lower-case name used in pass files and on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(format!(
                "`{other}` is not a supported protocol; write `tcp` or `udp` (TLS and HTTP are tcp; QUIC, DTLS and RTP are udp)"
            )),
        }
    }
}

/// One concrete thing a tool is about to touch: an address, a port and a
/// protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Target {
    /// The literal destination address.
    pub ip: IpAddr,
    /// The destination port (never 0).
    pub port: u16,
    /// The transport protocol.
    pub protocol: Protocol,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}/{}", self.port, self.protocol),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}/{}", self.port, self.protocol),
        }
    }
}

/// Parse a decimal port 1-65535 without sign, spaces or leading zeros.
pub fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty()
        || text.len() > 5
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse::<u16>().ok().filter(|p| *p != 0)
}

impl FromStr for Target {
    type Err = String;

    /// `ADDR:PORT/PROTO`, with IPv6 in brackets: `192.0.2.10:5060/udp`,
    /// `[2001:db8::1]:443/tcp`. Any valid address spelling is accepted here
    /// (it names one address either way), but not a host name, a zone, or a
    /// shortened or leading-zero IPv4 form.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let usage =
            "write ADDRESS:PORT/PROTOCOL, for example 192.0.2.10:5060/udp or [2001:db8::1]:443/tcp";
        let (endpoint, proto) = s
            .rsplit_once('/')
            .ok_or_else(|| format!("`{s}` has no protocol; {usage}"))?;
        let protocol: Protocol = proto.parse()?;
        let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("`{s}` has `[` without `]`; {usage}"))?;
            let port = after
                .strip_prefix(':')
                .ok_or_else(|| format!("`{s}` has no port after `]`; {usage}"))?;
            if !host.contains(':') {
                return Err(format!(
                    "`{s}`: brackets are only for IPv6 addresses; {usage}"
                ));
            }
            (host, port)
        } else {
            let (host, port) = endpoint
                .rsplit_once(':')
                .ok_or_else(|| format!("`{s}` has no port; {usage}"))?;
            if host.contains(':') {
                return Err(format!("`{s}`: put an IPv6 address in brackets; {usage}"));
            }
            (host, port)
        };
        let port =
            parse_port(port).ok_or_else(|| format!("`{port}` is not a port 1-65535; {usage}"))?;
        let ip = parse_query_address(host).map_err(|e| e.to_string())?;
        Ok(Self { ip, port, protocol })
    }
}

/// Parse an address a tool asks about: any unambiguous spelling.
fn parse_query_address(text: &str) -> Result<IpAddr, AddressError> {
    match parse_literal(text) {
        Ok(ip) => Ok(ip),
        Err(AddressError::NotCanonical { canonical, .. }) => canonical
            .parse()
            .map_err(|_| AddressError::NotAnAddress(text.to_owned())),
        Err(AddressError::EmbedsIpv4 { .. }) => {
            IpAddr::from_str(text).map_err(|_| AddressError::NotAnAddress(text.to_owned()))
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn addr_err(text: &str) -> AddressError {
        match parse_address(text) {
            Ok(ip) => panic!("{text} was accepted as {ip}"),
            Err(e) => e,
        }
    }

    fn net_err(text: &str) -> AddressError {
        match parse_network(text) {
            Ok(n) => panic!("{text} was accepted as {n}"),
            Err(e) => e,
        }
    }

    #[test]
    fn accepts_canonical_unicast() {
        for text in [
            "192.0.2.10",
            "198.51.100.1",
            "10.0.0.1",
            "127.0.0.2",
            "::1",
            "2001:db8::1",
            "203.0.113.255",
        ] {
            assert_eq!(
                parse_address(text).map(|ip| ip.to_string()),
                Ok(text.to_owned())
            );
        }
    }

    #[test]
    fn refuses_ambiguous_ipv4() {
        assert!(matches!(
            addr_err("010.0.0.1"),
            AddressError::LeadingZero(_)
        ));
        assert!(matches!(
            addr_err("10.0.0.01"),
            AddressError::LeadingZero(_)
        ));
        assert!(matches!(addr_err("10.1"), AddressError::Shortened(_)));
        assert!(matches!(addr_err("10.1.2"), AddressError::Shortened(_)));
        assert!(matches!(addr_err("2130706433"), AddressError::Shortened(_)));
        assert!(matches!(addr_err("10..0.1"), AddressError::Shortened(_)));
        assert!(matches!(
            addr_err("1.2.3.4.5"),
            AddressError::NotAnAddress(_)
        ));
        assert!(matches!(
            addr_err("256.0.0.1"),
            AddressError::NotAnAddress(_)
        ));
        assert!(matches!(addr_err("0x7f.0.0.1"), AddressError::Hostname(_)));
    }

    #[test]
    fn refuses_names_and_zones() {
        assert!(matches!(
            addr_err("sip.example.net"),
            AddressError::Hostname(_)
        ));
        assert!(matches!(addr_err("localhost"), AddressError::Hostname(_)));
        assert!(matches!(addr_err("fe80::1%eth0"), AddressError::Zone(_)));
        assert!(matches!(addr_err(""), AddressError::Empty));
        assert!(matches!(
            addr_err("192.0.2.1/32"),
            AddressError::UnexpectedPrefix(_)
        ));
    }

    #[test]
    fn refuses_non_canonical_ipv6() {
        assert!(matches!(
            addr_err("2001:DB8::1"),
            AddressError::NotCanonical { .. }
        ));
        assert!(matches!(
            addr_err("2001:0db8::1"),
            AddressError::NotCanonical { .. }
        ));
        assert!(matches!(
            addr_err("2001:db8:0:0:0:0:0:1"),
            AddressError::NotCanonical { .. }
        ));
    }

    #[test]
    fn refuses_ipv4_smuggled_in_ipv6() {
        for text in [
            "::ffff:192.0.2.1",
            "::ffff:c000:201",
            "::192.0.2.1",
            "64:ff9b::c000:201",
            "64:ff9b:1::c000:201",
        ] {
            assert!(
                matches!(addr_err(text), AddressError::EmbedsIpv4 { .. }),
                "{text}"
            );
        }
        assert!(matches!(
            net_err("::ffff:0:0/96"),
            AddressError::EmbedsIpv4 { .. }
        ));
        assert!(matches!(
            net_err("64:ff9b::/96"),
            AddressError::EmbedsIpv4 { .. }
        ));
        assert!(matches!(net_err("::/0"), AddressError::Unspecified(_)));
    }

    #[test]
    fn refuses_special_addresses() {
        assert!(matches!(addr_err("0.0.0.0"), AddressError::Unspecified(_)));
        assert!(matches!(addr_err("::"), AddressError::Unspecified(_)));
        assert!(matches!(addr_err("224.0.0.1"), AddressError::Multicast(_)));
        assert!(matches!(addr_err("ff02::1"), AddressError::Multicast(_)));
        assert!(matches!(
            addr_err("255.255.255.255"),
            AddressError::Broadcast(_)
        ));
        assert!(matches!(addr_err("240.0.0.1"), AddressError::Reserved(_)));
        assert!(matches!(
            addr_err("169.254.169.254"),
            AddressError::LinkLocal(_)
        ));
        assert!(matches!(addr_err("fe80::1"), AddressError::LinkLocal(_)));
        assert!(matches!(net_err("0.0.0.0/0"), AddressError::Unspecified(_)));
        assert!(matches!(net_err("192.0.0.0/2"), AddressError::Multicast(_)));
        assert!(matches!(net_err("169.0.0.0/8"), AddressError::LinkLocal(_)));
    }

    #[test]
    fn networks() {
        let n = parse_network("192.0.2.0/24").expect("valid");
        assert!(n.contains("192.0.2.200".parse().expect("ip")));
        assert!(!n.contains("192.0.3.1".parse().expect("ip")));
        assert!(!n.contains("2001:db8::1".parse().expect("ip")));
        assert_eq!(n.to_string(), "192.0.2.0/24");
        assert_eq!(
            parse_network("192.0.2.7/32").expect("v").to_string(),
            "192.0.2.7"
        );
        assert!(matches!(
            net_err("192.0.2.1/24"),
            AddressError::HostBits { .. }
        ));
        assert!(matches!(net_err("192.0.2.0/024"), AddressError::Prefix(_)));
        assert!(matches!(net_err("192.0.2.0/"), AddressError::Prefix(_)));
        assert!(matches!(
            net_err("192.0.2.0/33"),
            AddressError::PrefixTooLong { .. }
        ));
        assert!(matches!(
            net_err("2001:db8::/129"),
            AddressError::PrefixTooLong { .. }
        ));
        assert!(matches!(net_err("192.0.2.0/+4"), AddressError::Prefix(_)));
        let v6 = parse_network("2001:db8::/32").expect("valid");
        assert!(v6.contains("2001:db8:ffff::1".parse().expect("ip")));
    }

    #[test]
    fn targets() {
        let t: Target = "192.0.2.10:5060/udp".parse().expect("valid");
        assert_eq!(t.to_string(), "192.0.2.10:5060/udp");
        let t: Target = "[2001:db8::1]:443/tcp".parse().expect("valid");
        assert_eq!(t.to_string(), "[2001:db8::1]:443/tcp");
        let t: Target = "[2001:DB8::1]:443/tcp"
            .parse()
            .expect("any spelling of one address");
        assert_eq!(t.to_string(), "[2001:db8::1]:443/tcp");
        for bad in [
            "2001:db8::1:443/tcp",
            "192.0.2.10:5060",
            "192.0.2.10/udp",
            "192.0.2.10:0/udp",
            "192.0.2.10:05060/udp",
            "192.0.2.10:70000/udp",
            "192.0.2.10:80/icmp",
            "example.net:80/tcp",
            "[192.0.2.1]:80/tcp",
            "010.0.0.1:80/tcp",
            "[fe80::1%2]:80/tcp",
        ] {
            assert!(bad.parse::<Target>().is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn ipv4_round_trip(bits: u32) {
            let ip = Ipv4Addr::from(bits);
            let text = ip.to_string();
            match parse_address(&text) {
                Ok(parsed) => prop_assert_eq!(parsed, IpAddr::V4(ip)),
                Err(e) => prop_assert!(matches!(
                    e,
                    AddressError::Unspecified(_)
                        | AddressError::Multicast(_)
                        | AddressError::Broadcast(_)
                        | AddressError::Reserved(_)
                        | AddressError::LinkLocal(_)
                )),
            }
        }

        #[test]
        fn ipv6_round_trip(bits: u128) {
            let ip = Ipv6Addr::from(bits);
            let text = ip.to_string();
            if let Ok(parsed) = parse_address(&text) {
                prop_assert_eq!(parsed, IpAddr::V6(ip));
                prop_assert!(embedded_ipv4(ip).is_none());
            }
        }

        #[test]
        fn leading_zero_always_refused(a in 1u8..=255, b: u8, c: u8, d: u8, which in 0usize..4) {
            let mut parts = [a.to_string(), b.to_string(), c.to_string(), d.to_string()];
            parts[which] = format!("0{}", parts[which]);
            let text = parts.join(".");
            prop_assert!(parse_address(&text).is_err());
            let with_prefix = format!("{text}/32");
            prop_assert!(parse_network(&with_prefix).is_err());
        }

        #[test]
        fn shortened_always_refused(parts in proptest::collection::vec(0u32..70000, 1..4)) {
            let text = parts.iter().map(ToString::to_string).collect::<Vec<_>>().join(".");
            prop_assert!(parse_address(&text).is_err());
        }

        #[test]
        fn mapped_always_refused(bits: u32) {
            let ip = Ipv4Addr::from(bits).to_ipv6_mapped();
            prop_assert!(parse_address(&ip.to_string()).is_err());
            let compat = Ipv6Addr::from(u128::from(bits));
            if bits > 1 {
                prop_assert!(parse_address(&compat.to_string()).is_err());
            }
        }

        #[test]
        fn network_round_trip(bits: u32, prefix in 0u8..=32) {
            let cleared = Ipv4Addr::from(bits & mask32(prefix));
            let text = format!("{cleared}/{prefix}");
            if let Ok(network) = parse_network(&text) {
                let shown = network.to_string();
                prop_assert_eq!(parse_network(&shown), Ok(network));
                prop_assert!(network.contains(IpAddr::V4(cleared)));
            }
            if prefix < 32 && bits & !mask32(prefix) != 0 {
                let dirty = format!("{}/{prefix}", Ipv4Addr::from(bits));
                prop_assert!(parse_network(&dirty).is_err());
            }
        }

        #[test]
        fn target_round_trip(bits: u32, port in 1u16..=65535, udp: bool) {
            let protocol = if udp { Protocol::Udp } else { Protocol::Tcp };
            let target = Target { ip: IpAddr::V4(Ipv4Addr::from(bits)), port, protocol };
            prop_assert_eq!(target.to_string().parse::<Target>(), Ok(target));
            let v6 = Target { ip: IpAddr::V6(Ipv6Addr::from(u128::from(bits) << 64)), port, protocol };
            prop_assert_eq!(v6.to_string().parse::<Target>(), Ok(v6));
        }
    }
}
