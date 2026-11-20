//! Host names: the optional `names` restriction on a destination.
//!
//! A name never grants anything. A destination that lists names is allowed
//! only for a query that carries one of them; the address, protocol and
//! port must be listed as well. hallpass never resolves a name.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// The most names one destination may list.
pub const MAX_NAMES: usize = 64;

/// A DNS host name in canonical form.
///
/// ASCII lower case, no trailing dot, at most 253 characters, labels of 1
/// to 63 letters, digits, `-` or `_` that do not start or end with `-`. No
/// wildcards, not an IP address, and not a name whose last label is a
/// number (tools read `10.1` or `0x7f000001` as an IPv4 address). An
/// internationalized name is written in its `xn--` form.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

impl HostName {
    /// The canonical text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads a name exactly as a pass must spell it: already canonical.
    ///
    /// # Errors
    ///
    /// Says what is wrong and how to write it.
    pub fn canonical(text: &str) -> Result<Self, String> {
        let name: Self = text.parse()?;
        if name.0 == text {
            Ok(name)
        } else {
            Err(format!(
                "`{text}` is not in canonical form; write it as `{}` (lower case, no trailing dot)",
                name.0
            ))
        }
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// True when the last dot-separated part of `text` is a number: all digits,
/// or `0x` and hexadecimal digits. `inet_aton` and URL parsers read such a
/// host as an IPv4 address (`2130706433`, `0x7f.0.0.1`, `10.1`,
/// `010.0.0.1`), so it is never a host name here. No top-level domain is a
/// number.
pub(crate) fn ends_in_number(text: &str) -> bool {
    let last = text.rsplit('.').next().unwrap_or(text);
    let hex = last.strip_prefix("0x").or_else(|| last.strip_prefix("0X"));
    (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
        || hex.is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Reads a name as a tool would ask about it: upper case and one trailing
/// dot are accepted and removed.
impl FromStr for HostName {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            return Err("the name is empty".to_owned());
        }
        if !text.is_ascii() {
            return Err(format!(
                "`{}` has non-ASCII characters; write an internationalized name in its `xn--` form",
                text.escape_default()
            ));
        }
        if text.contains('*') {
            return Err(format!(
                "`{text}` has a wildcard; every approved name is written out in full"
            ));
        }
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        if trimmed.parse::<IpAddr>().is_ok() {
            return Err(format!(
                "`{text}` is an address, not a name; addresses go in `address` or `network`"
            ));
        }
        if ends_in_number(trimmed) {
            return Err(format!(
                "`{text}` ends in a number, so tools read it as an IPv4 address (in a shortened, octal or hexadecimal spelling) and not as a name; write the host name, and put an address in `address` or `network`"
            ));
        }
        if trimmed.len() > 253 {
            return Err("the name is longer than 253 characters".to_owned());
        }
        for label in trimmed.split('.') {
            let ok = (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !label.starts_with('-')
                && !label.ends_with('-');
            if !ok {
                return Err(format!(
                    "`{}` is not a DNS name: each dot-separated part is 1-63 letters, digits, `-` or `_`, and does not start or end with `-`",
                    text.escape_default()
                ));
            }
        }
        Ok(Self(trimmed.to_ascii_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_is_normalized() {
        let name: HostName = "App.Example.COM.".parse().expect("valid");
        assert_eq!(name.as_str(), "app.example.com");
        assert_eq!(name.to_string(), "app.example.com");
    }

    #[test]
    fn a_pass_must_spell_the_canonical_form() {
        assert!(HostName::canonical("app.example.com").is_ok());
        assert!(HostName::canonical("xn--bcher-kva.example").is_ok());
        for bad in ["App.example.com", "app.example.com."] {
            let message = HostName::canonical(bad).expect_err(bad);
            assert!(message.contains("`app.example.com`"), "{message}");
        }
    }

    #[test]
    fn names_that_are_not_host_names_are_refused() {
        let long_label = "a".repeat(64);
        let long_name = format!("{}.example", "a.".repeat(126));
        for bad in [
            "",
            ".",
            "*.example.com",
            "a..b",
            "-a.example",
            "a-.example",
            "a b.example",
            "bücher.example",
            "192.0.2.10",
            "192.0.2.10.",
            "2001:db8::1",
            "a/b",
            "a:443",
            "a\n.example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(bad.parse::<HostName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn spellings_that_tools_read_as_ipv4_are_not_names() {
        // The address parser refuses these as ambiguous addresses; a name
        // must not let them back in. inet_aton and URL parsers read a host
        // whose last part is a number as an IPv4 address.
        for bad in [
            "010.0.0.1",
            "10.1",
            "192.0.2",
            "2130706433",
            "0x7f.0.0.1",
            "0x7f000001",
            "0X7F000001",
            "1.2.3.4.5",
            "example.123",
            "example.0x1f",
            "foo.0x",
            "2130706433.",
        ] {
            let message = bad.parse::<HostName>().expect_err(bad);
            assert!(message.contains("ends in a number"), "{bad}: {message}");
            assert!(HostName::canonical(bad).is_err(), "{bad}");
        }
        // A number elsewhere, or letters in the last part, is a name.
        for good in [
            "1.example",
            "123.example.com",
            "0x7f.example",
            "a.x1",
            "a.1a",
        ] {
            assert!(good.parse::<HostName>().is_ok(), "{good}");
        }
    }

    #[test]
    fn single_labels_and_underscores_are_names() {
        for good in [
            "intranet",
            "_sip._tcp.example.net",
            "a1.example",
            "1a.example",
        ] {
            assert!(good.parse::<HostName>().is_ok(), "{good}");
        }
    }
}
