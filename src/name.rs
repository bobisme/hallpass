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
/// wildcards, and not an IP address. An internationalized name is written
/// in its `xn--` form.
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
