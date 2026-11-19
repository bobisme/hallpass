//! Port sets: one port, a list, or ranges.

use std::fmt;

use crate::address::parse_port;

/// A non-empty set of ports, kept as the inclusive ranges the pass wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortSet {
    ranges: Vec<(u16, u16)>,
}

impl PortSet {
    /// Build a set from inclusive ranges.
    ///
    /// # Errors
    ///
    /// An empty list, port 0, or a range whose start is above its end.
    pub fn from_ranges(ranges: Vec<(u16, u16)>) -> Result<Self, String> {
        if ranges.is_empty() {
            return Err("the port list is empty; name at least one port".to_owned());
        }
        for (start, end) in &ranges {
            if *start == 0 {
                return Err("port 0 is not a destination port; use 1-65535".to_owned());
            }
            if start > end {
                return Err(format!(
                    "the range {start}-{end} starts above its end; write the lower port first"
                ));
            }
        }
        Ok(Self { ranges })
    }

    /// The inclusive ranges, in the order written.
    #[must_use]
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.ranges
    }

    /// True when `port` is in the set.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.ranges.iter().any(|(s, e)| (*s..=*e).contains(&port))
    }

    /// Parse one element written as a string: `"443"` or `"8000-8100"`.
    ///
    /// # Errors
    ///
    /// Anything other than decimal ports 1-65535 without spaces, signs or
    /// leading zeros, joined by one `-`.
    pub fn parse_element(text: &str) -> Result<(u16, u16), String> {
        let bad = || {
            format!(
                "`{text}` is not a port or range; write a port 1-65535 (443) or a range (\"8000-8100\") without spaces or leading zeros"
            )
        };
        let (start, end) = if let Some((a, b)) = text.split_once('-') {
            (
                parse_port(a).ok_or_else(bad)?,
                parse_port(b).ok_or_else(bad)?,
            )
        } else {
            let port = parse_port(text).ok_or_else(bad)?;
            (port, port)
        };
        if start > end {
            return Err(format!(
                "the range `{text}` starts above its end; write the lower port first"
            ));
        }
        Ok((start, end))
    }
}

impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (start, end)) in self.ranges.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            if start == end {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn elements() {
        assert_eq!(PortSet::parse_element("443"), Ok((443, 443)));
        assert_eq!(PortSet::parse_element("8000-8100"), Ok((8000, 8100)));
        for bad in [
            "", "0", "0443", "65536", "-1", "+5", "1 - 2", "5-", "-5", "9-3", "1-2-3", "a",
        ] {
            assert!(PortSet::parse_element(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sets() {
        let set = PortSet::from_ranges(vec![(80, 80), (8000, 8100)]).expect("valid");
        assert!(set.contains(80));
        assert!(set.contains(8050));
        assert!(!set.contains(81));
        assert_eq!(set.to_string(), "80, 8000-8100");
        assert!(PortSet::from_ranges(vec![]).is_err());
        assert!(PortSet::from_ranges(vec![(0, 5)]).is_err());
        assert!(PortSet::from_ranges(vec![(9, 5)]).is_err());
    }

    proptest! {
        #[test]
        fn element_round_trip(a in 1u16..=65535, b in 1u16..=65535) {
            let (start, end) = (a.min(b), a.max(b));
            let text = if start == end { format!("{start}") } else { format!("{start}-{end}") };
            prop_assert_eq!(PortSet::parse_element(&text), Ok((start, end)));
            let set = PortSet::from_ranges(vec![(start, end)]).expect("valid");
            prop_assert_eq!(set.to_string(), text);
            prop_assert!(set.contains(start) && set.contains(end));
        }

        #[test]
        fn leading_zero_refused(port in 1u16..=65535) {
            let padded = format!("0{port}");
            prop_assert!(PortSet::parse_element(&padded).is_err());
        }

        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,12}") {
            let _ = PortSet::parse_element(&text);
        }
    }
}
