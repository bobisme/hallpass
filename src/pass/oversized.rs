//! Name the field of an integer that is too large for the TOML reader.
//!
//! The reader stops at an integer outside 64 bits and says only that the file
//! is not valid TOML. This finds the key and table of that line, so the
//! problem names the field and gives its rule, as for any other bad value.

use super::{MAX_CEILING, Problem};

/// The problem for an out-of-range integer at byte `start` of `text`, or
/// `None` when the error is about anything else (or the line cannot be read).
pub fn problem(text: &str, start: usize, message: &str) -> Option<Problem> {
    if !(message.contains("too large") || message.contains("as i128")) {
        return None;
    }
    let before = text.get(..start)?;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let rest = text.get(line_start..)?;
    let line = rest.lines().next()?;
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    let number: String = value
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
        .collect();
    if number.is_empty() {
        return None;
    }
    let mut table = String::new();
    let mut destinations = 0_usize;
    for l in before.lines() {
        let l = l.trim();
        if let Some(name) = l.strip_prefix("[[").and_then(|r| r.split("]]").next()) {
            name.trim().clone_into(&mut table);
            if table == "destination" {
                destinations += 1;
            }
        } else if let Some(name) = l.strip_prefix('[').and_then(|r| r.split(']').next()) {
            name.trim().clone_into(&mut table);
        }
    }
    let (field, rule) = match table.as_str() {
        "" if key == "format" => (
            key.to_owned(),
            format!(
                "is {number}, but this hallpass reads format {}; write `format = {}` or use a hallpass that reads this format",
                super::FORMAT_VERSION,
                super::FORMAT_VERSION
            ),
        ),
        "ceilings" => (
            format!("ceilings.{key}"),
            format!(
                "{number} is not a whole number from 0 to {MAX_CEILING}; write a ceiling in that range"
            ),
        ),
        "destination" if key == "ports" => (
            format!("destination[{destinations}].{key}"),
            format!(
                "{number} is not a port; write a port 1-65535 (443) or a range (\"8000-8100\")"
            ),
        ),
        "" => (
            key.to_owned(),
            format!(
                "{number} is larger than a whole number a pass can hold (9223372036854775807); write a smaller number or check the field"
            ),
        ),
        "destination" => (
            format!("destination[{destinations}].{key}"),
            format!(
                "{number} is larger than a whole number a pass can hold (9223372036854775807); write a smaller number or check the field"
            ),
        ),
        other => (
            format!("{other}.{key}"),
            format!(
                "{number} is larger than a whole number a pass can hold (9223372036854775807); write a smaller number or check the field"
            ),
        ),
    };
    Some(Problem {
        field,
        message: rule,
    })
}
