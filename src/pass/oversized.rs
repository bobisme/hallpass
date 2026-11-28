//! Name the field of an integer that is too large for the TOML reader.
//!
//! The reader stops at an integer outside 64 bits and says only that the file
//! is not valid TOML. [`scan`] finds each such integer on a `key = value`
//! line before parsing, records its problem with the field and its rule, and
//! puts a placeholder in its place, so the rest of the file is still checked.
//! [`problem`] handles the same integer when the reader reports it in some
//! other shape (an inline table or an array), and is the fallback.

use super::{FORMAT_VERSION, MAX_CEILING, Problem};

/// Replace each `key = integer` line whose integer does not fit in 64 bits
/// with a placeholder, and return the text to parse with one problem for
/// each replaced integer, in file order.
///
/// Only a whole line `key = integer` is read: a bare key, an integer with an
/// optional sign and digits (and `_` between them), then a space, a comment
/// or the end of the line. Lines inside a multi-line string are skipped.
/// Inline tables and arrays are not read here; [`problem`] covers the
/// reader's report for them.
pub fn scan(text: &str) -> (String, Vec<Problem>) {
    let mut out = String::with_capacity(text.len());
    let mut problems = Vec::new();
    let mut table = String::new();
    let mut destinations = 0_usize;
    let mut multiline = false;
    for raw in text.split_inclusive('\n') {
        let line = raw.trim_end_matches(['\r', '\n']);
        let ending = &raw[line.len()..];
        if multiline {
            out.push_str(raw);
        } else {
            match rewrite(line, &mut table, &mut destinations, &mut problems) {
                Some(new) => out.push_str(&new),
                None => out.push_str(line),
            }
            out.push_str(ending);
        }
        // An odd count of multi-line string delimiters opens or closes one.
        let delimiters = line.matches("\"\"\"").count() + line.matches("'''").count();
        if delimiters % 2 == 1 {
            multiline = !multiline;
        }
    }
    (out, problems)
}

/// The rewritten line when it holds an out-of-range integer, else `None`.
/// Also tracks the current table, as [`problem`] does.
fn rewrite(
    line: &str,
    table: &mut String,
    destinations: &mut usize,
    problems: &mut Vec<Problem>,
) -> Option<String> {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix("[[") {
        rest.split("]]")
            .next()
            .unwrap_or_default()
            .trim()
            .clone_into(table);
        if table == "destination" {
            *destinations += 1;
        }
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        rest.split(']')
            .next()
            .unwrap_or_default()
            .trim()
            .clone_into(table);
        return None;
    }
    let (key, value) = trimmed.split_once('=')?;
    let key = key.trim_end();
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return None;
    }
    let value = value.trim_start();
    // The value is the end of the line, so its offset is the line's length
    // minus the value's.
    let start = line.len() - value.len();
    let bytes = value.as_bytes();
    let mut end = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'_') {
        end += 1;
    }
    let literal = &value[..end];
    if !literal.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }
    if !matches!(value[end..].chars().next(), None | Some(' ' | '\t' | '#')) {
        return None;
    }
    let plain: String = literal.chars().filter(|c| *c != '_').collect();
    if plain.parse::<i64>().is_ok() {
        return None;
    }
    problems.push(describe(table, key, *destinations, literal));
    Some(format!(
        "{}{}{}",
        &line[..start],
        placeholder(table, key),
        &value[end..]
    ))
}

/// A value that reads as a valid one for its field, so the field itself
/// adds no second problem. Its problem is dropped by the caller anyway.
fn placeholder(table: &str, key: &str) -> String {
    match (table, key) {
        ("", "format") => FORMAT_VERSION.to_string(),
        ("destination", "ports") => "1".to_owned(),
        _ => "0".to_owned(),
    }
}

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
    Some(describe(&table, key, destinations, &number))
}

/// The field and rule for the integer `number` given for `key` in `table`
/// (`""` at the top level), where `destinations` `[[destination]]` tables
/// came before it.
fn describe(table: &str, key: &str, destinations: usize, number: &str) -> Problem {
    let (field, rule) = match table {
        "" if key == "format" => (
            key.to_owned(),
            format!(
                "is {number}, but this hallpass reads format {FORMAT_VERSION}; write `format = {FORMAT_VERSION}` or use a hallpass that reads this format"
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
    Problem {
        field,
        message: rule,
    }
}
