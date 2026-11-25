//! One spelling per value, as written in the file.
//!
//! TOML reads `0x10`, `0o17`, `0b110`, `1_0` and `+6` as integers, and
//! `"192.0.2.1\u0030"` as the text `192.0.2.10`. The parsed value hides how
//! it was written, so a reviewer could read one thing and the tool use
//! another. This pass over the source text refuses those spellings: numbers
//! are plain decimal digits, and a string is written with the characters it
//! holds (`\"` and `\\` are the only escapes that get through; the named
//! control characters such as `\n` are refused by each field's own rule).
//!
//! The file itself may hold no character that can make it display as
//! something else ([`hidden_characters`]), comments included: a reviewer
//! and the owner read every byte of it.

use toml::de::{DeTable, DeValue};

use crate::ledger::{describe_disguising, is_disguising};
use crate::pass::Problem;

/// The most characters [`hidden_characters`] reports one by one; one more
/// problem counts the rest.
const MAX_HIDDEN_REPORTED: usize = 16;

/// Whether `c` may not appear in a pass file: a control character other
/// than a tab or a line feed, or a character that can make text display as
/// something else ([`is_disguising`]). These are the characters text output
/// escapes, but for the tab and the line feed. A carriage return is allowed
/// only where it ends a line before a line feed, which the caller checks.
fn is_hidden(c: char) -> bool {
    (c.is_control() && c != '\t' && c != '\n') || is_disguising(c)
}

/// Every character of `text` that [`is_hidden`] refuses, outside string
/// values: in comments, keys, whitespace and anywhere TOML cannot read, each
/// with its line and column (both from 1, the column in characters). A
/// string value is left to its field's own rule, which names the field.
pub fn hidden_characters(text: &str) -> Vec<Problem> {
    let mut found = Vec::new();
    let (mut line, mut column) = (1, 0);
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        column += 1;
        if c == '\n' {
            line += 1;
            column = 0;
        } else if is_hidden(c) && !(c == '\r' && chars.peek().is_some_and(|(_, n)| *n == '\n')) {
            found.push((at, line, column, c));
        }
    }
    if found.is_empty() {
        return Vec::new();
    }
    let mut strings = Vec::new();
    if let Ok(table) = DeTable::parse(text) {
        string_spans(table.get_ref(), &mut strings);
    }
    // The spans do not overlap: sorted, the one that could hold a character
    // is the last that starts at or before it.
    strings.sort_unstable_by_key(|span| span.start);
    found.retain(|(at, ..)| {
        let after = strings.partition_point(|span| span.start <= *at);
        !after
            .checked_sub(1)
            .and_then(|i| strings.get(i))
            .is_some_and(|span| span.contains(at))
    });
    let mut out: Vec<Problem> = found
        .iter()
        .take(MAX_HIDDEN_REPORTED)
        .map(|&(at, line, column, c)| Problem {
            field: "(file)".to_owned(),
            message: hidden_message(at, line, column, c),
        })
        .collect();
    if let Some(&(_, line, column, _)) = found.get(MAX_HIDDEN_REPORTED - 1)
        && found.len() > MAX_HIDDEN_REPORTED
    {
        out.push(Problem {
            field: "(file)".to_owned(),
            message: format!(
                "{} more characters like these follow line {line}, column {column}; delete them too",
                found.len() - MAX_HIDDEN_REPORTED
            ),
        });
    }
    out
}

/// The problem for hidden character `c` at byte `at`, line `line` and
/// column `column`.
fn hidden_message(at: usize, line: usize, column: usize, c: char) -> String {
    const AFTER: &str = "then have the owner approve the edited file";
    if at == 0 && c == '\u{feff}' {
        return format!(
            "the file starts with a byte order mark (U+FEFF), an invisible character; save the file as UTF-8 without one, {AFTER}"
        );
    }
    if c.is_control() {
        return format!(
            "line {line}, column {column} holds a control character (U+{:04X}), and a pass may hold no control character other than a tab or a line end; delete it, {AFTER}",
            u32::from(c)
        );
    }
    format!(
        "line {line}, column {column} holds {}, which can make the file display as something else; delete it, {AFTER}",
        describe_disguising(c)
    )
}

/// The byte ranges of every string value in `table`, in arrays and inner
/// tables too.
fn string_spans(table: &DeTable<'_>, out: &mut Vec<std::ops::Range<usize>>) {
    for value in table.values() {
        value_spans(value.get_ref(), value.span(), out);
    }
}

fn value_spans(
    value: &DeValue<'_>,
    span: std::ops::Range<usize>,
    out: &mut Vec<std::ops::Range<usize>>,
) {
    match value {
        DeValue::String(_) => out.push(span),
        DeValue::Array(items) => {
            for item in items {
                value_spans(item.get_ref(), item.span(), out);
            }
        }
        DeValue::Table(table) => string_spans(table, out),
        _ => {}
    }
}

/// Every value or key in `text` whose spelling hides what it holds. Empty
/// when the text is not TOML at all: the caller reports the syntax error.
pub fn problems(text: &str) -> Vec<Problem> {
    let Ok(table) = DeTable::parse(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_table(text, table.get_ref(), "", &mut out);
    out
}

fn walk_table(text: &str, table: &DeTable<'_>, prefix: &str, out: &mut Vec<Problem>) {
    for (key, value) in table {
        let field = if prefix.is_empty() {
            key.get_ref().to_string()
        } else {
            format!("{prefix}.{}", key.get_ref())
        };
        if let Some(escape) = escape_in(text.get(key.span()).unwrap_or_default()) {
            out.push(Problem {
                field: field.clone(),
                message: format!(
                    "the key is written with {escape}; write the key in plain characters, so a reviewer reads the name hallpass reads"
                ),
            });
        }
        walk_value(text, value.get_ref(), value.span(), &field, out);
    }
}

fn walk_value(
    text: &str,
    value: &DeValue<'_>,
    span: std::ops::Range<usize>,
    field: &str,
    out: &mut Vec<Problem>,
) {
    let raw = text.get(span).unwrap_or_default();
    match value {
        DeValue::Integer(integer) if !is_plain_decimal(raw) => {
            let decimal = i128::from_str_radix(integer.as_str(), integer.radix())
                .map_or_else(|_| String::new(), |n| format!(" (TOML reads it as {n})"));
            out.push(Problem {
                field: field.to_owned(),
                message: format!(
                    "is written as `{raw}`{decimal}; write the number in plain decimal digits, without a sign, `_` or a base prefix such as 0x, so a reviewer reads the number hallpass uses"
                ),
            });
        }
        DeValue::String(_) => {
            if let Some(escape) = escape_in(raw) {
                out.push(Problem {
                    field: field.to_owned(),
                    message: format!(
                        "is written with {escape}; write the characters themselves (the file is UTF-8), so a reviewer reads the text hallpass uses. Only \\\" and \\\\ are accepted as escapes"
                    ),
                });
            }
        }
        DeValue::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let at = format!("{field}[{}]", i + 1);
                walk_value(text, item.get_ref(), item.span(), &at, out);
            }
        }
        DeValue::Table(table) => walk_table(text, table, field, out),
        _ => {}
    }
}

/// `0`, or digits that do not start with `0`, with an optional `-` (a
/// negative number is refused later, where the field is known).
fn is_plain_decimal(raw: &str) -> bool {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
}

/// The first escape in a double-quoted string as written, other than `\"`
/// and `\\`, in words. Single-quoted (literal) strings have no escapes.
fn escape_in(raw: &str) -> Option<String> {
    if !raw.starts_with('"') {
        return None;
    }
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            continue;
        }
        match chars.next() {
            // The named control characters (\n, \t, ...) are left to the
            // field's own rule, which refuses the control character itself
            // in every string a pass has; reporting both would say it twice.
            Some('"' | '\\' | 'b' | 't' | 'n' | 'f' | 'r' | 'e') => {}
            Some(next) if next.is_ascii_graphic() => {
                return Some(format!("the escape `\\{next}`"));
            }
            _ => return Some("a line-continuation escape (a backslash at a line end)".to_owned()),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_decimal() {
        for good in ["0", "6", "65535", "-1", "1000000000000"] {
            assert!(is_plain_decimal(good), "{good}");
        }
        for bad in ["", "+6", "0x10", "0o17", "0b1", "1_000", "-", "007", "6 "] {
            assert!(!is_plain_decimal(bad), "{bad}");
        }
    }

    #[test]
    fn escapes() {
        assert_eq!(escape_in(r#""plain \"quoted\" C:\\dir""#), None);
        assert_eq!(escape_in(r"'literal \u0041'"), None);
        assert!(escape_in(r#""a\u0041""#).is_some());
        assert!(escape_in(r#""a\x41""#).is_some());
        assert_eq!(escape_in(r#""a\tb""#), None, "left to the control rule");
        assert!(escape_in("\"\"\"a\\\n  b\"\"\"").is_some());
    }

    #[test]
    fn text_that_is_not_toml_is_left_to_the_parser() {
        assert_eq!(problems("format = \n"), Vec::new());
    }

    /// One source of truth: a pass file refuses what text output escapes
    /// (the set `tests/text_safety.rs` pins), but for the tab, the line feed
    /// and the backslash, which output escapes so its escapes cannot be
    /// forged.
    #[test]
    fn a_file_refuses_what_text_output_escapes() {
        for c in (0..=0x10_ffff_u32).filter_map(char::from_u32) {
            let escaped = crate::ledger::display_safe(&c.to_string()) != c.to_string();
            let allowed = matches!(c, '\t' | '\n' | '\\');
            assert_eq!(is_hidden(c), escaped && !allowed, "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn hidden_characters_give_line_and_column_outside_strings() {
        // Valid TOML: the string value is left to its field.
        let text =
            "a = \"x\u{202e}\" # \u{202e}\n\tb = 1 # \u{a0}\r\n\"\u{200b}c\" = [\"\u{200b}\"]\r\n";
        let found = hidden_characters(text);
        let shown: Vec<&str> = found.iter().map(|p| p.message.as_str()).collect();
        assert_eq!(shown.len(), 3, "{shown:#?}");
        assert!(
            shown[0].starts_with("line 1, column 12 holds a bidirectional text control (U+202E)")
        );
        assert!(shown[1].starts_with("line 2, column 10 holds a look-alike space (U+00A0)"));
        assert!(shown[2].starts_with("line 3, column 2 holds a Unicode format character (U+200B)"));
        assert!(found.iter().all(|p| p.field == "(file)"));
        // A carriage return that does not end a line.
        let found = hidden_characters("a = 1 # x\ry\n");
        assert_eq!(found.len(), 1);
        assert!(
            found[0]
                .message
                .starts_with("line 1, column 10 holds a control character (U+000D)")
        );
    }

    #[test]
    fn a_file_that_is_not_toml_is_scanned_everywhere() {
        let found = hidden_characters("a = \"x\u{202e}\n");
        assert_eq!(found.len(), 1);
        assert!(found[0].message.starts_with("line 1, column 7 holds"));
    }

    #[test]
    fn many_hidden_characters_are_counted_after_the_first_sixteen() {
        let text = "# \u{a0}\n".repeat(20);
        let found = hidden_characters(&text);
        assert_eq!(found.len(), MAX_HIDDEN_REPORTED + 1);
        assert_eq!(
            found[MAX_HIDDEN_REPORTED].message,
            "4 more characters like these follow line 16, column 3; delete them too"
        );
        assert_eq!(hidden_characters(&"# \u{a0}\n".repeat(16)).len(), 16);
    }

    #[test]
    fn a_leading_byte_order_mark_is_named() {
        let found = hidden_characters("\u{feff}a = 1\n# \u{feff}\n");
        assert_eq!(found.len(), 2);
        assert!(
            found[0]
                .message
                .starts_with("the file starts with a byte order mark (U+FEFF)")
        );
        assert!(
            found[1]
                .message
                .starts_with("line 2, column 3 holds a Unicode format character (U+FEFF)")
        );
    }
}
