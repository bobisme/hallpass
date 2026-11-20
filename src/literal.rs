//! One spelling per value, as written in the file.
//!
//! TOML reads `0x10`, `0o17`, `0b110`, `1_0` and `+6` as integers, and
//! `"192.0.2.1\u0030"` as the text `192.0.2.10`. The parsed value hides how
//! it was written, so a reviewer could read one thing and the tool use
//! another. This pass over the source text refuses those spellings: numbers
//! are plain decimal digits, and a string is written with the characters it
//! holds (`\"` and `\\` are the only escapes that get through; the named
//! control characters such as `\n` are refused by each field's own rule).

use toml::de::{DeTable, DeValue};

use crate::pass::Problem;

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
}
