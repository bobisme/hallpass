//! How two pass files differ when their declared fields are the same.
//!
//! Comments and layout are part of the signed and digested bytes, so two
//! revisions can have different digests and the same declared fields. A
//! reviewer then needs to know what did change.
use std::collections::BTreeMap;
use std::ops::Range;

use serde::Serialize;
use toml::de::{DeTable, DeValue};

use super::DiffReport;

/// Comments were added, removed, changed or moved.
pub const COMMENTS: &str = "comments";
/// Whitespace, line breaks, key order or the form of a table or list.
pub const LAYOUT: &str = "layout";
/// A value is written another way: a time with another offset, a list in
/// another order, or another form of the same number or text.
pub const VALUE_SPELLING: &str = "value-spelling";

/// What differs between two files with the same declared fields.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TextChanges {
    /// Each kind of change found, in this order: `comments`, `layout`,
    /// `value-spelling`. Empty when the files are the same.
    pub kinds: Vec<&'static str>,
    /// The comments in only one of the files: OLD's first, then NEW's.
    pub comments: Vec<CommentChange>,
}

/// A comment that only one of the two files has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommentChange {
    /// `removed` (only OLD has it) or `added` (only NEW has it).
    pub change: &'static str,
    /// The line it is on: in OLD when removed, in NEW when added. Counted from 1.
    pub line: usize,
    /// The comment as written, from `#` to the end of the line.
    pub text: String,
}

impl DiffReport {
    /// No declared field, destination, destination order or approval ID
    /// differs. The bytes, and so the digests, may still differ: see
    /// [`text_changes`].
    #[must_use]
    pub const fn same_declared_fields(&self) -> bool {
        !self.approval_changed
            && !self.order_changed
            && self.changes.is_empty()
            && self.introduced.is_empty()
            && self.removed.is_empty()
    }
}

/// Each comment in `text`, as its byte range from `#` to the end of the
/// line and its line number. A `#` inside a string or a quoted key is text,
/// not a comment.
fn comments(text: &str) -> Vec<(Range<usize>, usize)> {
    let bytes = text.as_bytes();
    let end_of_line = |from: usize| {
        let end = bytes[from..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |n| from + n);
        if end > from && bytes[end - 1] == b'\r' {
            end - 1
        } else {
            end
        }
    };
    let mut out = Vec::new();
    let (mut i, mut line) = (0, 1);
    while let Some(&byte) = bytes.get(i) {
        match byte {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'#' => {
                let end = end_of_line(i);
                out.push((i..end, line));
                i = end;
            }
            b'"' | b'\'' => {
                let end = string_end(bytes, i);
                line += text.get(i..end).map_or(0, |s| s.matches('\n').count());
                i = end;
            }
            _ => i += 1,
        }
    }
    out
}

/// The end of the string that starts at `start`: basic (`"`) or literal
/// (`'`), on one line or, tripled, on several.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let escapes = quote == b'"';
    let triple = [quote; 3];
    let mut i;
    if bytes[start..].starts_with(&triple) {
        i = start + 3;
        while i < bytes.len() {
            if escapes && bytes[i] == b'\\' {
                i += 2;
            } else if bytes[i..].starts_with(&triple) {
                // Up to two more quotes before the closing three belong to the text.
                i += 3;
                for _ in 0..2 {
                    if bytes.get(i) == Some(&quote) {
                        i += 1;
                    }
                }
                return i;
            } else {
                i += 1;
            }
        }
    } else {
        i = start + 1;
        while let Some(&byte) = bytes.get(i) {
            if byte == quote {
                return i + 1;
            }
            if byte == b'\n' {
                return i;
            }
            i += if escapes && byte == b'\\' { 2 } else { 1 };
        }
    }
    i.min(bytes.len())
}

/// Every scalar value, by its path, as written; and the byte ranges written.
fn values(text: &str) -> (BTreeMap<String, String>, Vec<Range<usize>>) {
    fn walk(
        text: &str,
        value: &DeValue<'_>,
        span: Range<usize>,
        path: String,
        out: &mut (BTreeMap<String, String>, Vec<Range<usize>>),
    ) {
        match value {
            DeValue::Table(table) => {
                for (key, value) in table {
                    let path = format!("{path}.{}", key.get_ref());
                    walk(text, value.get_ref(), value.span(), path, out);
                }
            }
            DeValue::Array(array) => {
                for (i, value) in array.iter().enumerate() {
                    walk(
                        text,
                        value.get_ref(),
                        value.span(),
                        format!("{path}[{i}]"),
                        out,
                    );
                }
            }
            _ => {
                out.0
                    .insert(path, text.get(span.clone()).unwrap_or_default().to_owned());
                out.1.push(span);
            }
        }
    }
    let mut out = (BTreeMap::new(), Vec::new());
    if let Ok(table) = DeTable::parse(text) {
        for (key, value) in table.get_ref() {
            let path = key.get_ref().to_string();
            walk(text, value.get_ref(), value.span(), path, &mut out);
        }
    }
    out
}

/// `text` without its comments, and with each scalar value replaced by one
/// placeholder, so what is left is the layout. A line that held only a
/// comment is dropped; the spaces before a comment at the end of a line go
/// with it.
fn skeleton(text: &str, comments: &[(Range<usize>, usize)], values: &[Range<usize>]) -> String {
    const VALUE: char = '\u{0}';
    const COMMENT: char = '\u{1}';
    let mut cuts: Vec<(Range<usize>, char)> = comments
        .iter()
        .map(|(range, _)| (range.clone(), COMMENT))
        .chain(values.iter().map(|range| (range.clone(), VALUE)))
        .collect();
    cuts.sort_by_key(|(range, _)| range.start);
    let mut marked = String::with_capacity(text.len());
    let mut at = 0;
    for (range, mark) in cuts {
        if range.start < at {
            continue;
        }
        marked.push_str(text.get(at..range.start).unwrap_or_default());
        marked.push(mark);
        at = range.end;
    }
    marked.push_str(text.get(at..).unwrap_or_default());
    let mut out = String::with_capacity(marked.len());
    for line in marked.split('\n') {
        if line.contains(COMMENT) {
            let kept = line.replace(COMMENT, "");
            let kept = kept.trim_end();
            if !kept.is_empty() {
                out.push_str(kept);
                out.push('\n');
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// The comments of `a` that `b` does not have, one for one, in `a`'s order.
fn unmatched(
    change: &'static str,
    a: (&str, &[(Range<usize>, usize)]),
    b: (&str, &[(Range<usize>, usize)]),
) -> Vec<CommentChange> {
    let text_of = |text: &str, range: &Range<usize>| {
        text.get(range.clone())
            .unwrap_or_default()
            .trim_end()
            .to_owned()
    };
    let mut left = BTreeMap::<String, usize>::new();
    for (range, _) in b.1 {
        *left.entry(text_of(b.0, range)).or_default() += 1;
    }
    let mut out = Vec::new();
    for (range, line) in a.1 {
        let text = text_of(a.0, range);
        match left.get_mut(&text) {
            Some(count) if *count > 0 => *count -= 1,
            _ => out.push(CommentChange {
                change,
                line: *line,
                text,
            }),
        }
    }
    out
}

/// What differs between two pass texts whose declared fields are the same:
/// the kinds of change, and the comments only one of them has. A comment
/// that changed is one removed and one added.
#[must_use]
pub fn text_changes(old: &str, new: &str) -> TextChanges {
    if old == new {
        return TextChanges::default();
    }
    let (old_comments, new_comments) = (comments(old), comments(new));
    let mut changed = unmatched("removed", (old, &old_comments), (new, &new_comments));
    changed.extend(unmatched(
        "added",
        (new, &new_comments),
        (old, &old_comments),
    ));
    let (old_values, old_spans) = values(old);
    let (new_values, new_spans) = values(new);
    let mut kinds = Vec::new();
    if !changed.is_empty() {
        kinds.push(COMMENTS);
    }
    if skeleton(old, &old_comments, &old_spans) != skeleton(new, &new_comments, &new_spans) {
        kinds.push(LAYOUT);
    }
    if old_values != new_values {
        kinds.push(VALUE_SPELLING);
    }
    if kinds.is_empty() {
        // The same comments, moved to other lines.
        fn lines<'a>(text: &'a str, list: &[(Range<usize>, usize)]) -> Vec<(&'a str, usize)> {
            list.iter()
                .map(|(range, line)| {
                    (
                        text.get(range.clone()).unwrap_or_default().trim_end(),
                        *line,
                    )
                })
                .collect()
        }
        kinds.push(if lines(old, &old_comments) == lines(new, &new_comments) {
            LAYOUT
        } else {
            COMMENTS
        });
    }
    TextChanges {
        kinds,
        comments: changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_in_a_string_or_key_is_not_a_comment() {
        let text = "a = \"x # y\" # one\n\"k#\" = 'z#'\nb = \"\"\"\n# in\n\"\"\"\" # two\nc = '''#''' # three\n";
        let found: Vec<_> = comments(text)
            .into_iter()
            .map(|(range, line)| (&text[range], line))
            .collect();
        assert_eq!(found, [("# one", 1), ("# two", 5), ("# three", 6)]);
    }

    #[test]
    fn kinds_are_told_apart() {
        let base = "a = 1\nb = 2026-11-20T08:00:00Z\n";
        let comment = text_changes(base, &format!("{base}# note\n"));
        assert_eq!(comment.kinds, [COMMENTS]);
        assert_eq!(
            comment.comments,
            [CommentChange {
                change: "added",
                line: 3,
                text: "# note".to_owned()
            }]
        );
        let trailing = text_changes(base, "a = 1 # note\nb = 2026-11-20T08:00:00Z\n");
        assert_eq!(trailing.kinds, [COMMENTS]);
        assert_eq!(
            text_changes(base, "b = 2026-11-20T08:00:00Z\na = 1\n").kinds,
            [LAYOUT]
        );
        assert_eq!(
            text_changes(base, "a = 1\nb = 2026-11-20T09:00:00+01:00\n").kinds,
            [VALUE_SPELLING]
        );
        assert_eq!(
            text_changes(base, "a =  1\n\nb = 2026-11-20T08:00:00Z\n").kinds,
            [LAYOUT]
        );
        let moved = text_changes("# x\na = 1\n", "a = 1\n# x\n");
        assert_eq!(moved.kinds, [COMMENTS]);
        assert_eq!(moved.comments.len(), 0);
        let edited = text_changes("a = 1 # old\n", "a = 1 # new\n");
        assert_eq!(edited.comments.len(), 2);
        assert_eq!(edited.comments[0].change, "removed");
        assert_eq!(text_changes(base, base).kinds.len(), 0);
    }
}
