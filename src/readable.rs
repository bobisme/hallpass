//! Text output for people: paths shown from the current directory, and long
//! prose broken into one step per line.
//!
//! Only the text and pretty formats use these. JSON replies keep every path
//! absolute and every message on one line.
//!
//! - [`paths`] shows a path under the current directory relative to it
//!   (`a.pass.toml.ledger`, `state/hallpass/a.witness`). A path outside it
//!   stays absolute: there are no `../` paths, which read worse than the
//!   absolute path once they climb past a project. A relative path that
//!   would start with `-` or `~` gets `./`, so a command shown with it still
//!   runs as written when pasted in the same directory.
//! - [`prose`] puts the first sentence on the first line and each later
//!   sentence (and each `; if ...` or `; otherwise ...` alternative) on its
//!   own `- ` line. It changes only white space: joined with spaces, the
//!   lines are the message. A command in backticks, a parenthesis and a
//!   double-quoted value are never split.
//! - Long lines are wrapped at word boundaries only when both standard
//!   output and standard error are terminals, at 100 columns (or `COLUMNS`
//!   when it is smaller). A command in backticks is never wrapped. Piped
//!   output and tests see one line per step.

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::sync::OnceLock;

/// The widest a wrapped line gets on a terminal.
const WIDTH: usize = 100;

/// The current directory as prefixes to strip (`/dir/`), longest first:
/// the physical directory, and `PWD` when it names the same directory by
/// another path (a symbolic link). None at the root directory.
fn prefixes() -> &'static [String] {
    static PREFIXES: OnceLock<Vec<String>> = OnceLock::new();
    PREFIXES.get_or_init(|| {
        let mut found = Vec::new();
        let Ok(cwd) = std::env::current_dir() else {
            return found;
        };
        let mut dirs = vec![cwd.clone()];
        if let Some(pwd) = std::env::var_os("PWD").map(PathBuf::from)
            && pwd.is_absolute()
            && pwd != cwd
            && same_dir(&pwd, &cwd)
        {
            dirs.push(pwd);
        }
        for dir in dirs {
            let Some(text) = dir.to_str() else { continue };
            let text = text.trim_end_matches('/');
            if !text.is_empty() {
                found.push(format!("{text}/"));
            }
        }
        found.sort_by_key(|p| std::cmp::Reverse(p.len()));
        found
    })
}

#[cfg(unix)]
fn same_dir(a: &std::path::Path, b: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_dir(_: &std::path::Path, _: &std::path::Path) -> bool {
    false
}

/// A character that can be part of a path word: a prefix that follows one
/// is inside a longer path, not the start of one.
const fn in_path(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_' | '~' | '+' | '@' | '%')
}

/// `text` with each path under the current directory shown relative to it.
pub fn paths(text: &str) -> String {
    relative_to(text, prefixes())
}

fn relative_to(text: &str, prefixes: &[String]) -> String {
    if prefixes.is_empty() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    'scan: while let Some(at) = rest.find('/') {
        let starts_word = rest[..at].chars().next_back().is_none_or(|c| !in_path(c))
            && (at > 0 || out.chars().next_back().is_none_or(|c| !in_path(c)));
        if starts_word {
            for prefix in prefixes {
                let Some(tail) = rest[at..].strip_prefix(prefix.as_str()) else {
                    continue;
                };
                // The directory itself, or a name that cannot stand alone.
                let Some(first) = tail.chars().next().filter(|&c| in_path(c) && c != '/') else {
                    continue;
                };
                out.push_str(&rest[..at]);
                if matches!(first, '-' | '~') {
                    out.push_str("./");
                }
                rest = tail;
                continue 'scan;
            }
        }
        out.push_str(&rest[..=at]);
        rest = &rest[at + 1..];
    }
    out.push_str(rest);
    out
}

/// Words that end in a full stop without ending a sentence.
const ABBREVIATIONS: &[&str] = &["e.g", "i.e", "etc", "vs", "cf", "no"];

/// The message split into steps: the first sentence, then each later
/// sentence or alternative. Only spaces between steps are dropped.
pub fn steps(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut steps = Vec::new();
    let (mut tick, mut quote, mut depth) = (false, false, 0_usize);
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            // An escaped character in a quoted value is part of it.
            b'\\' if quote => {
                i += 2;
                continue;
            }
            b'`' if !quote => tick = !tick,
            b'"' if !tick => quote = !quote,
            b'(' if !tick && !quote => depth += 1,
            b')' if !tick && !quote => depth = depth.saturating_sub(1),
            _ => {}
        }
        let top = !tick && !quote && depth == 0;
        if top && bytes.get(i + 1) == Some(&b' ') {
            let after = text[i + 1..].trim_start();
            let ends = match b {
                b'.' | b'?' | b'!' => {
                    let word = text[start..i]
                        .rsplit(|c: char| c.is_whitespace() || c == '(')
                        .next()
                        .unwrap_or_default();
                    !after.is_empty()
                        && !ABBREVIATIONS.contains(&word.to_ascii_lowercase().as_str())
                }
                // An alternative after the first sentence: `; if ...`.
                b';' => {
                    !steps.is_empty()
                        && ["if ", "otherwise", "or ", "else"]
                            .iter()
                            .any(|w| after.starts_with(w))
                }
                _ => false,
            };
            if ends {
                steps.push(text[start..=i].trim());
                i += 1;
                while bytes.get(i) == Some(&b' ') {
                    i += 1;
                }
                start = i;
                continue;
            }
        }
        i += 1;
    }
    let last = text[start..].trim();
    if !last.is_empty() || steps.is_empty() {
        steps.push(last);
    }
    steps
}

/// `text` as lines: its first step after `first`, each later step after
/// `rest` and `- `. Paths are shown relative; lines end in a newline.
pub fn prose(text: &str, first: &str, rest: &str) -> String {
    lines(&same_path(&paths(text)), first, rest, wrap_width())
}

/// `text` with a path that is named again in its prose, as `at PATH`,
/// shown as `at the same path` ("the ledger X is missing ...; the ledger
/// was last seen at the same path"). A path in a command is never changed.
fn same_path(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut seen: Vec<&str> = Vec::new();
    let mut tick = false;
    let mut previous = "";
    for (n, token) in text.split(' ').enumerate() {
        if n > 0 {
            out.push(' ');
        }
        let prose = !tick && !token.contains('`');
        tick ^= token.matches('`').count() % 2 == 1;
        let core = token
            .trim_start_matches(['(', '"'])
            .trim_end_matches(['.', ',', ';', ':', ')', '"']);
        let path = prose && core.len() > 2 && (core.contains('/') || core.contains('.'));
        if path && previous == "at" && seen.contains(&core) {
            out.push_str(&token.replacen(core, "the same path", 1));
        } else {
            if path {
                seen.push(core);
            }
            out.push_str(token);
        }
        previous = token;
    }
    out
}

fn lines(text: &str, first: &str, rest: &str, width: Option<usize>) -> String {
    let mut out = String::new();
    for (n, step) in steps(text).into_iter().enumerate() {
        let lead = if n == 0 {
            first.to_owned()
        } else {
            format!("{rest}- ")
        };
        let hang = " ".repeat(if n == 0 { rest.len() } else { lead.len() });
        wrapped(&mut out, &lead, &hang, step, width);
    }
    out
}

/// One step after `lead`, wrapped at `width` with `hang` before each later
/// line. A backtick span is one word, so a command is never broken.
fn wrapped(out: &mut String, lead: &str, hang: &str, step: &str, width: Option<usize>) {
    let Some(width) = width else {
        out.push_str(lead);
        out.push_str(step);
        out.push('\n');
        return;
    };
    let mut line = lead.to_owned();
    let mut empty = true;
    for word in words(step) {
        let len = |s: &str| s.chars().count();
        if !empty && len(&line) + 1 + len(word) > width {
            out.push_str(&line);
            out.push('\n');
            hang.clone_into(&mut line);
            empty = true;
        }
        if !empty {
            line.push(' ');
        }
        line.push_str(word);
        empty = false;
    }
    out.push_str(&line);
    out.push('\n');
}

/// The words of a step, with each backtick span kept whole.
fn words(step: &str) -> Vec<&str> {
    let mut words = Vec::new();
    let mut tick = false;
    let mut start = None;
    for (i, c) in step.char_indices() {
        if c == '`' {
            tick = !tick;
        }
        if c == ' ' && !tick {
            if let Some(s) = start.take() {
                words.push(&step[s..i]);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        words.push(&step[s..]);
    }
    words
}

/// The width to wrap at, or `None` when output is not on a terminal.
fn wrap_width() -> Option<usize> {
    static WIDTH_NOW: OnceLock<Option<usize>> = OnceLock::new();
    *WIDTH_NOW.get_or_init(|| {
        if !(std::io::stdout().is_terminal() && std::io::stderr().is_terminal()) {
            return None;
        }
        let columns = std::env::var("COLUMNS")
            .ok()
            .and_then(|c| c.trim().parse::<usize>().ok())
            .filter(|&c| c >= 40);
        Some(columns.map_or(WIDTH, |c| c.min(WIDTH)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(text: &str) -> String {
        relative_to(text, &["/w/run/".to_owned()])
    }

    #[test]
    fn paths_under_the_directory_are_relative() {
        assert_eq!(
            rel("the ledger /w/run/a.ledger is"),
            "the ledger a.ledger is"
        );
        assert_eq!(rel("`mv /w/run/a /w/run/b`"), "`mv a b`");
        assert_eq!(
            rel("(witness: /w/run/s/x.witness)."),
            "(witness: s/x.witness)."
        );
        assert_eq!(rel("\"/w/run/a b\""), "\"a b\"");
        assert_eq!(rel("'/w/run/it'\\''s'"), "'it'\\''s'");
        assert_eq!(rel("/w/run/a"), "a");
    }

    #[test]
    fn other_paths_stay_absolute() {
        assert_eq!(rel("/w/runner/a /w/other"), "/w/runner/a /w/other");
        assert_eq!(rel("/x/w/run/a"), "/x/w/run/a");
        assert_eq!(rel("dir/w/run/a"), "dir/w/run/a");
        assert_eq!(
            rel("the directory /w/run/ itself"),
            "the directory /w/run/ itself"
        );
        assert_eq!(rel("/w/run"), "/w/run");
    }

    #[test]
    fn a_relative_path_still_pastes() {
        assert_eq!(
            rel("`hallpass doctor /w/run/-x.toml`"),
            "`hallpass doctor ./-x.toml`"
        );
        assert_eq!(rel("/w/run/~a"), "./~a");
    }

    #[test]
    fn a_path_named_again_is_the_same_path() {
        assert_eq!(
            same_path(
                "the ledger a.ledger is missing; it was last seen at a.ledger on T. Run `mv x a.ledger` at b."
            ),
            "the ledger a.ledger is missing; it was last seen at the same path on T. Run `mv x a.ledger` at b."
        );
        assert_eq!(
            same_path("seen at s/a.ledger, not at s/b."),
            "seen at s/a.ledger, not at s/b."
        );
    }

    #[test]
    fn steps_split_sentences_not_commands() {
        assert_eq!(
            steps("one (a. b) is `x. y` \"q. r\". Two; if not, three. hallpass four"),
            [
                "one (a. b) is `x. y` \"q. r\".",
                "Two;",
                "if not, three.",
                "hallpass four"
            ]
        );
        assert_eq!(steps("first; if a, b. Then"), ["first; if a, b.", "Then"]);
        assert_eq!(
            steps("for example, e.g. this. Done."),
            ["for example, e.g. this.", "Done."]
        );
        assert_eq!(
            steps(r#"reason "a \" b. c". Next."#),
            [r#"reason "a \" b. c"."#, "Next."]
        );
        assert_eq!(steps("one line"), ["one line"]);
        assert_eq!(steps(""), [""]);
    }

    #[test]
    fn steps_join_back_to_the_message() {
        let text = "the ledger a is damaged at line 6: bad. hallpass will not guess; if so, run `x. y`. Then z.";
        assert_eq!(steps(text).join(" "), text);
    }

    #[test]
    fn lines_have_one_step_each() {
        assert_eq!(
            lines("A is wrong. Do B. Or C.", "  ", "    ", None),
            "  A is wrong.\n    - Do B.\n    - Or C.\n"
        );
        assert_eq!(
            lines("Just one.", "Next: ", "  ", None),
            "Next: Just one.\n"
        );
    }

    #[test]
    fn wrapping_keeps_commands_whole() {
        let text = "aaaa bbbb cccc. Run `hallpass adopt some/long/path --preview` then dddd eeee";
        assert_eq!(
            lines(text, "", "", Some(20)),
            "aaaa bbbb cccc.\n- Run\n  `hallpass adopt some/long/path --preview`\n  then dddd eeee\n"
        );
    }
}
