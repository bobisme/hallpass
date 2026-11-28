//! The short text form of an error, a refusal and doctor's report, shown
//! without `--verbose`: a headline, `Next:`, at most [`BULLETS`] bullets,
//! and a pointer to the full text. JSON and `--verbose` keep every word.
//!
//! How the bullets are chosen:
//!
//! - The errors an operator meets most when a ledger or its witness is in
//!   trouble (ledger-missing, ledger-elsewhere, witness-unavailable,
//!   lock-timeout, ledger-corrupt, ledger-changed) have a short form built
//!   here from the error's own fields: the one fact the headline leaves out,
//!   then the alternatives to `Next:` that name a command. Built from the
//!   fields, it cannot cut a sentence at the wrong place, and it never
//!   advises `hallpass adopt` in a command that only reads.
//! - Any other message is cut by one rule ([`select`]): a message that is
//!   already short is shown whole; a longer one keeps its first sentence
//!   (the fact) and the later sentences that are alternatives: they name a
//!   command other than the one in `Next:`, or start with the case they are
//!   for ("If ...", "For a ledger, ..."). The rule drops explanation, never a command that is the
//!   only way out, because `Next:` and the pointer always remain.

use hallpass::{BLANK_LINE, CUT_SHORT, Error, LastResort, NUL_LINE};

use super::readable::{self, BULLETS};

/// A message that is at most this long (in its sentences) is shown whole.
const WHOLE: usize = 360;

/// A sentence longer than this is never a bullet: it is an explanation.
const LONG: usize = 240;

/// The bullets of a short message, and whether anything was left out.
pub struct Short {
    pub bullets: Vec<String>,
    pub dropped: bool,
}

/// The bullets of an error's short form. `detail` is the full message as
/// lines ([`hallpass::Summary::detail`]); `next` is its next step.
pub fn error(error: &Error, read_only: bool, next: Option<&str>, detail: &[String]) -> Short {
    let built = match error {
        Error::LedgerMissing(m) => {
            let mut b = vec![format!(
                "the witness recorded sequence {} (spent: {}) on {}; the ledger was last seen at {}.",
                m.seq,
                hallpass::totals_text(&m.totals),
                m.updated,
                m.last_seen
            )];
            b.push("Put the ledger back beside the pass if a copy exists (move it there, or restore it from a backup).".to_owned());
            if !read_only {
                let pass = shell_word(&m.pass.display().to_string());
                b.push(if m.rehearsal {
                    format!("If it is really lost: `hallpass adopt {pass} --preview --carry-rehearsal`.")
                } else {
                    format!("If it is really lost: `hallpass adopt {pass} --preview`, then adopt with its token.")
                });
            }
            Some(b)
        }
        Error::LedgerElsewhere(e) => {
            let mut b = vec![format!(
                "the intact ledger is {} (last logical sequence {}, spent: {}).",
                e.live.display(),
                e.seq,
                hallpass::totals_text(&e.totals)
            )];
            b.push(e.live_pass.as_ref().map_or_else(
                || "No pass file is beside it, so this pass file may be that pass, moved without its ledger.".to_owned(),
                |lp| format!("The pass file beside it is {}, so this is a second pass file with the same id.", lp.display()),
            ));
            if !read_only {
                b.push("Do not run `hallpass adopt` on this pass file: the ledger is not lost.".to_owned());
            }
            Some(b)
        }
        Error::WitnessUnavailable { detail: why, .. } if next.is_some() => Some(vec![format!(
            "{}.",
            why.strip_suffix('.').unwrap_or(why)
        )]),
        Error::LockTimeout { .. } => Some(vec![
            "The lock is released when its holder exits or crashes, so a stale lock does not need removing.".to_owned(),
        ]),
        Error::LedgerCorrupt {
            path,
            line,
            detail: what,
            last,
            complete,
        } => Some(corrupt(path, *line, what, *last && !*complete, read_only)),
        Error::LedgerChanged {
            pass, detail: what, ..
        } => {
            let mut b = vec![
                format!("{}.", without_time(what.strip_suffix('.').unwrap_or(what))),
                "Restore the ledger hallpass last wrote from a backup, if there is one.".to_owned(),
            ];
            if !read_only {
                b.push(format!(
                    "Last resort: `hallpass adopt {} --preview` adopts it in place; {}",
                    shell_word(&pass.display().to_string()),
                    lower_first(&LastResort::AdoptInPlace.receipts(None))
                ));
            }
            Some(b)
        }
        _ => None,
    };
    built.map_or_else(
        || select(detail, next),
        |bullets| Short {
            bullets,
            dropped: true,
        },
    )
}

/// The bullets of a damaged ledger: where the damage is, the repair that
/// may apply, and the backup or the last resort (with what it does to the
/// receipts), as in the full message.
fn corrupt(
    path: &std::path::Path,
    line: usize,
    what: &str,
    open_end: bool,
    read_only: bool,
) -> Vec<String> {
    let ledger = path.display().to_string();
    let pass = shell_word(ledger.strip_suffix(".ledger").unwrap_or("PASS"));
    let mut b = vec![format!(
        "{ledger}, line {line}: {}.",
        what.strip_suffix('.').unwrap_or(what)
    )];
    if what == BLANK_LINE && line > 1 {
        b.push(format!("If only blank lines follow the line the witness recorded: `hallpass repair {pass} --drop-blank-tail --preview`."));
    } else if open_end && line > 1 && what == NUL_LINE {
        b.push(format!("If the witness proves it was never counted: `hallpass repair {pass} --drop-torn-tail --preview`."));
    } else if open_end && line > 1 && what == CUT_SHORT {
        b.push(format!("If the witness proves it was never counted: `hallpass repair {pass} --drop-torn-tail --preview` (or `--restore-final-newline`)."));
    } else {
        // `Next:` restores a backup already.
        b.push("Do not edit lines by hand.".to_owned());
        if !read_only {
            b.push(format!(
                "Last resort, with no backup: move the ledger aside and adopt; {}",
                lower_first(&LastResort::MoveAside.receipts(None))
            ));
        }
        return b;
    }
    b.push(if read_only {
        "Else restore the ledger from a backup (`hallpass compare-backups` finds the good copy).".to_owned()
    } else {
        format!(
            "Else restore a backup (`hallpass compare-backups`); last resort: move it aside and adopt; {}",
            lower_first(&LastResort::MoveAside.receipts(None))
        )
    });
    b
}

/// `text` without the time of its first ` on YYYY-MM-DDTHH:MM:SSZ` (the
/// full text keeps it).
fn without_time(text: &str) -> String {
    let stamp = |t: &str| {
        let b = t.as_bytes();
        b.len() >= 20
            && b[..20].iter().enumerate().all(|(i, c)| match i {
                4 | 7 => *c == b'-',
                10 => *c == b'T',
                13 | 16 => *c == b':',
                19 => *c == b'Z',
                _ => c.is_ascii_digit(),
            })
    };
    text.match_indices(" on ")
        .find(|(i, _)| stamp(&text[i + 4..]))
        .map_or_else(
            || text.to_owned(),
            |(i, _)| format!("{}{}", &text[..i], &text[i + 24..]),
        )
}

/// `text` with its first letter in lower case, to follow a semicolon.
fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_lowercase().chain(chars).collect())
}

/// The short form of a message by the one rule: shown whole when it is
/// short, else its first sentence and the later ones that are an
/// alternative (they name a command other than `next`'s, or start with the
/// case they are for), up to [`BULLETS`] in all.
pub fn select(lines: &[String], next: Option<&str>) -> Short {
    // Measured as shown: with paths under the current directory relative.
    let lines: Vec<String> = lines.iter().map(|l| readable::paths(l)).collect();
    let steps: Vec<&str> = lines
        .iter()
        .flat_map(|line| readable::steps(line))
        .filter(|s| !s.is_empty())
        .collect();
    let total: usize = steps.iter().map(|s| s.len()).sum();
    if steps.len() <= BULLETS && total <= WHOLE {
        return Short {
            bullets: steps.into_iter().map(str::to_owned).collect(),
            dropped: false,
        };
    }
    let next_keys = next.map_or_else(Vec::new, command_keys);
    let mut bullets: Vec<String> = steps.first().map(|s| (*s).to_owned()).into_iter().collect();
    for step in steps.iter().skip(1) {
        if bullets.len() == BULLETS {
            break;
        }
        let keys = command_keys(step);
        let alternative = if keys.is_empty() {
            is_condition(step)
        } else {
            keys.iter().any(|k| !next_keys.contains(k))
        };
        if step.len() <= LONG && alternative {
            bullets.push((*step).to_owned());
        }
    }
    Short {
        dropped: bullets.len() < steps.len(),
        bullets,
    }
}

/// A refusal's text without `--verbose`: its first sentence, a `Next:`
/// command when a long sentence holds one, and its short sentences (at most
/// [`BULLETS`]). "Nothing was recorded." is always kept.
pub fn refusal(message: &str) -> (String, Option<String>, Short) {
    let message = readable::paths(message);
    let steps = readable::steps(&message);
    let total: usize = steps.iter().map(|s| s.len()).sum();
    let first = steps.first().copied().unwrap_or_default().to_owned();
    let rest = steps.get(1..).unwrap_or_default();
    if total <= WHOLE {
        let bullets = rest.iter().map(|s| (*s).to_owned()).collect();
        return (
            first,
            None,
            Short {
                bullets,
                dropped: false,
            },
        );
    }
    let mut next = None;
    let mut bullets = Vec::new();
    let mut dropped = false;
    for step in rest {
        let fits = step.len() <= LONG && bullets.len() < BULLETS;
        if step.starts_with("Nothing was") || fits {
            bullets.push((*step).to_owned());
        } else {
            if next.is_none() {
                next = first_command(step);
            }
            dropped = true;
        }
    }
    (first, next, Short { bullets, dropped })
}

/// A doctor step cut to its first sentence and the later ones that are not
/// long, `keep` sentences in all.
pub fn step(text: &str, keep: usize) -> String {
    let text = readable::paths(text);
    let steps = readable::steps(&text);
    // The last resort is always kept, in one short sentence with what it
    // does to the receipts (the sentence after it).
    let resort = steps.iter().position(|s| s.starts_with(LAST_RESORT));
    let room = keep.saturating_sub(usize::from(resort.is_some()));
    let mut kept: Vec<String> = Vec::new();
    for (i, s) in steps.iter().enumerate() {
        if Some(i) == resort {
            let receipts = steps.get(i + 1).copied().unwrap_or_default();
            kept.push(short_resort(s, receipts));
        } else if resort.is_some_and(|r| i == r + 1) {
            // Part of the last resort's sentence.
        } else if i == 0 || (kept.len() < room && s.len() <= LONG) {
            kept.push((*s).to_owned());
        }
    }
    kept.join(" ")
}

/// How [`hallpass::LastResort::steps`] starts.
const LAST_RESORT: &str = "If no backup copy exists, the last resort is";

/// The last resort in one sentence: its first command, and what it does to
/// the receipts.
fn short_resort(full: &str, receipts: &str) -> String {
    let command = full.split('`').nth(1).unwrap_or_default();
    let how = if command.starts_with("mv ") {
        format!("`{command}` (keep the file), then doctor again")
    } else {
        format!("adopt this ledger in place, from `{command}`")
    };
    format!(
        "Last resort, with no backup: {how}; {}",
        lower_first(receipts)
    )
}

/// Whether a sentence is an alternative: it starts with the case it is for
/// ("If ...", "For a ledger, ...", "Otherwise ...").
fn is_condition(step: &str) -> bool {
    [
        "If ",
        "if ",
        "For ",
        "Otherwise",
        "otherwise",
        "Or ",
        "or ",
        "When ",
        "Unless ",
    ]
    .iter()
    .any(|w| step.starts_with(w))
}

/// The first command in backticks in `text` that starts with `hallpass`.
fn first_command(text: &str) -> Option<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .find(|span| span.starts_with("hallpass "))
        .map(str::to_owned)
}

/// What a step advises, as one key per command in backticks: the program,
/// its subcommand and its flags, without paths or values (`hallpass adopt
/// --preview`). Two steps with the same key give the same advice.
pub fn command_keys(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter_map(|span| {
            let mut words = span.split_whitespace();
            let program = words.next()?;
            if program.starts_with('-') {
                return None;
            }
            let mut key = program.to_owned();
            if program == "hallpass"
                && let Some(sub) = words.next()
            {
                key.push(' ');
                key.push_str(sub);
            }
            for flag in words.filter(|w| w.starts_with("--")) {
                key.push(' ');
                key.push_str(flag);
            }
            Some(key)
        })
        .collect()
}

/// `lines` without the sentences that repeat advice already given: a
/// sentence equal to one in `given`, or one whose every command
/// ([`command_keys`]) was already named, in `given` or earlier in `lines`.
/// The first sentence (the fact) always stays.
pub fn without_repeats(lines: &[String], given: &str) -> Vec<String> {
    let norm = |s: &str| {
        s.trim_end_matches(['.', ';', ':'])
            .trim()
            .to_ascii_lowercase()
    };
    let said: Vec<String> = readable::steps(given).into_iter().map(norm).collect();
    let mut named = command_keys(given);
    let mut out = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let mut kept: Vec<&str> = Vec::new();
        for (i, step) in readable::steps(line).into_iter().enumerate() {
            let keys = command_keys(step);
            let repeat = said.contains(&norm(step))
                || (!keys.is_empty() && keys.iter().all(|k| named.contains(k)));
            if (n == 0 && i == 0) || !repeat {
                kept.push(step);
            }
            named.extend(keys);
        }
        if !kept.is_empty() {
            out.push(kept.join(" "));
        }
    }
    out
}

/// A word as a shell would need it typed.
pub fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_resort_is_one_short_sentence() {
        for which in [LastResort::AdoptInPlace, LastResort::MoveAside] {
            let full = which.steps("p.toml", "p.toml.ledger", "p.toml.ledger.damaged", Some(2));
            assert!(full.trim_start().starts_with(LAST_RESORT), "{full}");
            let text = format!("Add the copies. Restore one.{full}");
            let short = step(&text, 3);
            assert_eq!(readable::steps(&short).len(), 3, "{short}");
            assert!(
                short.contains(&lower_first(&which.receipts(Some(2)))),
                "{short}"
            );
        }
    }

    #[test]
    fn a_time_is_left_to_the_full_text() {
        assert_eq!(
            without_time("sequence 2 on 2026-11-28T10:11:15Z, but this"),
            "sequence 2, but this"
        );
        assert_eq!(without_time("on and on"), "on and on");
    }

    #[test]
    fn keys_ignore_paths_and_values() {
        assert_eq!(
            command_keys("run `hallpass adopt a.toml --reason \"x\" --token T` or `mv a b`"),
            ["hallpass adopt --reason --token", "mv"]
        );
        assert_eq!(
            command_keys("`--drop-torn-tail` removes"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_short_message_is_whole() {
        let s = select(&["A is wrong. Do B.".to_owned()], None);
        assert_eq!(s.bullets, ["A is wrong.", "Do B."]);
        assert!(!s.dropped);
    }

    #[test]
    fn a_long_message_keeps_the_fact_and_other_commands() {
        let long = "x ".repeat(200);
        let text = format!(
            "the fact. {long}. Run `hallpass doctor p`. Or `hallpass repair p --preview`. Or `hallpass adopt p`."
        );
        let s = select(&[text], Some("run `hallpass doctor p`"));
        assert_eq!(
            s.bullets,
            [
                "the fact.",
                "Or `hallpass repair p --preview`.",
                "Or `hallpass adopt p`."
            ]
        );
        assert!(s.dropped);
    }

    #[test]
    fn repeats_are_dropped() {
        let lines = [
            "fact. Restore from a backup: `hallpass compare-backups` shows it. Do not edit."
                .to_owned(),
            "Other fact. Use `hallpass repair p --x`. Again `hallpass repair q --x`. The end."
                .to_owned(),
        ];
        let given = "Add each copy: `hallpass compare-backups p l`. Do not edit.";
        assert_eq!(
            without_repeats(&lines, given),
            ["fact.", "Other fact. Use `hallpass repair p --x`. The end."]
        );
    }
}
