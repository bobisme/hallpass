//! Errors: anything other than a policy refusal.

use std::path::PathBuf;

use crate::pass::Problem;

/// Something went wrong that is not a policy refusal: a file could not be
/// read, a pass is invalid, a ledger is damaged. Every variant fails
/// closed.
///
/// An append error may leave a debit; a witness update error after sync identifies a durable debit.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file could not be read or written.
    #[error("{}: {message}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What the operating system said, in words.
        message: String,
    },
    /// The path is a symbolic link, which hallpass never follows.
    #[error(
        "{} is a symbolic link; hallpass does not follow links for a pass, a ledger or any other file it reads. Use the path of the real file.",
        path.display()
    )]
    Symlink {
        /// The link.
        path: PathBuf,
    },
    /// The path is not a regular file.
    #[error("{} is not a regular file (it is a directory, pipe, device or other special file). hallpass reads only regular files. For a pass, give the path of the pass file. For a ledger, check the path and restore the ledger file from a backup. For any other input, save it to a regular file and give that path.", path.display())]
    NotRegular {
        /// The path.
        path: PathBuf,
    },
    /// The file is larger than a pass can be.
    #[error(
        "{} is larger than {limit} bytes, too large for a pass; a pass is a short text file: check that this is the pass file.",
        path.display()
    )]
    TooLarge {
        /// The file.
        path: PathBuf,
        /// The limit in bytes.
        limit: u64,
    },
    /// Other users may change the file.
    #[error(
        "{} has mode {mode:04o}, so {who}; run `chmod {fix} {}`, then {advice}.",
        path.display(),
        path.display()
    )]
    Insecure {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
        /// Who else has access, in words.
        who: &'static str,
        /// The mode to set.
        fix: &'static str,
        /// What to check once the mode is fixed, in words, without a full stop.
        advice: &'static str,
    },
    /// Any user can rename or delete files in the directory that holds the pass.
    #[error(
        "{} has mode {mode:04o}: any user can write it and it lacks the sticky bit, so another user can rename or delete the pass, its ledger and its lock file there, or put an older copy of the pass back; run `chmod o-w {}` (or `chmod +t {}` if the directory must stay shared), then check that the pass is the one the owner approved. Nothing was recorded.",
        path.display(),
        path.display(),
        path.display()
    )]
    SharedDirectory {
        /// The directory.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// A mutable approval must be controlled by the caller or system administrator.
    #[error("{} is owned by UID {owner}; use an approval owned by effective UID {effective} or root after verifying its content", path.display())]
    UntrustedOwner {
        path: PathBuf,
        owner: u32,
        effective: u32,
    },
    /// The pass does not validate.
    #[error("{} is not a valid pass ({} problem(s)); {}", path.display(), problems.len(), invalid_advice(problems))]
    Invalid {
        /// The pass file.
        path: PathBuf,
        /// Every problem found.
        problems: Vec<Problem>,
    },
    /// The ledger cannot be trusted.
    #[error(
        "the ledger {} is damaged at line {line}: {}. hallpass will not guess the count, so nothing more can be spent under this pass until it is repaired: {}",
        path.display(),
        without_stop(detail),
        corrupt_advice(path, *line, detail, *last, *complete)
    )]
    LedgerCorrupt {
        /// The ledger file.
        path: PathBuf,
        /// The line (1-based).
        line: usize,
        /// What is wrong.
        detail: String,
        /// True when `line` is the last line of the file. Only then can the
        /// damage be a final line cut short.
        last: bool,
        /// True when the damaged line is whole JSON: it is invalid, not cut
        /// short, so removing it is never the advice.
        complete: bool,
    },
    /// The ledger belongs to a different pass id.
    #[error(
        "the ledger {} belongs to pass `{ledger_id}`, but the pass now says `{pass_id}`. Changing the id does not start a new count. If the owner gave a new approval, write it as a new pass file; otherwise restore id = \"{ledger_id}\".",
        path.display()
    )]
    LedgerForeign {
        /// The ledger file.
        path: PathBuf,
        /// The id the ledger records.
        ledger_id: String,
        /// The id in the pass.
        pass_id: String,
    },
    /// A write would put a test-clock line in a ledger of real-clock lines,
    /// or a real-clock line in a ledger of test-clock lines. Rehearsal and
    /// live lines never mix in one ledger.
    #[error("{}", clock_mix_message(path, *seq, *rehearsal))]
    LedgerClockMix {
        /// The ledger file.
        path: PathBuf,
        /// The first entry of the other kind.
        seq: u64,
        /// True when the ledger holds test-clock lines (a rehearsal ledger)
        /// and the write uses the real clock; false when the ledger holds
        /// real-clock lines and the write uses the test clock.
        rehearsal: bool,
    },
    /// The ledger is gone, but the witness says spends were recorded.
    #[error("{0}")]
    LedgerMissing(Box<MissingLedger>),
    /// The pass has no ledger beside it, but the ledger of its pass id is
    /// intact where the witness last saw it: a second pass file with the
    /// same id, or a pass moved without its ledger. Adopting would fork the
    /// history, so nothing is adopted.
    #[error("{0}")]
    LedgerElsewhere(Box<ElsewhereLedger>),
    /// The ledger does not contain the line the witness recorded.
    #[error(
        "the ledger {} was changed outside hallpass: {detail} (witness: {}). hallpass will not trust its count. Restore the ledger hallpass last wrote (from a backup, or the other copy if one is named above); if this ledger is the one to keep, run `hallpass adopt {} --reason \"...\"`, which records the adoption in the ledger and never lowers a count below what the witness recorded.",
        path.display(),
        witness.display(),
        pass.display()
    )]
    LedgerChanged {
        /// The ledger file.
        path: PathBuf,
        /// The pass file.
        pass: PathBuf,
        /// The witness file.
        witness: PathBuf,
        /// What differs.
        detail: String,
    },
    /// The witness cannot be read or written, so a spend cannot be checked
    /// against it.
    #[error(
        "the witness for pass `{pass_id}` cannot be used: {}. hallpass keeps a record of each ledger's last line in its state directory ({}) so that a lost or rewound ledger is noticed, and does not record a spend without it.{}",
        without_stop(detail),
        dir.as_ref().map_or_else(|| "none".to_owned(), |d| crate::display_quoted(&d.display().to_string())),
        witness_advice(detail)
    )]
    WitnessUnavailable {
        /// The pass id.
        pass_id: String,
        /// The state directory, when one could be determined.
        dir: Option<PathBuf>,
        /// What went wrong.
        detail: String,
    },
    /// The spend was recorded in the ledger, but the witness could not be
    /// updated afterwards.
    #[error(
        "the spend was recorded in {} as entry {seq}, but the witness could not be updated afterwards ({detail}). Treat this spend as NOT permitted; it still counts against the ceiling. The next command accepts the ledger, since it only adds to what the witness recorded.",
        path.display()
    )]
    WitnessNotUpdated {
        /// The ledger file.
        path: PathBuf,
        /// The entry that was recorded.
        seq: u64,
        /// What went wrong.
        detail: String,
    },
    /// Append or sync failed. Reconcile the ledger before another attempt.
    #[error("could not confirm the {event} in {} ({detail}); inspect the ledger before continuing.", path.display())]
    AppendUncertain {
        path: PathBuf,
        event: String,
        detail: String,
    },
    /// Writing the line failed, and hallpass cut the ledger back to its
    /// length before the write and synced it, still under the lock, before
    /// the witness was updated: the ledger holds its previous bytes and
    /// nothing was recorded.
    #[error("could not write the {event} to {} ({detail}); hallpass cut the ledger back to its length before the write, so nothing was recorded. Free disk space or raise the file size limit, then run the command again.", path.display())]
    AppendRolledBack {
        path: PathBuf,
        event: String,
        detail: String,
    },
    /// The lock-wait budget ran out before the command took the lock, so it
    /// read and recorded nothing.
    #[error("timed out waiting for the lock on {}, which another process holds; this command recorded nothing. Retry, or find and stop the process holding it (`fuser {}`). The lock is released automatically when its holder exits or crashes, so a stale lock does not need removing.", path.display(), path.display())]
    LockTimeout { path: PathBuf },
    /// The file already exists (`init` and `retrieve --output` never overwrite).
    #[error("{} already exists; hallpass never overwrites a file or follows a link (`init`, `retrieve --output`). Choose another path.", path.display())]
    Exists {
        /// The file.
        path: PathBuf,
    },
    /// The request itself is malformed (for example `--n 0`).
    #[error("{0}")]
    Usage(String),
}

/// The message for [`Error::LedgerClockMix`].
fn clock_mix_message(path: &std::path::Path, seq: u64, rehearsal: bool) -> String {
    if rehearsal {
        format!(
            "the ledger {} is a rehearsal ledger: entry {seq} was recorded under a test clock (HALLPASS_UNSAFE_TEST_CLOCK), and this command uses the real clock. Rehearsal and live lines must not mix in one ledger, so nothing was recorded. To go on rehearsing, use a debug build with HALLPASS_UNSAFE_TEST_CLOCK set; for live work, use a pass with a new id, with no ledger yet.",
            path.display()
        )
    } else {
        format!(
            "the ledger {} is a live ledger: entry {seq} was recorded at the real time, and this command runs under a test clock (HALLPASS_UNSAFE_TEST_CLOCK). Rehearsal and live lines must not mix in one ledger, so nothing was recorded. Unset HALLPASS_UNSAFE_TEST_CLOCK to record at the real time; to rehearse, use a copy of the pass with a new id and its own state directory (XDG_STATE_HOME).",
            path.display()
        )
    }
}

/// The next step for an invalid pass. A read that caught a save in progress
/// has nothing to fix: the step is to run the command again.
fn invalid_advice(problems: &[Problem]) -> &'static str {
    if problems
        .iter()
        .any(|p| p.message == crate::files::CHANGED_WHILE_READ)
    {
        "it changed while it was read, so run the command again once the save has finished"
    } else {
        "fix each one, then run `hallpass check`"
    }
}

impl Error {
    /// The message for a command that cannot write. It never advises
    /// `hallpass adopt`: a read-only command that sends the reader to adopt a
    /// copy can fork the ledger of a live pass.
    #[must_use]
    pub fn read_only_message(&self) -> String {
        let text = self.to_string();
        match self {
            Self::LedgerMissing(_) => {
                let from = text.find("; if it is really lost").unwrap_or(text.len());
                let tail = text[from..]
                    .find(". If this pass")
                    .map_or("", |i| &text[from + i..]);
                format!(
                    "{}. This command only reads and changed nothing; run `hallpass status` on the pass to see how to recover{tail}",
                    &text[..from]
                )
            }
            Self::LedgerElsewhere(e) => e.lines(true).join(" "),
            Self::LedgerChanged { .. } => {
                let from = text
                    .find("; if this ledger is the one to keep")
                    .unwrap_or(text.len());
                format!(
                    "{}. This command only reads and changed nothing; run `hallpass status` on the pass to see how to recover",
                    &text[..from]
                )
            }
            Self::WitnessUnavailable { .. } => text.replace(
                "; move it aside and run `hallpass adopt` to record a new one",
                "; this command only reads and changed nothing",
            ),
            _ => text,
        }
    }

    /// The message as separate lines, for text output: a short first line,
    /// then the details and steps. Joined with a space, they are the
    /// message ([`Error::to_string`], or [`Error::read_only_message`] when
    /// `read_only`). Most errors are one line.
    #[must_use]
    pub fn message_lines(&self, read_only: bool) -> Vec<String> {
        match self {
            Self::LedgerElsewhere(e) => e.lines(read_only),
            _ if read_only => vec![self.read_only_message()],
            _ => vec![self.to_string()],
        }
    }

    /// A stable code for JSON output.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::LockTimeout { .. } => "lock-timeout",
            Self::AppendUncertain { .. } => "ledger-append-uncertain",
            Self::AppendRolledBack { .. } => "ledger-append-failed",
            Self::Symlink { .. } => "symlink",
            Self::NotRegular { .. } => "not-regular-file",
            Self::TooLarge { .. } => "too-large",
            Self::Insecure { .. } => "insecure-permissions",
            Self::SharedDirectory { .. } => "shared-directory",
            Self::Invalid { .. } => "invalid-pass",
            Self::UntrustedOwner { .. } => "untrusted-owner",
            Self::LedgerCorrupt { .. } => "ledger-corrupt",
            Self::LedgerForeign { .. } => "ledger-foreign",
            Self::LedgerClockMix { .. } => "ledger-clock-mix",
            Self::LedgerMissing(_) => "ledger-missing",
            Self::LedgerElsewhere(_) => "ledger-elsewhere",
            Self::LedgerChanged { .. } => "ledger-changed",
            Self::WitnessUnavailable { .. } => "witness-unavailable",
            Self::WitnessNotUpdated { .. } => "witness-not-updated",
            Self::Exists { .. } => "exists",
            Self::Usage(_) => "usage",
        }
    }

    pub(crate) fn io(path: &std::path::Path, error: &std::io::Error) -> Self {
        let message = match error.kind() {
            std::io::ErrorKind::NotFound => "no such file; check the path.".to_owned(),
            std::io::ErrorKind::PermissionDenied => {
                "permission denied; check the file's owner and mode.".to_owned()
            }
            _ => format!(
                "{error}; check the path and that this user can read or write it, then run the command again."
            ),
        };
        Self::Io {
            path: path.to_path_buf(),
            message,
        }
    }
}

/// The details of [`Error::LedgerMissing`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MissingLedger {
    /// The ledger file that is missing.
    pub path: PathBuf,
    /// The pass file.
    pub pass: PathBuf,
    /// The pass id.
    pub pass_id: String,
    /// The witness file.
    pub witness: PathBuf,
    /// The last sequence number the witness recorded.
    pub seq: u64,
    /// Where the ledger was when the witness was written.
    pub last_seen: String,
    /// The totals the witness recorded.
    pub totals: std::collections::BTreeMap<String, u64>,
    /// When the witness was written.
    pub updated: String,
}

impl std::fmt::Display for MissingLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the ledger {} for pass `{}` is missing, but the witness {} says its last logical ledger sequence was {} (spent: {}); the ledger was last seen at {} on {}. hallpass will not count from zero. Put the ledger back beside the pass (move it from there, or restore it from a backup); if it is really lost, run `hallpass adopt {} --reason \"...\"`, which starts a new ledger that carries those totals. If the ledger was moved to another account on purpose, do not adopt or spend here: that account now holds the count. If this pass is a different approval that reused the id, give it its own id",
            self.path.display(),
            self.pass_id,
            self.witness.display(),
            self.seq,
            crate::witness::totals_text(&self.totals),
            self.last_seen,
            self.updated,
            self.pass.display()
        )
    }
}

/// The details of [`Error::LedgerElsewhere`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ElsewhereLedger {
    /// The ledger file that would be beside this pass, and is not.
    pub path: PathBuf,
    /// The pass file.
    pub pass: PathBuf,
    /// The pass id.
    pub pass_id: String,
    /// The witness file.
    pub witness: PathBuf,
    /// The last sequence number the witness recorded, and the intact
    /// ledger's last sequence number.
    pub seq: u64,
    /// The intact ledger, where the witness last saw it.
    pub live: PathBuf,
    /// The pass file beside the intact ledger, when there is one.
    pub live_pass: Option<PathBuf>,
    /// The totals the witness recorded.
    pub totals: std::collections::BTreeMap<String, u64>,
    /// When the witness was written.
    pub updated: String,
}

impl ElsewhereLedger {
    /// The message as lines: what was found (each path once), then the
    /// steps. The read-only form never mentions adopting.
    #[must_use]
    pub fn lines(&self, read_only: bool) -> Vec<String> {
        let (pass, expected, live) = (
            self.pass.display(),
            self.path.display(),
            self.live.display(),
        );
        let mut out = vec![
            format!(
                "the ledger for pass `{}` is not beside this pass file, but an intact one exists elsewhere, and hallpass will not count from zero.",
                self.pass_id
            ),
            format!("This pass file: {pass}."),
            format!("Expected ledger: {expected} (does not exist)."),
            format!(
                "Live ledger: {live}, intact, as last recorded on {} (last logical sequence {}, spent: {}).",
                self.updated,
                self.seq,
                crate::witness::totals_text(&self.totals),
            ),
        ];
        out.push(self.live_pass.as_ref().map_or_else(
            || "No pass file is beside the live ledger, so this pass file may be that pass, moved without its ledger.".to_owned(),
            |lp| format!("Pass file beside the live ledger: {}, so this pass file is a second pass file with the same id.", lp.display()),
        ));
        if read_only {
            out.push("This command only reads and changed nothing; run `hallpass status` on the pass to see how to recover.".to_owned());
            out.push(
                "If this pass file is a different approval that reused the id, give it its own id."
                    .to_owned(),
            );
            return out;
        }
        if self.live_pass.is_some() {
            out.push("If this pass file revises that approval, copy it beside the live pass file, `mv` the copy over that file and spend from it: the count carries on.".to_owned());
            out.push("If the live pass file is being retired instead, move the live ledger to the expected ledger path.".to_owned());
        } else {
            out.push(
                "Move the live ledger to the expected ledger path, and the count carries on."
                    .to_owned(),
            );
        }
        out.push(
            "If this pass file is a different approval that reused the id, give it its own id."
                .to_owned(),
        );
        out.push("Do not run `hallpass adopt` on this pass file: the ledger is not lost, and adopting would fork it into a second ledger for this id.".to_owned());
        out
    }
}

impl std::fmt::Display for ElsewhereLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.lines(false).join(" "))
    }
}

/// The next step for a `witness-unavailable` cause. A cause that names its own
/// next step in its detail (a damaged, over-sized or world-readable witness,
/// a state directory with the wrong mode, an adoption whose witness was not
/// updated) gets nothing more; every other cause is a state directory that is
/// missing, not writable or not usable, whose step is the directory.
fn witness_advice(detail: &str) -> &'static str {
    const OWN_STEP: [&str; 6] = [
        "--carry-noted-totals",
        "move it aside and run `hallpass adopt`",
        "run `chmod ",
        "ask the approval owner",
        "run `hallpass adopt` again",
        "was recorded in the ledger",
    ];
    if OWN_STEP.iter().any(|marker| detail.contains(marker)) {
        ""
    } else {
        " Make that directory exist and be writable by this user, then run the command again."
    }
}

/// A detail that is joined into a sentence by a full stop of its own: the
/// join, not the detail, owns the stop, so a detail that ends in one (such as
/// the message of [`Error::Symlink`]) is not followed by a second.
fn without_stop(detail: &str) -> &str {
    detail.strip_suffix('.').unwrap_or(detail)
}

/// The detail of [`Error::LedgerCorrupt`] for a last line with no line end.
pub const CUT_SHORT: &str = "the last line is cut short (no line end)";

/// What to do about a damaged ledger, by where the damage is.
fn corrupt_advice(
    path: &std::path::Path,
    line: usize,
    detail: &str,
    last: bool,
    complete: bool,
) -> String {
    const BACKUP: &str = "Restore the ledger from a backup: `hallpass compare-backups` shows which copy is the good one.";
    if complete {
        format!(
            "the line is complete, not cut short, so do not remove it or edit it by hand. {BACKUP}"
        )
    } else if last && line > 1 && detail == CUT_SHORT {
        // The pass is the ledger's path without `.ledger`.
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let pass = name.strip_suffix(".ledger").map_or_else(
            || "PASS".to_owned(),
            |pass| path.with_file_name(pass).display().to_string(),
        );
        format!(
            "if a write failed while it recorded that line (for example on a full disk), the line was never confirmed. Do not edit the ledger by hand: `hallpass repair {pass} --drop-torn-tail --preview` checks that the witness proves the line was never counted, and then the repair removes it and keeps a copy. If it refuses, {}",
            BACKUP.replacen('R', "r", 1)
        )
    } else if last {
        format!("do not edit lines by hand. {BACKUP}")
    } else {
        format!("the damage is before the end of the file, so do not edit lines by hand. {BACKUP}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_messages_never_advise_adopt() {
        let changed = Error::LedgerChanged {
            path: "p.ledger".into(),
            pass: "p.toml".into(),
            witness: "w".into(),
            detail: "x".into(),
        };
        assert!(changed.to_string().contains("hallpass adopt"));
        assert!(!changed.read_only_message().contains("adopt"));
        let damaged = Error::WitnessUnavailable {
            pass_id: "a".into(),
            dir: None,
            detail: "w is damaged; move it aside and run `hallpass adopt` to record a new one"
                .into(),
        };
        assert!(!damaged.read_only_message().contains("adopt"));
    }

    /// No message ends with a doubled full stop, where a detail that ends in
    /// one is joined into a sentence (bn-110).
    #[test]
    fn no_message_has_a_doubled_stop() {
        let path = std::path::PathBuf::from("p.toml");
        let symlink = Error::Symlink { path: path.clone() }.to_string();
        let details = [
            symlink,
            "it is damaged".to_owned(),
            "it is damaged.".to_owned(),
        ];
        let mut messages = Vec::new();
        for detail in details {
            for last in [false, true] {
                for complete in [false, true] {
                    messages.push(Error::LedgerCorrupt {
                        path: path.clone(),
                        line: 2,
                        detail: detail.clone(),
                        last,
                        complete,
                    });
                }
            }
            for dir in [None, Some(std::path::PathBuf::from("/state"))] {
                let unavailable = Error::WitnessUnavailable {
                    pass_id: "a".into(),
                    dir,
                    detail: detail.clone(),
                };
                messages.push(unavailable);
            }
            messages.push(Error::LedgerChanged {
                path: path.clone(),
                pass: path.clone(),
                witness: path.clone(),
                detail: detail.clone(),
            });
            messages.push(Error::WitnessNotUpdated {
                path: path.clone(),
                seq: 1,
                detail: detail.clone(),
            });
            messages.push(Error::AppendUncertain {
                path: path.clone(),
                event: "spend".into(),
                detail: detail.clone(),
            });
            messages.push(Error::AppendRolledBack {
                path: path.clone(),
                event: "spend".into(),
                detail: detail.clone(),
            });
            messages.push(Error::Io {
                path: path.clone(),
                message: detail.clone(),
            });
            messages.push(Error::Usage(detail));
        }
        messages.extend([
            Error::Symlink { path: path.clone() },
            Error::NotRegular { path: path.clone() },
            Error::TooLarge {
                path: path.clone(),
                limit: 5,
            },
            Error::SharedDirectory {
                path: path.clone(),
                mode: 0o777,
            },
            Error::LockTimeout { path: path.clone() },
            Error::Exists { path: path.clone() },
            Error::LedgerForeign {
                path,
                ledger_id: "a".into(),
                pass_id: "b".into(),
            },
        ]);
        for error in messages {
            for text in [error.to_string(), error.read_only_message()] {
                assert!(!text.contains(".. ") && !text.ends_with(".."), "{text}");
            }
        }
    }
}
