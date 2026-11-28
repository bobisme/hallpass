//! `hallpass doctor`: diagnose a pass, its ledger, its witness and its state,
//! and name the one next step.
//!
//! Doctor runs the library's own checks (`load`, `read_summary`, the torn
//! tail and adoption previews, the window and the archive) and reads their
//! errors and statuses, so it says what the other commands say. It reads
//! only: its state directory is [`StateDir::read_only`], so it writes no
//! note, no witness and no lock file, and never creates the directory.
//!
//! It never recommends `adopt` while a ledger for the pass may be intact
//! elsewhere: the library classifies such a ledger as `ledger-elsewhere`,
//! and for a `ledger-missing` pass whose ledger path the witness last saw
//! still holds a file, doctor recommends `compare-backups` on that file.

use std::fmt::Write as _;
use std::path::Path;

use hallpass::time::Duration;
use hallpass::{Error, LedgerView, LoadedPass, StateDir, WitnessStatus};
use serde_json::{Value, json};

use super::{Clock, OK, Output, REFUSED, error_output, safe_message};

/// The command name, as in the replies.
const NAME: &str = "doctor";

/// One problem: its code, what is wrong (in lines), and the next step.
struct Issue {
    code: String,
    lines: Vec<String>,
    next: Option<Vec<String>>,
    step: String,
}

/// One secondary finding.
struct Finding {
    code: String,
    message: String,
}

/// What doctor found: the first problem that blocks a spend, the first
/// that needs action without blocking one, and everything else.
#[derive(Default)]
struct Diagnosis {
    pass_id: Option<String>,
    blocked: Option<Issue>,
    action: Option<Issue>,
    findings: Vec<Finding>,
    /// For a healthy verdict: what the ledger and witness are.
    ledger: String,
    /// For a healthy verdict: the counters at or over their ceiling.
    at_ceiling: Vec<String>,
}

impl Diagnosis {
    fn find(&mut self, code: &str, message: impl Into<String>) {
        self.findings.push(Finding {
            code: code.to_owned(),
            message: message.into(),
        });
    }

    fn demote(&mut self, issue: &Issue) {
        self.find(&issue.code, issue.lines.join(" "));
    }

    /// A problem that blocks a spend. The first one is the verdict.
    fn block(&mut self, issue: Issue) {
        if self.blocked.is_some() {
            self.demote(&issue);
        } else {
            self.blocked = Some(issue);
        }
    }

    /// A problem that needs action but does not block a spend.
    fn act(&mut self, issue: Issue) {
        if self.action.is_some() {
            self.demote(&issue);
        } else {
            self.action = Some(issue);
        }
    }
}

fn argv<I, S>(words: I) -> Option<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Some(
        words
            .into_iter()
            .map(|w| w.as_ref().to_string_lossy().into_owned())
            .collect(),
    )
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

/// `hallpass doctor FILE [--archive DIR]`.
pub fn doctor(file: &Path, archive: Option<&Path>, clock: &Clock) -> Output {
    let state = StateDir::from_env().read_only();
    match diagnose(file, archive, clock, &state) {
        Ok(diagnosis) => render(file, diagnosis),
        Err(e) => error_output(NAME, Some(file), &e),
    }
}

/// The diagnosis. An error is doctor's own: a pass path or an archive
/// directory it cannot read at all.
fn diagnose(
    file: &Path,
    archive: Option<&Path>,
    clock: &Clock,
    state: &StateDir,
) -> Result<Diagnosis, Error> {
    let mut d = Diagnosis::default();
    let loaded = match hallpass::load(file) {
        Ok(loaded) => loaded,
        Err(e @ (Error::Io { .. } | Error::NotRegular { .. })) => return Err(e),
        Err(e) => {
            d.block(error_issue(file, state, &e));
            return Ok(d);
        }
    };
    d.pass_id = Some(loaded.pass.id.clone());
    let archived = archive
        .map(|dir| hallpass::archive_provenance(dir, loaded.digest).map(|p| (dir, p)))
        .transpose()?;
    let directory_refused = hallpass::refuse_world_writable_directory(file).err();
    if let Some(e) = &directory_refused {
        d.block(error_issue(file, state, e));
    }
    let now = clock.sample();
    match hallpass::read_summary(&loaded, state) {
        Ok(view) => ledger_findings(
            &mut d,
            file,
            &loaded,
            &view,
            state,
            now,
            directory_refused.is_some(),
        ),
        Err(e @ Error::LockTimeout { .. }) => return Err(e),
        Err(e) => d.block(error_issue(file, state, &e)),
    }
    if let Some(warning) = state.observe_pass_file(&loaded) {
        d.find("pass-edited-in-place", warning);
    }
    if let Err(refusal) = loaded.pass.check_window(now, Duration::ZERO) {
        let step = if refusal.code == hallpass::RefusalCode::NotYetValid {
            "Wait for the window to open; nothing needs changing.".to_owned()
        } else {
            format!(
                "Ask the owner for a new written approval, then review it against this pass with `hallpass diff {} NEW` before it replaces this file.",
                shown(file)
            )
        };
        d.block(Issue {
            code: refusal.code.as_str().to_owned(),
            lines: vec![format!("{}.", refusal.message)],
            next: None,
            step,
        });
    }
    for warning in hallpass::review::window_warnings(&loaded.pass, Some(now)) {
        d.find(warning.code, warning.message);
    }
    match archived {
        Some((dir, hallpass::Provenance::Missing)) => d.act(Issue {
            code: "not-archived".to_owned(),
            lines: vec![format!(
                "the archive {} does not hold this revision of the pass ({}), so an audit cannot replay its decisions.",
                shown(dir),
                loaded.digest
            )],
            next: argv(["hallpass", "archive", &shown(file), &shown(dir)]),
            step: "This keeps the exact pass bytes in the archive. For a signed approval, use `hallpass verify-approval --archive` instead, which also keeps the signature.".to_owned(),
        }),
        Some((_, hallpass::Provenance::Unsigned)) => d.find(
            "archived-unsigned",
            "the archive holds this revision without a signature record; `hallpass verify-approval --archive` records one",
        ),
        _ => {}
    }
    Ok(d)
}

/// What a ledger that reads without an error still says.
fn ledger_findings(
    d: &mut Diagnosis,
    file: &Path,
    loaded: &LoadedPass,
    view: &LedgerView,
    state: &StateDir,
    now: hallpass::time::OffsetDateTime,
    directory_refused: bool,
) {
    let shared = hallpass::shared_directory_warning(file);
    let future = hallpass::future_mtime_warning(file);
    for warning in &view.warnings {
        let code = if future.as_ref() == Some(warning) {
            "pass-mtime-in-future"
        } else if shared.as_ref() == Some(warning) {
            if directory_refused {
                continue;
            }
            "shared-directory"
        } else if warning.starts_with("the witness last saw this ledger at") {
            "ledger-moved"
        } else {
            match &view.witness {
                // The problem below says it.
                WitnessStatus::Missing if last_seq(view) > 0 => continue,
                WitnessStatus::Missing => "no-witness",
                WitnessStatus::Extended { .. } => "witness-behind",
                // The problem below says it.
                WitnessStatus::NotChecked { .. } => continue,
                _ => "ledger",
            }
        };
        d.find(code, warning.clone());
    }
    if let WitnessStatus::NotChecked { reason } = &view.witness {
        d.block(witness_issue(file, loaded, view, state, reason));
    } else {
        write_access(d, file, loaded, view, state);
    }
    if let Err(e) = view.check_clock_kind() {
        d.block(error_issue(file, state, &e));
    }
    if let Some(warning) = view.clock_warning(now) {
        d.find("clock-behind-ledger", warning);
    }
    ceiling_findings(d, file, loaded, view);
    if let Some(seq) = view.unreconciled_adoption {
        d.act(Issue {
            code: "reference-inconclusive".to_owned(),
            lines: vec![format!(
                "adoption {seq} may have lost lines, and so caller references: a spend with --require-new-ref is refused as reference-inconclusive until the references that may be in those lines are reconciled."
            )],
            next: argv(["hallpass", "help", "reconcile-references"]),
            step: format!(
                "List every caller reference your run records used on this pass that may be in the lost lines, then record them with `hallpass reconcile-references {} --adoption {seq} --references LIST --reason \"...\"`. The help page shows the list format.",
                shown(file)
            ),
        });
    }
    if view.witness == WitnessStatus::Missing && last_seq(view) > 0 {
        d.act(no_witness_issue(file, loaded, view, state));
    }
}

/// The counters at or over their ceiling: `blocked` when that is every
/// one, since every spend is then refused, else findings.
fn ceiling_findings(d: &mut Diagnosis, file: &Path, loaded: &LoadedPass, view: &LedgerView) {
    let mut reached = Vec::new();
    for (name, total) in &loaded.pass.ceilings {
        let spent = view.tally.spent(name);
        if spent > *total {
            reached.push((
                "over-ceiling",
                format!(
                    "{name}: {spent} spent of {total}, over by {}; nothing more can be spent on it",
                    spent - total
                ),
            ));
        } else if spent == *total {
            reached.push((
                "ceiling-reached",
                format!("{name}: {spent} spent of {total}; nothing more can be spent on it"),
            ));
        }
    }
    d.at_ceiling = loaded
        .pass
        .ceilings
        .iter()
        .filter(|(name, total)| view.tally.spent(name) >= **total)
        .map(|(name, _)| name.clone())
        .collect();
    d.ledger = match (&view.witness, view.exists) {
        (_, false) => "there is no ledger yet (the first spend creates it)".to_owned(),
        (WitnessStatus::Matches, true) => "its ledger and witness agree".to_owned(),
        (WitnessStatus::Extended { .. }, true) => {
            "its ledger verifies and extends the witness (the next spend catches the witness up)"
                .to_owned()
        }
        _ => "its ledger verifies and has no entries yet".to_owned(),
    };
    if !reached.is_empty() && reached.len() == loaded.pass.ceilings.len() {
        d.block(Issue {
            code: hallpass::RefusalCode::CeilingReached.as_str().to_owned(),
            lines: std::iter::once(
                "every ceiling of the pass is reached, so every spend is refused:".to_owned(),
            )
            .chain(reached.into_iter().map(|(_, line)| format!("{line}.")))
            .collect(),
            next: None,
            step: format!(
                "Stop. To spend more, ask the owner for a new written approval with higher ceilings, then review it against this pass with `hallpass diff {} NEW` before it replaces this file.",
                shown(file)
            ),
        });
    } else {
        for (code, line) in reached {
            d.find(code, line);
        }
    }
}

/// The sequence number of the ledger's last logical entry (0: none).
fn last_seq(view: &LedgerView) -> u64 {
    view.tip.as_ref().map_or(0, |tip| tip.seq)
}

/// A ledger with entries and no witness: a plain spend goes ahead and
/// records a witness, but a guarded spend is refused as
/// `reference-inconclusive`, and the spend's advice is the adoption.
fn no_witness_issue(
    file: &Path,
    loaded: &LoadedPass,
    view: &LedgerView,
    state: &StateDir,
) -> Issue {
    let pass = shown(file);
    Issue {
        code: "no-witness".to_owned(),
        lines: vec![
            format!(
                "there is no witness for pass `{}`, but its ledger's last logical sequence is {}, so hallpass cannot tell whether later ledger data was lost (for example in a partial copy).",
                loaded.pass.id,
                last_seq(view)
            ),
            "A spend with --require-new-ref is refused as reference-inconclusive until an adoption records a witness.".to_owned(),
        ],
        next: adopt_preview(file, state),
        step: format!(
            "Only if this ledger is the complete history (for example it moved here with the pass): the preview shows that the adoption keeps every line and carries nothing, and prints its token; then run `hallpass adopt {pass} --reason \"...\" --token TOKEN`. Otherwise restore the complete ledger from a backup, or reconcile each caller reference with your run record."
        ),
    }
}

/// The adoption preview, with `--carry-noted-totals` when the library
/// refuses it without.
fn adopt_preview(file: &Path, state: &StateDir) -> Option<Vec<String>> {
    let pass = shown(file);
    let mut words = vec!["hallpass", "adopt", &pass, "--preview"];
    if hallpass::preview_adopt_with(file, state, false).is_err()
        && hallpass::preview_adopt_with(file, state, true).is_ok()
    {
        words.push("--carry-noted-totals");
    }
    argv(words)
}

/// Whether this user (the effective user id) owns `path`, so that it can
/// change its mode.
fn owned(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).is_ok_and(|meta| meta.uid() == rustix::process::geteuid().as_raw())
}

/// Whether this user may write `path` (and, for a directory, enter it), by
/// `access(2)` with the effective ids: it writes nothing.
fn may_write(path: &Path, dir: bool) -> bool {
    use rustix::fs::{Access, AtFlags, CWD, accessat};
    let mode = if dir {
        Access::WRITE_OK | Access::EXEC_OK
    } else {
        Access::WRITE_OK
    };
    accessat(CWD, path, mode, AtFlags::EACCESS).is_ok()
}

/// What a spend writes, checked without writing: the state directory (or
/// the directory a spend would create it in) and its lock file, then the
/// ledger, or the pass directory that a first spend creates it in. A spend
/// fails `witness-unavailable` for the first two and `io` for the others.
fn write_access(
    d: &mut Diagnosis,
    file: &Path,
    loaded: &LoadedPass,
    view: &LedgerView,
    state: &StateDir,
) {
    let again = format!("Then run `hallpass doctor {}` again.", shown(file));
    let blocked = |code: &str, what: String, path: &Path, mode: &str| {
        let lines = vec![format!(
            "{what} is not writable by this user, so every spend fails before it records anything."
        )];
        if owned(path) {
            Issue {
                code: code.to_owned(),
                lines,
                next: argv(["chmod", mode, &shown(path)]),
                step: again.clone(),
            }
        } else {
            Issue {
                code: code.to_owned(),
                lines,
                next: None,
                step: format!(
                    "Another user owns {}, so this user cannot change its mode: have its owner make it writable for this user, or restore it with this user as owner. {again}",
                    shown(path)
                ),
            }
        }
    };
    if let Ok(dir) = state.path() {
        let mut existing = dir;
        while std::fs::symlink_metadata(existing).is_err() {
            match existing.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => existing = parent,
                _ => break,
            }
        }
        let lock = dir.join(format!("{}.lock", loaded.pass.id));
        if !may_write(existing, true) {
            let what = if existing == dir {
                format!("the state directory {}", shown(dir))
            } else {
                format!(
                    "the state directory {} does not exist yet, and {}, where a spend creates it,",
                    shown(dir),
                    shown(existing)
                )
            };
            let mut issue = blocked("witness-unavailable", what, existing, "u+w");
            if existing != dir && !owned(existing) {
                issue.step = format!(
                    "Do not change {}: another user owns it. Set XDG_STATE_HOME to an absolute directory this user can write (hallpass keeps its witnesses in its `hallpass` subdirectory), and use the same value for every command on this pass. {again}",
                    shown(existing)
                );
            }
            d.block(issue);
        } else if lock.exists() && !may_write(&lock, false) {
            d.block(blocked(
                "witness-unavailable",
                format!("the witness lock file {}", shown(&lock)),
                &lock,
                "600",
            ));
        }
    }
    if view.exists {
        if !may_write(&view.path, false) {
            d.block(blocked(
                "io",
                format!("the ledger {}", shown(&view.path)),
                &view.path,
                "600",
            ));
        }
    } else {
        let parent = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !may_write(parent, true) {
            d.block(blocked(
                "io",
                format!(
                    "there is no ledger yet: the first spend creates {}, but the directory {}",
                    shown(&view.path),
                    shown(parent)
                ),
                parent,
                "u+w",
            ));
        }
    }
}

/// A witness that could not be checked: a spend fails `witness-unavailable`.
/// The next step comes from the advice the library gave in `reason`.
fn witness_issue(
    file: &Path,
    loaded: &LoadedPass,
    view: &LedgerView,
    state: &StateDir,
    reason: &str,
) -> Issue {
    let witness = state.witness_path(&loaded.pass.id).ok();
    let again = format!("Then run `hallpass doctor {}` again.", shown(file));
    let (next, step) = match (&witness, state.path()) {
        (Some(w), _) if reason.contains("is damaged (") && view.exists => (
            argv(["mv", &shown(w), &aside(w)]),
            format!(
                "The ledger beside the pass verifies, so it, not the damaged witness, holds the count: move the witness aside (keep it), then run `hallpass adopt {} --preview` and adopt the ledger with its token to record a new witness. Until then a spend with --require-new-ref is refused as reference-inconclusive. {again}",
                shown(file)
            ),
        ),
        (Some(_), _) if reason.contains("is damaged (") => (
            None,
            "Do not move the witness aside: the ledger is not beside the pass, and the witness is the record of its count. Put the ledger back beside the pass (restore it from a backup), then run doctor again.".to_owned(),
        ),
        (_, Ok(dir)) if reason.contains("run `chmod 700") => (
            argv(["chmod", "700", &shown(dir)]),
            again,
        ),
        (Some(w), _) if reason.contains("run `chmod 600` on it") => {
            (argv(["chmod", "600", &shown(w)]), again)
        }
        _ => (None, format!("Follow the advice in the message. {again}")),
    };
    Issue {
        code: "witness-unavailable".to_owned(),
        lines: vec![format!(
            "the witness cannot be used, so a spend is refused: {reason}"
        )],
        next,
        step,
    }
}

/// A new name beside `path` for a file moved aside.
fn aside(path: &Path) -> String {
    let mut n = 1;
    loop {
        let name = if n == 1 {
            format!("{}.damaged", shown(path))
        } else {
            format!("{}.damaged-{n}", shown(path))
        };
        if std::fs::symlink_metadata(&name).is_err() {
            return name;
        }
        n += 1;
    }
}

/// The issue for an error that a spend would fail with.
fn error_issue(file: &Path, state: &StateDir, error: &Error) -> Issue {
    let pass = shown(file);
    let again = format!("Then run `hallpass doctor {pass}` again.");
    // A damaged ledger's message ends in a last resort that adopts; doctor
    // names the step itself, so it shows the form without it.
    let mut lines = if matches!(error, Error::LedgerCorrupt { .. }) {
        error.message_lines(true)
    } else {
        error.message_lines(false)
    };
    let (next, step) = match error {
        Error::Insecure { path, fix, .. } => (argv(["chmod", fix, &shown(path)]), again),
        Error::SharedDirectory { path, .. } => (
            argv(["chmod", "o-w", &shown(path)]),
            format!(
                "Or `chmod +t {}` if the directory must stay shared. {again}",
                shown(path)
            ),
        ),
        Error::Invalid { .. } => (
            argv(["hallpass", "check", &pass]),
            "It lists every problem with what to do.".to_owned(),
        ),
        Error::LedgerCorrupt {
            path,
            last,
            complete,
            ..
        } => corrupt_step(file, state, path, *last && !*complete, &mut lines),
        Error::LedgerMissing(missing) => missing_step(file, state, missing, &mut lines),
        Error::LedgerElsewhere(elsewhere) => elsewhere_step(&pass, elsewhere),
        Error::LedgerChanged { path, .. } => changed_step(file, state, path),
        _ => (None, format!("Follow the advice in the message. {again}")),
    };
    Issue {
        code: error.code().to_owned(),
        lines,
        next,
        step,
    }
}

type Step = (Option<Vec<String>>, String);

/// The step for a changed ledger: `compare-backups` on it, and on the
/// ledger where the witness last saw it when that is another file that is
/// still there (a copy of the pass, with its ledger, spent from too).
fn changed_step(file: &Path, state: &StateDir, ledger: &Path) -> Step {
    let pass = shown(file);
    let other = hallpass::load(file).ok().and_then(|loaded| {
        state
            .last_seen_ledger(&loaded.pass.id)
            .filter(|seen| seen.is_absolute() && seen.is_file())
            .filter(|seen| std::fs::canonicalize(ledger).ok().as_ref() != Some(seen))
    });
    other.map_or_else(
        || {
            (
                argv(["hallpass", "compare-backups", &pass, &shown(ledger)]),
                format!(
                    "Add each backup copy of the ledger after {}: compare-backups shows which copy holds the line the witness recorded. Restore that copy beside the pass.",
                    shown(ledger)
                ),
            )
        },
        |seen| {
            (
                argv([
                    "hallpass",
                    "compare-backups",
                    &pass,
                    &shown(ledger),
                    &shown(&seen),
                ]),
                format!(
                    "The witness last saw the ledger at {}, another ledger for this pass id, and spends from that copy moved the witness on. compare-backups shows which ledger holds the line the witness recorded: spend from that copy only. Give a second pass file its own id, or move this copy away. Add any backup copies after them.",
                    shown(&seen)
                ),
            )
        },
    )
}

/// The step for a damaged ledger: the repair preview for a cut-short last
/// line it accepts, else `compare-backups`.
fn corrupt_step(
    file: &Path,
    state: &StateDir,
    ledger: &Path,
    cut_short: bool,
    lines: &mut Vec<String>,
) -> Step {
    let pass = shown(file);
    if cut_short && hallpass::preview_restore_final_newline(file, state).is_ok() {
        return (
            argv([
                "hallpass",
                "repair",
                &pass,
                "--restore-final-newline",
                "--preview",
            ]),
            "The last line is whole and the witness recorded it; only its line end is missing. The preview prints the token for the repair, which adds the line end and changes nothing else.".to_owned(),
        );
    }
    if cut_short {
        match hallpass::preview_drop_torn_tail(file, state) {
            Ok(_) => {
                return (
                    argv(["hallpass", "repair", &pass, "--drop-torn-tail", "--preview"]),
                    "The preview checks that the witness proves the cut-short line was never counted, and prints the token for the repair.".to_owned(),
                );
            }
            Err(e) => lines.push(format!(
                "The repair of a cut-short last line does not apply: {}",
                e.read_only_message()
            )),
        }
    }
    (
        argv(["hallpass", "compare-backups", &pass, &shown(ledger)]),
        format!(
            "Add each backup copy of the ledger after {}: compare-backups shows which copy is the good one. Restore that copy beside the pass. Do not edit the ledger by hand.",
            shown(ledger)
        ),
    )
}

/// The step for a missing ledger. When a file is still where the witness
/// last saw the ledger, it may be that ledger, so the step is
/// `compare-backups` on it, never an adoption. Otherwise it is the adoption
/// preview, with `--carry-noted-totals` when the library refuses it without.
fn missing_step(
    file: &Path,
    state: &StateDir,
    missing: &hallpass::MissingLedger,
    lines: &mut Vec<String>,
) -> Step {
    let pass = shown(file);
    let seen = Path::new(&missing.last_seen);
    if seen.is_absolute() && std::fs::symlink_metadata(seen).is_ok() {
        let text = missing.to_string();
        let found = text.find("; if it is really lost").unwrap_or(text.len());
        *lines = vec![
            format!("{}.", &text[..found]),
            format!(
                "A file is where the witness last saw the ledger ({}). It may be this ledger, changed or grown since, so do not adopt.",
                missing.last_seen
            ),
        ];
        return (
            argv(["hallpass", "compare-backups", &pass, &missing.last_seen]),
            format!(
                "It shows how that file relates to the witness. If it extends the witness, move it beside the pass ({}). Add any backup copies after it.",
                shown(&missing.path)
            ),
        );
    }
    (
        adopt_preview(file, state),
        "First put the ledger back beside the pass if a copy exists (restore it from a backup). If it is really lost, the preview shows what an adoption would carry and prints its token; it records nothing.".to_owned(),
    )
}

/// The step for a ledger intact elsewhere: move it here, or, with a pass
/// file beside it, see how this pass file differs from that one.
fn elsewhere_step(pass: &str, elsewhere: &hallpass::ElsewhereLedger) -> Step {
    elsewhere.live_pass.as_ref().map_or_else(
        || {
            (
                argv(["mv", &shown(&elsewhere.live), &shown(&elsewhere.path)]),
                "The count carries on from the live ledger. Do not adopt: the ledger is not lost."
                    .to_owned(),
            )
        },
        |live_pass| {
            (
                argv(["hallpass", "diff", &shown(live_pass), pass]),
                format!(
                    "It shows whether this pass file revises the live pass file {}. Then follow the steps above. Do not adopt: the ledger is not lost.",
                    shown(live_pass)
                ),
            )
        },
    )
}

/// A word as a shell would need it typed.
fn shell_word(word: &str) -> String {
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

fn command_line(words: &[String]) -> String {
    words
        .iter()
        .map(|w| shell_word(w))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render(file: &Path, d: Diagnosis) -> Output {
    let Diagnosis {
        pass_id,
        blocked,
        action,
        mut findings,
        ledger,
        at_ceiling,
    } = d;
    let (result, problem, issue) = match (blocked, action) {
        (Some(blocked), action) => {
            if let Some(a) = action {
                findings.insert(
                    0,
                    Finding {
                        code: a.code,
                        message: a.lines.join(" "),
                    },
                );
            }
            ("blocked", Some(blocked.code.clone()), Some(blocked))
        }
        (None, Some(action)) => ("needs-action", None, Some(action)),
        (None, None) => ("healthy", None, None),
    };
    let mut text = String::new();
    let (message, next, step) = if let Some(issue) = &issue {
        let label = if result == "blocked" {
            "BLOCKED"
        } else {
            "NEEDS ACTION"
        };
        let mut lines = issue.lines.iter();
        let _ = writeln!(
            text,
            "{label}: {}: {}",
            issue.code,
            safe_message(lines.next().map_or("", String::as_str))
        );
        for line in lines {
            let _ = writeln!(text, "  {}", safe_message(line));
        }
        (
            issue.lines.join(" "),
            issue.next.clone(),
            issue.step.clone(),
        )
    } else {
        let id = pass_id.as_deref().unwrap_or_default();
        let head = if at_ceiling.is_empty() {
            format!("nothing blocks a spend under pass `{id}`")
        } else {
            format!(
                "nothing blocks a spend under pass `{id}` that charges only counters below their ceiling ({} reached its ceiling)",
                at_ceiling.join(", ")
            )
        };
        let message = format!(
            "{head}: the pass validates, its window is open, {ledger}, and the state directory and the ledger (or the directory it goes in) are writable"
        );
        let _ = writeln!(text, "HEALTHY: {}.", safe_message(&message));
        (message, None, "Nothing to do.".to_owned())
    };
    match &next {
        Some(words) => {
            let _ = writeln!(text, "Next: {}", safe_message(&command_line(words)));
            let _ = writeln!(text, "  {}", safe_message(&step));
        }
        None if issue.is_some() => {
            let _ = writeln!(text, "Next: no command. {}", safe_message(&step));
        }
        None => text.push_str("Next: nothing to do.\n"),
    }
    if !findings.is_empty() {
        text.push_str("Also:\n");
        for f in &findings {
            let _ = writeln!(text, "  - {}: {}", f.code, safe_message(&f.message));
        }
    }
    let findings: Vec<Value> = findings
        .iter()
        .map(|f| json!({"code": f.code, "message": f.message}))
        .collect();
    Output {
        code: if issue.is_some() { REFUSED } else { OK },
        json: json!({
            "command": NAME,
            "result": result,
            "file": shown(file),
            "pass_id": pass_id,
            "problem": problem,
            "message": message,
            "next": next,
            "next_step": step,
            "findings": findings,
        }),
        text,
    }
}
