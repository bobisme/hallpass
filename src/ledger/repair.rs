//! `hallpass repair --drop-torn-tail`: remove a final ledger line that a
//! failed write cut short, when the witness proves that line was never
//! counted.
//!
//! The repair removes bytes only when all of these hold:
//!
//! - the ledger does not end with a line end, so its last line is cut short;
//! - every complete line before it verifies, for this pass;
//! - the witness exists and its line is one of those complete lines, so the
//!   witness never counted the cut-short line;
//! - the cut-short bytes start the way hallpass starts the next line, with
//!   the next sequence number (`{"seq":N,` for N one past the last complete
//!   line), or are a shorter start of that.
//!
//! Anything else is refused and nothing is changed. The removed bytes are
//! kept in a new private file beside the ledger before the ledger is cut,
//! and a token from the preview guards the cut: the pass, the ledger and
//! the witness must be as the preview saw them.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use super::{Parsed, WitnessStatus, check_private, compare, exists, ledger_path, parse_ledger};
use crate::error::Error;
use crate::files::{Digest, LoadedPass, LockBudget, load, lock_shared, open_no_follow};
use crate::witness::{StateDir, Witnessed, ledger_identity};

/// The advice for every refusal that only a backup can fix.
pub(super) const BACKUP: &str =
    "Restore the ledger from a backup: `hallpass compare-backups` shows which copy is the good one";

/// The token prefix: a repair token is never mistaken for an adoption token.
const TOKEN_PREFIX: &str = "tail1:";

/// What `--drop-torn-tail` would remove, or removed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TornTail {
    /// The pass id.
    pub pass_id: String,
    /// The ledger file.
    pub ledger: PathBuf,
    /// The sequence number of the last complete line, which is kept.
    pub seq: u64,
    /// The sequence number the witness recorded (at most `seq`).
    pub witness_seq: u64,
    /// The length the ledger is cut back to: everything up to and with the
    /// last line end.
    pub kept_bytes: u64,
    /// How many bytes of the cut-short line are removed.
    pub removed_bytes: u64,
    /// The guard for the repair, as `--preview` prints it.
    pub token: String,
    /// Where the removed bytes were kept (only after the repair).
    pub copy: Option<PathBuf>,
}

/// Show what `--drop-torn-tail` would remove from the ledger of the pass at
/// `pass_path`, and the token that guards it. Reads only.
///
/// # Errors
///
/// [`Error::Usage`] when there is nothing that may be removed safely (see
/// the module documentation), or any error reading the pass, the ledger or
/// the witness.
pub fn preview_drop_torn_tail(pass_path: &Path, state: &StateDir) -> Result<TornTail, Error> {
    let loaded = load(pass_path)?;
    let path = ledger_path(pass_path);
    let file = open_ledger(pass_path, &path, false)?;
    lock_shared(&file, &path)?;
    let witness = state.read(&loaded.pass.id)?;
    inspect(pass_path, &path, &file, &loaded, witness.as_ref(), state)
}

/// Remove the cut-short last line that [`preview_drop_torn_tail`] showed,
/// under both writer locks, after keeping a copy of its bytes beside the
/// ledger. `token` is the token the preview printed.
///
/// # Errors
///
/// As [`preview_drop_torn_tail`]; [`Error::Usage`] for a token that is
/// malformed or stale; [`Error::Io`] when the copy or the cut fails (the
/// ledger is not cut unless its copy was written and synced).
pub fn drop_torn_tail(pass_path: &Path, state: &StateDir, token: &str) -> Result<TornTail, Error> {
    check_token_shape(token, pass_path)?;
    crate::files::refuse_world_writable_directory(pass_path)?;
    let id = load(pass_path)?.pass.id;
    let wait = LockBudget::requested(None, None);
    let _witness_lock = state.lock(&id, wait)?;
    let path = ledger_path(pass_path);
    let file = open_ledger(pass_path, &path, true)?;
    wait.exclusive(&file, &path, |e| Error::io(&path, e))?;
    let loaded = load(pass_path)?;
    let witness = state.read(&loaded.pass.id)?;
    let mut torn = inspect(pass_path, &path, &file, &loaded, witness.as_ref(), state)?;
    if loaded.pass.id != id || torn.token != token {
        return Err(Error::Usage(format!(
            "the repair token is stale: the pass, the ledger or the witness changed since that preview; nothing was changed. Run `hallpass repair {} --drop-torn-tail --preview` again and use the new token",
            pass_path.display()
        )));
    }
    let mut removed = vec![0; usize::try_from(torn.removed_bytes).unwrap_or(usize::MAX)];
    file.read_exact_at(&mut removed, torn.kept_bytes)
        .map_err(|e| Error::io(&path, &e))?;
    let copy = keep_copy(&path, torn.seq + 1, &removed)?;
    file.set_len(torn.kept_bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::io(&path, &e))?;
    torn.copy = Some(copy);
    Ok(torn)
}

/// Refuse a token that is not shaped like one `--preview` prints, before any
/// lock is taken.
fn check_token_shape(token: &str, pass_path: &Path) -> Result<(), Error> {
    if token
        .strip_prefix(TOKEN_PREFIX)
        .is_some_and(|d| d.parse::<Digest>().is_ok())
    {
        return Ok(());
    }
    Err(Error::Usage(format!(
        "{} is not a repair token (a token looks like {TOKEN_PREFIX}sha256:<64 hex digits>); nothing was changed. Run `hallpass repair {} --drop-torn-tail --preview` and use the token it prints",
        super::display_quoted(token),
        pass_path.display()
    )))
}

/// Open the ledger, refusing a missing one with advice.
pub(super) fn open_ledger(pass_path: &Path, path: &Path, write: bool) -> Result<File, Error> {
    if !exists(path)? {
        return Err(Error::Usage(format!(
            "there is no ledger at {}, so there is no cut-short line to drop; nothing was changed. Run `hallpass status {}` to see the state of the pass",
            path.display(),
            pass_path.display()
        )));
    }
    let file = open_no_follow(path, OpenOptions::new().read(true).write(write))?;
    check_private(path, &file)?;
    Ok(file)
}

/// Check everything the module documentation lists, and make the token.
fn inspect(
    pass_path: &Path,
    path: &Path,
    file: &File,
    loaded: &LoadedPass,
    witness: Option<&Witnessed>,
    state: &StateDir,
) -> Result<TornTail, Error> {
    let refuse = |problem: String, action: &str| {
        Error::Usage(format!(
            "{problem}. Nothing was changed: `--drop-torn-tail` removes only a last line that is cut short (it has no line end) and that the witness proves was never counted. {action}"
        ))
    };
    let status = format!(
        "Run `hallpass status {}` to see whether the ledger is damaged",
        pass_path.display()
    );
    let len = file.metadata().map_err(|e| Error::io(path, &e))?.len();
    let Some(kept) = last_line_end(file, len).map_err(|e| Error::io(path, &e))? else {
        return Err(refuse(
            format!(
                "the ledger {} has no complete line, not even its header",
                path.display()
            ),
            BACKUP,
        ));
    };
    if kept == len {
        return Err(refuse(
            format!(
                "the last line of the ledger {} ends with a line end, so it is not cut short",
                path.display()
            ),
            &status,
        ));
    }
    let parsed = parse_prefix(path, file, kept, loaded, witness)?;
    let Some(witness) = witness else {
        return Err(refuse(
            format!(
                "there is no witness for pass `{}`, so nothing proves that the cut-short line was never counted",
                loaded.pass.id
            ),
            BACKUP,
        ));
    };
    match compare(
        pass_path,
        path,
        Some(&parsed),
        Some(witness),
        state,
        &loaded.pass.id,
    ) {
        Ok((WitnessStatus::Matches | WitnessStatus::Extended { .. }, _)) => {}
        Ok(_) | Err(Error::LedgerChanged { .. }) if witness.seq > parsed.seq => {
            return Err(refuse(
                format!(
                    "the witness recorded sequence {}, but the complete lines of the ledger end at sequence {}: the cut-short line was counted, so removing it would lower the count",
                    witness.seq, parsed.seq
                ),
                &format!(
                    "If that line is whole and only its line end is missing, `hallpass repair {0} --restore-final-newline --preview` checks it against the witness and adds the line end. Otherwise: {1}. With no backup, the last resort is to move the ledger aside (keep it) and run `hallpass adopt {0} --reason \"...\"`: the pass is then ledger-missing, and the adoption starts a new ledger that carries the witness totals. The receipts in the moved ledger are not in the new chain",
                    pass_path.display(),
                    BACKUP.replacen('R', "r", 1)
                ),
            ));
        }
        Ok(_) | Err(Error::LedgerChanged { .. }) => {
            return Err(refuse(
                format!(
                    "the complete lines of the ledger do not hold the line the witness recorded at sequence {}",
                    witness.seq
                ),
                BACKUP,
            ));
        }
        Err(e) => return Err(e),
    }
    let mut torn = vec![0; usize::try_from(len - kept).unwrap_or(usize::MAX)];
    file.read_exact_at(&mut torn, kept)
        .map_err(|e| Error::io(path, &e))?;
    check_torn_start(&torn, parsed.seq, witness.seq).map_err(|problem| refuse(problem, BACKUP))?;
    let input = serde_json::json!({
        "version": 1,
        "purpose": "drop-torn-tail",
        "pass_id": loaded.pass.id,
        "pass_digest": loaded.digest.to_string(),
        "ledger": ledger_identity(path),
        "length": len,
        "kept": kept,
        "seq": parsed.seq,
        "tail": parsed.tail().to_string(),
        "torn": Digest::of(&torn).to_string(),
        "witness": {"seq": witness.seq, "tail": witness.tail.to_string()},
    });
    Ok(TornTail {
        pass_id: loaded.pass.id.clone(),
        ledger: path.to_path_buf(),
        seq: parsed.seq,
        witness_seq: witness.seq,
        kept_bytes: kept,
        removed_bytes: len - kept,
        token: format!("{TOKEN_PREFIX}{}", Digest::of(input.to_string().as_bytes())),
        copy: None,
    })
}

/// Verify the complete lines (the first `kept` bytes) as a ledger of this
/// pass.
fn parse_prefix(
    path: &Path,
    file: &File,
    kept: u64,
    loaded: &LoadedPass,
    witness: Option<&Witnessed>,
) -> Result<Parsed, Error> {
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| Error::io(path, &e))?;
    parse_ledger(
        path,
        BufReader::new(reader.take(kept)),
        &loaded.pass.id,
        false,
        witness.map(|w| w.seq),
    )
    .map_err(|e| match e {
        Error::LedgerCorrupt { line, detail, .. } => Error::Usage(format!(
            "the ledger {} is damaged at line {line}, before its cut-short last line: {}. Dropping the last line would not repair it, so nothing was changed. {BACKUP}",
            path.display(),
            detail.strip_suffix('.').unwrap_or(&detail)
        )),
        other => other,
    })
}

/// The cut-short bytes must start the next line hallpass would write:
/// `{"seq":N,` with N one past `seq`, or a shorter start of it.
fn check_torn_start(torn: &[u8], seq: u64, witness_seq: u64) -> Result<(), String> {
    let next = seq + 1;
    let expected = format!("{{\"seq\":{next},");
    if torn.starts_with(expected.as_bytes()) || expected.as_bytes().starts_with(torn) {
        return Ok(());
    }
    let written = torn
        .strip_prefix(b"{\"seq\":")
        .map(|rest| {
            rest.iter()
                .take_while(|b| b.is_ascii_digit())
                .map(|b| char::from(*b))
                .collect::<String>()
        })
        .filter(|digits| !digits.is_empty() && torn.len() > 7 + digits.len());
    Err(written.map_or_else(
        || {
            format!(
                "the cut-short line does not start as hallpass starts the line after sequence {seq} ({}), so it is not a line hallpass was writing there",
                super::display_quoted(&expected)
            )
        },
        |digits| {
            format!(
                "the cut-short line has sequence {digits}, but the line after sequence {seq} must have sequence {next} (the witness recorded sequence {witness_seq}): it is not a line hallpass was writing there, so it may have been counted"
            )
        },
    ))
}

/// The length of the file up to and with its last line end, or `None` when
/// it has none. Reads backwards from the end.
pub(super) fn last_line_end(file: &File, len: u64) -> std::io::Result<Option<u64>> {
    const CHUNK: u64 = 64 * 1024;
    let mut end = len;
    let mut buffer = vec![0; usize::try_from(CHUNK).unwrap_or(usize::MAX)];
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let part = &mut buffer[..usize::try_from(end - start).unwrap_or(usize::MAX)];
        file.read_exact_at(part, start)?;
        if let Some(at) = part.iter().rposition(|b| *b == b'\n') {
            return Ok(Some(start + at as u64 + 1));
        }
        end = start;
    }
    Ok(None)
}

/// Keep the removed bytes in a new private file beside the ledger,
/// `LEDGER.torn-N` (or `LEDGER.torn-N.2` and on when that exists), synced
/// with its directory before the ledger is cut.
fn keep_copy(ledger: &Path, next: u64, bytes: &[u8]) -> Result<PathBuf, Error> {
    let mut name = ledger.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".torn-{next}"));
    let first = ledger.with_file_name(&name);
    for n in 1..=100 {
        let copy = if n == 1 {
            first.clone()
        } else {
            let mut numbered = name.clone();
            numbered.push(format!(".{n}"));
            ledger.with_file_name(numbered)
        };
        match crate::template::write_new_private(&copy, bytes) {
            Ok(()) => {
                let dir = match copy.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p,
                    _ => Path::new("."),
                };
                File::open(dir)
                    .and_then(|d| d.sync_all())
                    .map_err(|e| Error::io(dir, &e))?;
                return Ok(copy);
            }
            Err(Error::Exists { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::Usage(format!(
        "{} and 99 numbered copies beside it already exist; nothing was changed. Move the old copies of removed lines elsewhere, then run the command again",
        first.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::check_torn_start;

    #[test]
    fn the_torn_bytes_must_start_the_next_line() {
        for torn in [
            "{",
            "{\"se",
            "{\"seq\":",
            "{\"seq\":1",
            "{\"seq\":12",
            "{\"seq\":12,",
            "{\"seq\":12,\"time\":\"2026",
        ] {
            assert!(check_torn_start(torn.as_bytes(), 11, 11).is_ok(), "{torn}");
        }
        for torn in ["x", "{\"seq\":13", "{\"seq\":2,\"ti", "{\"seq\":120", "\n"] {
            check_torn_start(torn.as_bytes(), 11, 11).expect_err(torn);
        }
        let refused = check_torn_start(b"{\"seq\":3,\"time", 4, 4).expect_err("old seq");
        assert!(refused.contains("has sequence 3"), "{refused}");
        assert!(refused.contains("witness recorded sequence 4"), "{refused}");
    }
}
