//! `hallpass repair --drop-blank-tail`: remove empty lines, or lines of only
//! white space, that were added after the last line hallpass wrote (for
//! example by `echo >> ledger`).
//!
//! The repair removes bytes only when all of these hold:
//!
//! - everything after the last complete line is empty lines or white space
//!   (spaces, tabs, carriage returns, line ends), and there is some;
//! - the complete lines before it verify, for this pass;
//! - the witness exists and the hash of the last complete line is the tail
//!   the witness recorded at the last sequence number of the ledger.
//!
//! Anything else is refused and nothing is changed. No line hallpass wrote is
//! changed or removed, so no copy is kept: the removed bytes carry nothing.
//! A token from the preview guards the cut: the pass, the ledger and the
//! witness must be as the preview saw them.

use std::fs::File;
use std::io::{BufReader, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use super::repair::{BACKUP, open_ledger};
use super::{Parsed, WitnessStatus, compare, ledger_path, parse_ledger};
use crate::error::Error;
use crate::files::{Digest, LoadedPass, LockBudget, load, lock_shared};
use crate::witness::{StateDir, Witnessed, ledger_identity};

/// The token prefix: never mistaken for another repair or adoption token.
const TOKEN_PREFIX: &str = "blank1:";

/// What `--drop-blank-tail` would remove, or removed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct BlankTail {
    /// The pass id.
    pub pass_id: String,
    /// The ledger file.
    pub ledger: PathBuf,
    /// The sequence number of the last line, which the witness recorded.
    pub seq: u64,
    /// The length the ledger is cut back to.
    pub kept_bytes: u64,
    /// How many bytes of blank tail are removed.
    pub removed_bytes: u64,
    /// The guard for the repair, as `--preview` prints it.
    pub token: String,
    /// Whether the blank tail was removed (only after the repair).
    pub repaired: bool,
}

/// Show what `--drop-blank-tail` would remove from the ledger of the pass at
/// `pass_path`, and the token that guards it. Reads only.
///
/// # Errors
///
/// [`Error::Usage`] when the tail may not be removed safely (see the module
/// documentation), or any error reading the pass, the ledger or the witness.
pub fn preview_drop_blank_tail(pass_path: &Path, state: &StateDir) -> Result<BlankTail, Error> {
    let loaded = load(pass_path)?;
    let path = ledger_path(pass_path);
    let file = open_ledger(pass_path, &path, false)?;
    lock_shared(&file, &path)?;
    let witness = state.read(&loaded.pass.id)?;
    inspect(pass_path, &path, &file, &loaded, witness.as_ref(), state)
}

/// Remove the blank tail that [`preview_drop_blank_tail`] showed, under both
/// writer locks. `token` is the token the preview printed.
///
/// # Errors
///
/// As [`preview_drop_blank_tail`]; [`Error::Usage`] for a token that is
/// malformed or stale; [`Error::Io`] when the cut or the sync fails.
pub fn drop_blank_tail(
    pass_path: &Path,
    state: &StateDir,
    token: &str,
) -> Result<BlankTail, Error> {
    if token
        .strip_prefix(TOKEN_PREFIX)
        .is_none_or(|d| d.parse::<Digest>().is_err())
    {
        return Err(Error::Usage(format!(
            "{} is not a repair token (a token looks like {TOKEN_PREFIX}sha256:<64 hex digits>); nothing was changed. Run `hallpass repair {} --drop-blank-tail --preview` and use the token it prints",
            super::display_quoted(token),
            pass_path.display()
        )));
    }
    crate::files::refuse_world_writable_directory(pass_path)?;
    let id = load(pass_path)?.pass.id;
    let wait = LockBudget::requested(None, None);
    let _witness_lock = state.lock(&id, wait)?;
    let path = ledger_path(pass_path);
    let file = open_ledger(pass_path, &path, true)?;
    wait.exclusive(&file, &path, |e| Error::io(&path, e))?;
    let loaded = load(pass_path)?;
    let witness = state.read(&loaded.pass.id)?;
    let mut done = inspect(pass_path, &path, &file, &loaded, witness.as_ref(), state)?;
    if loaded.pass.id != id || done.token != token {
        return Err(Error::Usage(format!(
            "the repair token is stale: the pass, the ledger or the witness changed since that preview; nothing was changed. Run `hallpass repair {} --drop-blank-tail --preview` again and use the new token",
            pass_path.display()
        )));
    }
    file.set_len(done.kept_bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::io(&path, &e))?;
    done.repaired = true;
    Ok(done)
}

/// The length of the ledger up to and with the line end of its last line
/// that has content, and whether the bytes after it are all white space.
/// `None` when the file has no content, or the last content line has no line
/// end. Reads backwards from the end.
fn kept_length(file: &File, len: u64) -> std::io::Result<Option<u64>> {
    const CHUNK: u64 = 64 * 1024;
    let mut end = len;
    // The first line end seen so far, scanning from the end, among the white
    // space after the content.
    let mut first_end = None;
    let mut buffer = vec![0; usize::try_from(CHUNK).unwrap_or(usize::MAX)];
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let part = &mut buffer[..usize::try_from(end - start).unwrap_or(usize::MAX)];
        file.read_exact_at(part, start)?;
        for (i, b) in part.iter().enumerate().rev() {
            if matches!(b, b' ' | b'\t' | b'\r') {
                continue;
            }
            if *b == b'\n' {
                first_end = Some(start + i as u64);
                continue;
            }
            return Ok(first_end.map(|at| at + 1));
        }
        end = start;
    }
    Ok(None)
}

/// Check everything the module documentation lists, and make the token.
fn inspect(
    pass_path: &Path,
    path: &Path,
    file: &File,
    loaded: &LoadedPass,
    witness: Option<&Witnessed>,
    state: &StateDir,
) -> Result<BlankTail, Error> {
    let refuse = |problem: String, action: &str| {
        Error::Usage(format!(
            "{problem}. Nothing was changed: `--drop-blank-tail` removes only empty lines or white space after a last line that follows the line before it and that the witness recorded as its last line. {action}"
        ))
    };
    let status = format!(
        "Run `hallpass status {}` to see whether the ledger is damaged",
        pass_path.display()
    );
    let len = file.metadata().map_err(|e| Error::io(path, &e))?.len();
    let Some(kept) = kept_length(file, len).map_err(|e| Error::io(path, &e))? else {
        return Err(refuse(
            format!(
                "after its last line of content, the ledger {} has no line end to cut back to (it has no complete line, or its last line is cut short)",
                path.display()
            ),
            "If the last line is cut short, `hallpass repair --drop-torn-tail --preview` may apply. Otherwise restore the ledger from a backup: `hallpass compare-backups` shows which copy is the good one",
        ));
    };
    if kept == len {
        return Err(refuse(
            format!(
                "the ledger {} does not end with an empty line or white space",
                path.display()
            ),
            &status,
        ));
    }
    let Some(witness) = witness else {
        return Err(refuse(
            format!(
                "there is no witness for pass `{}`, so nothing proves that the last line is the one that was counted",
                loaded.pass.id
            ),
            BACKUP,
        ));
    };
    let parsed = parse_kept(path, file, kept, loaded, witness.seq)?;
    let matches = matches!(
        compare(
            pass_path,
            path,
            Some(&parsed),
            Some(witness),
            state,
            &loaded.pass.id,
        ),
        Ok((WitnessStatus::Matches, _))
    );
    if !matches || parsed.seq != witness.seq {
        return Err(refuse(
            format!(
                "the last line of the ledger {} (sequence {}) is not the line the witness recorded (sequence {}, tail {})",
                path.display(),
                parsed.seq,
                witness.seq,
                witness.tail
            ),
            BACKUP,
        ));
    }
    let mut tail = vec![0; usize::try_from(len - kept).unwrap_or(usize::MAX)];
    file.read_exact_at(&mut tail, kept)
        .map_err(|e| Error::io(path, &e))?;
    let input = serde_json::json!({
        "version": 1,
        "purpose": "drop-blank-tail",
        "pass_id": loaded.pass.id,
        "pass_digest": loaded.digest.to_string(),
        "ledger": ledger_identity(path),
        "length": len,
        "kept": kept,
        "seq": parsed.seq,
        "tail": parsed.tail().to_string(),
        "blank": Digest::of(&tail).to_string(),
        "witness": {"seq": witness.seq, "tail": witness.tail.to_string()},
    });
    Ok(BlankTail {
        pass_id: loaded.pass.id.clone(),
        ledger: path.to_path_buf(),
        seq: parsed.seq,
        kept_bytes: kept,
        removed_bytes: len - kept,
        token: format!("{TOKEN_PREFIX}{}", Digest::of(input.to_string().as_bytes())),
        repaired: false,
    })
}

/// Verify the lines before the blank tail (the first `kept` bytes) as a
/// ledger of this pass.
fn parse_kept(
    path: &Path,
    file: &File,
    kept: u64,
    loaded: &LoadedPass,
    witness_seq: u64,
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
        Some(witness_seq),
    )
    .map_err(|e| match e {
        Error::LedgerCorrupt { line, detail, .. } => Error::Usage(format!(
            "the ledger {} is damaged at line {line}, before its blank tail, so removing the tail would not repair it: {}. Nothing was changed. {BACKUP}",
            path.display(),
            detail.strip_suffix('.').unwrap_or(&detail)
        )),
        other => other,
    })
}
