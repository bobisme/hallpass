//! `hallpass repair --restore-final-newline`: add the line end that a failed
//! write left off a last ledger line the witness counted.
//!
//! The repair appends one byte, `\n`, only when all of these hold:
//!
//! - the ledger does not end with a line end, and it has a complete header;
//! - the ledger with that line end added verifies, for this pass, so the
//!   last line parses and chains to the line before it;
//! - the witness exists, and the hash of that last line is the tail the
//!   witness recorded at the last sequence number of the ledger.
//!
//! Anything else is refused and nothing is changed. No line is changed or
//! removed: the line stays as it was written. A token from the preview
//! guards the repair: the pass, the ledger and the witness must be as the
//! preview saw them.

use std::fs::File;
use std::io::{BufReader, Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use super::repair::{BACKUP, last_line_end, open_ledger};
use super::{WitnessStatus, compare, ledger_path, parse_ledger};
use crate::error::Error;
use crate::files::{Digest, LoadedPass, LockBudget, load, lock_shared};
use crate::witness::{StateDir, Witnessed, ledger_identity};

/// The token prefix: never mistaken for a `--drop-torn-tail` or adoption token.
const TOKEN_PREFIX: &str = "newline1:";

/// What `--restore-final-newline` would do, or did.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FinalNewline {
    /// The pass id.
    pub pass_id: String,
    /// The ledger file.
    pub ledger: PathBuf,
    /// The sequence number of the last line, which the witness recorded.
    pub seq: u64,
    /// The length of the ledger before the line end is added.
    pub length: u64,
    /// The guard for the repair, as `--preview` prints it.
    pub token: String,
    /// Whether the line end was added (only after the repair).
    pub restored: bool,
}

/// Show what `--restore-final-newline` would do to the ledger of the pass at
/// `pass_path`, and the token that guards it. Reads only.
///
/// # Errors
///
/// [`Error::Usage`] when the last line may not be completed safely (see the
/// module documentation), or any error reading the pass, the ledger or the
/// witness.
pub fn preview_restore_final_newline(
    pass_path: &Path,
    state: &StateDir,
) -> Result<FinalNewline, Error> {
    let loaded = load(pass_path)?;
    let path = ledger_path(pass_path);
    let file = open_ledger(pass_path, &path, false)?;
    lock_shared(&file, &path)?;
    let witness = state.read(&loaded.pass.id)?;
    inspect(pass_path, &path, &file, &loaded, witness.as_ref(), state)
}

/// Add the missing line end that [`preview_restore_final_newline`] showed,
/// under both writer locks. `token` is the token the preview printed.
///
/// # Errors
///
/// As [`preview_restore_final_newline`]; [`Error::Usage`] for a token that
/// is malformed or stale; [`Error::Io`] when the write or the sync fails.
pub fn restore_final_newline(
    pass_path: &Path,
    state: &StateDir,
    token: &str,
) -> Result<FinalNewline, Error> {
    if token
        .strip_prefix(TOKEN_PREFIX)
        .is_none_or(|d| d.parse::<Digest>().is_err())
    {
        return Err(Error::Usage(format!(
            "{} is not a repair token (a token looks like {TOKEN_PREFIX}sha256:<64 hex digits>); nothing was changed. Run `hallpass repair {} --restore-final-newline --preview` and use the token it prints",
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
            "the repair token is stale: the pass, the ledger or the witness changed since that preview; nothing was changed. Run `hallpass repair {} --restore-final-newline --preview` again and use the new token",
            pass_path.display()
        )));
    }
    file.write_all_at(b"\n", done.length)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::io(&path, &e))?;
    done.restored = true;
    Ok(done)
}

/// Check everything the module documentation lists, and make the token.
fn inspect(
    pass_path: &Path,
    path: &Path,
    file: &File,
    loaded: &LoadedPass,
    witness: Option<&Witnessed>,
    state: &StateDir,
) -> Result<FinalNewline, Error> {
    let refuse = |problem: String, action: &str| {
        Error::Usage(format!(
            "{problem}. Nothing was changed: `--restore-final-newline` adds a line end only to a last line that is whole, that follows the line before it, and that the witness recorded as its last line. {action}"
        ))
    };
    let status = format!(
        "Run `hallpass status {}` to see whether the ledger is damaged",
        pass_path.display()
    );
    let len = file.metadata().map_err(|e| Error::io(path, &e))?.len();
    let kept = last_line_end(file, len).map_err(|e| Error::io(path, &e))?;
    if kept == Some(len) {
        return Err(refuse(
            format!(
                "the last line of the ledger {} already ends with a line end",
                path.display()
            ),
            &status,
        ));
    }
    if kept.is_none() {
        return Err(refuse(
            format!(
                "the ledger {} has no complete line, not even its header",
                path.display()
            ),
            BACKUP,
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
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| Error::io(path, &e))?;
    let with_end = BufReader::new(reader.take(len).chain(&b"\n"[..]));
    let parsed = parse_ledger(path, with_end, &loaded.pass.id, false, Some(witness.seq)).map_err(
        |e| match e {
            Error::LedgerCorrupt { line, detail, .. } => refuse(
                format!(
                    "the ledger {} is damaged at line {line}, so adding a line end would not repair it: {}",
                    path.display(),
                    detail.strip_suffix('.').unwrap_or(&detail)
                ),
                BACKUP,
            ),
            other => other,
        },
    )?;
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
            "If the line is cut short and was never counted, `hallpass repair --drop-torn-tail --preview` may apply. Otherwise restore the ledger from a backup: `hallpass compare-backups` shows which copy is the good one",
        ));
    }
    let input = serde_json::json!({
        "version": 1,
        "purpose": "restore-final-newline",
        "pass_id": loaded.pass.id,
        "pass_digest": loaded.digest.to_string(),
        "ledger": ledger_identity(path),
        "length": len,
        "seq": parsed.seq,
        "tail": parsed.tail().to_string(),
        "witness": {"seq": witness.seq, "tail": witness.tail.to_string()},
    });
    Ok(FinalNewline {
        pass_id: loaded.pass.id.clone(),
        ledger: path.to_path_buf(),
        seq: parsed.seq,
        length: len,
        token: format!("{TOKEN_PREFIX}{}", Digest::of(input.to_string().as_bytes())),
        restored: false,
    })
}
