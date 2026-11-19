//! Errors: anything other than a policy refusal.

use std::path::PathBuf;

use crate::pass::Problem;

/// Something went wrong that is not a policy refusal: a file could not be
/// read, a pass is invalid, a ledger is damaged. Every variant fails
/// closed: nothing is permitted and nothing is recorded.
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
        "{} is a symbolic link; hallpass does not follow links for a pass or a ledger. Use the path of the real file",
        path.display()
    )]
    Symlink {
        /// The link.
        path: PathBuf,
    },
    /// The path is not a regular file.
    #[error("{} is not a regular file; give the path of the pass file", path.display())]
    NotRegular {
        /// The path.
        path: PathBuf,
    },
    /// The file is larger than a pass can be.
    #[error("{} is larger than {limit} bytes, too large for a pass", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
        /// The limit in bytes.
        limit: u64,
    },
    /// Other users may change the file.
    #[error(
        "{} has mode {mode:04o}, so {who}; run `chmod {fix} {}` and check that its content is what the owner approved",
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
    },
    /// The pass does not validate.
    #[error("{} is not a valid pass ({} problem(s)); fix each one, then run `hallpass check`", path.display(), problems.len())]
    Invalid {
        /// The pass file.
        path: PathBuf,
        /// Every problem found.
        problems: Vec<Problem>,
    },
    /// The ledger cannot be trusted.
    #[error(
        "the ledger {} is damaged at line {line}: {detail}. hallpass will not guess the count, so nothing more can be spent under this pass until it is repaired: compare it with your notes, and remove only a final line that was cut short (that spend was never confirmed)",
        path.display()
    )]
    LedgerCorrupt {
        /// The ledger file.
        path: PathBuf,
        /// The line (1-based).
        line: usize,
        /// What is wrong.
        detail: String,
    },
    /// The ledger belongs to a different pass id.
    #[error(
        "the ledger {} belongs to pass `{ledger_id}`, but the pass now says `{pass_id}`. Changing the id does not start a new count. If the owner gave a new approval, write it as a new pass file; otherwise restore id = \"{ledger_id}\"",
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
    /// The ledger is gone, but the witness says spends were recorded.
    #[error("{0}")]
    LedgerMissing(Box<MissingLedger>),
    /// The ledger does not contain the line the witness recorded.
    #[error(
        "the ledger {} was changed outside hallpass: {detail} (witness: {}). hallpass will not trust its count. Restore the ledger hallpass last wrote (from a backup, or the other copy if one is named above); if this ledger is the one to keep, run `hallpass adopt {} --reason \"...\"`, which records the adoption in the ledger and never lowers a count below what the witness recorded",
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
        "the witness for pass `{pass_id}` cannot be used: {detail}. hallpass keeps a record of each ledger's last line in its state directory ({}) so that a lost or rewound ledger is noticed, and does not record a spend without it",
        dir.as_ref().map_or_else(|| "none".to_owned(), |d| d.display().to_string())
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
        "the spend was recorded in {} as entry {seq}, but the witness could not be updated afterwards ({detail}). Treat this spend as NOT permitted; it still counts against the ceiling. The next command accepts the ledger, since it only adds to what the witness recorded",
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
    /// The file already exists (`init` never overwrites).
    #[error("{} already exists; hallpass init never overwrites. Choose another path", path.display())]
    Exists {
        /// The file.
        path: PathBuf,
    },
    /// The request itself is malformed (for example `--n 0`).
    #[error("{0}")]
    Usage(String),
}

impl Error {
    /// A stable code for JSON output.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Io { .. } => "io",
            Self::Symlink { .. } => "symlink",
            Self::NotRegular { .. } => "not-regular-file",
            Self::TooLarge { .. } => "too-large",
            Self::Insecure { .. } => "insecure-permissions",
            Self::Invalid { .. } => "invalid-pass",
            Self::LedgerCorrupt { .. } => "ledger-corrupt",
            Self::LedgerForeign { .. } => "ledger-foreign",
            Self::LedgerMissing(_) => "ledger-missing",
            Self::LedgerChanged { .. } => "ledger-changed",
            Self::WitnessUnavailable { .. } => "witness-unavailable",
            Self::WitnessNotUpdated { .. } => "witness-not-updated",
            Self::Exists { .. } => "exists",
            Self::Usage(_) => "usage",
        }
    }

    pub(crate) fn io(path: &std::path::Path, error: &std::io::Error) -> Self {
        let message = match error.kind() {
            std::io::ErrorKind::NotFound => "no such file; check the path".to_owned(),
            std::io::ErrorKind::PermissionDenied => {
                "permission denied; check the file's owner and mode".to_owned()
            }
            _ => error.to_string(),
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
            "the ledger {} for pass `{}` is missing, but the witness {} says hallpass recorded {} ledger line(s) for this pass id (spent: {}); the ledger was last seen at {} on {}. hallpass will not count from zero. Put the ledger back beside the pass (move it from there, or restore it from a backup); if it is really lost, run `hallpass adopt {} --reason \"...\"`, which starts a new ledger that carries those totals. If this pass is a different approval that reused the id, give it its own id",
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
