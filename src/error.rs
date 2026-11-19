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
