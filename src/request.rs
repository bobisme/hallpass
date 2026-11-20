//! File-backed decisions for an ordered group of literal targets.
use std::path::Path;
use time::{Duration, OffsetDateTime};

use crate::{
    Decision, Digest, Error, HostName, LoadedPass, Refusal, RefusalCode, StateDir, Target, load,
    read_ledger,
};

/// Maximum number of destinations in one question.
pub const MAX_TARGETS: usize = 64;

/// A literal endpoint and the optional name the caller intends to use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedTarget {
    pub target: Target,
    pub name: Option<HostName>,
}

impl std::str::FromStr for NamedTarget {
    type Err = String;
    fn from_str(text: &str) -> Result<Self, String> {
        let (literal, name) = text
            .split_once('@')
            .map_or((text, None), |(addr, name)| (addr, Some(name)));
        Ok(Self {
            target: literal.parse()?,
            name: name.map(str::parse).transpose()?,
        })
    }
}

/// A policy refusal and, for a target-specific decision, its one-based position.
#[derive(Clone, Debug)]
pub struct TargetRefusal {
    pub reason: Refusal,
    pub index: Option<usize>,
}

/// The pass and state used for an uncounted decision. Labels follow query order.
#[derive(Clone, Debug)]
pub struct PermitOutcome {
    pub loaded: LoadedPass,
    pub decision: Result<Vec<String>, TargetRefusal>,
    pub warnings: Vec<String>,
}

pub fn decide_targets<'a>(
    loaded: &LoadedPass,
    targets: impl Iterator<Item = (Target, Option<&'a HostName>)>,
    expected: Option<Digest>,
    now: OffsetDateTime,
    needed: Duration,
) -> Result<Vec<String>, TargetRefusal> {
    if let Some(expected) = expected
        && expected != loaded.digest
    {
        return Err(TargetRefusal {
            reason: Refusal {
                code: RefusalCode::PassChanged,
                message: format!(
                    "the pass has changed since this run started (expected {}, now {}); stop, review the pass, and start again under the new one",
                    expected, loaded.digest
                ),
            },
            index: None,
        });
    }
    loaded
        .pass
        .check_window(now, needed)
        .map_err(|reason| TargetRefusal {
            reason,
            index: None,
        })?;
    targets
        .enumerate()
        .map(
            |(i, (target, name))| match loaded.pass.permits_named(&target, name, now, needed) {
                Decision::Allowed { label } => Ok(label),
                Decision::Refused(reason) => Err(TargetRefusal {
                    reason,
                    index: Some(i + 1),
                }),
            },
        )
        .collect()
}

/// Read the current pass and ledger, then check every target against one revision.
///
/// # Errors
/// An invalid request, unreadable pass, or inconsistent ledger. Unavailable
/// witness evidence follows the same warning policy as read-only CLI commands.
pub fn permits_in(
    path: &Path,
    targets: &[NamedTarget],
    expected: Option<Digest>,
    now: OffsetDateTime,
    needed: Duration,
    state: &StateDir,
) -> Result<PermitOutcome, Error> {
    if targets.is_empty() || targets.len() > MAX_TARGETS || needed.is_negative() {
        return Err(Error::Usage(format!(
            "provide 1 to {MAX_TARGETS} targets and a nonnegative duration"
        )));
    }
    let loaded = load(path)?;
    let view = read_ledger(&loaded, state)?;
    let decision = decide_targets(
        &loaded,
        targets.iter().map(|t| (t.target, t.name.as_ref())),
        expected,
        now,
        needed,
    );
    Ok(PermitOutcome {
        loaded,
        decision,
        warnings: view.warnings,
    })
}
