//! File-backed decisions for an ordered group of literal targets.
use std::path::Path;
use time::{Duration, OffsetDateTime};

use crate::{
    Decision, Digest, Error, HostName, LoadedPass, Refusal, RefusalCode, StateDir, Target, load,
    read_summary,
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
        let target = literal.parse()?;
        if name == Some("") {
            return Err(format!(
                "the name after `@` is empty; drop the `@`, or write the name after it, for example `{literal}@app.example.com`"
            ));
        }
        Ok(Self {
            target,
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
    /// Time at which the policy decision was made.
    pub now: OffsetDateTime,
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
    check_revision_window(loaded, expected, now, needed)?;
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

pub fn check_revision_window(
    loaded: &LoadedPass,
    expected: Option<Digest>,
    now: OffsetDateTime,
    needed: Duration,
) -> Result<(), TargetRefusal> {
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
        })
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
    permits_with_clock_in(path, targets, expected, needed, state, || now)
}

/// Check targets with a clock sampled after verifying the ledger.
///
/// # Errors
/// As [`permits_in`].
pub fn permits_with_clock_in(
    path: &Path,
    targets: &[NamedTarget],
    expected: Option<Digest>,
    needed: Duration,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
) -> Result<PermitOutcome, Error> {
    if targets.is_empty() || targets.len() > MAX_TARGETS || needed.is_negative() {
        return Err(Error::Usage(format!(
            "provide 1 to {MAX_TARGETS} targets and a nonnegative duration"
        )));
    }
    let loaded = load(path)?;
    let mut view = read_summary(&loaded, state)?;
    view.warnings.extend(state.observe_pass_file(&loaded));
    view.warnings
        .extend(crate::files::future_mtime_warning(path));
    let now = clock();
    view.warnings.extend(view.clock_warning(now));
    let decision = decide_targets(
        &loaded,
        targets.iter().map(|t| (t.target, t.name.as_ref())),
        expected,
        now,
        needed,
    );
    Ok(PermitOutcome {
        now,
        loaded,
        decision,
        warnings: view.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};
    use time::macros::datetime;

    #[test]
    fn clock_is_sampled_only_after_evidence_is_verified() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("pass");
        fs::write(&path, crate::pass::tests::GOOD).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let ledger = crate::ledger_path(&path);
        fs::write(&ledger, b"broken\n").expect("ledger");
        fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600)).expect("mode");
        let state = StateDir::new(dir.path().join("state"));
        let targets = ["192.0.2.10:5060/udp".parse().expect("target")];
        let called = Cell::new(false);
        let clock = || {
            called.set(true);
            datetime!(2026-11-20 17:00 UTC)
        };
        assert!(
            permits_with_clock_in(&path, &targets, None, Duration::ZERO, &state, clock).is_err()
        );
        assert!(!called.get());
        fs::remove_file(ledger).expect("remove");
        let outcome = permits_with_clock_in(&path, &targets, None, Duration::ZERO, &state, clock)
            .expect("decision");
        assert!(called.get());
        assert_eq!(outcome.now, datetime!(2026-11-20 17:00 UTC));
        assert_eq!(
            outcome.decision.expect_err("expired").reason.code,
            RefusalCode::Expired
        );
    }
}
