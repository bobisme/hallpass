//! Read-only budget capacity for identical debits at one decision instant.

use std::path::Path;

use serde::Serialize;
use time::OffsetDateTime;

use super::{
    check_clock,
    debit::{decide_debit_policy, validate_unit},
    decide_ceiling, declared_ceiling, preview_snapshot, warn_clock_rollback, warn_left_counters,
};
use crate::{Charge, Digest, Error, Refusal, SpendRequest, StateDir, TargetRefusal};

/// One budget's capacity at the snapshot, in request order.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct CounterCapacity {
    pub counter: String,
    #[serde(rename = "n")]
    pub cost: u64,
    pub total: u64,
    pub spent: u64,
    pub remaining: u64,
    /// Units this counter can pay for on its own.
    pub units: u64,
    /// Budget left here after charging the overall number of units.
    pub remaining_after: u64,
}

/// Capacity of a valid unit across every one of its counters.
#[derive(Debug)]
#[non_exhaustive]
pub struct BudgetCapacity {
    pub units: u64,
    pub limiting_counters: Vec<String>,
    pub counters: Vec<CounterCapacity>,
    /// Matched destinations in request order.
    pub labels: Vec<String>,
    /// The first budget refusal a single debit would encounter, present at zero capacity.
    pub unit_refusal: Option<Refusal>,
}

/// Read-only decision from one verified snapshot.
#[derive(Debug)]
#[non_exhaustive]
pub struct CapacityOutcome {
    pub pass_id: String,
    pub digest: Digest,
    pub now: OffsetDateTime,
    /// An invalid unit yields a policy refusal instead of a budget count.
    pub decision: Result<BudgetCapacity, TargetRefusal>,
    pub warnings: Vec<String>,
}

/// Count identical units that fit the budgets at an explicit instant.
///
/// The scalar counter and amount in `policy` are ignored. Supply the entire
/// unit through `charges` and the policy's targets, duration and expected digest.
/// The count is a budget calculation and reserves nothing.
///
/// # Errors
///
/// Invalid input or an unavailable or inconsistent preview snapshot.
pub fn capacity_in(
    path: &Path,
    charges: &[Charge<'_>],
    policy: &SpendRequest<'_>,
    now: OffsetDateTime,
    state: &StateDir,
) -> Result<CapacityOutcome, Error> {
    check_clock(now)?;
    capacity_with_clock_in(path, charges, policy, state, || now)
}

/// As [`capacity_in`], sampling the clock after verifying the snapshot.
///
/// # Errors
///
/// As [`capacity_in`].
pub fn capacity_with_clock_in(
    path: &Path,
    charges: &[Charge<'_>],
    policy: &SpendRequest<'_>,
    state: &StateDir,
    clock: impl FnOnce() -> OffsetDateTime,
) -> Result<CapacityOutcome, Error> {
    validate_unit(charges, policy)?;
    let (loaded, mut view) =
        crate::files::with_requested_wait(policy.lock_timeout, policy.on_lock_wait, || {
            preview_snapshot(path, state)
        })?;
    let now = clock();
    check_clock(now)?;
    warn_clock_rollback(now, view.latest_time, &mut view.warnings);
    warn_left_counters(&loaded.pass, &view.tally, &mut view.warnings);
    let decision = decide_debit_policy(&loaded, policy, charges, now).and_then(|labels| {
        let mut counters = Vec::with_capacity(charges.len());
        for charge in charges {
            let total =
                declared_ceiling(&loaded.pass, charge.counter).map_err(|reason| TargetRefusal {
                    reason,
                    index: None,
                })?;
            let spent = view.tally.spent(charge.counter);
            let remaining = total.saturating_sub(spent);
            counters.push(CounterCapacity {
                counter: charge.counter.to_owned(),
                cost: charge.amount,
                total,
                spent,
                remaining,
                units: remaining / charge.amount,
                remaining_after: remaining,
            });
        }

        let units = counters.iter().map(|c| c.units).min().unwrap_or_default();
        let unit_refusal = counters
            .iter()
            .find(|c| c.units == 0)
            .and_then(|c| decide_ceiling(&loaded.pass, &c.counter, c.cost, c.spent).err());
        let mut limiting_counters = Vec::new();
        for counter in &mut counters {
            if counter.units == units {
                limiting_counters.push(counter.counter.clone());
            }
            // The minimum ensures the product fits each remaining budget.
            counter.remaining_after -= units * counter.cost;
        }
        Ok(BudgetCapacity {
            units,
            limiting_counters,
            counters,
            labels,
            unit_refusal,
        })
    });
    Ok(CapacityOutcome {
        pass_id: loaded.pass.id,
        digest: loaded.digest,
        now,
        decision,
        warnings: view.warnings,
    })
}
