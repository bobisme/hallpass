//! Read-only rehearsal of a sequence of debits against one verified snapshot.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read as _,
    path::Path,
};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    check_clock,
    debit::{check_charges, decide_debit},
    verified_snapshot,
};
use crate::{
    Charge, DebitCharge, Error, LoadedPass, MAX_TARGETS, NamedTarget, SpendChargesOutcome,
    SpendChargesRequest, StateDir, Tally,
};

/// Maximum UTF-8 scenario size, including whitespace.
pub const MAX_SCENARIO_BYTES: u64 = 256 * 1024;
/// Maximum number of ordered steps in one scenario.
pub const MAX_STEPS: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioFile {
    version: u32,
    step: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    id: String,
    at: String,
    #[serde(default)]
    duration: u32,
    #[serde(default)]
    targets: Vec<String>,
    charges: Vec<DebitCharge>,
}

struct ValidatedStep {
    input: Step,
    instant: OffsetDateTime,
    targets: Vec<NamedTarget>,
}

fn steps(path: &Path) -> Result<Vec<ValidatedStep>, Error> {
    let file = crate::files::open_no_follow(path, OpenOptions::new().read(true))?;
    let mut bytes = Vec::new();
    file.take(MAX_SCENARIO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(path, &e))?;
    let invalid =
        |reason: String| Error::Usage(format!("invalid scenario {}: {reason}", path.display()));
    if bytes.len() as u64 > MAX_SCENARIO_BYTES {
        return Err(invalid(format!(
            "maximum size is {MAX_SCENARIO_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid("expected UTF-8 TOML".into()))?;
    let raw: ScenarioFile = toml::from_str(text).map_err(|e| invalid(e.to_string()))?;
    if raw.version != 1 || !(1..=MAX_STEPS).contains(&raw.step.len()) {
        return Err(invalid(format!(
            "expected version = 1 and between 1 and {MAX_STEPS} steps"
        )));
    }
    let mut ids = BTreeSet::new();
    let mut previous = None;
    let mut checked = Vec::with_capacity(raw.step.len());
    for step in raw.step {
        if !crate::pass::is_identifier(&step.id) || !ids.insert(step.id.clone()) {
            return Err(invalid(format!(
                "expected a unique identifier for step {}",
                crate::display_quoted(&step.id)
            )));
        }
        let bad_step = |detail: &str| invalid(format!("step {}: {detail}", step.id));
        let instant = OffsetDateTime::parse(&step.at, &Rfc3339).map_err(|_| {
            bad_step("at must be a quoted RFC 3339 instant with an explicit UTC offset")
        })?;
        check_clock(instant)?;
        if previous.is_some_and(|at| instant < at) {
            return Err(bad_step("instants must be nondecreasing"));
        }
        if step.targets.len() > MAX_TARGETS {
            return Err(bad_step(&format!("maximum is {MAX_TARGETS} targets")));
        }
        let targets = step
            .targets
            .iter()
            .map(|s| s.parse::<NamedTarget>().map_err(|e| bad_step(&e)))
            .collect::<Result<_, _>>()?;
        check_charges(
            step.charges.len(),
            step.charges.iter().map(|c| (c.counter.as_str(), c.amount)),
        )
        .map_err(bad_step)?;
        previous = Some(instant);
        checked.push(ValidatedStep {
            input: step,
            instant,
            targets,
        });
    }
    Ok(checked)
}

/// The source accounting state and the final projected totals for one simulation.
#[derive(Debug, Serialize)]
pub struct Rehearsal {
    pub pass_id: String,
    pub digest: String,
    pub witness: &'static str,
    /// Recorded spends and adoption carry, including zeroes for unspent ceilings.
    pub starting_spent: BTreeMap<String, u64>,
    pub ceilings: BTreeMap<String, u64>,
    /// Includes only steps preceding the first refusal.
    pub projected_spent: BTreeMap<String, u64>,
    pub steps: Vec<StepResult>,
    pub stopped_at: Option<String>,
    pub warnings: Vec<String>,
}

/// Evidence from one simulated step, in input order.
#[derive(Debug, Serialize)]
pub struct StepResult {
    pub id: String,
    pub at: String,
    pub duration: u32,
    pub targets: Vec<String>,
    pub charges: Vec<DebitCharge>,
    /// One of `would-allow`, `refused`, or `unevaluated`.
    pub status: &'static str,
    pub refusal: Option<StepRefusal>,
    pub labels: Vec<String>,
    /// Balances of requested counters after this step. Empty for unevaluated steps.
    pub balances: Vec<StepBalance>,
}

/// Projected balances of a requested counter, before and after this step.
#[derive(Debug, Serialize)]
pub struct StepBalance {
    pub counter: String,
    pub before: u64,
    pub after: u64,
    pub remaining: Option<u64>,
}

/// A refusal from the live debit policy, including the one-based target index if applicable.
#[derive(Debug, Serialize)]
pub struct StepRefusal {
    pub code: &'static str,
    pub message: String,
    pub target: Option<usize>,
}

impl ValidatedStep {
    fn decide(
        &self,
        pass: &LoadedPass,
        tally: &Tally,
        last: Option<OffsetDateTime>,
    ) -> SpendChargesOutcome {
        let charges: Vec<_> = self
            .input
            .charges
            .iter()
            .map(|c| Charge {
                counter: &c.counter,
                amount: c.amount,
            })
            .collect();
        let mut request = SpendChargesRequest::new(&charges);
        request.dry_run = true;
        request.policy.needed = Duration::seconds(i64::from(self.input.duration));
        if let Some((first, rest)) = self.targets.split_first() {
            request.policy.target = Some(first.target);
            request.policy.name = first.name.as_ref();
            request.policy.additional_targets = rest;
        }
        decide_debit(pass, tally, &request, self.instant, Vec::new(), last, None)
    }
}

/// Evaluate each step at its supplied instant, stopping after the first refusal.
/// Reads one pass and ledger summary. All projections are private to this call.
///
/// # Errors
///
/// Returns an error for malformed or oversized scenarios, invalid passes or unverifiable evidence.
pub fn rehearse(
    pass_path: &Path,
    scenario_path: &Path,
    state: &StateDir,
) -> Result<Rehearsal, Error> {
    let steps = steps(scenario_path)?;
    let (loaded, mut view) = verified_snapshot(pass_path, state)?;
    for counter in loaded.pass.ceilings.keys() {
        view.tally.spent.entry(counter.clone()).or_default();
    }
    let starting_spent = view.tally.spent.clone();
    let mut stopped_at = None;
    let mut results = Vec::with_capacity(steps.len());
    for step in steps {
        let mut balances = Vec::new();
        let mut labels = Vec::new();
        let mut refusal = None;
        let mut status = "unevaluated";
        if stopped_at.is_none() {
            let decision = step.decide(&loaded, &view.tally, view.last_time);
            view.warnings.extend(decision.warnings);
            labels = decision.labels;
            for c in decision.charges {
                let after = c.projected_spent.unwrap_or(c.spent);
                balances.push(StepBalance {
                    counter: c.counter.clone(),
                    before: c.spent,
                    after,
                    remaining: c.total.map(|limit| limit.saturating_sub(after)),
                });
                if let Some(projected) = c.projected_spent {
                    view.tally.spent.insert(c.counter, projected);
                }
            }
            if let Some(r) = decision.refusal {
                status = "refused";
                stopped_at = Some(step.input.id.clone());
                refusal = Some(StepRefusal {
                    code: r.code.as_str(),
                    message: r.message,
                    target: decision.refused_target,
                });
            } else {
                status = "would-allow";
                view.last_time = Some(step.instant);
            }
        }
        results.push(StepResult {
            id: step.input.id,
            at: step.input.at,
            duration: step.input.duration,
            targets: step.input.targets,
            charges: step.input.charges,
            status,
            refusal,
            labels,
            balances,
        });
    }
    Ok(Rehearsal {
        pass_id: loaded.pass.id,
        digest: loaded.digest.to_string(),
        witness: view.witness.as_str(),
        starting_spent,
        ceilings: loaded.pass.ceilings,
        projected_spent: view.tally.spent,
        steps: results,
        stopped_at,
        warnings: view.warnings,
    })
}
