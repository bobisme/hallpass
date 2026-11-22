//! Shared spend unit syntax and rendering for the read-only capacity query.

use std::{fmt::Write as _, path::PathBuf};

use clap::Args;
use hallpass::{
    Charge, Digest, Error, NamedTarget, SpendRequest, StateDir, capacity, stamp, time::Duration,
};
use serde_json::{Value, json};

use super::{
    Clock, OK, Output, REFUSED, error_output, parse_targets, refusal_json, safe, targets_json,
};

#[derive(Args)]
pub struct DebitUnit {
    /// Validated TOML pass supplying the window, scope and ceilings.
    pub file: PathBuf,
    /// The counter name, one of the pass's ceilings.
    #[arg(required_unless_present = "charges", conflicts_with = "charges")]
    pub counter: Option<String>,
    /// The amount to spend (default 1 with a positional counter).
    #[arg(long = "n", value_name = "N", requires = "counter")]
    amount: Option<u64>,
    /// One named cost of this unit. Repeat for each counter.
    #[arg(long = "charge", value_name = "COUNTER=N", conflicts_with_all = ["counter", "amount"])]
    charges: Vec<String>,
    /// Literal endpoint to check with the debit. Supply at least one when the owner requires a target.
    #[arg(long, value_name = "ADDR:PORT/PROTO[@NAME]")]
    to: Vec<String>,
    /// The host name the request will carry, as for `permits --name`. Only with --to.
    #[arg(long, value_name = "HOSTNAME", requires = "to")]
    name: Option<String>,
    /// Refuse unless the pass still has this digest (from `hallpass digest`).
    #[arg(long, value_name = "DIGEST")]
    digest: Option<String>,
    /// Refuse unless the window stays open this many seconds more.
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    duration: u32,
}

impl DebitUnit {
    pub fn policy_inputs(&self) -> Result<(Option<Digest>, Vec<NamedTarget>), Error> {
        let digest = self
            .digest
            .as_deref()
            .map(str::parse::<Digest>)
            .transpose()
            .map_err(|message| Error::Usage(format!("--digest: {message}")))?;
        let targets = parse_targets(&self.to, self.name.as_deref())?;
        Ok((digest, targets))
    }

    pub fn policy<'a>(
        &'a self,
        digest: Option<Digest>,
        targets: &'a [NamedTarget],
    ) -> SpendRequest<'a> {
        let mut request = SpendRequest::new(
            self.counter.as_deref().unwrap_or_default(),
            self.amount.unwrap_or(1),
        );
        request.expect_digest = digest;
        request.needed = Duration::seconds(i64::from(self.duration));
        request.target = targets.first().map(|t| t.target);
        request.name = targets.first().and_then(|t| t.name.as_ref());
        request.additional_targets = targets.get(1..).unwrap_or_default();
        request
    }

    pub fn charges(&self) -> Result<Vec<Charge<'_>>, Error> {
        if let Some(counter) = &self.counter {
            return Ok(vec![Charge {
                counter,
                amount: self.amount.unwrap_or(1),
            }]);
        }
        self.charges
            .iter()
            .map(|charge| {
                let (counter, n) = charge.split_once('=').ok_or_else(|| {
                    Error::Usage(format!("--charge expects COUNTER=N (got {})", safe(charge)))
                })?;
                if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Usage(
                        "--charge expects a positive whole number".to_owned(),
                    ));
                }
                let amount = n.parse::<u64>().map_err(|_| {
                    Error::Usage("--charge amount exceeds the maximum whole number".to_owned())
                })?;
                Ok(Charge { counter, amount })
            })
            .collect()
    }
}

pub fn run_capacity(unit: &DebitUnit, clock: &Clock) -> Output {
    let file = &unit.file;
    let evaluate = || {
        let (digest, targets) = unit.policy_inputs()?;
        let policy = unit.policy(digest, &targets);
        let charges = unit.charges()?;
        let decision = capacity::capacity_with_clock_in(
            file,
            &charges,
            &policy,
            &StateDir::from_env(),
            || clock.sample(),
        )?;
        Ok::<_, Error>((decision, targets))
    };
    let (outcome, targets) = match evaluate() {
        Ok(answer) => answer,
        Err(e) => return error_output("capacity", Some(file), &e),
    };
    let mut json = json!({
        "command": "capacity",
        "file": file.display().to_string(),
        "pass_id": outcome.pass_id,
        "digest": outcome.digest.to_string(),
        "now": stamp(outcome.now),
        "test_clock": clock.test,
        "warnings": outcome.warnings,
    });
    match outcome.decision {
        Ok(budget) => {
            json["result"] = json!("capacity");
            json["units"] = json!(budget.units);
            json["limiting_counters"] = json!(budget.limiting_counters);
            json["counters"] = json!(budget.counters);
            json["targets"] = targets_json(&targets, &budget.labels);
            json["unit_refusal"] = json!(budget.unit_refusal.as_ref().map(refusal_json));
            let mut text = format!(
                "{}  {} unit(s)  limited by {}\n",
                outcome.pass_id,
                budget.units,
                budget.limiting_counters.join(", ")
            );
            for c in &budget.counters {
                let _ = writeln!(
                    text,
                    "{}  {} per unit  {} left  {} left after {} unit(s)",
                    c.counter, c.cost, c.remaining, c.remaining_after, budget.units
                );
            }
            Output {
                code: OK,
                text,
                json,
            }
        }
        Err(refusal) => {
            json["result"] = json!("refused");
            json["refusal"] = refusal_json(&refusal.reason);
            json["refused_target"] = json!(refusal.index);
            json["targets"] = targets_json(&targets, &[]);
            json["units"] = Value::Null;
            Output {
                code: REFUSED,
                text: format!("REFUSED: {}\n", safe(&refusal.reason.message)),
                json,
            }
        }
    }
}
