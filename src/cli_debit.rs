//! Shared spend unit syntax, the spend reply and rendering for the
//! read-only capacity query.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use clap::Args;
use hallpass::{
    Charge, ChargeOutcome, DebitReceipt, Digest, Error, HostName, NamedTarget, ReferenceEvidence,
    Refusal, SpendOutcome, SpendRequest, StateDir, capacity, stamp,
    time::{Duration, OffsetDateTime},
};
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    Clock, OK, Output, REFUSED, error_output, parse_targets, refusal_json, safe, targets_json,
};

/// The warning on an allowed or previewed debit that checked no destination.
/// A pass with `require_target_v1 = true` refuses such a debit, so a reply
/// with this warning always comes from a pass without that term.
pub const NO_TARGET_CHECKED: &str = "no destination was checked: this spend has no --to target, and the pass does not set require_target_v1. Supply --to for each debit. The owner can add require_target_v1 = true to the pass to refuse debits without a target";

/// One charge of a spend reply. Every key is always present.
#[derive(Serialize)]
pub struct ChargeReply<'a> {
    counter: &'a str,
    n: u64,
    total: Option<u64>,
    spent: u64,
    remaining: Option<u64>,
    projected_spent: Option<u64>,
}

impl<'a> ChargeReply<'a> {
    /// The single charge of a scalar spend. A positive preview projects the
    /// balance after the charge.
    pub fn scalar(outcome: &'a SpendOutcome, dry_run: bool) -> Self {
        Self {
            counter: &outcome.counter,
            n: outcome.amount,
            total: outcome.total,
            spent: outcome.spent,
            remaining: outcome.remaining(),
            projected_spent: (dry_run && outcome.refusal.is_none())
                .then(|| outcome.spent.checked_add(outcome.amount))
                .flatten(),
        }
    }
}

impl<'a> From<&'a ChargeOutcome> for ChargeReply<'a> {
    fn from(charge: &'a ChargeOutcome) -> Self {
        Self {
            counter: &charge.counter,
            n: charge.amount,
            total: charge.total,
            spent: charge.spent,
            remaining: charge.remaining,
            projected_spent: charge.projected_spent,
        }
    }
}

/// A retained receipt in a spend reply. The ledger line omits an absent
/// reference, an empty target list and an absent name; this view keeps
/// every key, so the reply shape does not depend on the flags. It is
/// never written to the ledger.
#[derive(Serialize)]
struct ReceiptReply<'a> {
    caller_ref: Option<&'a str>,
    targets: Vec<RecordedTargetReply<'a>>,
}

#[derive(Serialize)]
struct RecordedTargetReply<'a> {
    target: &'a str,
    name: Option<&'a str>,
    label: &'a str,
}

impl<'a> From<&'a DebitReceipt> for ReceiptReply<'a> {
    fn from(receipt: &'a DebitReceipt) -> Self {
        Self {
            caller_ref: receipt.caller_ref.as_deref(),
            targets: receipt
                .targets
                .iter()
                .map(|t| RecordedTargetReply {
                    target: &t.target,
                    name: t.name.as_deref(),
                    label: &t.label,
                })
                .collect(),
        }
    }
}

/// The decision behind one spend reply: allowed, refused or previewed,
/// scalar or charged.
pub struct SpendReply<'a> {
    pub result: &'static str,
    pub file: &'a Path,
    pub digest: Digest,
    pub pass_id: &'a str,
    pub now: OffsetDateTime,
    pub test_clock: bool,
    pub charges: Vec<ChargeReply<'a>>,
    pub seq: Option<u64>,
    pub note: Option<&'a str>,
    pub targets: &'a [NamedTarget],
    pub labels: &'a [String],
    pub refused_target: Option<usize>,
    pub receipt: Option<&'a DebitReceipt>,
    pub refusal: Option<&'a Refusal>,
    pub reference_evidence: Option<&'a ReferenceEvidence>,
    pub warnings: &'a [String],
}

impl SpendReply<'_> {
    /// The JSON reply. Every spend reply has the same keys. The scalar
    /// fields repeat the only charge of a one-counter unit and are null
    /// when the unit charges several counters.
    pub fn json(&self) -> Value {
        let only = match self.charges.as_slice() {
            [charge] => Some(charge),
            _ => None,
        };
        let first = self.targets.first();
        let mut warnings = self.warnings.to_vec();
        if self.refusal.is_none() && self.targets.is_empty() {
            warnings.push(NO_TARGET_CHECKED.to_owned());
        }
        json!({
            "command": "spend",
            "result": self.result,
            "file": self.file.display().to_string(),
            "digest": self.digest.to_string(),
            "pass_id": self.pass_id,
            "now": stamp(self.now),
            "test_clock": self.test_clock,
            "charges": self.charges,
            "counter": only.map(|c| c.counter),
            "n": only.map(|c| c.n),
            "total": only.and_then(|c| c.total),
            "spent": only.map(|c| c.spent),
            "remaining": only.and_then(|c| c.remaining),
            "projected_spent": only.and_then(|c| c.projected_spent),
            "seq": self.seq,
            "note": self.note,
            "targets": targets_json(self.targets, self.labels),
            "refused_target": self.refused_target,
            "target": first.map(|t| t.target.to_string()),
            "name": first.and_then(|t| t.name.as_ref()).map(HostName::as_str),
            "label": self.labels.first(),
            "receipt": self.receipt.map(ReceiptReply::from),
            "refusal": self.refusal.map(refusal_json),
            "reference_evidence": self.reference_evidence,
            "warnings": warnings,
        })
    }
}

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
