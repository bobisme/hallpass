//! Compare an operator's declaration with all enforced terms of a pass.
use crate::{LoadedPass, MAX_COUNTERS, is_counter_name};
use serde::Serialize;
use std::collections::BTreeSet;

/// Features the integrator declares across all cooperating components.
#[allow(
    clippy::struct_excessive_bools,
    reason = "capabilities are independent declarations"
)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub endpoints: bool,
    pub names: bool,
    pub live_window: bool,
    pub target_on_every_debit: bool,
    pub counters: BTreeSet<String>,
}

impl Capabilities {
    /// Parse CLI capability tokens into a feature declaration.
    ///
    /// # Errors
    ///
    /// Rejects empty, unknown, repeated or oversized declarations.
    pub fn parse(tokens: &[String]) -> Result<Self, String> {
        let mut caps = Self::default();
        if tokens.len() == 1 && tokens[0] == "none" {
            return Ok(caps);
        }
        if tokens.is_empty() || tokens.len() > MAX_COUNTERS + 4 {
            return Err(format!(
                "supply 1 to {} capability tokens",
                MAX_COUNTERS + 4
            ));
        }
        for token in tokens {
            let fresh = match token.as_str() {
                "endpoints" => !std::mem::replace(&mut caps.endpoints, true),
                "names" => !std::mem::replace(&mut caps.names, true),
                "live-window" => !std::mem::replace(&mut caps.live_window, true),
                "target-on-every-debit" => {
                    !std::mem::replace(&mut caps.target_on_every_debit, true)
                }
                "none" => return Err("use none as the sole capability".into()),
                t => {
                    let name = t
                        .strip_prefix("charge:")
                        .filter(|s| is_counter_name(s))
                        .ok_or_else(|| {
                            "use endpoints, names, live-window, target-on-every-debit, charge:COUNTER or none".to_owned()
                        })?;
                    if caps.counters.len() >= MAX_COUNTERS {
                        return Err(format!("declare at most {MAX_COUNTERS} counters"));
                    }
                    caps.counters.insert(name.to_owned())
                }
            };
            if !fresh {
                return Err(format!("repeated capability {token}"));
            }
        }
        Ok(caps)
    }
}

/// One pass requirement the consumer did not declare it can enforce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "kebab-case")]
pub enum CoverageFinding {
    MissingEndpoints { label: String },
    MissingNames { label: String },
    MissingLiveWindow,
    MissingTargetOnEveryDebit,
    MissingCounter { counter: String },
}

impl std::fmt::Display for CoverageFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEndpoints { label } => write!(
                f,
                "Check literal address, port and protocol for destination {label}."
            ),
            Self::MissingNames { label } => write!(
                f,
                "Check the application name carried to destination {label}."
            ),
            Self::MissingLiveWindow => {
                f.write_str("Check the live approval window and revocation.")
            }
            Self::MissingTargetOnEveryDebit => {
                f.write_str("Supply a literal target for scope checking on every debit.")
            }
            Self::MissingCounter { counter } => write!(
                f,
                "Charge the {counter} counter for each applicable operation."
            ),
        }
    }
}

/// Compatibility for the exact pass revision, independent of any live request.
#[derive(Clone, Debug, Serialize)]
pub struct CoverageReport {
    pub pass_id: String,
    pub digest: String,
    pub require_target: bool,
    pub findings: Vec<CoverageFinding>,
}

/// Compare the entire validated approval with explicitly declared capabilities.
#[must_use]
pub fn consumer_coverage(loaded: &LoadedPass, caps: &Capabilities) -> CoverageReport {
    let mut findings = Vec::new();
    if !caps.live_window {
        findings.push(CoverageFinding::MissingLiveWindow);
    }
    if loaded.pass.require_target && !caps.target_on_every_debit {
        findings.push(CoverageFinding::MissingTargetOnEveryDebit);
    }
    for rule in &loaded.pass.destinations {
        if !caps.endpoints {
            findings.push(CoverageFinding::MissingEndpoints {
                label: rule.label.clone(),
            });
        }
        if !caps.names && !rule.names.is_empty() {
            findings.push(CoverageFinding::MissingNames {
                label: rule.label.clone(),
            });
        }
    }
    for counter in loaded.pass.ceilings.keys() {
        if !caps.counters.contains(counter) {
            findings.push(CoverageFinding::MissingCounter {
                counter: counter.clone(),
            });
        }
    }
    CoverageReport {
        digest: loaded.digest.to_string(),
        pass_id: loaded.pass.id.clone(),
        require_target: loaded.pass.require_target,
        findings,
    }
}
