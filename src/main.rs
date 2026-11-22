//! The `hallpass` command line.
//!
//! Exit codes: 0 ok or allowed, 2 refused by the pass, 1 any other error.
//! Every command accepts `--format json` and then prints one JSON object on
//! standard output.

mod cli_debit;
mod cli_evidence;
mod cli_help;

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{FromArgMatches, Parser, Subcommand, ValueEnum, error::ErrorKind};
use hallpass::time::{Duration, OffsetDateTime};
use hallpass::{
    Digest, Error, LoadedPass, NamedTarget, Pass, Problem, Refusal, SpendRequest, StateDir,
    WindowState, span, stamp,
};
use serde_json::{Value, json};

/// The environment variable that sets the clock in tests. Honoured only by
/// debug builds and builds with the `test-clock` feature.
const TEST_CLOCK_VAR: &str = "HALLPASS_UNSAFE_TEST_CLOCK";

#[derive(Parser)]
#[command(
    name = "hallpass",
    version,
    propagate_version = true,
    disable_help_subcommand = true,
    about = "Check written approval for literal network destinations and record usage against shared limits"
)]
struct Cli {
    /// Output format (flag overrides FORMAT; default is pretty on a terminal, text in a pipe).
    #[arg(long, value_enum, global = true, overrides_with = "format")]
    format: Option<Format>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Pretty,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Discover commands, arguments, examples and the agent workflow.
    Help {
        /// Command to inspect (omit for the command directory).
        topic: Option<String>,
    },
    /// Report the installed CLI version.
    Version,
    /// Write a commented template with nothing approved (never overwrites).
    Init {
        /// The new pass file.
        file: PathBuf,
    },
    /// Validate a pass and list every problem.
    Check {
        /// The pass file.
        file: PathBuf,
    },
    /// Simulate ordered debits against one verified accounting snapshot.
    Rehearse {
        /// The pass file supplying policy, ledger and witness identity.
        file: PathBuf,
        /// Local version 1 TOML scenario with ordered steps, explicit instants and charge lists.
        scenario: PathBuf,
    },
    /// Count identical debit units that fit the current budgets.
    #[command(
        override_usage = "hallpass capacity [OPTIONS] <FILE> <COUNTER> [--n N]\n       hallpass capacity [OPTIONS] <FILE> --charge COUNTER=N [--charge COUNTER=N ...]"
    )]
    Capacity(cli_debit::DebitUnit),
    /// Show who approved, the window, destinations and ceilings.
    Status {
        /// The pass file.
        file: PathBuf,
    },
    /// Say whether a destination is permitted right now.
    Permits {
        /// The pass file.
        file: PathBuf,
        /// Repeat for each endpoint (up to 64). For example `192.0.2.10:5060/udp` or `[2001:db8::1]:443/tcp`.
        #[arg(long, required = true, value_name = "ADDR:PORT/PROTO[@NAME]")]
        to: Vec<String>,
        /// Require this exact pass revision.
        #[arg(long)]
        digest: Option<String>,
        /// The host name the request will carry (TLS server name, `Host` header). Needed when the destination lists `names`; it never grants anything.
        #[arg(long, value_name = "HOSTNAME")]
        name: Option<String>,
        /// Refuse unless the window stays open this many seconds more.
        #[arg(long, value_name = "SECONDS", default_value_t = 0)]
        duration: u32,
    },
    /// Record a spend against a ceiling, atomically, or refuse and record nothing.
    ///
    /// With --to, one command answers "may I send N of COUNTER to this
    /// destination now, and count it": the destination, the window and the
    /// ceiling are decided together, and a refusal records nothing.
    #[command(
        override_usage = "hallpass spend [OPTIONS] <FILE> <COUNTER> [--n N]\n       hallpass spend [OPTIONS] <FILE> --charge COUNTER=N [--charge COUNTER=N ...]"
    )]
    Spend {
        #[command(flatten)]
        unit: cli_debit::DebitUnit,
        /// Maximum milliseconds to acquire both writer locks. Zero tries each once.
        #[arg(long, value_name = "MILLISECONDS", conflicts_with = "dry_run")]
        lock_timeout_ms: Option<u64>,
        /// Retain this caller/run reference with the debit.
        #[arg(long, value_name = "TEXT")]
        caller_ref: Option<String>,
        /// Retain the checked literal target, request name and matched destination label.
        #[arg(long, requires = "to")]
        record_target: bool,
        /// Assess what would fit without recording anything or reserving budget.
        #[arg(long)]
        dry_run: bool,
        /// A note recorded with the entry.
        #[arg(long)]
        note: Option<String>,
    },
    /// Print the digest of the pass (SHA-256 of its bytes).
    Digest {
        /// The pass file.
        file: PathBuf,
    },
    /// List the ledger of a pass: every spend, the totals, and whether the chain verified.
    Ledger {
        /// The pass file.
        file: PathBuf,
        /// Show only this counter.
        #[arg(long, value_name = "NAME")]
        counter: Option<String>,
    },
    /// Retain the exact validated pass bytes in a private archive directory.
    Archive {
        /// Validated pass to retain.
        file: PathBuf,
        /// Existing private archive directory (mode 0700).
        directory: PathBuf,
    },
    /// Print an archived pass byte-for-byte by its full digest.
    Retrieve {
        /// Private directory populated by archive.
        directory: PathBuf,
        /// Full sha256 digest from archive or a ledger entry.
        digest: String,
    },
    /// Find retained debit receipts for one exact caller reference across revisions.
    Receipt {
        /// Pass whose available ledger history to search.
        file: PathBuf,
        /// Exact, case-sensitive opaque reference supplied at debit time.
        #[arg(long, value_name = "TEXT")]
        caller_ref: String,
    },
    /// Replay retained endpoint decisions using their exact archived passes.
    AuditReceipts {
        /// Pass identifying the ledger to verify.
        file: PathBuf,
        /// Private directory populated by archive.
        directory: PathBuf,
    },
    /// Audit historical charges against archived pass revisions.
    AuditCharges {
        /// Pass identifying the ledger to verify.
        file: PathBuf,
        /// Private directory populated by archive.
        directory: PathBuf,
    },
    /// Reconcile expected debits from a local JSON manifest.
    Reconcile {
        /// Pass identifying the ledger.
        file: PathBuf,
        /// Versioned JSON manifest.
        manifest: PathBuf,
    },
    /// Compare explicit ledger backups against a single local witness.
    CompareBackups {
        /// Pass identifying the local witness. The live ledger may be missing.
        file: PathBuf,
        /// One to 32 ledger files, in the order to report.
        #[arg(required = true, num_args = 1.., value_name = "CANDIDATE")]
        candidates: Vec<PathBuf>,
        /// Verify prefix relationships between witnessed extensions.
        #[arg(long)]
        ancestry: bool,
    },
    /// Export a checkpoint to retain separately from the ledger.
    Checkpoint {
        /// Pass with an existing ledger to checkpoint.
        file: PathBuf,
    },
    /// Verify a ledger against a retained checkpoint JSON file.
    VerifyCheckpoint {
        /// Ledger file itself (typically FILE.ledger).
        ledger: PathBuf,
        /// Retained JSON from the checkpoint command.
        checkpoint: PathBuf,
    },
    /// Accept a ledger that was lost, changed outside hallpass, or has no witness, and record why.
    ///
    /// The adoption is written into the ledger. A lost or rewound ledger
    /// keeps the count its witness recorded: adoption never lowers a count.
    Adopt {
        /// The pass file.
        file: PathBuf,
        /// Why (one line; it is recorded in the ledger).
        #[arg(long, value_name = "TEXT", required_unless_present = "preview")]
        reason: Option<String>,
        /// Inspect without recording anything.
        #[arg(long)]
        preview: bool,
        /// Require the exact reviewed preview token.
        #[arg(long, value_name = "TOKEN", conflicts_with = "preview")]
        token: Option<String>,
    },
    /// Verify an owner's detached SSH signature over the exact validated pass.
    VerifyApproval {
        /// Signed pass file.
        file: PathBuf,
        /// Detached signature produced by the owner.
        #[arg(long)]
        signature: PathBuf,
        /// Trusted OpenSSH allowed-signers file supplied independently by the verifier.
        #[arg(long)]
        allowed_signers: PathBuf,
        /// Expected signer identity selected by the verifier.
        #[arg(long)]
        principal: String,
    },
    /// Compare two pass revisions without authorizing either one.
    Diff(DiffArgs),
    /// Compare an entire approval with a consumer's declared features.
    ConsumerCoverage {
        /// Pass whose enforced terms should be covered.
        file: PathBuf,
        /// Repeat for endpoints, names, live-window, target-on-every-debit and charge:COUNTER, or use none alone.
        #[arg(long, required = true, value_name = "CAPABILITY")]
        can: Vec<String>,
    },
    /// Report name-restriction overlaps as advisory findings.
    Lint {
        /// Pass whose destination rules should be reviewed.
        file: PathBuf,
    },
    /// Replay a bounded, offline TOML case suite.
    #[command(name = "test-pass", alias = "cases")]
    Cases {
        /// Validated approval to evaluate.
        file: PathBuf,
        /// TOML suite with version = 1 and dated `[[case]]` examples.
        cases: PathBuf,
    },
    /// Derive a stable ID from an owner's written approval identity.
    ApprovalId {
        /// Owner identity from the written approval.
        #[arg(long)]
        owner: String,
        /// Stable written approval reference.
        #[arg(long)]
        reference: String,
    },
}

#[derive(clap::Args)]
struct DiffArgs {
    /// Previously reviewed pass.
    old: PathBuf,
    /// Proposed replacement pass.
    new: PathBuf,
    /// Project balances under both revisions using the current pass's verified ledger.
    #[arg(long)]
    budget_impact: bool,
    /// Sample changed destination decisions at the supplied review instant.
    #[arg(long, requires = "at")]
    examples: bool,
    /// Prove that every proposed endpoint allowance was already in scope.
    #[arg(long, requires = "at")]
    containment: bool,
    /// RFC 3339 instant for --examples or --containment.
    #[arg(long, value_name = "TIMESTAMP")]
    at: Option<String>,
}

impl Command {
    const fn name(&self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version => "version",
            Self::Init { .. } => "init",
            Self::Check { .. } => "check",
            Self::Rehearse { .. } => "rehearse",
            Self::Capacity(_) => "capacity",
            Self::Status { .. } => "status",
            Self::Permits { .. } => "permits",
            Self::Spend { .. } => "spend",
            Self::Digest { .. } => "digest",
            Self::Ledger { .. } => "ledger",
            Self::Adopt { .. } => "adopt",
            Self::Archive { .. } => "archive",
            Self::Retrieve { .. } => "retrieve",
            Self::Receipt { .. } => "receipt",
            Self::AuditReceipts { .. } => "audit-receipts",
            Self::AuditCharges { .. } => "audit-charges",
            Self::Reconcile { .. } => "reconcile",
            Self::CompareBackups { .. } => "compare-backups",
            Self::Checkpoint { .. } => "checkpoint",
            Self::VerifyCheckpoint { .. } => "verify-checkpoint",
            Self::VerifyApproval { .. } => "verify-approval",
            Self::Diff(_) => "diff",
            Self::ConsumerCoverage { .. } => "consumer-coverage",
            Self::Lint { .. } => "lint",
            Self::Cases { .. } => "test-pass",
            Self::ApprovalId { .. } => "approval-id",
        }
    }
}

/// What a command produced: an exit code, a JSON object, and text.
struct Output {
    code: u8,
    json: Value,
    text: String,
}

const OK: u8 = 0;
const ERROR: u8 = 1;
const REFUSED: u8 = 2;

/// The clock: the real one, or the test clock where it is honoured.
struct Clock {
    now: OffsetDateTime,
    test: bool,
}

impl Clock {
    fn sample(&self) -> OffsetDateTime {
        if self.test {
            self.now
        } else {
            OffsetDateTime::now_utc()
        }
    }
}

fn clock() -> Result<Clock, Error> {
    let real = Clock {
        now: OffsetDateTime::now_utc(),
        test: false,
    };
    let Some(value) = std::env::var_os(TEST_CLOCK_VAR) else {
        return Ok(real);
    };
    if !cfg!(any(debug_assertions, feature = "test-clock")) {
        eprintln!(
            "hallpass: {TEST_CLOCK_VAR} is set but ignored: this build uses the real clock only"
        );
        return Ok(real);
    }
    let text = value.to_string_lossy();
    let now = OffsetDateTime::parse(&text, &hallpass::time::format_description::well_known::Rfc3339)
        .map_err(|_| {
            Error::Usage(format!(
                "{TEST_CLOCK_VAR} is `{text}`, not an RFC 3339 timestamp; unset it to use the real clock"
            ))
        })?;
    eprintln!(
        "hallpass: WARNING: test clock in use ({TEST_CLOCK_VAR}={text}); decisions are NOT about the real time"
    );
    Ok(Clock { now, test: true })
}

fn refusal_json(refusal: &Refusal) -> Value {
    json!({ "code": refusal.code.as_str(), "message": refusal.message })
}

fn problems_json(problems: &[Problem]) -> Value {
    json!(problems)
}

fn error_output(command: &str, file: Option<&Path>, error: &Error) -> Output {
    let problems: &[Problem] = match error {
        Error::Invalid { problems, .. } => problems,
        _ => &[],
    };
    let mut text = format!("hallpass {command}: error: {}\n", safe(&error.to_string()));
    for p in problems {
        let _ = writeln!(text, "  - {}", safe(&p.to_string()));
    }
    text.push_str(match error {
        Error::WitnessNotUpdated { .. } => {
            "Nothing was permitted. The spend was recorded and counts against the ceiling.\n"
        }
        Error::AppendUncertain { .. } => {
            "Do not proceed or retry automatically. Inspect the ledger.\n"
        }
        _ => "Nothing was permitted.\n",
    });
    Output {
        code: ERROR,
        json: json!({
            "command": command,
            "result": "error",
            "file": file.map(|f| f.display().to_string()),
            "error": {
                "code": error.code(),
                "recording": match error { Error::WitnessNotUpdated{..} => Some("recorded"), Error::AppendUncertain{..}=>Some("uncertain"), Error::LockTimeout{..}=>Some("not-recorded"), _=>None },
                "seq": match error { Error::WitnessNotUpdated{seq,..}=>Some(seq), _=>None },
                "ledger": match error { Error::WitnessNotUpdated{path,..}|Error::AppendUncertain{path,..}=>Some(path), _=>None },
                "message": error.to_string(),
                "line": match error {
                    Error::LedgerCorrupt { line, .. } => Some(*line),
                    _ => None,
                },
            },
            "problems": problems_json(problems),
        }),
        text,
    }
}

fn window_json(pass: &Pass, state: &WindowState) -> Value {
    let seconds = |d: &Duration| d.whole_seconds().max(0);
    let (remaining, opens, ended, reason) = match state {
        WindowState::Valid { remaining } => (Some(seconds(remaining)), None, None, None),
        WindowState::NotYetValid { opens_in } => (None, Some(seconds(opens_in)), None, None),
        WindowState::Expired { ended_ago } => (None, None, Some(seconds(ended_ago)), None),
        WindowState::Revoked { reason } => (None, None, None, reason.clone()),
    };
    json!({
        "state": state.as_str(),
        "valid_from": stamp(pass.approval.valid_from),
        "valid_until": stamp(pass.approval.valid_until),
        "seconds_remaining": remaining,
        "seconds_until_open": opens,
        "seconds_since_end": ended,
        "revoked_reason": reason,
    })
}

fn window_text(pass: &Pass, state: &WindowState) -> String {
    let range = format!(
        "{} to {}",
        stamp(pass.approval.valid_from),
        stamp(pass.approval.valid_until)
    );
    match state {
        WindowState::Valid { remaining } => format!("VALID, {} left ({range})", span(*remaining)),
        WindowState::NotYetValid { opens_in } => {
            format!("NOT YET VALID, opens in {} ({range})", span(*opens_in))
        }
        WindowState::Expired { ended_ago } => {
            format!("EXPIRED {} ago ({range})", span(*ended_ago))
        }
        WindowState::Revoked { reason } => format!(
            "REVOKED{} ({range})",
            reason
                .as_ref()
                .map_or_else(String::new, |r| format!(": {}", safe(r)))
        ),
    }
}

fn init(file: &Path) -> Output {
    match hallpass::write_template(file) {
        Ok(()) => Output {
            code: OK,
            json: json!({ "command": "init", "result": "ok", "file": file.display().to_string() }),
            text: format!(
                "Wrote {} (mode 0600). It approves nothing: fill it in from the owner's written approval, then run `hallpass check {}`.\n",
                file.display(),
                file.display()
            ),
        },
        Err(e) => error_output("init", Some(file), &e),
    }
}

fn check(file: &Path) -> Output {
    match hallpass::load(file) {
        Ok(loaded) => {
            let breadth = hallpass::review::breadth(&loaded.pass);
            let target_term = if loaded.pass.require_target {
                "Every debit requires a checked destination.\n"
            } else {
                ""
            };
            Output {
                code: OK,
                json: json!({
                    "command": "check",
                    "result": "ok",
                    "file": file.display().to_string(),
                    "digest": loaded.digest.to_string(),
                    "pass_id": loaded.pass.id,
                    "require_target": loaded.pass.require_target,
                    "problems": [],
                    "breadth": breadth,
                    "warnings": hallpass::review::breadth_warnings(&breadth),
                }),
                text: format!(
                    "{}: OK, pass {} with {} destination(s) and {} ceiling(s). Declared breadth: IPv4 {}, IPv6 {}. The window is checked by `hallpass status`.\nDigest: {}\n{target_term}",
                    file.display(),
                    loaded.pass.id,
                    loaded.pass.destinations.len(),
                    loaded.pass.ceilings.len(),
                    breadth.ipv4,
                    breadth.ipv6,
                    loaded.digest
                ),
            }
        }
        Err(e) => error_output("check", Some(file), &e),
    }
}

mod cli_diff;
mod cli_verify;

fn consumer_coverage(file: &Path, tokens: &[String]) -> Output {
    use hallpass::review::{Capabilities, consumer_coverage as coverage};
    let caps = match Capabilities::parse(tokens) {
        Ok(caps) => caps,
        Err(e) => return error_output("consumer-coverage", Some(file), &Error::Usage(e)),
    };
    let loaded = match hallpass::load(file) {
        Ok(p) => p,
        Err(e) => return error_output("consumer-coverage", Some(file), &e),
    };
    let report = coverage(&loaded, &caps);
    let (code, result) = if report.findings.is_empty() {
        (OK, "covered")
    } else {
        (REFUSED, "gaps")
    };
    let mut text = format!(
        "Declared consumer coverage for {} ({}): {result}.\n",
        report.pass_id, report.digest
    );
    for f in &report.findings {
        let _ = writeln!(text, "{f}");
    }
    text.push_str("Each live operation still requires a policy decision.\n");
    Output {
        code,
        text,
        json: json!({"command":"consumer-coverage","result":result,"pass_id":report.pass_id,"digest":report.digest,"declared":caps,"require_target":report.require_target,"findings":report.findings,"file":file.display().to_string()}),
    }
}

fn review_lint(file: &Path, clock: &Clock) -> Output {
    let loaded = match hallpass::load(file) {
        Ok(v) => v,
        Err(e) => return error_output("lint", Some(file), &e),
    };
    let report = hallpass::review::lint(&loaded.pass, clock.now);
    let findings = report.findings;
    let truncated = report.truncated;
    let mut text = format!(
        "{} advisory finding(s) for {}\n",
        findings.len(),
        loaded.pass.id
    );
    if truncated {
        text.push_str("Additional overlaps omitted after 256 findings.\n");
    }
    for f in &findings {
        let _ = writeln!(
            text,
            "{}: {} overlaps {} in {} on {}-{} / {} (example {}, effective unnamed permission: {}){}",
            f.code,
            f.named_label,
            f.unnamed_label,
            f.network,
            f.port,
            f.port_end,
            f.protocol,
            f.address,
            f.effective,
            f.inactive_reason
                .as_ref()
                .map_or(String::new(), |r| format!(" ({r})"))
        );
    }
    Output {
        code: OK,
        json: json!({"command":"lint","result":"ok","file":file.display().to_string(),"digest":loaded.digest.to_string(),"findings":findings,"truncated":truncated,"warnings":[]}),
        text,
    }
}

fn review_cases(file: &Path, cases_file: &Path) -> Output {
    let loaded = match hallpass::load(file) {
        Ok(v) => v,
        Err(e) => return error_output("test-pass", Some(file), &e),
    };
    let mut file_handle = match std::fs::File::open(cases_file) {
        Ok(v) => v,
        Err(e) => return error_output("test-pass", Some(cases_file), &Error::Usage(e.to_string())),
    };
    let mut bytes = Vec::new();
    if let Err(e) = file_handle
        .by_ref()
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
    {
        return error_output("test-pass", Some(cases_file), &Error::Usage(e.to_string()));
    }
    if bytes.len() > 256 * 1024 {
        return error_output(
            "test-pass",
            Some(cases_file),
            &Error::Usage("case suite exceeds 256 KiB".to_owned()),
        );
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return error_output(
            "test-pass",
            Some(cases_file),
            &Error::Usage("case suite is not UTF-8".to_owned()),
        );
    };
    let results = match hallpass::review::cases(&loaded.pass, &text) {
        Ok(v) => v,
        Err(e) => return error_output("test-pass", Some(cases_file), &Error::Usage(e)),
    };
    let mismatches = results.iter().filter(|v| v["match"] == false).count();
    Output {
        code: if mismatches == 0 { OK } else { REFUSED },
        json: json!({"command":"test-pass","result":if mismatches==0{"ok"}else{"mismatch"},"file":file.display().to_string(),"cases":cases_file.display().to_string(),"digest":loaded.digest.to_string(),"results":results,"mismatches":mismatches,"warnings":[]}),
        text: {
            let mut text = format!(
                "{} case(s), {} mismatch(es), digest {}\n",
                results.len(),
                mismatches,
                loaded.digest
            );
            for result in &results {
                if result["match"] == false {
                    let _ = writeln!(
                        text,
                        "MISMATCH {}: expected {}, actual {}",
                        result["id"], result["expected"], result["actual"]
                    );
                }
            }
            text
        },
    }
}

fn approval_id(owner: &str, reference: &str) -> Output {
    let id = hallpass::review::approval_id(owner, reference);
    Output {
        code: OK,
        json: json!({"command":"approval-id","result":"ok","id":id,"owner":owner,"reference":reference,"warnings":[]}),
        text: format!("{id}\n"),
    }
}

fn status_text(
    file: &Path,
    loaded: &LoadedPass,
    tally: &hallpass::Tally,
    state: &WindowState,
    refusal: Option<&Refusal>,
) -> String {
    let pass = &loaded.pass;
    let mut text = format!(
        "Pass {} \"{}\" ({})\nApproved by: {} (reference: {})\nOperator: {}\nWindow: {}\n",
        pass.id,
        safe(&pass.name),
        safe(&file.display().to_string()),
        safe(&pass.approval.owner),
        safe(&pass.approval.reference),
        safe(&pass.approval.operator),
        window_text(pass, state)
    );
    text.push_str("Destinations:\n");
    for d in &pass.destinations {
        let _ = writeln!(
            text,
            "  {:<16} {:<24} {} {}{}{}{}",
            d.label,
            d.network.to_string(),
            d.protocol,
            d.ports,
            d.hostname.as_ref().map_or_else(String::new, |h| format!(
                "  (owner calls it {}; grants nothing)",
                safe(h)
            )),
            if d.names.is_empty() {
                String::new()
            } else {
                format!(
                    "  [only as: {}]",
                    d.names
                        .iter()
                        .map(hallpass::HostName::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            if d.whole_network_approved {
                "  [whole network approved]"
            } else {
                ""
            }
        );
    }
    if !pass.required_counters.is_empty() {
        let _ = writeln!(
            text,
            "Required on every debit: {}",
            pass.required_counters.join(", ")
        );
    }
    if pass.require_target {
        text.push_str("Every debit requires a checked destination.\n");
    }
    text.push_str("Ceilings:\n");
    if pass.ceilings.is_empty() {
        text.push_str("  none\n");
    }
    for (name, total) in &pass.ceilings {
        let spent = tally.spent(name);
        let _ = writeln!(
            text,
            "  {name:<16} {total} total, {spent} spent, {} left",
            total.saturating_sub(spent)
        );
    }
    for (name, spent) in tally
        .spent
        .iter()
        .filter(|(n, _)| !pass.ceilings.contains_key(*n))
    {
        let _ = writeln!(
            text,
            "  {name:<16} no ceiling in this pass any more, {spent} spent earlier"
        );
    }
    let _ = writeln!(text, "Digest: {}", loaded.digest);
    if let Some(r) = refusal {
        let _ = writeln!(text, "This pass permits NOTHING now: {}.", safe(&r.message));
    }
    text
}

fn rehearse(file: &Path, scenario: &Path) -> Output {
    let report = match hallpass::scenario::rehearse(file, scenario, &StateDir::from_env()) {
        Ok(report) => report,
        Err(error) => return error_output("rehearse", Some(file), &error),
    };
    let (code, result) = if report.stopped_at.is_some() {
        (REFUSED, "simulation-refused")
    } else {
        (OK, "simulated")
    };
    let mut text = format!(
        "Simulation {result} for {} ({})\n",
        report.pass_id, report.digest
    );
    for step in &report.steps {
        let _ = writeln!(text, "  {} at {}: {}", step.id, step.at, step.status);
        for balance in &step.balances {
            let _ = writeln!(
                text,
                "    {}: {} -> {}",
                balance.counter, balance.before, balance.after
            );
        }
        if let Some(reason) = &step.refusal {
            let _ = writeln!(text, "    {}: {}", reason.code, reason.message);
        }
    }
    let mut json = json!(report);
    json["command"] = json!("rehearse");
    json["result"] = json!(result);
    Output { code, json, text }
}

fn status(file: &Path, clock: &Clock) -> Output {
    status_with_clock(file, clock, &StateDir::from_env(), || clock.sample())
}

fn status_with_clock(
    file: &Path,
    clock: &Clock,
    state_dir: &StateDir,
    sample: impl FnOnce() -> OffsetDateTime,
) -> Output {
    let loaded = match hallpass::load(file) {
        Ok(l) => l,
        Err(e) => return error_output("status", Some(file), &e),
    };
    let mut view = match hallpass::read_summary(&loaded, state_dir) {
        Ok(v) => v,
        Err(e) => return error_output("status", Some(file), &e),
    };
    let now = sample();
    if let Some(previous) = view.last_time.filter(|last| now < *last) {
        view.warnings.push(format!("the decision clock ({}) precedes the last ledger entry ({}); check the system clock before continuing", stamp(now), stamp(previous)));
    }
    let tally = &view.tally;
    let pass = &loaded.pass;
    let state = pass.window_at(now);
    let refusal = pass.check_window(now, Duration::ZERO).err();
    let destinations: Vec<Value> = pass
        .destinations
        .iter()
        .map(|d| {
            json!({
                "label": d.label,
                "kind": if d.network.is_host() { "address" } else { "network" },
                "destination": d.network.to_string(),
                "protocol": d.protocol.as_str(),
                "ports": d.ports.ranges().iter().map(|(s, e)| json!({"start": s, "end": e})).collect::<Vec<_>>(),
                "ports_text": d.ports.to_string(),
                "hostname": d.hostname,
                "names": d.names.iter().map(hallpass::HostName::as_str).collect::<Vec<_>>(),
                "whole_network_approved": d.whole_network_approved,
            })
        })
        .collect();
    let counters: Vec<Value> = pass
        .ceilings
        .iter()
        .map(|(name, total)| {
            let spent = tally.spent(name);
            json!({
                "name": name,
                "total": total,
                "spent": spent,
                "remaining": total.saturating_sub(spent),
            })
        })
        .collect();
    let unlisted: Vec<Value> = tally
        .spent
        .iter()
        .filter(|(name, _)| !pass.ceilings.contains_key(*name))
        .map(|(name, spent)| json!({ "name": name, "spent": spent }))
        .collect();

    let breadth = hallpass::review::breadth(pass);
    let mut warnings = view.warnings.clone();
    warnings.extend(hallpass::review::breadth_warnings(&breadth));
    let mut text = status_text(file, &loaded, tally, &state, refusal.as_ref());
    let _ = writeln!(
        text,
        "Declared breadth: IPv4 {}, IPv6 {}.",
        breadth.ipv4, breadth.ipv6
    );
    let _ = writeln!(text, "Ledger: {}", ledger_state_text(&view));
    Output {
        code: if refusal.is_some() { REFUSED } else { OK },
        json: json!({
            "command": "status",
            "result": if refusal.is_some() { "refused" } else { "ok" },
            "file": file.display().to_string(),
            "digest": loaded.digest.to_string(),
            "now": stamp(now),
            "test_clock": clock.test,
            "pass": {
                "id": pass.id,
                "name": pass.name,
                "owner": pass.approval.owner,
                "reference": pass.approval.reference,
                "operator": pass.approval.operator,
            },
            "window": window_json(pass, &state),
            "destinations": destinations,
            "breadth": breadth,
            "counters": counters,
            "required_counters": pass.required_counters,
            "require_target": pass.require_target,
            "unlisted_spends": unlisted,
            "ledger": ledger_json(&view),
            "warnings": warnings,
            "refusal": refusal.as_ref().map(refusal_json),
        }),
        text,
    }
}

fn parse_targets(values: &[String], name: Option<&str>) -> Result<Vec<NamedTarget>, Error> {
    if values.len() > hallpass::MAX_TARGETS {
        return Err(Error::Usage(format!(
            "at most {} targets can be checked per question",
            hallpass::MAX_TARGETS
        )));
    }
    let mut targets = values
        .iter()
        .map(|v| {
            v.parse::<NamedTarget>()
                .map_err(|e| Error::Usage(format!("--to: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(name) = name {
        let [target] = targets.as_mut_slice() else {
            return Err(Error::Usage("--name requires exactly one --to; use --to ADDRESS:PORT/PROTO@NAME for per-target names".into()));
        };
        if target.name.is_some() {
            return Err(Error::Usage("supply the name once per target".into()));
        }
        target.name = Some(name.parse().map_err(Error::Usage)?);
    }
    Ok(targets)
}

fn targets_json(targets: &[NamedTarget], labels: &[String]) -> Value {
    json!(targets.iter().enumerate().map(|(i,t)|json!({"target": t.target.to_string(),"name": t.name.as_ref().map(hallpass::HostName::as_str),"label":labels.get(i)})).collect::<Vec<_>>())
}

fn permits(
    file: &Path,
    to: &[String],
    name: Option<&str>,
    digest: Option<&str>,
    duration: u32,
    clock: &Clock,
) -> Output {
    let call = || {
        let targets = parse_targets(to, name)?;
        let expected = digest
            .map(str::parse::<Digest>)
            .transpose()
            .map_err(Error::Usage)?;
        let result = hallpass::permits_with_clock_in(
            file,
            &targets,
            expected,
            Duration::seconds(i64::from(duration)),
            &StateDir::from_env(),
            || clock.sample(),
        )?;
        Ok::<_, Error>((targets, result))
    };
    let (targets, outcome) = match call() {
        Ok(value) => value,
        Err(e) => return error_output("permits", Some(file), &e),
    };
    let first = &targets[0];
    let asked = targets
        .iter()
        .map(|t| {
            t.name
                .as_ref()
                .map_or_else(|| t.target.to_string(), |n| format!("{} as {n}", t.target))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let now = outcome.now;
    let loaded = outcome.loaded;
    let state = loaded.pass.window_at(now);
    let labels = outcome.decision.as_deref().unwrap_or(&[]);
    let refused = outcome.decision.as_ref().err();
    let text = refused.map_or_else(
        || {
            format!(
                "ALLOWED: {asked} by destination {} of pass {} (window: {})\n",
                labels.join(", "),
                loaded.pass.id,
                window_text(&loaded.pass, &state)
            )
        },
        |r| format!("REFUSED: {asked}: {}.\n", safe(&r.reason.message)),
    );
    Output {
        code: if refused.is_some() { REFUSED } else { OK },
        text,
        json: json!({
            "command":"permits","result":if refused.is_some(){"refused"}else{"allowed"},"file":file.display().to_string(),"digest":loaded.digest.to_string(),"pass_id":loaded.pass.id,
            "now":stamp(now),"test_clock":clock.test,"target":first.target.to_string(),"name":first.name.as_ref().map(hallpass::HostName::as_str),"label":labels.first(),"refusal":refused.map(|r|refusal_json(&r.reason)),"refused_target":refused.and_then(|r|r.index),"targets":targets_json(&targets,labels),"window":window_json(&loaded.pass,&state),"warnings":outcome.warnings
        }),
    }
}

struct SpendArgs<'a> {
    unit: &'a cli_debit::DebitUnit,
    lock_timeout_ms: Option<u64>,
    caller_ref: Option<&'a str>,
    record_target: bool,
    dry_run: bool,
    note: Option<&'a str>,
}

fn spend(args: &SpendArgs<'_>, clock: &Clock) -> Output {
    let file = &args.unit.file;
    let (expect_digest, targets) = match args.unit.policy_inputs() {
        Ok(inputs) => inputs,
        Err(e) => return error_output("spend", Some(file), &e),
    };
    let mut request = args.unit.policy(expect_digest, &targets);
    request.lock_timeout = args.lock_timeout_ms.map(std::time::Duration::from_millis);
    request.note = args.note;
    if args.unit.counter.is_none() || args.caller_ref.is_some() || args.record_target {
        return debit_spend(args, request, &targets, clock);
    }
    let target = request.target;
    let name = request.name;
    let state = StateDir::from_env();
    let answer = if args.dry_run {
        hallpass::preview_spend_with_clock_in(file, &request, &state, || clock.sample())
    } else {
        hallpass::spend_with_clock_in(file, &request, &state, || clock.sample())
    };
    let outcome = match answer {
        Ok(o) => o,
        Err(e) => return error_output("spend", Some(file), &e),
    };
    let remaining = outcome.remaining();
    let asked = target.map(|t| {
        name.as_ref()
            .map_or_else(|| t.to_string(), |n| format!("{t} as {n}"))
    });
    let text = match (&outcome.refusal, outcome.total, outcome.seq) {
        (None, Some(total), Some(seq)) => format!(
            "RECORDED: {} {}{} ({} of {total} spent, {} left; ledger entry {seq})\n",
            outcome.amount,
            outcome.counter,
            match (&asked, &outcome.label) {
                (Some(asked), Some(label)) => format!(" for {asked} by destination {label}"),
                _ => String::new(),
            },
            outcome.spent,
            remaining.unwrap_or(0)
        ),
        (None, Some(_), None) if args.dry_run => format!(
            "WOULD ALLOW: {} {}; no debit recorded.\n",
            outcome.amount, outcome.counter
        ),
        (Some(r), _, _) => format!("REFUSED: {}.\n", safe(&r.message)),
        _ => "REFUSED: no decision.\n".to_owned(),
    };
    Output {
        code: if outcome.refusal.is_some() {
            REFUSED
        } else {
            OK
        },
        json: json!({
            "command": "spend",
            "result": if outcome.refusal.is_some() { "refused" } else if args.dry_run {"would-allow"} else { "allowed" },
            "file": file.display().to_string(),
            "digest": outcome.digest.to_string(),
            "pass_id": outcome.pass_id,
            "now": stamp(outcome.now),
            "test_clock": clock.test,
            "projected_spent": if args.dry_run && outcome.refusal.is_none(){ Some(outcome.spent+outcome.amount) }else{None},
            "refused_target":outcome.refused_target,
            "targets":targets_json(&targets,&outcome.labels),
            "counter": outcome.counter,
            "n": outcome.amount,
            "total": outcome.total,
            "spent": outcome.spent,
            "remaining": remaining,
            "seq": outcome.seq,
            "note": args.note,
            "target": target.map(|t| t.to_string()),
            "name": name.map(hallpass::HostName::as_str),
            "label": outcome.label,
            "refusal": outcome.refusal.as_ref().map(refusal_json),
            "warnings": outcome.warnings,
        }),
        text,
    }
}

fn debit_spend(
    args: &SpendArgs<'_>,
    policy: SpendRequest<'_>,
    targets: &[NamedTarget],
    clock: &Clock,
) -> Output {
    let file = &args.unit.file;
    let charges = match args.unit.charges() {
        Ok(charges) => charges,
        Err(e) => return error_output("spend", Some(file), &e),
    };
    let mut request = hallpass::SpendChargesRequest::new(&charges);
    request.policy = policy;
    request.caller_ref = args.caller_ref;
    request.record_targets = args.record_target;
    request.dry_run = args.dry_run;
    let outcome =
        match hallpass::spend_charges_with_clock_in(file, &request, &StateDir::from_env(), || {
            clock.sample()
        }) {
            Ok(o) => o,
            Err(e) => return error_output("spend", Some(file), &e),
        };
    let (result, code, mut text) = match (&outcome.refusal, outcome.seq) {
        (Some(r), _) => (
            "refused",
            REFUSED,
            format!("REFUSED: {}.\n", safe(&r.message)),
        ),
        (None, Some(seq)) => ("allowed", OK, format!("RECORDED: ledger entry {seq}\n")),
        (None, None) => (
            "would-allow",
            OK,
            "WOULD ALLOW: no debit recorded\n".to_owned(),
        ),
    };
    for charge in &outcome.charges {
        let remaining = charge
            .remaining
            .map_or_else(|| "unknown".to_owned(), |n| n.to_string());
        let _ = writeln!(
            text,
            "  {} {} ({} spent, {remaining} left)",
            charge.amount, charge.counter, charge.spent
        );
    }
    if let Some(receipt) = &outcome.receipt {
        let _ = writeln!(text, "  receipt {}", debit_receipt_text(receipt));
    }
    let mut json = json!({
        "command": "spend",
        "result": result,
        "file": file.display().to_string(),
        "digest": outcome.digest.to_string(),
        "pass_id": outcome.pass_id,
        "now": stamp(outcome.now),
        "test_clock": clock.test,
        "charges": outcome.charges,
        "seq": outcome.seq,
        "note": args.note,
        "targets": targets_json(targets, &outcome.labels),
        "refused_target": outcome.refused_target,
        "target": request.policy.target.map(|t| t.to_string()),
        "name": request.policy.name.map(hallpass::HostName::as_str),
        "label": outcome.labels.first(),
        "receipt": outcome.receipt,
        "refusal": outcome.refusal.as_ref().map(refusal_json),
        "warnings": outcome.warnings,
    });
    if args.unit.counter.is_some()
        && let Some(charge) = outcome.charges.first()
    {
        json["counter"] = json!(charge.counter);
        json["n"] = json!(charge.amount);
        json["total"] = json!(charge.total);
        json["spent"] = json!(charge.spent);
        json["remaining"] = json!(charge.remaining);
        json["projected_spent"] = json!(charge.projected_spent);
    }
    Output { code, json, text }
}

fn debit_receipt_text(receipt: &hallpass::DebitReceipt) -> String {
    // Quote and escape reliably in text mode, including labels from a pass.
    let printable = serde_json::to_string(receipt).unwrap_or_default();
    safe(&printable).into_owned()
}

fn digest(file: &Path) -> Output {
    match hallpass::load(file) {
        Ok(loaded) => Output {
            code: OK,
            json: json!({
                "command": "digest",
                "result": "ok",
                "file": file.display().to_string(),
                "digest": loaded.digest.to_string(),
                "pass_id": loaded.pass.id,
            }),
            text: format!("{}\n", loaded.digest),
        },
        Err(e) => error_output("digest", Some(file), &e),
    }
}

/// The short form of a digest for a table column: `sha256:` and 12 hex digits.
fn short_digest(digest: &Digest) -> String {
    digest.to_string().chars().take(19).collect()
}

/// Counter name, amount spent, and the pass's total for it.
type Total<'a> = (&'a str, u64, Option<u64>);

fn ledger_text(
    loaded: &LoadedPass,
    view: &hallpass::LedgerView,
    entries: &[&hallpass::LedgerEntry],
    debits: &[&hallpass::LedgerDebit],
    totals: &[Total<'_>],
    counter: Option<&str>,
) -> String {
    let pass = &loaded.pass;
    let mut text = String::new();
    let ledger_shown = safe(&view.path.display().to_string()).into_owned();
    if view.exists {
        let _ = writeln!(text, "Ledger of pass {} ({ledger_shown})", pass.id);
        if let Some(c) = counter {
            let _ = writeln!(text, "Only counter {c} (adoptions are always shown).");
        }
        let mut rows: Vec<(u64, String)> = entries
            .iter()
            .map(|e| {
                (
                    e.seq,
                    format!(
                        "  {:>5}  {:<20}  {:<16} {:>8}  {:<19}  {}",
                        e.seq,
                        stamp(e.time),
                        e.counter,
                        e.amount,
                        short_digest(&e.digest),
                        e.note
                            .as_deref()
                            .map_or_else(String::new, |n| safe(n).into_owned())
                    ),
                )
            })
            .collect();
        rows.extend(debits.iter().map(|e| {
            let charges = e
                .charges
                .iter()
                .map(|charge| format!("{}={}", charge.counter, charge.amount))
                .collect::<Vec<_>>()
                .join(", ");
            let note = e
                .note
                .as_deref()
                .map_or_else(String::new, |n| safe(n).into_owned());
            let receipt = e.receipt.as_ref().map_or_else(String::new, |r| {
                format!(" receipt {}", debit_receipt_text(r))
            });
            (
                e.seq,
                format!(
                    "  {:>5}  {:<20}  DEBIT {charges}  {}  {note}{receipt}",
                    e.seq,
                    stamp(e.time),
                    short_digest(&e.digest)
                ),
            )
        }));
        rows.extend(view.adoptions.iter().map(|a| {
            (
                a.seq,
                format!(
                    "  {:>5}  {:<20}  ADOPTED, carried from the witness: {}; reason: {}",
                    a.seq,
                    stamp(a.time),
                    hallpass::totals_text(&a.carried),
                    safe(&a.reason)
                ),
            )
        }));
        rows.sort_by_key(|(seq, _)| *seq);
        if rows.is_empty() {
            text.push_str("  no entries\n");
        } else {
            let _ = writeln!(
                text,
                "  {:>5}  {:<20}  {:<16} {:>8}  {:<19}  note",
                "seq", "time", "counter", "n", "digest"
            );
        }
        for (_, row) in rows {
            let _ = writeln!(text, "{}", row.trim_end());
        }
    } else {
        let _ = writeln!(
            text,
            "No ledger yet for pass {} ({ledger_shown} does not exist): nothing has been spent.",
            pass.id
        );
    }
    text.push_str("Totals:\n");
    if totals.is_empty() {
        text.push_str("  none\n");
    }
    for (name, spent, total) in totals {
        let _ = match total {
            Some(t) => writeln!(text, "  {name:<16} {spent} spent of {t}"),
            None => writeln!(text, "  {name:<16} {spent} spent (no ceiling in this pass)"),
        };
    }
    let _ = writeln!(text, "Ledger: {}", ledger_state_text(view));
    let _ = writeln!(text, "Current pass digest: {}", loaded.digest);
    text
}

/// One line on the ledger and its witness, for `status` and `ledger`.
fn ledger_state_text(view: &hallpass::LedgerView) -> String {
    use hallpass::WitnessStatus as W;
    if !view.exists {
        return "none yet (nothing spent)".to_owned();
    }
    let lines = view.tally.entries + view.adoption_count;
    let witness = match &view.witness {
        W::Matches => "the witness matches",
        W::Extended { .. } => "the witness is behind (see the warning)",
        W::Missing => "NO WITNESS yet (see the warning)",
        W::NotChecked { .. } => "the witness was NOT CHECKED (see the warning)",
        _ => "",
    };
    format!(
        "{lines} line(s) after the header, chain verified, {witness}{}",
        if view.moved_from.is_some() {
            "; it was moved or copied (see the warning)"
        } else {
            ""
        }
    )
}

/// The `ledger` object in `status` output.
fn ledger_json(view: &hallpass::LedgerView) -> Value {
    json!({
        "path": view.path.display().to_string(),
        "exists": view.exists,
        "entries": view.tally.entries,
        "adoptions": view.adoption_count,
        "witness": view.witness.as_str(),
        "moved_from": view.moved_from,
    })
}

fn witnessed_json(w: &hallpass::Witnessed) -> Value {
    json!({
        "ledger": w.ledger,
        "seq": w.seq,
        "totals": w.totals,
        "updated": w.updated,
    })
}

fn spend_events_json(
    entries: &[&hallpass::LedgerEntry],
    debits: &[&hallpass::LedgerDebit],
) -> Vec<Value> {
    let mut events: Vec<_> = entries
        .iter()
        .map(|e| {
            (
                e.seq,
                json!({
                    "seq": e.seq,
                    "time": stamp(e.time),
                    "counter": e.counter,
                    "n": e.amount,
                    "digest": e.digest.to_string(),
                    "note": e.note,
                }),
            )
        })
        .chain(debits.iter().map(|e| {
            (
                e.seq,
                json!({
                    "seq": e.seq,
                    "time": stamp(e.time),
                    "event": "debit",
                    "version": 1,
                    "charges": e.charges,
                    "digest": e.digest.to_string(),
                    "note": e.note,
                    "receipt": e.receipt,
                }),
            )
        }))
        .collect();
    events.sort_by_key(|(seq, _)| *seq);

    events.into_iter().map(|(_, entry)| entry).collect()
}

fn ledger(file: &Path, counter: Option<&str>) -> Output {
    if let Some(name) = counter
        && !hallpass::is_counter_name(name)
    {
        return error_output(
            "ledger",
            Some(file),
            &Error::Usage(format!(
                "--counter: `{}` is not a counter name (lower-case letters, digits, `_` and `-`, starting with a letter)",
                safe(name)
            )),
        );
    }
    let loaded = match hallpass::load(file) {
        Ok(l) => l,
        Err(e) => return error_output("ledger", Some(file), &e),
    };
    let view = match hallpass::read_ledger(&loaded, &StateDir::from_env()) {
        Ok(v) => v,
        Err(e) => return error_output("ledger", Some(file), &e),
    };
    let pass = &loaded.pass;
    let wanted = |name: &str| counter.is_none_or(|c| c == name);
    let entries: Vec<&hallpass::LedgerEntry> =
        view.entries.iter().filter(|e| wanted(&e.counter)).collect();
    let debits: Vec<&hallpass::LedgerDebit> = view
        .debits
        .iter()
        .filter(|e| e.charges.iter().any(|charge| wanted(&charge.counter)))
        .collect();
    let mut names: Vec<&str> = pass
        .ceilings
        .keys()
        .chain(view.tally.spent.keys())
        .map(String::as_str)
        .filter(|n| wanted(n))
        .collect();
    if let Some(c) = counter {
        names.push(c);
    }
    names.sort_unstable();
    names.dedup();
    let totals: Vec<Total<'_>> = names
        .iter()
        .map(|n| (*n, view.tally.spent(n), pass.ceilings.get(*n).copied()))
        .collect();

    let text = ledger_text(&loaded, &view, &entries, &debits, &totals, counter);

    Output {
        code: OK,
        json: json!({
            "command": "ledger",
            "result": "ok",
            "file": file.display().to_string(),
            "ledger": view.path.display().to_string(),
            "exists": view.exists,
            "pass_id": pass.id,
            "digest": loaded.digest.to_string(),
            "counter": counter,
            "verified": true,
            "witness": view.witness.as_str(),
            "moved_from": view.moved_from,
            "entries": spend_events_json(&entries, &debits),
            "adoptions": view.adoptions.iter().map(|a| json!({
                "seq": a.seq,
                "time": stamp(a.time),
                "reason": a.reason,
                "digest": a.digest.to_string(),
                "carried": a.carried,
                "previous": a.previous.as_ref().map(witnessed_json),
            })).collect::<Vec<_>>(),
            "totals": totals.iter().map(|(name, spent, total)| json!({
                "name": name,
                "spent": spent,
                "total": total,
                "remaining": total.map(|t| t.saturating_sub(*spent)),
            })).collect::<Vec<_>>(),
            "warnings": view.warnings,
        }),
        text,
    }
}

fn preview_adopt(file: &Path) -> Output {
    match hallpass::preview_adopt(file, &StateDir::from_env()) {
        Ok(p) => Output {
            code: 0,
            text: format!(
                "ADOPTION PREVIEW: {} for {} at sequence {}. Present: {}. Carry: {}. Projected: {}. Token: {}\n",
                p.case.as_str(),
                p.pass_id,
                p.seq,
                hallpass::totals_text(&p.present),
                hallpass::totals_text(&p.carried),
                hallpass::totals_text(&p.totals),
                p.token
            ),
            json: json!({"command":"adopt", "result":"preview", "case":p.case.as_str(), "pass_id":p.pass_id, "seq":p.seq, "present":p.present, "carried":p.carried, "totals":p.totals, "previous":p.previous.as_ref().map(witnessed_json), "token":p.token}),
        },
        Err(e) => error_output("adopt", Some(file), &e),
    }
}

fn adopt(file: &Path, reason: &str, token: Option<&str>, clock: &Clock) -> Output {
    let outcome =
        match hallpass::adopt_guarded(file, reason, clock.now, &StateDir::from_env(), token) {
            Ok(o) => o,
            Err(e) => return error_output("adopt", Some(file), &e),
        };
    let what = match outcome.case {
        hallpass::AdoptCase::LedgerMissing => "the ledger was missing; a new one was started",
        hallpass::AdoptCase::LedgerChanged => "the ledger did not match its witness",
        hallpass::AdoptCase::NoWitness => "the ledger had no witness",
        _ => "adopted",
    };
    let a = &outcome.adoption;
    let text = format!(
        "ADOPTED: {} for pass {} ({what}). Recorded as ledger entry {} with the reason \"{}\". Carried from the witness: {}. Spent now: {}.\n",
        safe(&outcome.ledger.display().to_string()),
        outcome.pass_id,
        a.seq,
        safe(&a.reason),
        hallpass::totals_text(&a.carried),
        hallpass::totals_text(&outcome.totals),
    );
    Output {
        code: OK,
        json: json!({
            "command": "adopt",
            "result": "ok",
            "file": file.display().to_string(),
            "ledger": outcome.ledger.display().to_string(),
            "pass_id": outcome.pass_id,
            "digest": a.digest.to_string(),
            "now": stamp(clock.now),
            "test_clock": clock.test,
            "case": outcome.case.as_str(),
            "created": outcome.created,
            "seq": a.seq,
            "reason": a.reason,
            "carried": a.carried,
            "previous": a.previous.as_ref().map(witnessed_json),
            "totals": outcome.totals,
        }),
        text,
    }
}

/// Operator-supplied text, escaped for a terminal.
fn safe(text: &str) -> std::borrow::Cow<'_, str> {
    hallpass::display_safe(text)
}

fn archive(file: &Path, directory: &Path) -> Output {
    match hallpass::archive_pass(file, directory) {
        Ok(digest) => Output {
            code: 0,
            text: format!("Archived: {digest}\n"),
            json: json!({"command": "archive", "result": "ok", "digest": digest.to_string()}),
        },
        Err(e) => error_output("archive", Some(file), &e),
    }
}

fn retrieve(directory: &Path, digest: &str) -> Output {
    let result = digest
        .parse::<hallpass::Digest>()
        .map_err(Error::Usage)
        .and_then(|digest| hallpass::retrieve_pass(directory, digest));
    match result {
        Ok(bytes) => {
            let Ok(text) = String::from_utf8(bytes) else {
                return error_output(
                    "retrieve",
                    None,
                    &Error::Usage("archived pass is not UTF-8".into()),
                );
            };
            Output {
                code: 0,
                json: json!({"command": "retrieve", "result": "ok", "digest": digest, "bytes": text}),
                text,
            }
        }
        Err(e) => error_output("retrieve", None, &e),
    }
}

fn checkpoint(file: &Path) -> Output {
    let result = hallpass::load(file)
        .and_then(|loaded| hallpass::export_checkpoint(&loaded, &StateDir::from_env()));
    match result {
        Ok((checkpoint, corroborated)) => {
            let value = json!({"version": checkpoint.version, "pass_id": checkpoint.pass_id, "seq": checkpoint.seq, "hash": checkpoint.hash});
            Output {
                code: 0,
                text: format!("{value}\n"),
                json: json!({"command": "checkpoint", "result": "ok", "checkpoint": value, "local_corroboration": corroborated, "warnings": [if corroborated { "The witness corroborates a prefix and may lag the exported tail." } else { "There is no local witness corroboration." }]}),
            }
        }
        Err(e) => error_output("checkpoint", Some(file), &e),
    }
}

fn verify_checkpoint(ledger: &Path, checkpoint: &Path) -> Output {
    let result = (|| {
        let file = std::fs::File::open(checkpoint)
            .map_err(|e| Error::Usage(format!("cannot read checkpoint: {e}")))?;
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Usage(format!("cannot read checkpoint: {e}")))?;
        if bytes.len() > 65536 {
            return Err(Error::Usage("checkpoint too large".to_owned()));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Usage(format!("invalid checkpoint JSON: {e}")))?;
        let value = value.get("checkpoint").cloned().unwrap_or(value);
        let checkpoint = serde_json::from_value(value)
            .map_err(|e| Error::Usage(format!("invalid checkpoint: {e}")))?;
        hallpass::verify_checkpoint(ledger, &checkpoint)
    })();
    match result {
        Ok(status) => {
            let (name, added, code) = match status {
                hallpass::CheckpointStatus::Exact => ("exact", 0, 0),
                hallpass::CheckpointStatus::Extended(n) => ("extended", n, 0),
                hallpass::CheckpointStatus::Mismatch => ("mismatch", 0, 2),
            };
            Output {
                code,
                text: format!(
                    "Checkpoint verification: {name} ({added} later lines). Trust input: supplied checkpoint.\n"
                ),
                json: json!({"command": "verify-checkpoint", "result": name, "added": added, "trust_input": "supplied-checkpoint"}),
            }
        }
        Err(e) => error_output("verify-checkpoint", Some(ledger), &e),
    }
}

fn command_clock(command: &Command) -> Result<Clock, Error> {
    let needs_clock = matches!(
        command,
        Command::Status { .. }
            | Command::Permits { .. }
            | Command::Spend { .. }
            | Command::Capacity(_)
            | Command::Adopt { .. }
            | Command::Lint { .. }
    );
    if needs_clock {
        clock()
    } else {
        Ok(Clock {
            now: OffsetDateTime::now_utc(),
            test: false,
        })
    }
}

#[allow(clippy::too_many_lines)]
fn run(cli: &Cli, format: Format) -> Output {
    let name = cli.command.name();
    let clock = match command_clock(&cli.command) {
        Ok(clock) => clock,
        Err(e) => return error_output(name, None, &e),
    };
    match &cli.command {
        Command::Help { topic } => cli_help::help(topic.as_deref(), format),
        Command::Version => cli_help::version(),
        Command::Init { file } => init(file),
        Command::Check { file } => check(file),
        Command::Rehearse { file, scenario } => rehearse(file, scenario),
        Command::Capacity(unit) => cli_debit::run_capacity(unit, &clock),
        Command::Status { file } => status(file, &clock),
        Command::Permits {
            file,
            to,
            name,
            duration,
            digest,
        } => permits(
            file,
            to,
            name.as_deref(),
            digest.as_deref(),
            *duration,
            &clock,
        ),
        Command::Spend {
            unit,
            lock_timeout_ms,
            caller_ref,
            record_target,
            dry_run,
            note,
        } => spend(
            &SpendArgs {
                unit,
                lock_timeout_ms: *lock_timeout_ms,
                caller_ref: caller_ref.as_deref(),
                record_target: *record_target,
                dry_run: *dry_run,
                note: note.as_deref(),
            },
            &clock,
        ),
        Command::Digest { file } => digest(file),
        Command::Ledger { file, counter } => ledger(file, counter.as_deref()),
        Command::Archive { file, directory } => archive(file, directory),
        Command::Retrieve { directory, digest } => retrieve(directory, digest),
        Command::Receipt { file, caller_ref } => cli_evidence::receipt(file, caller_ref),
        Command::AuditReceipts { file, directory } => cli_evidence::audit(file, directory),
        Command::AuditCharges { file, directory } => cli_evidence::audit_charges(file, directory),
        Command::Reconcile { file, manifest } => cli_evidence::reconcile(file, manifest),
        Command::CompareBackups {
            file,
            candidates,
            ancestry,
        } => cli_evidence::backups(file, candidates, *ancestry),
        Command::Checkpoint { file } => checkpoint(file),
        Command::VerifyCheckpoint { ledger, checkpoint } => verify_checkpoint(ledger, checkpoint),
        Command::Adopt {
            file,
            reason,
            preview,
            token,
        } => {
            if *preview {
                preview_adopt(file)
            } else {
                adopt(
                    file,
                    reason.as_deref().unwrap_or_default(),
                    token.as_deref(),
                    &clock,
                )
            }
        }
        Command::VerifyApproval {
            file,
            signature,
            allowed_signers,
            principal,
        } => cli_verify::verify_approval(file, signature, allowed_signers, principal),
        Command::Diff(args) => cli_diff::review_diff(args),
        Command::ConsumerCoverage { file, can } => consumer_coverage(file, can),
        Command::Lint { file } => review_lint(file, &clock),
        Command::Cases { file, cases } => review_cases(file, cases),
        Command::ApprovalId { owner, reference } => approval_id(owner, reference),
    }
}

/// Help, version and usage errors can exit clap before it returns parsed
/// options. Remember the requested output and the top-level command for those
/// paths. Leave argument order, non-UTF-8 paths and everything after -- intact.
struct Invocation {
    args: Vec<OsString>,
    json: bool,
    topic: Option<OsString>,
}

impl Invocation {
    fn read() -> Self {
        let mut args: Vec<_> = std::env::args_os().collect();
        let mut requested_format = None;
        let mut expects_format = false;
        let mut topic = None;
        let mut looking_for_command = true;
        for arg in args.iter_mut().skip(1).take_while(|arg| *arg != "--") {
            if arg == "--json" {
                *arg = "--format=json".into();
            }
            if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--format=")) {
                requested_format = Some(OsString::from(value));
                expects_format = false;
            } else if arg == "--format" {
                requested_format = Some(OsString::new());
                expects_format = true;
            } else if expects_format {
                requested_format = Some(arg.clone());
                expects_format = false;
            } else if looking_for_command {
                looking_for_command = false;
                if !arg.as_encoded_bytes().starts_with(b"-") {
                    topic = Some(arg.clone());
                }
            }
        }
        // Feed the environment default to the same value parser as an explicit
        // flag, only when neither spelling appeared on the command line.
        if requested_format.is_none()
            && let Some(value) = std::env::var_os("FORMAT")
        {
            let mut option = OsString::from("--format=");
            option.push(&value);
            args.insert(1, option);
            requested_format = Some(value);
        }
        let json = requested_format.as_deref() == Some(OsStr::new("json"));
        Self { args, json, topic }
    }
}

fn emit(mut output: Output, format: Format) -> ExitCode {
    if output.json.get("warnings").is_none() {
        output.json["warnings"] = json!([]);
    }
    match format {
        Format::Json => {
            let mut advice = output.json["advice"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for warning in output.json["warnings"].as_array().into_iter().flatten() {
                advice.push(json!({"level":"warn","type":"warning","message":warning}));
            }
            if matches!(
                output.json["error"]["recording"].as_str(),
                Some("recorded" | "uncertain")
            ) {
                advice.push(json!({"level":"warn","type":"reconcile-ledger","message":"Inspect the ledger and reconcile this operation before considering a retry."}));
            } else if output.json["error"]["code"] == "usage" && advice.is_empty() {
                advice.push(help_advice(output.json["command"].as_str()));
            } else if output.json["command"] == "init" && output.code == OK {
                advice.push(json!({"level":"info","type":"check-pass","message":"Fill in the owner's written approval, then run hallpass check on the new file."}));
            }
            output.json["advice"] = Value::Array(advice);
            println!("{}", output.json);
        }
        Format::Text | Format::Pretty => {
            for w in output.json["warnings"].as_array().into_iter().flatten() {
                eprintln!(
                    "hallpass: warning: {}",
                    safe(w.as_str().unwrap_or_default())
                );
            }
            if output.code == ERROR {
                eprint!("{}", output.text);
            } else {
                print!("{}", output.text);
            }
        }
    }
    ExitCode::from(output.code)
}

/// Only a command name from clap's definition is passed here.
fn help_advice(topic: Option<&str>) -> Value {
    let mut argv = vec!["hallpass", "help"];
    argv.extend(topic);
    argv.extend(["--format", "json"]);
    json!({"level":"info","type":"command-help","message":format!("Run {} for usage and examples.", argv.join(" ")), "argv":argv})
}

fn main() -> ExitCode {
    let input = Invocation::read();
    let mut definition = cli_help::definition();
    let cli = definition
        .try_get_matches_from_mut(input.args)
        .and_then(|matches| Cli::from_arg_matches(&matches));
    match cli {
        Ok(cli) => {
            let format = cli.format.unwrap_or_else(|| {
                if std::io::stdout().is_terminal() {
                    Format::Pretty
                } else {
                    Format::Text
                }
            });
            emit(run(&cli, format), format)
        }
        Err(e) => {
            if input.json {
                let out = match e.kind() {
                    ErrorKind::DisplayHelp => {
                        cli_help::help(input.topic.as_deref().and_then(OsStr::to_str), Format::Json)
                    }
                    ErrorKind::DisplayVersion => cli_help::version(),
                    _ => {
                        let _ = e.print();
                        let topic = input
                            .topic
                            .and_then(|s| definition.find_subcommand(s))
                            .map(clap::Command::get_name);
                        Output {
                            code: ERROR,
                            text: String::new(),
                            json: json!({
                                "command":null, "file":null, "result":"error", "problems":[],
                                "error":{"code":"usage","message":e.render().to_string().trim_end(),"line":null},
                                "advice":[help_advice(topic)]
                            }),
                        }
                    }
                };
                emit(out, Format::Json)
            } else {
                let code = if e.use_stderr() { ERROR } else { OK };
                let _ = e.print();
                ExitCode::from(code)
            }
        }
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use time::macros::datetime;

    #[test]
    fn status_samples_after_ledger_verification() {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("pass");
        let docs = include_str!("../docs/INTEGRATING.md");
        let pass = docs
            .split("```toml\n")
            .nth(1)
            .expect("pass block")
            .split("```")
            .next()
            .expect("pass");
        fs::write(&path, pass).expect("pass");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let clock = Clock {
            now: datetime!(2026-11-20 09:00 UTC),
            test: true,
        };
        let output = status_with_clock(
            &path,
            &clock,
            &StateDir::new(dir.path().join("state")),
            || {
                fs::write(hallpass::ledger_path(&path), b"corrupt\n")
                    .expect("change after snapshot");
                datetime!(2026-11-20 17:00 UTC)
            },
        );
        assert_eq!(output.code, REFUSED);
        assert_eq!(output.json["now"], "2026-11-20T17:00:00Z");
        assert_eq!(output.json["refusal"]["code"], "expired");
    }
}

#[cfg(test)]
mod caller_errors {
    use super::*;
    #[test]
    fn failures_after_the_append_starts_have_explicit_reconciliation_state() {
        let path = PathBuf::from("approval.pass.ledger");
        for (err, recording, seq) in [
            (
                Error::WitnessNotUpdated {
                    path: path.clone(),
                    seq: 3,
                    detail: "fixture".into(),
                },
                "recorded",
                Some(3),
            ),
            (
                Error::AppendUncertain {
                    path: path.clone(),
                    event: "spend".into(),
                    detail: "fixture".into(),
                },
                "uncertain",
                None,
            ),
        ] {
            let out = error_output("spend", None, &err);
            assert_eq!(out.code, 1);
            assert_eq!(out.json["result"], "error");
            assert_eq!(out.json["error"]["recording"], recording);
            assert_eq!(out.json["error"]["seq"], json!(seq));
            assert_eq!(out.json["error"]["ledger"], json!(path));
        }
    }
}
