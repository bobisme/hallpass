//! The `hallpass` command line.
//!
//! Exit codes: 0 ok or allowed, 2 refused by the pass, 1 any other error.
//! Every command accepts `--format json` and then prints one JSON object on
//! standard output.

mod cli_debit;
mod cli_doctor;
mod cli_evidence;
mod cli_help;
mod cli_repair;

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{FromArgMatches, Parser, Subcommand, ValueEnum, error::ErrorKind};
use hallpass::time::{Duration, OffsetDateTime};
use hallpass::{
    Digest, Error, LoadedPass, NamedTarget, Pass, Problem, Refusal, SpendRequest, StateDir,
    WindowState, span, span_left, span_until, stamp,
};
use serde_json::{Value, json};

/// The environment variable that sets the default output format.
const FORMAT_VAR: &str = "HALLPASS_FORMAT";

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
    /// Output format (flag overrides `HALLPASS_FORMAT`; default is pretty on a terminal, text in a pipe).
    #[arg(long, value_enum, global = true, overrides_with = "format")]
    format: Option<Format>,
    // Listed for help only: `Invocation::read` rewrites `--json` before clap parses.
    #[arg(long, global = true, help = "Same as `--format json`")]
    #[expect(
        dead_code,
        reason = "Invocation::read turns --json into --format=json before clap sees it"
    )]
    json: bool,
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
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Count identical debit units that fit the current budgets.
    #[command(
        override_usage = "hallpass capacity [OPTIONS] <FILE> <COUNTER> [--n N]\n       hallpass capacity [OPTIONS] <FILE> --charge COUNTER=N [--charge COUNTER=N ...]"
    )]
    Capacity {
        #[command(flatten)]
        unit: cli_debit::DebitUnit,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Show who approved, the window, destinations and ceilings.
    Status {
        /// The pass file.
        file: PathBuf,
        #[command(flatten)]
        lock: LockArgs,
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
        #[arg(long, value_name = "SECONDS", default_value_t = 0, value_parser = cli_debit::whole::<u32>)]
        duration: u32,
        #[command(flatten)]
        lock: LockArgs,
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
        /// Maximum milliseconds to wait in total for both writer locks (with --dry-run, for the ledger lock) while another process holds them. Zero tries each lock once; without it, the spend waits as long as it takes.
        #[arg(long, value_name = "MILLISECONDS", value_parser = cli_debit::whole::<u64>)]
        lock_timeout_ms: Option<u64>,
        /// Retain this caller/run reference with the debit.
        #[arg(long, value_name = "TEXT")]
        caller_ref: Option<String>,
        /// Refuse a caller reference already present in the local ledger, or whose absence is inconclusive.
        #[arg(long, requires = "caller_ref")]
        require_new_ref: bool,
        /// Retain the checked literal target, request name and matched destination label (the endpoint evidence that audit-receipts replays).
        #[arg(long, requires = "to")]
        record_target: bool,
        /// Assess what would fit without recording anything or reserving budget.
        #[arg(long)]
        dry_run: bool,
        /// A note recorded with the entry.
        #[arg(long)]
        note: Option<String>,
    },
    /// Diagnose a pass, its ledger and its witness, and name the one next step. Reads only.
    ///
    /// Runs the checks the other commands run and prints a verdict
    /// (healthy, needs action or blocked), exactly one next command with
    /// the real paths, or nothing to do, and other findings. It never
    /// writes or creates anything.
    Doctor {
        /// The pass file.
        file: PathBuf,
        /// Also check that this archive directory holds this revision of the pass.
        #[arg(long, value_name = "DIR")]
        archive: Option<PathBuf>,
        #[command(flatten)]
        lock: LockArgs,
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
        /// Show only the last N entries (after --counter and --since). The whole chain is still verified.
        #[arg(long, value_name = "N", value_parser = cli_debit::whole::<usize>)]
        tail: Option<usize>,
        /// Show only entries with sequence number >= SEQ (before --tail). The whole chain is still verified.
        #[arg(long, value_name = "SEQ", value_parser = cli_debit::whole::<u64>)]
        since: Option<u64>,
        #[command(flatten)]
        lock: LockArgs,
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
        /// Write the bytes to this new file (mode 0600) instead of printing
        /// them. Refuses an existing file or a link.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Find retained debit receipts for one exact caller reference across revisions.
    Receipt {
        /// Pass whose available ledger history to search.
        file: PathBuf,
        /// Exact, case-sensitive opaque reference supplied at debit time.
        #[arg(long, value_name = "TEXT")]
        caller_ref: String,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Replay retained endpoint decisions using their exact archived passes.
    AuditReceipts {
        /// Pass identifying the ledger to verify.
        file: PathBuf,
        /// Private directory populated by archive.
        directory: PathBuf,
        #[command(flatten)]
        signatures: cli_verify::SignatureArgs,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Audit historical charges against archived pass revisions.
    AuditCharges {
        /// Pass identifying the ledger to verify.
        file: PathBuf,
        /// Private directory populated by archive.
        directory: PathBuf,
        #[command(flatten)]
        signatures: cli_verify::SignatureArgs,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Reconcile expected debits from a local JSON manifest.
    Reconcile {
        /// Pass identifying the ledger.
        file: PathBuf,
        /// Versioned JSON manifest.
        manifest: PathBuf,
        #[command(flatten)]
        lock: LockArgs,
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
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Export a checkpoint to retain separately from the ledger.
    Checkpoint {
        /// Pass with an existing ledger to checkpoint.
        file: PathBuf,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Verify a ledger against a retained checkpoint JSON file.
    VerifyCheckpoint {
        /// Ledger file itself (typically FILE.ledger).
        ledger: PathBuf,
        /// Retained JSON from the checkpoint command.
        checkpoint: PathBuf,
        #[command(flatten)]
        lock: LockArgs,
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
        /// When a command proved the witness damaged before the ledger was
        /// lost, carry per counter the higher of the witness's total and the
        /// verified total it noted (without this, such an adoption is
        /// refused).
        #[arg(long)]
        carry_noted_totals: bool,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// Remove a last ledger line that a failed write cut short, when the witness proves it was never counted.
    ///
    /// The removed bytes are kept in a new file beside the ledger
    /// (LEDGER.torn-N). Anything else (a complete last line, damage before
    /// it, a line the witness counted) is refused and nothing is changed.
    Repair {
        /// The pass file.
        file: PathBuf,
        /// Remove the cut-short last line (the only repair there is).
        #[arg(long, required = true)]
        drop_torn_tail: bool,
        /// Show what would be removed, and the token, without changing anything.
        #[arg(long)]
        preview: bool,
        /// The token the preview printed; the repair runs only if nothing changed since.
        #[arg(
            long,
            value_name = "TOKEN",
            conflicts_with = "preview",
            required_unless_present = "preview"
        )]
        token: Option<String>,
        #[command(flatten)]
        lock: LockArgs,
    },
    /// After an adoption that may have lost lines, record which caller references may be in them, so guarded spends resume.
    ///
    /// The reconciliation is written into the ledger. From it on, a spend
    /// with --require-new-ref refuses a listed reference as a duplicate and
    /// checks any other reference against the ledger, until another
    /// adoption may lose lines.
    ReconcileReferences {
        /// The pass file.
        file: PathBuf,
        /// The sequence number of the latest adoption that may have lost lines (`unreconciled_adoption` in `hallpass ledger`).
        #[arg(long, value_name = "SEQ", value_parser = cli_debit::whole::<u64>)]
        adoption: u64,
        /// JSON file with `version` 1, the `pass_id` and the `references`: every caller reference that may be in the lost lines.
        #[arg(long, value_name = "LIST")]
        references: PathBuf,
        /// Why the list is complete (one line; it is recorded in the ledger).
        #[arg(long, value_name = "TEXT")]
        reason: String,
        #[command(flatten)]
        lock: LockArgs,
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
        /// Retain the exact verified pass bytes in this private archive.
        #[arg(long, value_name = "DIR")]
        archive: Option<PathBuf>,
        /// Verify as of this RFC 3339 instant instead of now, such as the time a revision was first used. A key the trusted signers file limits with valid-after or valid-before counts only inside that window.
        #[arg(long, value_name = "TIME")]
        at: Option<String>,
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
    /// Report name-restriction overlaps and wide port grants as advisory findings.
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
        /// Replay the suite against bounded in-memory loosened-rule mutations.
        #[arg(long)]
        strength: bool,
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

// Each flag selects one independent review report.
#[allow(clippy::struct_excessive_bools)]
#[derive(clap::Args)]
struct DiffArgs {
    /// Previously reviewed pass.
    old: PathBuf,
    /// Proposed replacement pass.
    new: PathBuf,
    /// Project balances under both revisions using the live ledger: the one beside NEW, else the one beside OLD.
    #[arg(long)]
    budget_impact: bool,
    /// Sample changed destination decisions at the supplied review instant.
    #[arg(long, requires = "at")]
    examples: bool,
    /// List refused-to-refused changes in --examples where only the refusal code changed.
    #[arg(long, requires = "examples")]
    refusal_changes: bool,
    /// Prove that every proposed endpoint allowance was already in scope.
    #[arg(long, requires = "at")]
    containment: bool,
    /// RFC 3339 instant for --examples or --containment.
    #[arg(long, value_name = "TIMESTAMP")]
    at: Option<String>,
    /// With --budget-impact, maximum milliseconds to wait for the ledger lock while another process holds it. Zero tries once; without it, diff waits as long as it takes.
    #[arg(long, value_name = "MILLISECONDS", requires = "budget_impact", value_parser = cli_debit::whole::<u64>)]
    lock_timeout_ms: Option<u64>,
}

/// `--lock-timeout-ms` for a command that takes the ledger lock.
#[derive(clap::Args)]
struct LockArgs {
    /// Maximum milliseconds to wait in total for the locks this command takes, while another process holds them. Zero tries each lock once; without it, the command waits as long as it takes.
    #[arg(long, value_name = "MILLISECONDS", value_parser = cli_debit::whole::<u64>)]
    lock_timeout_ms: Option<u64>,
}

impl Command {
    const fn name(&self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version => "version",
            Self::Init { .. } => "init",
            Self::Check { .. } => "check",
            Self::Rehearse { .. } => "rehearse",
            Self::Capacity { .. } => "capacity",
            Self::Status { .. } => "status",
            Self::Permits { .. } => "permits",
            Self::Spend { .. } => "spend",
            Self::Doctor { .. } => "doctor",
            Self::Digest { .. } => "digest",
            Self::Ledger { .. } => "ledger",
            Self::Adopt { .. } => "adopt",
            Self::Repair { .. } => "repair",
            Self::ReconcileReferences { .. } => "reconcile-references",
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

    /// The `--lock-timeout-ms` of a command that takes the ledger lock.
    const fn lock_timeout_ms(&self) -> Option<u64> {
        match self {
            Self::Rehearse { lock, .. }
            | Self::Capacity { lock, .. }
            | Self::Status { lock, .. }
            | Self::Doctor { lock, .. }
            | Self::Permits { lock, .. }
            | Self::Ledger { lock, .. }
            | Self::Adopt { lock, .. }
            | Self::Repair { lock, .. }
            | Self::ReconcileReferences { lock, .. }
            | Self::Receipt { lock, .. }
            | Self::AuditReceipts { lock, .. }
            | Self::AuditCharges { lock, .. }
            | Self::Reconcile { lock, .. }
            | Self::CompareBackups { lock, .. }
            | Self::Checkpoint { lock, .. }
            | Self::VerifyCheckpoint { lock, .. } => lock.lock_timeout_ms,
            Self::Spend {
                lock_timeout_ms, ..
            } => *lock_timeout_ms,
            Self::Diff(args) => args.lock_timeout_ms,
            // These never take a ledger or witness lock.
            Self::Help { .. }
            | Self::Version
            | Self::Init { .. }
            | Self::Check { .. }
            | Self::Digest { .. }
            | Self::Archive { .. }
            | Self::Retrieve { .. }
            | Self::VerifyApproval { .. }
            | Self::ConsumerCoverage { .. }
            | Self::Lint { .. }
            | Self::Cases { .. }
            | Self::ApprovalId { .. } => None,
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

/// Set when the test clock variable is present in a build that ignores it.
/// A caller in rehearsal mode reads this in `warnings`, as well as on stderr.
fn ignored_clock_warning() -> Option<String> {
    (!cfg!(any(debug_assertions, feature = "test-clock"))
        && std::env::var_os(TEST_CLOCK_VAR).is_some())
    .then(|| {
        format!(
            "{TEST_CLOCK_VAR} is set but ignored: this build uses the real clock only, so its decisions and debits are live, not rehearsed; use a debug build or one with the test-clock feature to rehearse, or unset it"
        )
    })
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
        // The notice is a warning on every command: see `ignored_clock_warning`.
        return Ok(real);
    }
    let text = value.to_string_lossy();
    let now = OffsetDateTime::parse(&text, &hallpass::time::format_description::well_known::Rfc3339)
        .map_err(|_| {
            Error::Usage(format!(
                "{TEST_CLOCK_VAR} is `{text}`, not an RFC 3339 timestamp; unset it to use the real clock"
            ))
        })?;
    stderr_line(&format!(
        "hallpass: WARNING: test clock in use ({TEST_CLOCK_VAR}={text}); decisions are NOT about the real time"
    ));
    Ok(Clock { now, test: true })
}

fn refusal_json(refusal: &Refusal) -> Value {
    json!({ "code": refusal.code.as_str(), "message": refusal.message })
}

fn problems_json(problems: &[Problem]) -> Value {
    json!(problems)
}

/// Commands that never append to a ledger, so any failure of one left it as
/// it was.
const READ_ONLY_COMMANDS: &[&str] = &[
    "help",
    "version",
    "init",
    "check",
    "rehearse",
    "capacity",
    "permits",
    "digest",
    "doctor",
    "ledger",
    "archive",
    "retrieve",
    "receipt",
    "audit-receipts",
    "audit-charges",
    "reconcile",
    "compare-backups",
    "checkpoint",
    "verify-checkpoint",
    "verify-approval",
    "diff",
    "consumer-coverage",
];

/// What a failed command left in the ledger, as `error.recording`: `recorded`
/// or `uncertain` where the error says so, and `not-recorded` where hallpass
/// knows nothing was appended: a usage error (arguments are checked before any
/// write), a lock timeout, and any error of a command that never appends. It
/// is null for another error of a command that can append, such as an `io`
/// error from `spend`, because the write may or may not have happened.
fn recording(command: &str, error: &Error) -> Option<&'static str> {
    match error {
        Error::WitnessNotUpdated { .. } => Some("recorded"),
        Error::AppendUncertain { .. } => Some("uncertain"),
        Error::LockTimeout { .. }
        | Error::AppendRolledBack { .. }
        | Error::Usage(_)
        | Error::ArchiveCorrupt(_)
        | Error::SharedDirectory { .. }
        | Error::LedgerClockMix { .. } => Some("not-recorded"),
        Error::WitnessUnavailable { detail, .. }
            if !detail.contains("was recorded in the ledger") =>
        {
            Some("not-recorded")
        }
        // `repair` removes only bytes that are not an entry: it never records.
        _ if READ_ONLY_COMMANDS.contains(&command) || command == "repair" => Some("not-recorded"),
        _ => None,
    }
}

fn error_output(command: &str, file: Option<&Path>, error: &Error) -> Output {
    let problems: &[Problem] = match error {
        Error::Invalid { problems, .. } => problems,
        _ => &[],
    };
    // Only the commands that write may advise a recovery that writes.
    let message = if matches!(
        command,
        "spend" | "adopt" | "reconcile-references" | "status"
    ) {
        error.to_string()
    } else {
        error.read_only_message()
    };
    // A message in several lines shows the first after the prefix and the
    // rest indented; each line is made safe on its own, so nothing in a
    // path can add a line.
    let read_only = !matches!(command, "spend" | "adopt" | "status");
    let mut lines = error.message_lines(read_only).into_iter();
    let first = lines.next().unwrap_or_default();
    let mut text = format!("hallpass {command}: error: {}\n", safe_message(&first));
    for line in lines {
        let _ = writeln!(text, "  {}", safe_message(&line));
    }
    for p in problems {
        let _ = writeln!(text, "  - {}", safe_message(&p.to_string()));
    }
    text.push_str(match error {
        Error::WitnessNotUpdated { .. } => {
            "Nothing was permitted. The spend was recorded and counts against the ceiling.\n"
        }
        Error::AppendUncertain { .. } => {
            "Do not proceed or retry automatically. Inspect the ledger.\n"
        }
        // Only commands that decide whether something is permitted say so.
        _ if matches!(
            command,
            "spend" | "permits" | "check" | "rehearse" | "capacity" | "status"
        ) =>
        {
            "Nothing was permitted.\n"
        }
        _ => "",
    });
    Output {
        code: ERROR,
        json: json!({
            "command": command,
            "result": "error",
            "file": file.map(|f| f.display().to_string()),
            "error": {
                "code": error.code(),
                "recording": recording(command, error),
                "seq": match error { Error::WitnessNotUpdated{seq,..}=>Some(seq), _=>None },
                "ledger": match error { Error::WitnessNotUpdated{path,..}|Error::AppendUncertain{path,..}|Error::AppendRolledBack{path,..}=>Some(path), _=>None },
                "message": message,
                "line": match error {
                    Error::LedgerCorrupt { line, .. } => Some(*line),
                    _ => None,
                },
                "last_line": match error {
                    Error::LedgerCorrupt { last, .. } => Some(*last),
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
    // Time left rounds down, so it never promises more than the decision
    // allows; time until opening rounds up, so nobody starts early.
    let up = |d: &Duration| hallpass::whole_seconds_up(*d);
    let (remaining, opens, ended, reason) = match state {
        WindowState::Valid { remaining } => (Some(seconds(remaining)), None, None, None),
        WindowState::NotYetValid { opens_in } => (None, Some(up(opens_in)), None, None),
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
        WindowState::Valid { remaining } => {
            format!("VALID, {} left ({range})", span_left(*remaining))
        }
        WindowState::NotYetValid { opens_in } => {
            format!(
                "NOT YET VALID, opens in {} ({range})",
                span_until(*opens_in)
            )
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

fn check(file: &Path, clock: &Clock) -> Output {
    match hallpass::load(file) {
        Ok(loaded) => {
            let breadth = hallpass::review::breadth(&loaded.pass);
            let required_term = if loaded.pass.required_counters.is_empty() {
                "Required on every debit: none\n".to_owned()
            } else {
                format!(
                    "Required on every debit: {}\n",
                    loaded.pass.required_counters.join(", ")
                )
            };
            let target_term = if loaded.pass.require_target {
                "Every debit requires a checked destination.\n"
            } else {
                ""
            };
            let overlaps = hallpass::review::name_overlap_warnings(&loaded.pass);
            let mut warnings = hallpass::review::breadth_warnings(&breadth);
            warnings.extend(overlaps.iter().map(|w| w.message.clone()));
            warnings.extend(hallpass::review::duplicate_destination_warnings(
                &loaded.pass,
            ));
            let window = hallpass::review::window_warnings(&loaded.pass, Some(clock.now));
            warnings.extend(window.iter().map(|w| w.message.clone()));
            warnings.extend(approval_text_warnings(&loaded.pass));
            warnings.extend(hallpass::shared_directory_warning(file));
            Output {
                code: OK,
                json: json!({
                    "command": "check",
                    "now": stamp(clock.now),
                    "test_clock": clock.test,
                    "window_warnings": window,
                    "result": "ok",
                    "file": file.display().to_string(),
                    "digest": loaded.digest.to_string(),
                    "pass_id": loaded.pass.id,
                    "require_target": loaded.pass.require_target,
                    "required_counters": loaded.pass.required_counters,
                    "problems": [],
                    "breadth": breadth,
                    "warnings": warnings,
                    "name_restriction_overlaps": overlaps,
                }),
                text: format!(
                    "{}: OK, pass {} with {} destination(s) and {} ceiling(s). Declared breadth: IPv4 {}, IPv6 {}. The window is checked by `hallpass status`.\nDigest: {}\n{required_term}{target_term}",
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

/// The advice of [`hallpass::review::approval_identity_warnings`] for the
/// owner and reference of `pass`, each message after its field, as `check`
/// and `lint` give it.
fn approval_text_warnings(pass: &hallpass::Pass) -> Vec<String> {
    hallpass::review::approval_identity_warnings(&pass.approval.owner, &pass.approval.reference)
        .into_iter()
        .map(|p| format!("{} {}", p.field, p.message))
        .collect()
}

/// The lint report. Its first line counts every finding it lists and every
/// warning `emit` prints for it, so a report with only a warning does not
/// read as clean.
fn review_lint(file: &Path, clock: &Clock) -> Output {
    let loaded = match hallpass::load(file) {
        Ok(v) => v,
        Err(e) => return error_output("lint", Some(file), &e),
    };
    let report = hallpass::review::lint(&loaded.pass, clock.now);
    let findings = report.findings;
    let ports = report.port_findings;
    let truncated = report.truncated;
    let stale: Vec<String> = hallpass::review::name_overlap_warnings(&loaded.pass)
        .into_iter()
        .filter(|w| w.code == "overlap-acknowledgement-unmatched")
        .map(|w| w.message)
        .collect();
    let window = hallpass::review::window_warnings(&loaded.pass, Some(clock.now));
    let mut warnings = stale;
    warnings.extend(hallpass::review::duplicate_destination_warnings(
        &loaded.pass,
    ));
    warnings.extend(window.iter().map(|w| w.message.clone()));
    warnings.extend(approval_text_warnings(&loaded.pass));
    let mut text = format!(
        "{} advisory finding(s) and {} warning(s) for {}\n",
        findings.len() + ports.len(),
        warnings.len(),
        loaded.pass.id
    );
    if truncated {
        text.push_str("Additional overlaps omitted after 256 findings.\n");
    }
    for f in &findings {
        let _ = writeln!(
            text,
            "{}: {} overlaps {} in {} on {}-{} / {} (example {}, effective unnamed permission: {}){}{}",
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
                .map_or(String::new(), |r| format!(" ({r})")),
            if f.acknowledged {
                " [acknowledged by the owner in the pass; still applies]"
            } else {
                ""
            }
        );
    }
    for f in &ports {
        let _ = writeln!(text, "{}: {}", f.code, f.message);
    }
    let mut listed = json!(findings);
    if let Some(list) = listed.as_array_mut() {
        list.extend(ports.iter().map(|f| json!(f)));
    }
    Output {
        code: OK,
        json: json!({"command":"lint","result":"ok","file":file.display().to_string(),"digest":loaded.digest.to_string(),"findings":listed,"truncated":truncated,"warnings":warnings,"window_warnings":window}),
        text,
    }
}

/// One summary line, then one line per mutation.
fn strength_text(report: &Value, out: &mut String) {
    let count = |key: &str| report[key].as_u64().unwrap_or(0);
    let _ = writeln!(
        out,
        "{} mutation(s) tested, {} survived, {} skipped.",
        count("mutations_tested"),
        count("mutations_survived"),
        count("mutations_skipped")
    );
    let field = |v: &Value| {
        v.as_str()
            .map_or_else(String::new, |t| safe(t).into_owned())
    };
    for mutation in report["mutations"].as_array().into_iter().flatten() {
        let _ = write!(
            out,
            "  {:<14} {}",
            field(&mutation["status"]),
            field(&mutation["changed_term"])
        );
        if let Some(first) = mutation["first_distinguishing_case"].as_object() {
            let _ = write!(
                out,
                " (case {}: {} -> {})",
                field(&first["id"]),
                field(&first["baseline"]),
                field(&first["mutated"])
            );
        }
        if let Some(reason) = mutation["reason"].as_str() {
            let _ = write!(out, " ({})", safe(reason));
        }
        out.push('\n');
    }
}

fn review_cases(file: &Path, cases_file: &Path, strength: bool) -> Output {
    let loaded = match hallpass::load(file) {
        Ok(v) => v,
        Err(e) => return error_output("test-pass", Some(file), &e),
    };
    let mut file_handle = match hallpass::open_input(cases_file) {
        Ok(v) => v,
        Err(e) => return error_output("test-pass", Some(cases_file), &e),
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
    let reviewed = if strength {
        hallpass::review::cases_with_strength(&loaded.pass, &text)
            .map(|(rows, report)| (rows, Some(report)))
    } else {
        hallpass::review::cases(&loaded.pass, &text).map(|rows| (rows, None))
    };
    let (results, strength_report) = match reviewed {
        Ok(v) => v,
        Err(e) => return error_output("test-pass", Some(cases_file), &Error::Usage(e)),
    };
    let mismatches = results.iter().filter(|v| v["match"] == false).count();
    let mut output = Output {
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
    };
    if let Some(report) = strength_report {
        let status = report["result"].as_str().unwrap_or("error");
        let _ = writeln!(output.text, "Mutation-strength result: {status}.");
        strength_text(&report, &mut output.text);
        if report["truncated"] == true {
            output.text.push_str(
                "Mutation analysis was truncated; it does not establish full suite strength.\n",
            );
        }
        output.code = if status == "complete" { OK } else { REFUSED };
        output.json["result"] = status.into();
        output.json["mutation_strength"] = report;
    }
    output
}

/// The id for an owner and reference, or a usage error when a pass could not
/// hold them: each problem names the option, its pass field and what is
/// wrong, as `check` does, and JSON lists them under `problems`. An id that
/// depends on how the text was typed comes with a warning for each field
/// that makes it so.
fn approval_id(owner: &str, reference: &str) -> Output {
    let flag = |field: &str| {
        let name = field.strip_prefix("approval.").unwrap_or(field);
        format!("--{name} ({field})")
    };
    match hallpass::review::approval_id(owner, reference) {
        Ok(id) => {
            let warnings: Vec<String> =
                hallpass::review::approval_identity_warnings(owner, reference)
                    .into_iter()
                    .map(|p| format!("{} {}", flag(&p.field), p.message))
                    .collect();
            Output {
                code: OK,
                json: json!({"command":"approval-id","result":"ok","id":id,"owner":owner,"reference":reference,"warnings":warnings}),
                text: format!("{id}\n"),
            }
        }
        Err(problems) => {
            let mut message = String::new();
            for p in &problems {
                let _ = write!(message, "{} {}. ", flag(&p.field), p.message);
            }
            message.push_str(
                "A pass with this owner and reference would not load, so no id was printed",
            );
            let mut output = error_output("approval-id", None, &Error::Usage(message));
            output.json["problems"] = problems_json(&problems);
            output
        }
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
        "Pass {} {} ({})\nApproved by: {} (reference: {})\nOperator: {}\nWindow: {}\n",
        pass.id,
        quoted(&pass.name),
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
        let _ = if spent > *total {
            writeln!(
                text,
                "  {name:<16} {total} total, {spent} spent, 0 left: OVER by {} (more is spent than the ceiling allows, for example because the ceiling was lowered after spending; nothing more can be spent)",
                spent - total
            )
        } else {
            writeln!(
                text,
                "  {name:<16} {total} total, {spent} spent, {} left",
                total - spent
            )
        };
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
        let _ = writeln!(
            text,
            "This pass permits NOTHING now: {}.",
            safe_message(&r.message)
        );
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

/// An overlap the owner acknowledged is one line of text, not a warning on
/// every call; `check` and `lint` still show it in full.
fn status_overlaps(
    overlaps: &[hallpass::review::NameOverlapWarning],
    warnings: &mut Vec<String>,
    text: &mut String,
) {
    warnings.extend(
        overlaps
            .iter()
            .filter(|w| !w.acknowledged)
            .map(|w| w.message.clone()),
    );
    let acknowledged = overlaps.iter().filter(|w| w.acknowledged).count();
    if acknowledged > 0 {
        let _ = writeln!(
            text,
            "Note: {acknowledged} name-restriction overlap(s) acknowledged by the owner in the pass; they still apply. `hallpass check` and `hallpass lint` list them."
        );
    }
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
    view.warnings.extend(state_dir.observe_pass_file(&loaded));
    view.warnings.extend(hallpass::future_mtime_warning(file));
    let now = sample();
    view.warnings.extend(view.clock_warning(now));
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
                "overlap_acknowledged": d.overlap_acknowledged,
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
                "over_ceiling": spent > *total,
                "over_by": spent.saturating_sub(*total),
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
    let window_warnings = hallpass::review::window_warnings(pass, Some(now));
    warnings.extend(window_warnings.iter().map(|w| w.message.clone()));
    let overlaps = hallpass::review::name_overlap_warnings(pass);
    let mut text = status_text(file, &loaded, tally, &state, refusal.as_ref());
    status_overlaps(&overlaps, &mut warnings, &mut text);
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
            "window_warnings": window_warnings,
            "name_restriction_overlaps": overlaps,
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
        |r| format!("REFUSED: {asked}: {}\n", sentence(&r.reason.message)),
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
    require_new_ref: bool,
    record_target: bool,
    dry_run: bool,
    note: Option<&'a str>,
}

/// Tell the user, on stderr only (so JSON stdout stays one object), that the
/// command is still waiting for a lock: the writer lock of a spend, adoption
/// or reconciliation, or the ledger lock of a read.
fn announce_lock_wait(wait: &hallpass::LockWait) {
    let path = wait.path.display().to_string();
    let path = safe(&path);
    let who = wait.holder_pid.map_or_else(
        || format!("held by another process; find it with `fuser {path}`"),
        |pid| format!("held by process {pid}"),
    );
    let lock = if wait.shared { "ledger" } else { "writer" };
    let end = wait.give_up_in.map_or_else(
        || "press Ctrl-C to give up, or use --lock-timeout-ms to stop waiting".to_owned(),
        |left| {
            format!(
                "giving up in {} ms (--lock-timeout-ms); press Ctrl-C to stop sooner",
                left.as_millis()
            )
        },
    );
    stderr_line(&format!(
        "hallpass: waiting for the {lock} lock on {path}, {who}. Nothing is recorded yet; {end}."
    ));
}

fn spend(args: &SpendArgs<'_>, clock: &Clock) -> Output {
    let file = &args.unit.file;
    let (expect_digest, targets) = match args.unit.policy_inputs() {
        Ok(inputs) => inputs,
        Err(e) => return error_output("spend", Some(file), &e),
    };
    let mut request = args.unit.policy(expect_digest, &targets);
    request.lock_timeout = args.lock_timeout_ms.map(std::time::Duration::from_millis);
    request.on_lock_wait = Some(announce_lock_wait);
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
        (Some(r), _, _) => format!("REFUSED: {}\n", sentence(&r.message)),
        _ => "REFUSED: no decision.\n".to_owned(),
    };
    let reply = cli_debit::SpendReply {
        result: if outcome.refusal.is_some() {
            "refused"
        } else if args.dry_run {
            "would-allow"
        } else {
            "allowed"
        },
        file,
        digest: outcome.digest,
        pass_id: &outcome.pass_id,
        now: outcome.now,
        test_clock: clock.test,
        charges: vec![cli_debit::ChargeReply::scalar(&outcome, args.dry_run)],
        seq: outcome.seq,
        note: args.note,
        targets: &targets,
        labels: &outcome.labels,
        refused_target: outcome.refused_target,
        receipt: None,
        refusal: outcome.refusal.as_ref(),
        reference_evidence: None,
        warnings: &outcome.warnings,
    };
    Output {
        code: if outcome.refusal.is_some() {
            REFUSED
        } else {
            OK
        },
        json: reply.json(),
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
    request.require_new_ref = args.require_new_ref;
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
            format!("REFUSED: {}\n", sentence(&r.message)),
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
    let json = cli_debit::SpendReply {
        result,
        file,
        digest: outcome.digest,
        pass_id: &outcome.pass_id,
        now: outcome.now,
        test_clock: clock.test,
        charges: outcome.charges.iter().map(Into::into).collect(),
        seq: outcome.seq,
        note: args.note,
        targets,
        labels: &outcome.labels,
        refused_target: outcome.refused_target,
        receipt: outcome.receipt.as_ref(),
        refusal: outcome.refusal.as_ref(),
        reference_evidence: outcome.reference_evidence.as_ref(),
        warnings: &outcome.warnings,
    }
    .json();
    Output { code, json, text }
}

/// A receipt in `spend` and `ledger` text: every value quoted once.
fn debit_receipt_text(receipt: &hallpass::DebitReceipt) -> String {
    let mut parts = Vec::new();
    if let Some(reference) = &receipt.caller_ref {
        parts.push(format!("ref {}", quoted(reference)));
    }
    if !receipt.targets.is_empty() {
        let targets = receipt
            .targets
            .iter()
            .map(|t| {
                let name = t
                    .name
                    .as_deref()
                    .map_or_else(String::new, |n| format!(" name {}", quoted(n)));
                format!("{}{name} label {}", quoted(&t.target), quoted(&t.label))
            })
            .collect::<Vec<_>>()
            .join("; ");
        parts.push(format!("targets {targets}"));
    }
    parts.join(", ")
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

/// What `--tail` and `--since` left of the ledger.
struct Slice {
    tail: Option<usize>,
    since: Option<u64>,
    from: Option<u64>,
    to: Option<u64>,
    of: usize,
}

impl Slice {
    fn json(&self) -> Value {
        json!({"from": self.from, "to": self.to, "of": self.of})
    }

    fn text(&self) -> String {
        let mut by = Vec::new();
        if let Some(since) = self.since {
            by.push(format!("--since {since}"));
        }
        if let Some(tail) = self.tail {
            by.push(format!("--tail {tail}"));
        }
        let which = match (self.from, self.to) {
            (Some(from), Some(to)) => format!("entries {from} to {to}"),
            _ => "no entries".to_owned(),
        };
        format!(
            "Showing {which} of {} in the ledger ({}); totals cover the whole ledger.",
            self.of,
            by.join(", ")
        )
    }
}

/// The ledger events to print, after `--counter`, `--since` and `--tail`.
struct Selected<'a> {
    entries: Vec<&'a hallpass::LedgerEntry>,
    debits: Vec<&'a hallpass::LedgerDebit>,
    adoptions: Vec<&'a hallpass::Adoption>,
    reconciliations: Vec<&'a hallpass::ReferenceReconciliation>,
    slice: Option<Slice>,
}

fn select_rows<'a>(
    view: &'a hallpass::LedgerView,
    counter: Option<&str>,
    tail: Option<usize>,
    since: Option<u64>,
) -> Selected<'a> {
    let wanted = |name: &str| counter.is_none_or(|c| c == name);
    let mut entries: Vec<&hallpass::LedgerEntry> =
        view.entries.iter().filter(|e| wanted(&e.counter)).collect();
    let mut debits: Vec<&hallpass::LedgerDebit> = view
        .debits
        .iter()
        .filter(|e| e.charges.iter().any(|charge| wanted(&charge.counter)))
        .collect();
    let mut adoptions: Vec<&hallpass::Adoption> = view.adoptions.iter().collect();
    let mut reconciliations: Vec<&hallpass::ReferenceReconciliation> =
        view.reconciliations.iter().collect();
    let slice = if tail.is_some() || since.is_some() {
        let mut seqs: Vec<u64> = entries
            .iter()
            .map(|e| e.seq)
            .chain(debits.iter().map(|e| e.seq))
            .chain(adoptions.iter().map(|a| a.seq))
            .chain(reconciliations.iter().map(|r| r.seq))
            .filter(|seq| since.is_none_or(|s| *seq >= s))
            .collect();
        seqs.sort_unstable();
        if let Some(n) = tail {
            seqs.drain(..seqs.len().saturating_sub(n));
        }
        let keep: std::collections::HashSet<u64> = seqs.iter().copied().collect();
        entries.retain(|e| keep.contains(&e.seq));
        debits.retain(|e| keep.contains(&e.seq));
        adoptions.retain(|a| keep.contains(&a.seq));
        reconciliations.retain(|r| keep.contains(&r.seq));
        Some(Slice {
            tail,
            since,
            from: seqs.first().copied(),
            to: seqs.last().copied(),
            of: view.entries.len()
                + view.debits.len()
                + view.adoptions.len()
                + view.reconciliations.len(),
        })
    } else {
        None
    };
    Selected {
        entries,
        debits,
        adoptions,
        reconciliations,
        slice,
    }
}

/// The last `ledger` column. A receipt and a note each carry their own label.
/// The receipt comes first, with every value in it quoted, and the note comes
/// last and runs to the end of the line, so a note cannot pass for a receipt.
fn details_text(note: Option<&str>, receipt: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(receipt) = receipt {
        parts.push(format!("receipt: {receipt}"));
    }
    if let Some(note) = note {
        parts.push(format!("note: {}", safe(note)));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" {}", parts.join("  "))
    }
}

/// How many references of a reconciliation `ledger` text names.
const SHOWN_REFERENCES: usize = 10;

/// A reference reconciliation as one row of `ledger` text: the adoption it
/// reconciles and the number of references, then, as in the details column,
/// the first few references, each quoted, and the reason last, so the
/// reason runs to the end of the line and cannot pass for a reference.
fn reconciliation_row_text(r: &hallpass::ReferenceReconciliation) -> String {
    let mut shown: Vec<String> = r
        .references
        .iter()
        .take(SHOWN_REFERENCES)
        .map(|reference| quoted(reference))
        .collect();
    if r.references.len() > SHOWN_REFERENCES {
        shown.push(format!(
            "and {} more (see --format json)",
            r.references.len() - SHOWN_REFERENCES
        ));
    }
    let listed = if shown.is_empty() {
        String::new()
    } else {
        format!("  references: {}", shown.join(", "))
    };
    format!(
        "  {:>5}  {:<20}  REFERENCES RECONCILED for the adoption at {}: {} reference(s){listed}  reason: {}",
        r.seq,
        stamp(r.time),
        r.adoption,
        r.references.len(),
        safe(&r.reason)
    )
}

/// One line per charge of a debit unit, in the columns of a plain spend; the
/// first line carries the sequence, time, digest and details.
fn debit_rows_text(e: &hallpass::LedgerDebit) -> String {
    let details = details_text(
        e.note.as_deref(),
        e.receipt.as_ref().map(debit_receipt_text).as_deref(),
    );
    // One line per charge, in the same columns as a plain spend; the
    // first line carries the sequence, time, digest and note.
    let mut lines = Vec::new();
    for (i, charge) in e.charges.iter().enumerate() {
        let (seq, time, digest, tail) = if i == 0 {
            (
                e.seq.to_string(),
                stamp(e.time),
                short_digest(&e.digest),
                format!("DEBIT of {} counter(s){details}", e.charges.len()),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };
        lines.push(
            format!(
                "  {seq:>5}  {time:<20}  {:<16} {:>8}  {digest:<19}  {tail}",
                charge.counter, charge.amount
            )
            .trim_end()
            .to_owned(),
        );
    }
    lines.join("\n")
}

fn ledger_text(
    loaded: &LoadedPass,
    view: &hallpass::LedgerView,
    selected: &Selected<'_>,
    totals: &[Total<'_>],
    counter: Option<&str>,
) -> String {
    let (entries, debits, adoptions) = (&selected.entries, &selected.debits, &selected.adoptions);
    let pass = &loaded.pass;
    let mut text = String::new();
    let ledger_shown = safe(&view.path.display().to_string()).into_owned();
    if view.exists {
        let _ = writeln!(text, "Ledger of pass {} ({ledger_shown})", pass.id);
        text.push_str(&rehearsal_text(view));
        if let Some(c) = counter {
            let _ = writeln!(
                text,
                "Only counter {c} (adoptions and reference reconciliations are always shown)."
            );
        }
        if let Some(slice) = &selected.slice {
            let _ = writeln!(text, "{}", slice.text());
        }
        let mut rows: Vec<(u64, String)> = entries
            .iter()
            .map(|e| {
                (
                    e.seq,
                    format!(
                        "  {:>5}  {:<20}  {:<16} {:>8}  {:<19} {}",
                        e.seq,
                        stamp(e.time),
                        e.counter,
                        e.amount,
                        short_digest(&e.digest),
                        details_text(e.note.as_deref(), None)
                    ),
                )
            })
            .collect();
        rows.extend(debits.iter().map(|e| (e.seq, debit_rows_text(e))));
        rows.extend(adoptions.iter().map(|a| {
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
        rows.extend(
            selected
                .reconciliations
                .iter()
                .map(|r| (r.seq, reconciliation_row_text(r))),
        );
        rows.sort_by_key(|(seq, _)| *seq);
        if rows.is_empty() {
            text.push_str("  no entries\n");
        } else {
            let _ = writeln!(
                text,
                "  {:>5}  {:<20}  {:<16} {:>8}  {:<19}  details",
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
            Some(t) if spent > t => writeln!(
                text,
                "  {name:<16} {spent} spent of {t}: OVER by {}",
                spent - t
            ),
            Some(t) => writeln!(text, "  {name:<16} {spent} spent of {t}"),
            None => writeln!(text, "  {name:<16} {spent} spent (no ceiling in this pass)"),
        };
    }
    let _ = writeln!(text, "Ledger: {}", ledger_state_text(view));
    if let Some(seq) = view.unreconciled_adoption {
        let _ = writeln!(
            text,
            "References: the adoption at {seq} may have lost lines and is not reconciled, so guarded spends (--require-new-ref) are refused as reference-inconclusive (see hallpass help reconcile-references)."
        );
    }
    let _ = writeln!(text, "Current pass digest: {}", loaded.digest);
    text
}

/// The line that says a ledger holds test-clock lines, or nothing.
fn rehearsal_text(view: &hallpass::LedgerView) -> String {
    view.test_clock_from.map_or_else(String::new, |seq| {
        format!(
            "REHEARSAL: from entry {seq}, this ledger was recorded under a test clock (HALLPASS_UNSAFE_TEST_CLOCK). Those times are not the real time, and an audit of this ledger is never complete.\n"
        )
    })
}

/// One line on the ledger and its witness, for `status` and `ledger`.
fn ledger_state_text(view: &hallpass::LedgerView) -> String {
    use hallpass::WitnessStatus as W;
    if !view.exists {
        return "none yet (nothing spent)".to_owned();
    }
    let entries = view.tip.as_ref().map_or(0, |tip| tip.seq);
    let witness = match &view.witness {
        W::Matches => "the witness matches",
        W::Extended { .. } => "the witness is behind (see the warning)",
        W::Missing => "NO WITNESS yet (see the warning)",
        W::NotChecked { .. } => "the witness was NOT CHECKED (see the warning)",
        _ => "",
    };
    format!(
        "logical entries after the header: {entries}; chain verified, {witness}{}",
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
                    "time": hallpass::rfc3339(e.time),
                    "counter": e.counter,
                    "n": e.amount,
                    "digest": e.digest.to_string(),
                    "note": e.note,
                    "test_clock": e.test_clock,
                }),
            )
        })
        .chain(debits.iter().map(|e| {
            (
                e.seq,
                json!({
                    "seq": e.seq,
                    "time": hallpass::rfc3339(e.time),
                    "event": "debit",
                    "version": 1,
                    "charges": e.charges,
                    "digest": e.digest.to_string(),
                    "note": e.note,
                    "receipt": e.receipt,
                    "test_clock": e.test_clock,
                }),
            )
        }))
        .collect();
    events.sort_by_key(|(seq, _)| *seq);

    events.into_iter().map(|(_, entry)| entry).collect()
}

fn ledger(file: &Path, counter: Option<&str>, tail: Option<usize>, since: Option<u64>) -> Output {
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
    let selected = select_rows(&view, counter, tail, since);
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

    let text = ledger_text(&loaded, &view, &selected, &totals, counter);

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
            "shown": selected.slice.as_ref().map(Slice::json),
            "verified": true,
            "witness": view.witness.as_str(),
            "moved_from": view.moved_from,
            "entries": spend_events_json(&selected.entries, &selected.debits),
            "adoptions": selected.adoptions.iter().map(|a| json!({
                "seq": a.seq,
                "time": hallpass::rfc3339(a.time),
                "reason": a.reason,
                "digest": a.digest.to_string(),
                "carried": a.carried,
                "previous": a.previous.as_ref().map(witnessed_json),
                "may_have_lost_references": a.makes_references_inconclusive(),
                "test_clock": a.test_clock,
            })).collect::<Vec<_>>(),
            "reference_reconciliations": selected.reconciliations.iter().map(|r| json!({
                "seq": r.seq,
                "time": hallpass::rfc3339(r.time),
                "adoption": r.adoption,
                "reason": r.reason,
                "digest": r.digest.to_string(),
                "references": r.references,
                "test_clock": r.test_clock,
            })).collect::<Vec<_>>(),
            "unreconciled_adoption": view.unreconciled_adoption,
            "test_clock_from": view.test_clock_from,
            "totals": totals.iter().map(|(name, spent, total)| json!({
                "name": name,
                "spent": spent,
                "total": total,
                "remaining": total.map(|t| t.saturating_sub(*spent)),
                "over_ceiling": total.is_some_and(|t| *spent > t),
                "over_by": total.map(|t| spent.saturating_sub(t)),
            })).collect::<Vec<_>>(),
            "warnings": view.warnings,
        }),
        text,
    }
}

fn preview_adopt(file: &Path, carry_noted: bool) -> Output {
    match hallpass::preview_adopt_with(file, &StateDir::from_env(), carry_noted) {
        Ok(p) => Output {
            code: 0,
            text: format!(
                "ADOPTION PREVIEW: {} for {} at sequence {}. Present: {}. Carry: {}{}. Projected: {}. Token: {}\n",
                p.case.as_str(),
                p.pass_id,
                p.seq,
                hallpass::totals_text(&p.present),
                hallpass::totals_text(&p.carried),
                if p.from_note.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (the higher of the witness's and the noted verified totals; from the note: {})",
                        hallpass::totals_text(&p.from_note)
                    )
                },
                hallpass::totals_text(&p.totals),
                p.token
            ),
            json: json!({"command":"adopt", "result":"preview", "case":p.case.as_str(), "pass_id":p.pass_id, "seq":p.seq, "present":p.present, "carried":p.carried, "totals":p.totals, "from_note":p.from_note, "previous":p.previous.as_ref().map(witnessed_json), "token":p.token, "warnings": inconclusive_references(p.makes_references_inconclusive(), "after this adoption,").into_iter().chain(carried_from_witness(&p)).chain(hallpass::shared_directory_warning(file)).collect::<Vec<_>>()}),
        },
        Err(e) => error_output("adopt", Some(file), &e),
    }
}

/// The warning for an adoption that carries totals the ledger cannot
/// confirm: they come from the witness alone.
fn carried_from_witness(p: &hallpass::AdoptPreview) -> Option<String> {
    let why = match p.case {
        hallpass::AdoptCase::LedgerMissing => "the ledger is missing",
        hallpass::AdoptCase::LedgerChanged => {
            "the ledger does not hold the line the witness recorded"
        }
        _ => return None,
    };
    let behind = p.last_seen_unchecked.as_ref().map(|(at, why)| format!(
        " The witness last saw the ledger at {}, and a file is there that hallpass could not check ({why}): the witness may be behind that ledger, so the count there may be higher. Check that file, and put it back if it is the ledger, before you adopt.",
        at.display()
    ));
    if p.carried.is_empty() {
        return behind.map(|b| b.trim_start().to_owned());
    }
    let source = if p.from_note.is_empty() {
        "come from the witness alone".to_owned()
    } else {
        format!(
            "are, per counter, the higher of the witness's total and the verified total noted when the witness was found damaged (from the note: {})",
            hallpass::totals_text(&p.from_note)
        )
    };
    Some(format!(
        "the carried totals ({}) {source}: {why}, so hallpass cannot check them. Compare them with your run records before you adopt. If the ledger hallpass last wrote can be found, put it back instead.{}",
        hallpass::totals_text(&p.carried),
        behind.unwrap_or_default()
    ))
}

/// Where carried totals came from, for the adoption lines.
fn carried_source(from_note: &std::collections::BTreeMap<String, u64>) -> String {
    if from_note.is_empty() {
        "Carried from the witness".to_owned()
    } else {
        format!(
            "Carried, per counter, the higher of the witness's total and the verified total noted when the witness was found damaged (from the note: {})",
            hallpass::totals_text(from_note)
        )
    }
}

/// The warning for an adoption after which guarded spends cannot show that
/// a reference is new (see `reference-inconclusive`), or none.
fn inconclusive_references(applies: bool, when: &str) -> Vec<String> {
    applies
        .then(|| format!(
            "{when} guarded spends (--require-new-ref) on this ledger cannot show that a caller reference is new: the adopted ledger may lack lines hallpass had recorded, so they are refused as reference-inconclusive until the references that may be in the lost lines are reconciled: list them from your run records and record them with `hallpass reconcile-references` (see hallpass help reconcile-references). Check each reference against your run record."
        ))
        .into_iter()
        .collect()
}

fn adopt(
    file: &Path,
    reason: &str,
    token: Option<&str>,
    carry_noted: bool,
    clock: &Clock,
) -> Output {
    let state = StateDir::from_env();
    let outcome =
        match hallpass::adopt_guarded_with(file, reason, clock.now, &state, token, carry_noted) {
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
        "ADOPTED: {} for pass {} ({what}). Recorded as ledger entry {} with the reason {}. {}: {}. Spent now: {}.\n",
        safe(&outcome.ledger.display().to_string()),
        outcome.pass_id,
        a.seq,
        quoted(&a.reason),
        carried_source(&outcome.from_note),
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
            "from_note": outcome.from_note,
            "previous": a.previous.as_ref().map(witnessed_json),
            "totals": outcome.totals,
            "warnings": inconclusive_references(a.makes_references_inconclusive(), "from this adoption on,").into_iter().chain(hallpass::shared_directory_warning(file)).collect::<Vec<_>>(),
        }),
        text,
    }
}

fn reconcile_references(
    file: &Path,
    adoption: u64,
    list: &Path,
    reason: &str,
    clock: &Clock,
) -> Output {
    let state = StateDir::from_env();
    let outcome = match hallpass::load(file)
        .and_then(|loaded| hallpass::read_reference_list(list, &loaded.pass.id))
        .and_then(|references| {
            hallpass::reconcile_references(file, adoption, &references, reason, clock.now, &state)
        }) {
        Ok(o) => o,
        Err(e) => return error_output("reconcile-references", Some(file), &e),
    };
    let r = &outcome.reconciliation;
    let text = format!(
        "RECONCILED: {} caller reference(s) for the adoption at sequence {} of pass {}, recorded in {} as entry {} with the reason {}. From here on a guarded spend (--require-new-ref) refuses a listed reference as duplicate-reference, and the adoption at sequence {} no longer makes other references inconclusive.\n",
        r.references.len(),
        r.adoption,
        outcome.pass_id,
        safe(&outcome.ledger.display().to_string()),
        r.seq,
        quoted(&r.reason),
        r.adoption,
    );
    Output {
        code: OK,
        json: json!({
            "command": "reconcile-references",
            "result": "ok",
            "file": file.display().to_string(),
            "ledger": outcome.ledger.display().to_string(),
            "pass_id": outcome.pass_id,
            "digest": r.digest.to_string(),
            "now": stamp(clock.now),
            "test_clock": clock.test,
            "seq": r.seq,
            "adoption": r.adoption,
            "reason": r.reason,
            "references": r.references,
            "warnings": outcome.warnings,
        }),
        text,
    }
}

/// Operator-supplied text, escaped for a terminal.
fn safe(text: &str) -> std::borrow::Cow<'_, str> {
    hallpass::display_safe(text)
}

/// Caller- or pass-supplied text as one quoted value in text output, escaped
/// once (`\"`, `\\` and `\u{...}`), so it cannot end its quotes early and
/// read as more fields.
fn quoted(text: &str) -> String {
    hallpass::display_quoted(text)
}

/// An error message made safe for a terminal, with its backslashes left as
/// written. The messages already carry their own escapes (`\"`, `\\`, and
/// `\u{...}` from `escape_default`), so escaping each backslash again would
/// show every one doubled. Every other unsafe character is still escaped.
/// A refusal message as one sentence: it gets a full stop unless it already
/// ends with one, so the text never shows a doubled stop.
fn sentence(message: &str) -> String {
    let shown = safe_message(message);
    if shown.ends_with('.') {
        shown
    } else {
        format!("{shown}.")
    }
}

fn safe_message(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == '\\' {
                c.to_string()
            } else {
                safe(&c.to_string()).into_owned()
            }
        })
        .collect()
}

/// `archive` stores bytes only. It never writes a signature record, so it
/// cannot upgrade a digest's provenance, and a record already there stays.
fn archive(file: &Path, directory: &Path) -> Output {
    let archived = hallpass::archive_pass(file, directory).and_then(|digest| {
        hallpass::archive_provenance(directory, digest).map(|provenance| (digest, provenance))
    });
    match archived {
        Ok((digest, provenance)) => {
            let how = provenance.approval().map_or_else(
                || " without a signature record (verify-approval --archive records one)".to_owned(),
                |approval| {
                    format!(
                        "; its signature record for principal {} is kept",
                        quoted(&approval.principal)
                    )
                },
            );
            Output {
                code: 0,
                text: format!("Archived: {digest}{how}\n"),
                json: json!({"command": "archive", "result": "ok", "digest": digest.to_string(), "provenance": provenance.as_str(), "approval": provenance.approval()}),
            }
        }
        Err(e) => error_output("archive", Some(file), &e),
    }
}

fn retrieve(directory: &Path, digest: &str, output: Option<&Path>) -> Output {
    let result = digest
        .parse::<hallpass::Digest>()
        .map_err(Error::Usage)
        .and_then(|digest| hallpass::retrieve_pass(directory, digest));
    match result {
        Ok(bytes) => {
            if let Some(path) = output {
                if let Err(e) = hallpass::write_new_private(path, &bytes) {
                    return error_output("retrieve", Some(path), &e);
                }
                return Output {
                    code: 0,
                    json: json!({"command": "retrieve", "result": "ok", "digest": digest, "output": path.display().to_string(), "mode": "0600", "length": bytes.len()}),
                    text: format!(
                        "Retrieved {digest} to {} (mode 0600, {} bytes)\n",
                        safe(&path.display().to_string()),
                        bytes.len()
                    ),
                };
            }
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
        .and_then(|loaded| hallpass::export_checkpoint_observed(&loaded, &StateDir::from_env()));
    match result {
        Ok(hallpass::CheckpointExport::Exported(checkpoint, relation)) => {
            let value = json!({"version": checkpoint.version, "pass_id": checkpoint.pass_id, "seq": checkpoint.seq, "hash": checkpoint.hash});
            let (corroboration, warning) = match relation {
                hallpass::WitnessRelation::Matches => (
                    json!({"relation": "matches", "witnessed_seq": checkpoint.seq, "exported_seq": checkpoint.seq}),
                    None,
                ),
                hallpass::WitnessRelation::Lags {
                    witnessed,
                    exported,
                } => (
                    json!({"relation": "lags", "witnessed_seq": witnessed, "exported_seq": exported}),
                    Some(format!(
                        "The witness corroborates only through sequence {witnessed}; the exported checkpoint is at sequence {exported}."
                    )),
                ),
                hallpass::WitnessRelation::Absent => (
                    json!({"relation": "absent", "witnessed_seq": null, "exported_seq": checkpoint.seq}),
                    Some("There is no local witness corroboration.".to_owned()),
                ),
            };
            Output {
                code: 0,
                text: format!("{value}\n"),
                json: json!({"command": "checkpoint", "result": "ok", "checkpoint": value, "local_corroboration": relation != hallpass::WitnessRelation::Absent, "witness": corroboration, "warnings": warning.into_iter().collect::<Vec<_>>()}),
            }
        }
        // Nothing is recorded, so there is no line to commit to. Exit 2 and an
        // empty stdout keep a redirected checkpoint file from looking valid.
        Ok(hallpass::CheckpointExport::Empty) => Output {
            code: REFUSED,
            text: String::new(),
            json: json!({"command": "checkpoint", "result": "empty", "checkpoint": null, "local_corroboration": false, "witness": {"relation": "absent", "witnessed_seq": null, "exported_seq": null}, "warnings": ["Nothing has been recorded yet: no ledger exists, so there is no checkpoint to export."]}),
        },
        Err(e) => error_output("checkpoint", Some(file), &e),
    }
}

fn verify_checkpoint(ledger: &Path, checkpoint: &Path) -> Output {
    let result = (|| {
        let file = hallpass::open_input(checkpoint)?;
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
                _ => ("mismatch", 0, 2),
            };
            let relation = status.relation();
            let detail = if relation == name {
                String::new()
            } else {
                format!(", relation {relation}")
            };
            Output {
                code,
                text: format!(
                    "Checkpoint verification: {name}{detail} ({added} later entries). Trust input: supplied checkpoint.\n"
                ),
                json: json!({"command": "verify-checkpoint", "result": name, "relation": relation, "added": added, "trust_input": "supplied-checkpoint"}),
            }
        }
        Err(e) => error_output("verify-checkpoint", Some(ledger), &e),
    }
}

/// The commands that read the clock, and so honour the test clock. The
/// "Test clock" section of `docs/spec.md` lists the same names, which
/// `tests/doc_lists.rs` checks: keep each name on a line of its own.
const CLOCK_COMMANDS: &[&str] = &[
    "status",
    "doctor",
    "check",
    "permits",
    "spend",
    "capacity",
    "adopt",
    "reconcile-references",
    "lint",
];

fn command_clock(command: &Command) -> Result<Clock, Error> {
    if CLOCK_COMMANDS.contains(&command.name()) {
        clock()
    } else {
        Ok(Clock {
            now: OffsetDateTime::now_utc(),
            test: false,
        })
    }
}

/// Run the command. A command that takes the ledger lock waits for it as long
/// as its `--lock-timeout-ms` allows, and says on stderr when it has waited a
/// while.
fn run(cli: &Cli, format: Format) -> Output {
    let limit = cli
        .command
        .lock_timeout_ms()
        .map(std::time::Duration::from_millis);
    hallpass::with_lock_wait(limit, Some(announce_lock_wait), || dispatch(cli, format))
}

#[allow(clippy::too_many_lines)] // One exhaustive dispatch keeps the command mapping reviewable.
fn dispatch(cli: &Cli, format: Format) -> Output {
    let name = cli.command.name();
    let clock = match command_clock(&cli.command) {
        Ok(clock) => clock,
        Err(e) => return error_output(name, None, &e),
    };
    // Under the test clock, every ledger line the command writes is marked.
    let run = || match &cli.command {
        Command::Help { topic } => cli_help::help(topic.as_deref(), format),
        Command::Version => cli_help::version(),
        Command::Init { file } => init(file),
        Command::Check { file } => check(file, &clock),
        Command::Rehearse { file, scenario, .. } => rehearse(file, scenario),
        Command::Capacity { unit, .. } => cli_debit::run_capacity(unit, &clock),
        Command::Status { file, .. } => status(file, &clock),
        Command::Permits {
            file,
            to,
            name,
            duration,
            digest,
            ..
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
            require_new_ref,
            record_target,
            dry_run,
            note,
        } => spend(
            &SpendArgs {
                unit,
                lock_timeout_ms: *lock_timeout_ms,
                caller_ref: caller_ref.as_deref(),
                require_new_ref: *require_new_ref,
                record_target: *record_target,
                dry_run: *dry_run,
                note: note.as_deref(),
            },
            &clock,
        ),
        Command::Doctor { file, archive, .. } => {
            cli_doctor::doctor(file, archive.as_deref(), &clock)
        }
        Command::Digest { file } => digest(file),
        Command::Ledger {
            file,
            counter,
            tail,
            since,
            ..
        } => ledger(file, counter.as_deref(), *tail, *since),
        Command::Archive { file, directory } => archive(file, directory),
        Command::Retrieve {
            directory,
            digest,
            output,
        } => retrieve(directory, digest, output.as_deref()),
        Command::Receipt {
            file, caller_ref, ..
        } => cli_evidence::receipt(file, caller_ref),
        Command::AuditReceipts {
            file,
            directory,
            signatures,
            ..
        } => cli_evidence::audit(file, directory, signatures),
        Command::AuditCharges {
            file,
            directory,
            signatures,
            ..
        } => cli_evidence::audit_charges(file, directory, signatures),
        Command::Reconcile { file, manifest, .. } => cli_evidence::reconcile(file, manifest),
        Command::CompareBackups {
            file,
            candidates,
            ancestry,
            ..
        } => cli_evidence::backups(file, candidates, *ancestry),
        Command::Checkpoint { file, .. } => checkpoint(file),
        Command::VerifyCheckpoint {
            ledger, checkpoint, ..
        } => verify_checkpoint(ledger, checkpoint),
        Command::Adopt {
            file,
            reason,
            preview,
            token,
            carry_noted_totals,
            ..
        } => {
            if *preview {
                preview_adopt(file, *carry_noted_totals)
            } else {
                adopt(
                    file,
                    reason.as_deref().unwrap_or_default(),
                    token.as_deref(),
                    *carry_noted_totals,
                    &clock,
                )
            }
        }
        Command::Repair {
            file,
            preview,
            token,
            ..
        } => cli_repair::repair(file, *preview, token.as_deref()),
        Command::ReconcileReferences {
            file,
            adoption,
            references,
            reason,
            ..
        } => reconcile_references(file, *adoption, references, reason, &clock),
        Command::VerifyApproval {
            file,
            signature,
            allowed_signers,
            principal,
            archive,
            at,
        } => cli_verify::verify_approval(
            file,
            signature,
            allowed_signers,
            principal,
            archive.as_deref(),
            at.as_deref(),
        ),
        Command::Diff(args) => cli_diff::review_diff(args),
        Command::ConsumerCoverage { file, can } => consumer_coverage(file, can),
        Command::Lint { file } => review_lint(file, &clock),
        Command::Cases {
            file,
            cases,
            strength,
        } => review_cases(file, cases, *strength),
        Command::ApprovalId { owner, reference } => approval_id(owner, reference),
    };
    if clock.test {
        hallpass::with_test_clock(run)
    } else {
        run()
    }
}

/// Help, version and usage errors can exit clap before it returns parsed
/// options. Remember the requested output and the top-level command for those
/// paths. Leave argument order, non-UTF-8 paths and everything after -- intact.
struct Invocation {
    args: Vec<OsString>,
    json: bool,
    topic: Option<OsString>,
    /// A `HALLPASS_FORMAT` value that is not a format.
    env_error: Option<String>,
    /// Set when the ignored `FORMAT` variable is present.
    env_warning: Vec<String>,
    /// `--json` together with `--format` set to something else.
    flag_conflict: Option<String>,
}

impl Invocation {
    fn read() -> Self {
        let mut args: Vec<_> = std::env::args_os().collect();
        let mut requested_format = None;
        let mut expects_format = false;
        let mut topic = None;
        let mut looking_for_command = true;
        let mut json_flag = false;
        let mut json_count = 0;
        let mut format_count = 0;
        let mut other_format: Option<String> = None;
        for arg in args.iter_mut().skip(1).take_while(|arg| *arg != "--") {
            if arg == "--format" || arg.to_str().is_some_and(|s| s.starts_with("--format=")) {
                format_count += 1;
            }
            if arg == "--json" {
                json_count += 1;
                json_flag = true;
                *arg = "--format=json".into();
            } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--format=")) {
                if value != "json" {
                    other_format.get_or_insert_with(|| format!("--format={value}"));
                }
            } else if expects_format && arg != "json" {
                other_format.get_or_insert_with(|| format!("--format {}", arg.to_string_lossy()));
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
        let mut env_error = None;
        let mut env_warning = Vec::new();
        if requested_format.is_none()
            && let Some(value) = std::env::var_os(FORMAT_VAR)
        {
            match value
                .to_str()
                .filter(|v| Format::from_str(v, false).is_ok())
            {
                Some(valid) => {
                    args.insert(1, format!("--format={valid}").into());
                    requested_format = Some(value);
                }
                None => {
                    env_error = Some(format!(
                        "{FORMAT_VAR}: invalid value `{}`; use text, pretty or json",
                        safe_message(&value.to_string_lossy())
                    ));
                }
            }
        }
        if std::env::var_os("FORMAT").is_some() && std::env::var_os(FORMAT_VAR).is_none() {
            env_warning.push(format!(
                "the FORMAT environment variable is ignored; set {FORMAT_VAR} to choose the output format"
            ));
        }
        env_warning.extend(ignored_clock_warning());
        let flag_conflict = if json_count > 1 {
            Some("`--json` is given more than once; give it once".to_string())
        } else if format_count > 1 {
            Some(
                "`--format` is given more than once; give one format, for example `--format json`"
                    .to_string(),
            )
        } else {
            other_format.filter(|_| json_flag).map(|format| {
                format!(
                    "`{format}` conflicts with `--json`, which means `--format json`; use one of them"
                )
            })
        };
        let json = json_flag || requested_format.as_deref() == Some(OsStr::new("json"));
        Self {
            args,
            json,
            topic,
            env_error,
            env_warning,
            flag_conflict,
        }
    }
}

fn emit(mut output: Output, format: Format) -> ExitCode {
    if output.json.get("warnings").is_none() {
        output.json["warnings"] = json!([]);
    }
    let mut stdout_text = String::new();
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
            stdout_text = format!("{}\n", output.json);
        }
        Format::Text | Format::Pretty => {
            for w in output.json["warnings"].as_array().into_iter().flatten() {
                let w = safe_message(w.as_str().unwrap_or_default());
                // An evidence report already prints its warnings in its own text.
                if output
                    .text
                    .lines()
                    .any(|l| l.strip_prefix("Warning: ") == Some(w.as_str()))
                {
                    continue;
                }
                stderr_line(&format!("hallpass: warning: {w}"));
            }
            if output.code == ERROR {
                stderr_text(&output.text);
            } else {
                stdout_text = std::mem::take(&mut output.text);
            }
        }
    }
    if let Err(error) = write_stdout(&stdout_text) {
        return unwritten_reply(&output, &error);
    }
    ExitCode::from(output.code)
}

fn stderr_text(text: &str) {
    use std::io::Write as _;
    // There is nowhere left to report a failure to write the error stream.
    let _ = std::io::stderr().write_all(text.as_bytes());
}

fn stderr_line(line: &str) {
    stderr_text(&format!("{line}\n"));
}

fn write_stdout(text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}

/// What a command that finished leaves behind that the caller must know of,
/// phrased for "... IS recorded". `None` when the reply held nothing durable.
fn durable_effect(json: &Value) -> Option<String> {
    let seq = json["seq"].as_u64();
    let reference = json["receipt"]["caller_ref"]
        .as_str()
        .map(|r| format!(" (caller reference {})", hallpass::display_quoted(r)));
    let command = json["command"].as_str()?;
    if json["result"] == "error" {
        let seq = json["error"]["seq"].as_u64();
        return match json["error"]["recording"].as_str()? {
            "recorded" => Some(format!(
                "the {command} IS recorded{}",
                seq.map_or_else(String::new, |n| format!(" as ledger entry {n}"))
            )),
            "uncertain" => Some(format!("the {command} MAY be recorded; inspect the ledger")),
            _ => None,
        };
    }
    let entry = |what: &str| {
        Some(format!(
            "the {what} IS recorded{}{}",
            seq.map_or_else(String::new, |n| format!(" as ledger entry {n}")),
            reference.clone().unwrap_or_default()
        ))
    };
    match (command, json["result"].as_str()?) {
        ("spend", "allowed") => entry("debit"),
        ("adopt", "ok") => entry("adoption"),
        ("reconcile-references", "ok") => entry("reference reconciliation"),
        ("repair", "repaired") => Some("the repair IS done".to_string()),
        ("archive", "ok") => Some("the pass IS archived".to_string()),
        ("verify-approval", "verified") if !json["archive"].is_null() => {
            Some("the signature record IS archived".to_string())
        }
        ("retrieve", "ok") if json.get("output").is_some() => {
            Some("the output file IS written".to_string())
        }
        ("init", "ok") => Some("the pass file IS created".to_string()),
        _ => None,
    }
}

/// The reply could not be written to standard output. Nothing is lost for a
/// command that only reads: a closed pipe is quiet, and any other failure is
/// said on standard error. After a command recorded something, standard error
/// says what is recorded and the status is 1, so a caller reconciles instead
/// of reading the empty reply as "nothing happened". A reply that said an
/// error (1) or a refusal (2) keeps that status; a success becomes 1.
fn unwritten_reply(output: &Output, error: &std::io::Error) -> ExitCode {
    let effect = durable_effect(&output.json);
    let broken_pipe = error.kind() == std::io::ErrorKind::BrokenPipe;
    if let Some(effect) = &effect {
        stderr_line(&format!(
            "hallpass {}: error: the reply could not be written ({error}); {effect}: reconcile before retrying.",
            output.json["command"].as_str().unwrap_or("hallpass")
        ));
        return ExitCode::from(ERROR);
    }
    if broken_pipe {
        return ExitCode::from(output.code);
    }
    stderr_line(&format!(
        "hallpass {}: error: the reply could not be written ({error}); nothing was recorded.",
        output.json["command"].as_str().unwrap_or("hallpass")
    ));
    ExitCode::from(if output.code == OK {
        ERROR
    } else {
        output.code
    })
}

/// Only a command name from clap's definition is passed here.
fn help_advice(topic: Option<&str>) -> Value {
    let mut argv = vec!["hallpass", "help"];
    argv.extend(topic);
    argv.extend(["--format", "json"]);
    json!({"level":"info","type":"command-help","message":format!("Run {} for usage and examples.", argv.join(" ")), "argv":argv})
}

/// A usage error that happened before any command ran. `command` is null when
/// the subcommand was not recognized.
fn parse_error(command: Option<&str>, message: &str) -> Output {
    let mut output = error_output(
        command.unwrap_or("hallpass"),
        None,
        &Error::Usage(message.to_string()),
    );
    output.json["command"] = command.map_or(Value::Null, Value::from);
    output.json["error"]["recording"] = json!("not-recorded");
    output
}

fn add_warning(output: &mut Output, warning: &str) {
    if output.json.get("warnings").is_none() {
        output.json["warnings"] = json!([]);
    }
    if let Some(list) = output.json["warnings"].as_array_mut() {
        list.push(json!(warning));
    }
}

fn main() -> ExitCode {
    let input = Invocation::read();
    let mut definition = cli_help::definition();
    let topic = input
        .topic
        .as_deref()
        .and_then(OsStr::to_str)
        .and_then(|s| definition.find_subcommand(s))
        .map(|c| c.get_name().to_string());
    if let Some(message) = &input.flag_conflict {
        return emit(parse_error(topic.as_deref(), message), Format::Json);
    }
    if let Some(message) = &input.env_error {
        let mut output = parse_error(topic.as_deref(), message);
        output.text = format!("hallpass: error: {message}\n");
        return emit(output, Format::Text);
    }
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
            let mut output = run(&cli, format);
            for warning in &input.env_warning {
                add_warning(&mut output, warning);
            }
            if let Some(warning) = StateDir::ignored_env_warning() {
                add_warning(&mut output, &warning);
            }
            emit(output, format)
        }
        Err(e) if e.kind() == ErrorKind::ValueValidation => {
            // A bad value is a usage error like any other: the usual error
            // format, without clap's own prefix and trailing hint.
            let rendered = e.render().to_string();
            let first = rendered.lines().next().unwrap_or_default();
            let message = first.strip_prefix("error: ").unwrap_or(first);
            let mut out = parse_error(topic.as_deref(), message);
            for warning in &input.env_warning {
                add_warning(&mut out, warning);
            }
            emit(
                out,
                if input.json {
                    Format::Json
                } else {
                    Format::Text
                },
            )
        }
        Err(e) => {
            if input.json {
                let out = match e.kind() {
                    ErrorKind::DisplayHelp => {
                        cli_help::help(input.topic.as_deref().and_then(OsStr::to_str), Format::Json)
                    }
                    ErrorKind::DisplayVersion => cli_help::version(),
                    _ => {
                        let mut out =
                            parse_error(topic.as_deref(), e.render().to_string().trim_end());
                        for warning in &input.env_warning {
                            add_warning(&mut out, warning);
                        }
                        out
                    }
                };
                emit(out, Format::Json)
            } else {
                for warning in &input.env_warning {
                    stderr_line(&format!("hallpass: warning: {}", safe_message(warning)));
                }
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
