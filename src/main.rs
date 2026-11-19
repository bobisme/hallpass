//! The `hallpass` command line.
//!
//! Exit codes: 0 ok or allowed, 2 refused by the pass, 1 any other error.
//! Every command accepts `--format json` and then prints one JSON object on
//! standard output.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use hallpass::time::{Duration, OffsetDateTime};
use hallpass::{
    Decision, Digest, Error, LoadedPass, Pass, Problem, Refusal, SpendRequest, StateDir, Target,
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
    about = "Read a pass (the written permission slip for an authorized test), decide what it permits now, and count what has been spent",
    after_help = "Exit codes: 0 ok or allowed, 2 refused by the pass, 1 any other error.\nhallpass is advisory: it answers tools that ask; it cannot stop a tool that does not."
)]
struct Cli {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text, global = true)]
    format: Format,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
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
    /// Show who approved, the window, destinations and ceilings.
    Status {
        /// The pass file.
        file: PathBuf,
    },
    /// Say whether a destination is permitted right now.
    Permits {
        /// The pass file.
        file: PathBuf,
        /// `ADDRESS:PORT/PROTOCOL`, for example `192.0.2.10:5060/udp` or `[2001:db8::1]:443/tcp`.
        #[arg(long, value_name = "ADDR:PORT/PROTO")]
        to: String,
        /// Refuse unless the window stays open this many seconds more.
        #[arg(long, value_name = "SECONDS", default_value_t = 0)]
        duration: u32,
    },
    /// Record a spend against a ceiling, atomically, or refuse and record nothing.
    Spend {
        /// The pass file.
        file: PathBuf,
        /// The counter name, one of the pass's ceilings.
        counter: String,
        /// The amount to spend.
        #[arg(long = "n", value_name = "N", default_value_t = 1)]
        amount: u64,
        /// A note recorded with the entry.
        #[arg(long)]
        note: Option<String>,
        /// Refuse unless the pass still has this digest (from `hallpass digest`).
        #[arg(long, value_name = "DIGEST")]
        digest: Option<String>,
        /// Refuse unless the window stays open this many seconds more.
        #[arg(long, value_name = "SECONDS", default_value_t = 0)]
        duration: u32,
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
    /// Accept a ledger that was lost, changed outside hallpass, or has no witness, and record why.
    ///
    /// The adoption is written into the ledger. A lost or rewound ledger
    /// keeps the count its witness recorded: adoption never lowers a count.
    Adopt {
        /// The pass file.
        file: PathBuf,
        /// Why (one line; it is recorded in the ledger).
        #[arg(long, value_name = "TEXT")]
        reason: String,
    },
}

impl Command {
    const fn name(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Check { .. } => "check",
            Self::Status { .. } => "status",
            Self::Permits { .. } => "permits",
            Self::Spend { .. } => "spend",
            Self::Digest { .. } => "digest",
            Self::Ledger { .. } => "ledger",
            Self::Adopt { .. } => "adopt",
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
        _ => "Nothing was permitted and nothing was recorded.\n",
    });
    Output {
        code: ERROR,
        json: json!({
            "command": command,
            "result": "error",
            "file": file.map(|f| f.display().to_string()),
            "error": {
                "code": error.code(),
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
        Ok(loaded) => Output {
            code: OK,
            json: json!({
                "command": "check",
                "result": "ok",
                "file": file.display().to_string(),
                "digest": loaded.digest.to_string(),
                "pass_id": loaded.pass.id,
                "problems": [],
            }),
            text: format!(
                "{}: OK, pass {} with {} destination(s) and {} ceiling(s). The window is checked by `hallpass status`.\nDigest: {}\n",
                file.display(),
                loaded.pass.id,
                loaded.pass.destinations.len(),
                loaded.pass.ceilings.len(),
                loaded.digest
            ),
        },
        Err(e) => error_output("check", Some(file), &e),
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
            "  {:<16} {:<24} {} {}{}{}",
            d.label,
            d.network.to_string(),
            d.protocol,
            d.ports,
            d.hostname.as_ref().map_or_else(String::new, |h| format!(
                "  (owner calls it {}; grants nothing)",
                safe(h)
            )),
            if d.whole_network_approved {
                "  [whole network approved]"
            } else {
                ""
            }
        );
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

fn status(file: &Path, clock: &Clock) -> Output {
    let loaded = match hallpass::load(file) {
        Ok(l) => l,
        Err(e) => return error_output("status", Some(file), &e),
    };
    let view = match hallpass::read_ledger(&loaded, &StateDir::from_env()) {
        Ok(v) => v,
        Err(e) => return error_output("status", Some(file), &e),
    };
    let tally = &view.tally;
    let pass = &loaded.pass;
    let state = pass.window_at(clock.now);
    let refusal = pass.check_window(clock.now, Duration::ZERO).err();
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

    let mut text = status_text(file, &loaded, tally, &state, refusal.as_ref());
    let _ = writeln!(text, "Ledger: {}", ledger_state_text(&view));
    Output {
        code: if refusal.is_some() { REFUSED } else { OK },
        json: json!({
            "command": "status",
            "result": if refusal.is_some() { "refused" } else { "ok" },
            "file": file.display().to_string(),
            "digest": loaded.digest.to_string(),
            "now": stamp(clock.now),
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
            "counters": counters,
            "unlisted_spends": unlisted,
            "ledger": ledger_json(&view),
            "warnings": view.warnings,
            "refusal": refusal.as_ref().map(refusal_json),
        }),
        text,
    }
}

fn permits(file: &Path, to: &str, duration: u32, clock: &Clock) -> Output {
    let target: Target = match to.parse() {
        Ok(t) => t,
        Err(message) => {
            return error_output(
                "permits",
                Some(file),
                &Error::Usage(format!("--to: {message}")),
            );
        }
    };
    let loaded: LoadedPass = match hallpass::load(file) {
        Ok(l) => l,
        Err(e) => return error_output("permits", Some(file), &e),
    };
    // The ledger and its witness are checked too: a lost or changed record
    // fails closed here as everywhere else.
    let view = match hallpass::read_ledger(&loaded, &StateDir::from_env()) {
        Ok(v) => v,
        Err(e) => return error_output("permits", Some(file), &e),
    };
    let pass = &loaded.pass;
    let decision = pass.permits(&target, clock.now, Duration::seconds(i64::from(duration)));
    let state = pass.window_at(clock.now);
    let (code, result, label, refusal, text) = match &decision {
        Decision::Allowed { label } => (
            OK,
            "allowed",
            Some(label.clone()),
            None,
            format!(
                "ALLOWED: {target} by destination {label} of pass {} (window: {})\n",
                pass.id,
                window_text(pass, &state)
            ),
        ),
        Decision::Refused(r) => (
            REFUSED,
            "refused",
            None,
            Some(refusal_json(r)),
            format!("REFUSED: {target}: {}.\n", safe(&r.message)),
        ),
    };
    Output {
        code,
        json: json!({
            "command": "permits",
            "result": result,
            "file": file.display().to_string(),
            "digest": loaded.digest.to_string(),
            "pass_id": pass.id,
            "now": stamp(clock.now),
            "test_clock": clock.test,
            "target": target.to_string(),
            "label": label,
            "refusal": refusal,
            "window": window_json(pass, &state),
            "warnings": view.warnings,
        }),
        text,
    }
}

struct SpendArgs<'a> {
    file: &'a Path,
    counter: &'a str,
    amount: u64,
    note: Option<&'a str>,
    digest: Option<&'a str>,
    duration: u32,
}

fn spend(args: &SpendArgs<'_>, clock: &Clock) -> Output {
    let file = args.file;
    let expect_digest = match args.digest.map(str::parse::<Digest>).transpose() {
        Ok(d) => d,
        Err(message) => {
            return error_output(
                "spend",
                Some(file),
                &Error::Usage(format!("--digest: {message}")),
            );
        }
    };
    let request = SpendRequest {
        counter: args.counter,
        amount: args.amount,
        note: args.note,
        expect_digest,
        needed: Duration::seconds(i64::from(args.duration)),
    };
    let outcome = match hallpass::spend(file, &request, clock.now) {
        Ok(o) => o,
        Err(e) => return error_output("spend", Some(file), &e),
    };
    let remaining = outcome.remaining();
    let text = match (&outcome.refusal, outcome.total, outcome.seq) {
        (None, Some(total), Some(seq)) => format!(
            "RECORDED: {} {} ({} of {total} spent, {} left; ledger entry {seq})\n",
            outcome.amount,
            outcome.counter,
            outcome.spent,
            remaining.unwrap_or(0)
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
            "result": if outcome.refusal.is_some() { "refused" } else { "allowed" },
            "file": file.display().to_string(),
            "digest": outcome.digest.to_string(),
            "pass_id": outcome.pass_id,
            "now": stamp(clock.now),
            "test_clock": clock.test,
            "counter": outcome.counter,
            "n": outcome.amount,
            "total": outcome.total,
            "spent": outcome.spent,
            "remaining": remaining,
            "seq": outcome.seq,
            "note": args.note,
            "refusal": outcome.refusal.as_ref().map(refusal_json),
            "warnings": outcome.warnings,
        }),
        text,
    }
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
    let lines = view.entries.len() + view.adoptions.len();
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
        "entries": view.entries.len(),
        "adoptions": view.adoptions.len(),
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

    let text = ledger_text(&loaded, &view, &entries, &totals, counter);

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
            "entries": entries.iter().map(|e| json!({
                "seq": e.seq,
                "time": stamp(e.time),
                "counter": e.counter,
                "n": e.amount,
                "digest": e.digest.to_string(),
                "note": e.note,
            })).collect::<Vec<_>>(),
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

fn adopt(file: &Path, reason: &str, clock: &Clock) -> Output {
    let outcome = match hallpass::adopt(file, reason, clock.now, &StateDir::from_env()) {
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

fn run(cli: &Cli) -> Output {
    let name = cli.command.name();
    let needs_clock = matches!(
        cli.command,
        Command::Status { .. }
            | Command::Permits { .. }
            | Command::Spend { .. }
            | Command::Adopt { .. }
    );
    let clock = if needs_clock {
        match clock() {
            Ok(c) => c,
            Err(e) => return error_output(name, None, &e),
        }
    } else {
        Clock {
            now: OffsetDateTime::now_utc(),
            test: false,
        }
    };
    match &cli.command {
        Command::Init { file } => init(file),
        Command::Check { file } => check(file),
        Command::Status { file } => status(file, &clock),
        Command::Permits { file, to, duration } => permits(file, to, *duration, &clock),
        Command::Spend {
            file,
            counter,
            amount,
            note,
            digest,
            duration,
        } => spend(
            &SpendArgs {
                file,
                counter,
                amount: *amount,
                note: note.as_deref(),
                digest: digest.as_deref(),
                duration: *duration,
            },
            &clock,
        ),
        Command::Digest { file } => digest(file),
        Command::Ledger { file, counter } => ledger(file, counter.as_deref()),
        Command::Adopt { file, reason } => adopt(file, reason, &clock),
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { ERROR } else { OK };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    let mut output = run(&cli);
    if output.json.get("warnings").is_none() {
        output.json["warnings"] = json!([]);
    }
    match cli.format {
        Format::Json => println!("{}", output.json),
        Format::Text => {
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
