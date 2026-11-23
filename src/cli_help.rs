//! Discovery information shared by terminal help and machine-readable help.
use clap::{CommandFactory as _, builder::ArgAction};
use serde_json::{Value, json};

use super::{Cli, Error, Format, OK, Output, error_output};

const EXITS: &str = "Exit codes\n  0  Success (inspect command and result)\n  1  Usage, file or accounting error\n  2  Policy refusal, verification mismatch, coverage gaps or inconclusive evidence";

struct Guide {
    examples: &'static [&'static str],
    workflow: &'static str,
}

#[allow(
    clippy::too_many_lines,
    reason = "one declarative help entry per CLI command"
)]
fn guide(name: &str) -> Guide {
    let (examples, workflow): (&[&str], &str) = match name {
        "hallpass" => (
            &[
                "hallpass --format json help spend",
                "hallpass --format json check engagement.pass.toml",
                "hallpass --format json status engagement.pass.toml",
            ],
            "Start with an owner's written approval in a TOML pass. Use init for a blank template. Run check, review status, and retain the reviewed digest. Use permits for a read-only decision or spend --to to check and debit together. In JSON, inspect command, result and the exit code.",
        ),
        "help" => (
            &["hallpass help", "hallpass help permits --format json"],
            "Read commands at the root. Request a command by name for its arguments, examples and workflow. Help reads no engagement files.",
        ),
        "version" => (
            &["hallpass version --format json"],
            "Record version with integration diagnostics. Use hallpass help COMMAND to discover the installed interface.",
        ),
        "init" => (
            &["hallpass init engagement.pass.toml"],
            "Choose a new file and fill in the owner's written approval. If each debit must include a destination or specific counters, uncomment require_target_v1 or required_counters_v1 in the template. Set the approved totals under [ceilings], then run hallpass check on the filled pass.",
        ),
        "check" => (
            &["hallpass --format json check engagement.pass.toml"],
            "On an invalid pass, correct each problems[].field using the owner's approval. Read warnings: a name-restriction-overlap warning means another destination allows the same addresses without names, so run lint for details. The pass stays valid and check exits 0. After validation, use status to inspect the live window, balances and witness.",
        ),
        "rehearse" => (
            &["hallpass --format json rehearse docs/required-counters.toml docs/rehearse.toml"],
            "Read a version 1 TOML scenario. Each [[step]] needs a unique id, a quoted RFC 3339 at, and charges = [{counter = 'bytes', n = 40}]. Optional duration is in seconds and targets use ADDR:PORT/PROTO[@NAME]. Inspect starting_spent, steps[].balances and stopped_at. Exit 2 marks the first simulated refusal. A simulation reserves nothing. Submit live spend for each actual unit.",
        ),
        "capacity" => (
            &[
                "hallpass --format json capacity docs/required-counters.toml --charge requests=1 --charge bytes=24 --to 192.0.2.10:443/tcp@app.example.org",
            ],
            "Supply the same costs, ordered targets, duration and digest as one spend. On exit 0 read units, limiting_counters and counters[].remaining_after. A valid unit can have units=0 with a budget unit_refusal. Exit 2 reports invalid policy with no usable count. The result is a budget snapshot. Each live unit still needs a successful spend.",
        ),
        "status" => (
            &["hallpass --format json status engagement.pass.toml"],
            "Review the owner, literal destinations, window, ceilings and warnings. Capture digest for the next permits or spend request. A valid window alone grants no target or debit.",
        ),
        "permits" => (
            &[
                "hallpass --format json permits engagement.pass.toml --to 192.0.2.10:5060/udp --duration 30",
                "hallpass --format json permits web.pass.toml --to '[2001:db8::10]:443/tcp@app.example.org' --digest \"$digest\"",
            ],
            "Check literal endpoints without spending. Substitute the digest from the reviewed pass. Repeat --to for each endpoint of one unit. Read result and refusal.code. For a counted unit, use spend --to at commit time.",
        ),
        "spend" => (
            &[
                "hallpass --format json spend engagement.pass.toml calls --to 192.0.2.10:5060/udp --dry-run",
                "hallpass --format json spend engagement.pass.toml --charge calls=1 --charge bytes=100 --to 192.0.2.10:5060/udp --duration 30 --digest \"$digest\"",
                "hallpass --format json spend docs/required-counters.toml --charge requests=1 --charge bytes=24 --to 192.0.2.10:443/tcp@app.example.org --dry-run",
                "hallpass --format json spend engagement.pass.toml calls --to 192.0.2.10:5060/udp --caller-ref batch-42 --require-new-ref --digest \"$digest\"",
            ],
            "Use COUNTER with optional --n, or repeat --charge COUNTER=N. Read require_target from check or status. When true, supply --to for every debit. A targetless request returns refusal.code=target-required. When false, a debit without --to checks no destination and has a warning that says so. Retain a checked target only with --record-target. Preview with --dry-run, then submit with the reviewed digest and required targets and charges. Use --caller-ref with --require-new-ref to deny duplicates under the writer locks. Require exit 0, command=spend, result=allowed, a positive seq, test_clock=false and a reply matching the request. A preview reserves nothing. On duplicate-reference, reconcile reference_evidence.sequences with your run record and receipt. After a lost reply, uncertain error or reference-inconclusive refusal, reconcile with the ledger and your run record before retrying.",
        ),
        "digest" => (
            &["hallpass --format json digest engagement.pass.toml"],
            "Read digest from the reviewed bytes and supply that exact value to permits --digest or spend --digest. A changed pass requires fresh review.",
        ),
        "ledger" => (
            &[
                "hallpass --format json ledger engagement.pass.toml --counter calls",
                "hallpass --format json ledger engagement.pass.toml --tail 20",
            ],
            "Use the pass path. --tail N shows the last N entries and --since SEQ shows entries with seq >= SEQ; together they give the intersection (since first, then the last N of those), and both apply after --counter. The whole chain is verified first, a tampered earlier line still fails, and totals stay for the whole ledger. A slice sets shown to {from, to, of} (null when unsliced); --tail 0 and a --since past the end show no entries. Read the verified events, sequences, totals and witness status. Reconcile an uncertain spend with your run record before considering a retry.",
        ),
        "archive" => (
            &[
                "mkdir -m 700 approval-archive",
                "hallpass --format json archive engagement.pass.toml approval-archive",
            ],
            "Create a private directory once. Archive each reviewed revision there and save its digest. Use retrieve with that digest to recover the exact approved text.",
        ),
        "retrieve" => (
            &["hallpass --format json retrieve approval-archive \"$digest\""],
            "Supply the full digest from archive or ledger. Read bytes for the exact pass text. Select --format text when redirecting the original bytes to a file.",
        ),
        "verify-approval" => (
            &[
                "hallpass --format json verify-approval engagement.pass.toml --signature engagement.pass.toml.sig --allowed-signers trusted_signers --principal owner@example.org",
                "hallpass --format json verify-approval engagement.pass.toml --signature engagement.pass.toml.sig --allowed-signers trusted_signers --principal owner@example.org --archive approval-archive",
            ],
            "Select the principal and trusted signers independently. On exit 0 and result=verified, pin the returned digest with permits --digest or spend --digest. With --archive, the exact verified bytes are retained after signature success; keep the detached signature, trust file and expected principal separately to verify them again. Those live operations check current policy.",
        ),
        "diff" => (
            &[
                "hallpass --format json diff reviewed.pass.toml proposed.pass.toml",
                "hallpass --format json diff current.toml proposed.toml --budget-impact",
                "hallpass --format json diff current.toml proposed.toml --containment --at 2026-11-20T09:00:00Z",
                "hallpass --format json diff reviewed.pass.toml proposed.pass.toml --examples --at 2026-11-20T09:00:00Z",
            ],
            "Inspect review_required, changes and destination order. For replayable decision changes supply --examples with an explicit offset timestamp. Inspect examples.rows (newly allowed first) and truncated; refusal-code-only changes are counted, and listed with --refusal-changes. For a containment verdict at that instant, use --containment --at. The verdict covers the whole pass: containment.endpoint_result is the endpoint proof alone, and containment.loosenings lists each later window end, earlier window start, higher or newly spendable ceiling, dropped required counter or require_target, un-revoke or changed approver or operator. Only contained exits 0 in this mode; widened means something other than the endpoints loosens. An expansion lists up to eight counterexamples, one per widened rule and port range, and sets more_counterexamples when others may exist. An empty sample cannot establish policy equivalence. Use --budget-impact to compare both ceilings against the live ledger: the one beside NEW, or the one beside OLD when NEW has none. Inspect budget_impact.ledger and ledger_source. Inspect over_proposed even on exit 0. A different approval ID makes the projection inapplicable (exit 2).",
        ),
        "consumer-coverage" => (
            &[
                "hallpass --format json consumer-coverage engagement.pass.toml --can endpoints --can live-window --can charge:calls",
            ],
            "Declare features your consumer implements. Supply --can names when it checks the application name. Supply --can target-on-every-debit when it sends a checked target on every debit and repeat --can charge:COUNTER for every budget it charges. Use --can none for an empty profile. Inspect findings on exit 2 (gaps). Exit 0 (covered) describes declared features. Live requests still need permits or spend.",
        ),
        "lint" => (
            &["hallpass --format json lint engagement.pass.toml"],
            "Inspect findings for overlapping destination names and ports, and truncated for omitted findings. Lint is advisory and can return exit 0 with findings.",
        ),
        "test-pass" => (
            &[
                "hallpass --format json test-pass docs/review-approval.toml docs/review-suite.toml",
                "hallpass --format json test-pass engagement.pass.toml owner-suite.toml --strength",
            ],
            "Run the bundled example from the checkout, or supply your own pass and suite paths. Each case provides id, at, to and expected, with optional name and duration. --strength evaluates the baseline, then bounded in-memory copies with destination names removed, an adjacent valid port added, a network widened by one bit, the other transport added, or the window moved one second wider. Mutations that cannot be observed or would not validate, such as ceilings, are reported as skipped. Inspect mutation_strength.mutations and first_distinguishing_case. Survivors and partial analysis exit 2; survivors are review prompts. All evaluations are offline.",
        ),
        "approval-id" => (
            &[
                "hallpass --format json approval-id --owner 'Example Corp' --reference 'approval-42'",
            ],
            "Use the id in revisions of the same written approval. Preserve the owner and reference strings exactly. Distinct approvals need distinct identities and budgets.",
        ),
        _ => return history_guide(name),
    };
    Guide { examples, workflow }
}

fn history_guide(name: &str) -> Guide {
    let (examples, workflow): (&[&str], &str) = match name {
        "receipt" => (
            &["hallpass --format json receipt engagement.pass.toml --caller-ref run-42"],
            "After a lost spend reply, supply the exact reference from your durable run record. Compare matching sequences, digests, charges and retained targets. Found exits 0. Absent or ambiguous exits 2. Reconcile before retrying. A receipt records a debit and cannot establish that the external action occurred.",
        ),
        "audit-receipts" => (
            &["hallpass --format json audit-receipts engagement.pass.toml approval-archive"],
            "Archive each reviewed revision before spending with --record-target. Replay retained endpoints at their recorded instant, then inspect mismatches, gaps and the independent witness status. Complete exits 0. Incomplete or mismatch exits 2. A damaged input exits 1.",
        ),
        "audit-charges" => (
            &[
                "hallpass audit-charges engagement.pass.toml approval-archive",
                "hallpass --format json audit-charges engagement.pass.toml approval-archive",
            ],
            "Replay each recorded charge against its archived revision and earlier totals. Mismatches and gaps can coexist; carry is not an original debit. The witness is reported separately. This checks accounting, not external work or endpoints.",
        ),
        "reconcile" => (
            &[
                "hallpass reconcile engagement.pass.toml manifest.json",
                "hallpass --format json reconcile engagement.pass.toml manifest.json",
            ],
            "Compare a version 1 local manifest with the available verified ledger in one pass. See docs/EVIDENCE.md for the JSON schema. Read rows[].differences: each entry names a field that differs, the candidate sequence, the manifest value (expected) and the ledger value (recorded); null means that side has none. Missing or duplicate references and mismatched or unrecorded details exit 2; invalid input or history exits 1. This is accounting evidence, not proof of external work.",
        ),
        "compare-backups" => (
            &[
                "hallpass --format json compare-backups engagement.pass.toml backup-a.ledger backup-b.ledger",
                "hallpass --format json compare-backups engagement.pass.toml --ancestry backup-a.ledger backup-b.ledger",
            ],
            "Supply up to 32 candidate ledger files and the pass identifying the witness. Inspect each verified tip, relation and tip_group, then review the assessment. By default distinct extensions are ambiguous. With --ancestry, verified prefix links and maximal groups distinguish successive backups from competing branches. Only candidates that extend the witness are compared, so empty prefix_links does not mean the backups are unrelated. Recheck the chosen file after restoration. Per-file input failures exit 1, preserving other rows.",
        ),
        "checkpoint" => (
            &["hallpass --format json checkpoint engagement.pass.toml > checkpoint.json"],
            "After a ledger exists, retain this JSON separately from it. Before the first spend it exits 2 with result empty and exports nothing. JSON witness.relation says matches, lags or absent. Use verify-checkpoint on the ledger and the retained JSON to check the history later.",
        ),
        "verify-checkpoint" => (
            &[
                "hallpass --format json verify-checkpoint engagement.pass.toml.ledger checkpoint.json",
            ],
            "Supply the ledger itself and an independently retained checkpoint. Exact and extended histories exit 0, a mismatch exits 2, and missing or damaged input exits 1.",
        ),
        "adopt" => (
            &[
                "hallpass --format json adopt engagement.pass.toml --preview",
                "hallpass --format json adopt engagement.pass.toml --reason 'restored from backup' --token \"$token\"",
            ],
            "Use this for recovery. Inspect case, present, carry, totals and warnings in the preview: an adoption that carries totals leaves later --require-new-ref spends reference-inconclusive. After reviewing them, supply its token and a reason to record the adoption. A stale token requires a new review. An appended adoption still counts after a witness update failure. A ledger that is intact where the witness last saw it is not adopted (ledger-elsewhere): replace that pass file's content instead.",
        ),
        _ => unreachable!("missing help for {name}"),
    };
    Guide { examples, workflow }
}

fn guided(command: clap::Command) -> clap::Command {
    let info = guide(command.get_name());
    let examples = info.examples.join("\n  ");
    command.after_help(format!(
        "Examples\n  {examples}\n\nAgent workflow\n  {}\n\n{EXITS}",
        info.workflow
    ))
}

pub fn definition() -> clap::Command {
    guided(Cli::command().mut_subcommands(guided))
}

pub fn version() -> Output {
    let version = env!("CARGO_PKG_VERSION");
    Output {
        code: OK,
        text: format!("hallpass {version}\n"),
        json: json!({"command":"version", "result":"ok", "version":version}),
    }
}

fn arguments(command: &clap::Command) -> Vec<Value> {
    command.get_arguments().filter(|arg| !arg.is_hide_set()).map(|arg| {
        let names = arg.get_value_names().unwrap_or_default();
        let values = arg.get_possible_values();
        let conflicts = command.get_arg_conflicts_with(arg);
        json!({
            "name": arg.get_id().as_str(),
            "long": arg.get_long(),
            "short": arg.get_short(),
            "positional": arg.is_positional(),
            "required": arg.is_required_set(),
            "value_names": names.iter().map(clap::builder::Str::as_str).collect::<Vec<_>>(),
            "values": values.iter().filter(|v| !v.is_hide_set()).map(clap::builder::PossibleValue::get_name).collect::<Vec<_>>(),
            "defaults": arg.get_default_values().iter().map(|v| v.to_string_lossy()).collect::<Vec<_>>(),
            "conflicts_with": conflicts.iter().map(|a| a.get_id().as_str()).collect::<Vec<_>>(),
            "repeatable": matches!(arg.get_action(), ArgAction::Append | ArgAction::Count),
            "help": arg.get_long_help().or_else(|| arg.get_help()).map(ToString::to_string),
        })
    }).collect()
}

pub fn help(topic: Option<&str>, format: Format) -> Output {
    let mut root = definition();
    root.build();
    let command = if let Some(topic) = topic {
        let Some(sub) = root.find_subcommand_mut(topic) else {
            return error_output(
                "help",
                None,
                &Error::Usage(format!(
                    "unknown help topic `{topic}`; run hallpass help to list commands"
                )),
            );
        };
        sub
    } else {
        &mut root
    };
    let info = guide(command.get_name());
    let usage = command.render_usage().to_string();
    let text = match format {
        Format::Pretty => command.render_long_help().to_string(),
        Format::Text => command.render_help().to_string(),
        Format::Json => String::new(),
    };
    Output {
        code: OK,
        json: json!({
            "command":"help", "result":"ok", "topic":topic.map(|_| command.get_name()),
            "description": command.get_long_about().or_else(|| command.get_about()).map(ToString::to_string),
            "usage":usage, "arguments":arguments(command),
            "commands":command.get_subcommands().filter(|c| !c.is_hide_set()).map(|c| json!({"name":c.get_name(),"description":c.get_about().map(ToString::to_string)})).collect::<Vec<_>>(),
            "examples":info.examples, "workflow":info.workflow,
            "exit_codes":{"0":"success; inspect command and result","1":"usage, file or accounting error","2":"policy refusal, verification mismatch, coverage gaps or inconclusive evidence"}
        }),
        text: format!("{text}\n"),
    }
}
