//! Discovery information shared by terminal help and machine-readable help.
use clap::{CommandFactory as _, builder::ArgAction};
use serde_json::{Value, json};

use super::{Cli, Error, Format, OK, Output, error_output};

const EXITS: &str = "Exit codes\n  0  Success (inspect command and result)\n  1  Usage, file or accounting error\n  2  Policy refusal or verification mismatch";

struct Guide {
    examples: &'static [&'static str],
    workflow: &'static str,
}

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
            "Choose a new file. Fill in the owner's written approval, then run hallpass check on that file. The private template grants nothing.",
        ),
        "check" => (
            &["hallpass --format json check engagement.pass.toml"],
            "On an invalid pass, correct each problems[].field using the owner's approval. After validation, use status to inspect the live window, balances and witness.",
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
            ],
            "Use COUNTER with optional --n, or repeat --charge COUNTER=N. Preview with --dry-run, then submit once with the reviewed digest and all required targets and charges. Require exit 0, command=spend, result=allowed, a positive seq, test_clock=false and a reply matching the request. A preview reserves nothing. After a lost reply or recorded/uncertain error, inspect ledger before retrying.",
        ),
        "digest" => (
            &["hallpass --format json digest engagement.pass.toml"],
            "Read digest from the reviewed bytes and supply that exact value to permits --digest or spend --digest. A changed pass requires fresh review.",
        ),
        "ledger" => (
            &["hallpass --format json ledger engagement.pass.toml --counter calls"],
            "Use the pass path. Read the verified events, sequences, totals and witness status. Reconcile an uncertain spend with your run record before considering a retry.",
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
        "checkpoint" => (
            &["hallpass --format json checkpoint engagement.pass.toml > checkpoint.json"],
            "After a ledger exists, retain this JSON separately from it. Use verify-checkpoint on the ledger and the retained JSON to check the history later.",
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
            "Use this for recovery. Inspect case, present, carry and totals in the preview. After reviewing them, supply its token and a reason to record the adoption. A stale token requires a new review. An appended adoption still counts after a witness update failure.",
        ),
        "diff" => (
            &["hallpass --format json diff reviewed.pass.toml proposed.pass.toml"],
            "Inspect review_required, changes, and destination order before accepting a revision. Exit 0 means the comparison completed. Use test-pass to check the owner's expected decisions.",
        ),
        "lint" => (
            &["hallpass --format json lint engagement.pass.toml"],
            "Inspect findings for overlapping destination names and ports, and truncated for omitted findings. Lint is advisory and can return exit 0 with findings.",
        ),
        "test-pass" => (
            &["hallpass --format json test-pass docs/review-approval.toml docs/review-suite.toml"],
            "Run the bundled example from the checkout, or supply your own pass and suite paths. Each case provides id, at, to and expected, with optional name and duration. Inspect mismatches and results. All evaluations are offline.",
        ),
        "approval-id" => (
            &[
                "hallpass --format json approval-id --owner 'Example Corp' --reference 'approval-42'",
            ],
            "Use the id in revisions of the same written approval. Preserve the owner and reference strings exactly. Distinct approvals need distinct identities and budgets.",
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
            "exit_codes":{"0":"success; inspect command and result","1":"usage, file or accounting error","2":"policy refusal or verification mismatch"}
        }),
        text: format!("{text}\n"),
    }
}
