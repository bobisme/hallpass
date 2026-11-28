//! Discovery information shared by terminal help and machine-readable help.
use clap::{CommandFactory as _, builder::ArgAction};
use serde_json::{Value, json};

use super::{Cli, Error, Format, OK, Output, error_output};

const EXITS: &str = "Exit codes\n  0  Success (inspect command and result)\n  1  Usage, file or accounting error, or a reply that could not be written (stderr says what is recorded)\n  2  Policy refusal, verification mismatch, coverage gaps or inconclusive evidence";

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
            "Start with an owner's written approval in a TOML pass. Use init for a blank template. Run check, review status, and retain the reviewed digest. Use permits for a read-only decision or spend --to to check and debit together. If anything goes wrong, run doctor for the one next step. In JSON, inspect command, result and the exit code.",
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
            "On an invalid pass, correct each problems[].field using the owner's approval. Read warnings: a window-too-long, window-ended or window-starts-far-ahead warning means the window may be a typo (check judges it by the clock, or the test clock in a debug build); a name-restriction-overlap warning means another destination allows the same addresses without names, so run lint for details. The pass stays valid and check exits 0. After validation, use status to inspect the live window, balances and witness.",
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
        "doctor" => (
            &[
                "hallpass doctor engagement.pass.toml",
                "hallpass --format json doctor engagement.pass.toml --archive approvals",
            ],
            "Run this first when anything goes wrong, and before recovering. Read result (healthy, needs-action or blocked), problem (the error or refusal code a spend would fail with, or null), next (the one command to run, as an argv array with real paths, or null), next_step (what to do, in words) and findings (other {code, message} rows). Run next, then doctor again, until result is healthy. Doctor never writes: next can be a preview, chmod or mv, and a recovery that records still needs its own reviewed token. It never names adopt while the ledger may be intact elsewhere. With --checkpoint CHECKPOINT it also compares the ledger with a retained checkpoint, as verify-checkpoint does: a ledger behind it (checkpoint-behind), or another history (checkpoint-fork), blocks. Healthy exits 0, needs-action and blocked exit 2, and a pass path, archive directory or checkpoint it cannot read exits 1.",
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
            "Use COUNTER with optional --n, or repeat --charge COUNTER=N. Read require_target from check or status. When true, supply --to for every debit. A targetless request returns refusal.code=target-required. When false, a debit without --to checks no destination and has a warning that says so. Retain a checked target only with --record-target; audit-receipts can replay only retained targets. Preview with --dry-run, then submit with the reviewed digest and required targets and charges. Use --caller-ref with --require-new-ref to deny duplicates under the writer locks. Require exit 0, command=spend, result=allowed, a positive seq, test_clock=false and a reply matching the request. A preview reserves nothing. On duplicate-reference, reconcile reference_evidence.sequences (and reconciled_at, the reference reconciliations that list it) with your run record and receipt. After an adoption that may have lost lines, reference-inconclusive lasts until reconcile-references records the references from your run records. After a lost reply, uncertain error or reference-inconclusive refusal, reconcile with the ledger and your run record before retrying.",
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
            "Create a private directory once. Archive each reviewed revision there and save its digest. Use retrieve with that digest to recover the exact approved text. archive stores bytes only and reports provenance: unsigned, or signature-recorded when verify-approval --archive already recorded a signature for these bytes (that record is kept). The audits are complete only when run with --allowed-signers and --principal, and every revision's recorded signature verifies again for a principal named.",
        ),
        "retrieve" => (
            &["hallpass --format json retrieve approval-archive \"$digest\""],
            "Supply the full digest from archive or ledger. Read bytes for the exact pass text. To keep the bytes as a file, use --output FILE: it creates a new file with mode 0600 and refuses an existing file or a link. Redirecting --format text output makes a file with your umask's mode, which diff and archive refuse when group or others can write it.",
        ),
        "verify-approval" => (
            &[
                "hallpass --format json verify-approval engagement.pass.toml --signature engagement.pass.toml.sig --allowed-signers trusted_signers --principal owner@example.org",
                "hallpass --format json verify-approval engagement.pass.toml --signature engagement.pass.toml.sig --allowed-signers trusted_signers --principal owner@example.org --archive approval-archive",
                "hallpass --format json verify-approval engagement.pass.toml --signature engagement.pass.toml.sig --allowed-signers trusted_signers --principal owner@example.org --at 2026-11-20T09:00:00Z",
            ],
            "Select the principal and trusted signers independently. On exit 0 and result=verified, pin the returned digest with permits --digest or spend --digest. The signer key's valid-after and valid-before window in the trusted signers file is checked as of now; use --at TIME to check an approval as of the time it was first used. A key outside its window is unverified with reason key-not-valid-at-time. With --archive, the exact verified bytes, the signature and a record of the principal and trust file digest are retained after signature success, and the reply's provenance is signature-recorded. An earlier, different record for the same bytes is kept, with a warning; when it names another principal, the reply is provenance signature-not-stored and the exit status is 2, because this signature was not stored. The reply names the signing key's fingerprint as key, and principal_match says how the trust file matched the principal: named, certificate, or pattern for a line whose principals use *, ? or !, which warns unless --allow-pattern-principals. --signer-key FINGERPRINT requires that key, else the reason is signer-key-mismatch. Keep the trust file and expected principal separately: the audits verify the signatures again only with --allowed-signers and --principal. Those live operations check current policy.",
        ),
        "diff" => (
            &[
                "hallpass --format json diff reviewed.pass.toml proposed.pass.toml",
                "hallpass --format json diff current.toml proposed.toml --budget-impact",
                "hallpass --format json diff current.toml proposed.toml --containment --at 2026-11-20T09:00:00Z",
                "hallpass --format json diff reviewed.pass.toml proposed.pass.toml --examples --at 2026-11-20T09:00:00Z",
            ],
            "Inspect review_required, changes and destination order. When the digests differ and same_declared_fields is true, text_changes says what differs (comments, layout or value-spelling) and comment_changes lists each comment only one file has; comments are signed and digested like every other byte. For replayable decision changes supply --examples with an explicit offset timestamp. Inspect examples.rows (newly allowed first) and truncated; refusal-code-only changes are counted, and listed with --refusal-changes. Rows with bypasses_names_of come first: NEW allows them, without a name or with an unlisted one, through a nameless destination it adds or changes, although the destination named there restricts that address and port to names. For a containment verdict, use --containment --at; the verdict holds at every instant, and --at only chooses where counterexamples are replayed. The verdict covers the whole pass: containment.endpoint_result is the endpoint proof alone, and containment.loosenings lists each later window end, earlier window start, higher or newly spendable ceiling, ceiling replaced under a new name (code counter-substitution), dropped required counter or require_target, un-revoke or changed approver, operator or approval reference. Only contained exits 0 in this mode. The endpoint proof compares the destination rules without a window, and the window and revocation are loosenings of their own; a revoked NEW admits nothing at any instant and is contained (new-admits-nothing). Counterexamples are replayed at --at when NEW's window holds it, otherwise at its start (containment.replayed_at), with OLD under NEW's window. widened means something other than the endpoints loosens. An expansion lists up to eight counterexamples, each in a widened class that no earlier one is in: a NEW destination and port range that no single OLD destination covers, an IPv4 network or broadcast address that NEW no longer excludes, or a bypassed names list (unnamed and with an unlisted name, listed first). more_counterexamples is true when the list is not empty and some widened class has no counterexample in it (a class may hold no new allowance), the eight are not enough, or a work limit leaves the classes unknown; false with a non-empty list means every widened class has one. An empty sample cannot establish policy equivalence. Use --budget-impact to compare both ceilings against the live ledger: the one beside NEW, or the one beside OLD when NEW has none. Inspect budget_impact.ledger and ledger_source. Inspect over_proposed and counter_substitution even on exit 0. A different approval ID makes the projection inapplicable (exit 2).",
        ),
        "consumer-coverage" => (
            &[
                "hallpass --format json consumer-coverage engagement.pass.toml --can endpoints --can live-window --can charge:calls",
            ],
            "Declare features your consumer implements. Supply --can names when it checks the application name. Supply --can target-on-every-debit when it sends a checked target on every debit and repeat --can charge:COUNTER for every budget it charges. Use --can none for an empty profile. Inspect findings on exit 2 (gaps). Exit 0 (covered) describes declared features. Live requests still need permits or spend.",
        ),
        "lint" => (
            &["hallpass --format json lint engagement.pass.toml"],
            "Inspect findings for overlapping destination names and ports and for destinations that grant more than 1024 ports (wide-port-grant), truncated for omitted overlaps, and warnings. Lint is advisory and can return exit 0 with findings.",
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
            "Use the id in revisions of the same written approval. Preserve the owner and reference strings exactly. They follow the rules of approval.owner and approval.reference: an owner or reference a pass could not hold, such as one with a zero-width or no-break space, is a usage error that names the field and the character, and no id is printed. Distinct approvals need distinct identities and budgets.",
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
            &[
                "hallpass --format json audit-receipts engagement.pass.toml approval-archive --allowed-signers trusted_signers --principal owner@example.org",
                "hallpass --format json audit-receipts engagement.pass.toml approval-archive --allowed-signers trusted_signers --principal owner@example.org --principal owner@example.net",
            ],
            "Archive each reviewed revision with verify-approval --archive before spending with --record-target. Supply your own trusted signers file with --allowed-signers and the owner's principal with --principal: the file decides whose keys count, and --principal decides who must have approved. The audit runs ssh-keygen -Y verify again for each recorded signature over the archived bytes, once per digest and principal until one verifies (repeat --principal for an owner with several), as of the time the revision was first used (--signatures-as-of now for the current time). Replay retained endpoints at their recorded instant, then inspect mismatches, gaps, revisions, signatures and the independent witness status. Complete exits 0 only when every revision used is signature-verified for a principal named, so never without --allowed-signers and --principal: a signature record alone is signature-recorded with a signature-not-reverified gap, and a signature verified only for the principal its record names is a signer-not-pinned gap. Each verified revision names its signer_key from this audit's own verification. A key that the trust file holds for the principal only on a pattern line (*, ? or !) is a signer-matched-by-pattern gap unless --allow-pattern-principals. A rejected signature is a signature-rejected gap with a reason, such as key-not-valid-at-time for a key outside its valid-after or valid-before window; revisions without a record are approval-unverified gaps. A revision archived before a pass rule it breaks is a revision-unparsable gap, and its signature is still verified: never edit archived bytes; re-run the audit with the hallpass version that recorded the work, or accept the gap. Incomplete or mismatch exits 2. A damaged input, an unreadable trusted signers file, or an ssh-keygen that cannot run when a recorded signature needs verifying, exits 1.",
        ),
        "audit-charges" => (
            &[
                "hallpass audit-charges engagement.pass.toml approval-archive --allowed-signers trusted_signers --principal owner@example.org",
                "hallpass --format json audit-charges engagement.pass.toml approval-archive --allowed-signers trusted_signers --principal owner@example.org",
            ],
            "Replay each recorded charge against its archived revision and earlier totals. Mismatches and gaps can coexist; carry is not an original debit. Supply your own trusted signers file with --allowed-signers and the owner's principal with --principal so that each recorded signature is verified again, as in audit-receipts. Inspect revisions for each digest used, with its first and last sequence, first use, verification time and provenance; complete needs every one signature-verified for a principal named, so never without --allowed-signers and --principal. The witness is reported separately. This checks accounting, not external work or endpoints.",
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
            "Supply up to 32 candidate ledger files and the pass identifying the witness. Inspect each verified tip, relation and tip_group, then review the assessment. By default distinct extensions are ambiguous. With --ancestry, verified prefix links and maximal groups distinguish successive backups from competing branches. Candidates that extend, equal or lie behind the witness are compared (read-only; the assessment does not change), so empty prefix_links does not mean the backups are unrelated. Recheck the chosen file after restoration. Per-file input failures exit 1, preserving other rows.",
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
            "Use this for recovery. Inspect case, present, carry, totals and warnings in the preview: an adoption that carries totals leaves later --require-new-ref spends reference-inconclusive until reconcile-references records the references that may be in the lost lines. After reviewing them, supply its token and a reason to record the adoption. A stale token requires a new review. An appended adoption still counts after a witness update failure. A ledger that is intact where the witness last saw it is not adopted (ledger-elsewhere): replace that pass file's content instead. When the witness shows a rehearsal (every entry it counts was recorded under a test clock), an adoption on the real clock is refused until you choose: --drop-rehearsal FILE carries nothing once FILE, the rehearsal ledger moved aside, proves the rehearsal; --carry-rehearsal carries the rehearsal units. After the ledger and the state directory were both restored from an older copy, --checkpoint CHECKPOINT carries, per counter, what a retained checkpoint records beyond the ledger, when the checkpoint shows the ledger is behind it; it never lowers a count, and its totals are only as trustworthy as the place you kept it.",
        ),
        "repair" => (
            &[
                "hallpass --format json repair engagement.pass.toml --drop-torn-tail --preview",
                "hallpass --format json repair engagement.pass.toml --drop-torn-tail --token \"$token\"",
                "hallpass --format json repair engagement.pass.toml --restore-final-newline --preview",
                "hallpass --format json repair engagement.pass.toml --drop-blank-tail --preview",
            ],
            "Use this when a command fails ledger-corrupt because the last line is cut short (no line end), for example after a disk filled up during a spend, or holds only NUL bytes, as a crash can leave. The preview checks that every complete line verifies, that the witness recorded one of them, and that the cut-short bytes start the next line hallpass would write. Review seq, witness_seq and removed_bytes, then supply the token. The removed bytes are kept in the file named by copy. If the cut-short last line is whole and the witness recorded it, --drop-torn-tail refuses and --restore-final-newline (same preview and --token flow) adds the missing line end and drops nothing. If empty lines were added after the last line (for example by `echo >> ledger`) and the witness recorded that last line, --drop-blank-tail (same flow) removes them. Any other damage is refused: restore the ledger from a backup instead.",
        ),
        "reconcile-references" => (
            &[
                "hallpass --format json ledger engagement.pass.toml",
                "hallpass --format json reconcile-references engagement.pass.toml --adoption 1 --references lost-references.json --reason 'every reference in the run journals of shift 17'",
            ],
            "Use this after an adoption that may have lost lines, when guarded spends are refused as reference-inconclusive. Read unreconciled_adoption from ledger. From your run records, list every caller reference that may be in the lost lines, in a JSON file {\"version\": 1, \"pass_id\": ID, \"references\": [...]}, and give a reason. A listed reference is then refused as duplicate-reference; any other is checked against the ledger. A reference left off the list is accepted as new, so list every reference your run records used on this pass. Another adoption that may lose lines needs its own reconciliation. A reconciliation permits nothing and changes no count.",
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
