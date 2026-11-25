# hallpass

![HALLPASS — Permission slips for authorized tests. Two cloaked figures exchange a paper pass beside a misty stone bridge.](docs/hallpass.webp)

A pass is the written permission slip for an authorized test: who approved
it, which literal network destinations may be touched, from when until
when, and how much. hallpass reads a pass, says whether something is
permitted right now, and keeps count of what has been spent, across
processes.

It is a Rust library and a command line tool (`hallpass`). Rust tools use
the library; other tools run the command with `--format json`.

The whole project in one page: [docs/spec.md](docs/spec.md). The file
format: [docs/PASS-FORMAT.md](docs/PASS-FORMAT.md). Why it is built this
way: [docs/DESIGN.md](docs/DESIGN.md). Calling hallpass from another tool:
[docs/INTEGRATING.md](docs/INTEGRATING.md).
A first shift, from written approval to handoff: [docs/WALKTHROUGH.md](docs/WALKTHROUGH.md).
Every call verifies the whole ledger, so for many small units read
[Cost per call and batching](docs/INTEGRATING.md#cost-per-call-and-batching).

## Build

```sh
cargo build --release
cp target/release/hallpass ~/.local/bin/   # or run it from target/release
```

Linux and other Unix systems only (it relies on Unix file modes and
`flock`).

## CLI discovery

Run `hallpass help` to see the command directory. An agent can request the same
directory, inspect one command, or identify the installed version in JSON.

```sh
hallpass help --json
hallpass help spend --format json
hallpass version --format json
```

Each help page includes arguments, examples, an agent workflow and exit codes.
JSON callers should check the returned `command`, `result` and exit code.

| If you need to… | Start with |
|---|---|
| Retain the precise approval an owner signed | `verify-approval --archive DIR` |
| Check whether a proposed revision only narrows (endpoints, window, ceilings, requirements), or see remaining budget after an edit | `diff --containment --at TIMESTAMP`, `diff --budget-impact` |
| Find restrictions an owner's regression suite fails to protect | `test-pass --strength` |
| Compare a consumer's declared capabilities with the pass requirements | `consumer-coverage` |
| Estimate how many identical units fit, or where a varied sequence first exceeds budget | `capacity`, `rehearse` |
| Reconcile a lost spend reply or a full run of expected debits | `receipt`, `reconcile` |
| Audit recorded charges and destination receipts against archived approvals | `audit-charges`, `audit-receipts` |
| Identify the newest verified copy on each backup branch | `compare-backups --ancestry` |

## Two-minute example

```sh
hallpass init engagement.pass.toml      # commented template, mode 0600, approves nothing
$EDITOR engagement.pass.toml            # copy in the owner's written approval
hallpass check engagement.pass.toml     # lists every problem, with what to do
```

A historical example using a documentation address. For a live engagement, enter the window from the owner's written approval.

```toml
format = 1
id = "example-2026-11"
name = "Example voice edge"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = [5060, "10000-10100"]

[ceilings]
calls = 6
```

At 09:00 UTC on November 20, 2026, this pass produced the following results (output abbreviated).

```text
$ hallpass status engagement.pass.toml
Pass example-2026-11 "Example voice edge" (engagement.pass.toml)
Approved by: Pat Owner, Example Corp (reference: email of 2026-11-18)
Operator: Sam Tester
Window: VALID, 8 h 0 min left (2026-11-20T08:00:00Z to 2026-11-20T17:00:00Z)
Destinations:
  sip-edge         192.0.2.10               udp 5060, 10000-10100
Ceilings:
  calls            6 total, 0 spent, 6 left
Digest: sha256:…
Declared breadth: IPv4 1, IPv6 0.
Ledger: none yet (nothing spent)

$ hallpass permits engagement.pass.toml --to 192.0.2.10:5060/udp
ALLOWED: 192.0.2.10:5060/udp by destination sip-edge of pass example-2026-11 (…)

$ hallpass permits engagement.pass.toml --to 192.0.2.11:5060/udp; echo $?
REFUSED: 192.0.2.11:5060/udp: 192.0.2.11 is not in any destination of this pass; do not touch it. …
2

$ hallpass spend engagement.pass.toml calls --to 192.0.2.10:5060/udp --note "first call"
RECORDED: 1 calls for 192.0.2.10:5060/udp by destination sip-edge (1 of 6 spent, 5 left; ledger entry 1)

$ hallpass ledger engagement.pass.toml
Ledger of pass example-2026-11 (engagement.pass.toml.ledger)
    seq  time                  counter                 n  digest               details
      1  2026-11-20T09:00:00Z  calls                   1  sha256:b28f258fae01  note: first call
Totals:
  calls            1 spent of 6
Ledger: 1 line(s) after the header, chain verified, the witness matches
Current pass digest: sha256:…
```

`spend --to` checks the destination, the approval window, revocation and the
requested charges under the writer locks. A policy refusal adds no debit.
The ledger keeps the checked destination only with `--record-target`. Add it
when an audit should replay the endpoint later; see
[Retaining and checking history](#retaining-and-checking-history).
With `require_target_v1 = true`, omitting `--to` refuses the debit.
Other passes allow a targetless debit, and `spend` then warns that no
destination was checked. An owner can use
`required_counters_v1` to require several counters on every debit. Supply
their costs together, for example `--charge requests=1 --charge bytes=100`.
The sixth `spend` of `calls` succeeds and the seventh is refused (exit 2),
assuming one call per spend under the example approval. Concurrent CLI
processes sharing the ledger and witness use the same ceiling. Set
`revoked = true` in the file and the next CLI `spend` or `permits` refuses.
To change a pass that is in use, write the new version to a file in the same
directory, `chmod 600` it, and `mv` it over the old file, so that no command
reads a half-saved pass. See [Changing a pass](docs/PASS-FORMAT.md#changing-a-pass).

If the ledger goes missing after the local witness recorded a debit, hallpass
reports the missing history. Restore the ledger if available. If it was lost,
preview adoption and review the totals before recording recovery. Set
`reviewed_token` to the `token` from that preview.

```text
$ hallpass status engagement.pass.toml
hallpass status: error: the ledger engagement.pass.toml.ledger for pass `example-2026-11` is missing, but the witness ~/.local/state/hallpass/example-2026-11.witness says hallpass recorded 1 ledger line(s) for this pass id (spent: calls 1); the ledger was last seen at … Put the ledger back beside the pass …; if it is really lost, run `hallpass adopt engagement.pass.toml --reason "..."` …

$ hallpass adopt engagement.pass.toml --preview --json
…
$ hallpass adopt engagement.pass.toml --reason "original ledger lost" --token "$reviewed_token"
ADOPTED: engagement.pass.toml.ledger for pass example-2026-11 (the ledger was missing; a new one was started). Recorded as ledger entry 1 … Carried from the witness: calls 1. Spent now: calls 1.
```

Every command accepts `--json` and writes one JSON object to stdout.
**0** means the command succeeded. **2** covers a policy refusal, a verification
mismatch, a coverage gap or inconclusive evidence. **1** reports a usage,
file or accounting error. For a live debit, require exit 0 and a matching
`spend` reply with `result = "allowed"`, `test_clock = false` and a positive
`seq`. A caller can submit a durable unit reference with `--caller-ref REF --require-new-ref`
to guard against a second debit for that reference. After a lost reply or an
error marked `recorded` or `uncertain`,
reconcile the debit with the caller's run record before retrying.
[Caller response contract](docs/INTEGRATING.md#rules-for-a-command-line-caller)

In Rust, `Pass::permits` evaluates a pass already in memory at the supplied
instant. Later file edits, ledger damage and balances are outside that query.
For a counted operation, use `spend_with_clock_in` to reload the approval,
verify accounting history and record the debit. [Rust spend example](docs/INTEGRATING.md#the-library)

```rust
let loaded = hallpass::load(path)?;
let target: hallpass::Target = "192.0.2.10:5060/udp".parse().map_err(hallpass::Error::Usage)?;
match loaded.pass.permits(&target, now, hallpass::time::Duration::ZERO) {
    hallpass::Decision::Allowed { label } => println!("In scope for this snapshot: {label}"),
    hallpass::Decision::Refused(refusal) => println!("Refused: {}", refusal.message),
}
```

## Threat model

**hallpass is advisory.** It answers tools that ask it, and a tool must
obey the answer. It does not stop a tool that does not ask. It does not
filter packets, does not see traffic, and cannot tell whether a tool did
what it said. Pair it with an egress filter if you need enforcement.

What it guards against:

- **Mistakes in the approval record**: a typo in a key (unknown keys are
  errors), an ambiguous address (`010.0.0.1`, `10.1`), a host name used as
  authorization, an IPv4 address hidden in IPv6 (`::ffff:192.0.2.1`, and
  the 6to4, Teredo, ISATAP and SIIT forms), the broadcast address of a
  listed network, "any"
  (`0.0.0.0/0`), a network far wider than the owner's service (breadth
  cap), a time without an offset.
- **Testing outside the window or after revocation**: the CLI's `permits` and `spend`
  check the window and the `revoked` marker each time; `spend` re-reads the
  pass from disk under its lock.
- **Ceilings that only hold per command**: the ledger beside the pass makes
  a ceiling hold across commands and concurrent processes.
- **A pass that changed mid-run**: the digest identifies the exact file;
  `spend --digest` refuses if it changed.
- **A pass read while it is being saved**: a pass modified in the last
  quarter second is read again once it has gone that long unchanged, and refused as
  `invalid-pass` if it changed meanwhile. A pass whose last line has no
  newline is refused too.
- **Damaged state**: CLI `permits` and `spend` return an error if the pass
  is unreadable or the ledger fails verification.
- **A lost, replaced or rewound ledger**: a small witness in
  `~/.local/state/hallpass/` (or `$XDG_STATE_HOME/hallpass/`) records each
  ledger's last witnessed sequence, hash and totals. A ledger lost in a copy or a `git clean`, a pass
  moved without its ledger, an older copy put back, or an edited last line
  is refused until it is restored or adopted with
  `hallpass adopt FILE --reason TEXT`, which is recorded in the ledger and
  keeps the count.
- **File permissions and links**: the final path component for the pass or
  ledger must be a regular file. Keep their parent directories trusted.
  The pass must belong to the effective user or root and disallow group
  and other writes. The ledger must disallow all group and other access.

What it does not guard against:

- a tool that does not ask, or ignores the answer;
- a determined operator: they own the pass, the ledger and the witness,
  and can edit or delete all of them consistently. The witness catches
  accidents and casual edits, not a deliberate cheat;
- the same pass used from two machines or user accounts (each has its own
  witness);
- a wrong system clock (the window uses the decision clock; status, permits and spends warn if it is strictly earlier than the latest time recorded in the ledger);
- a save over the pass that pauses for more than a quarter second part-way:
  replace the pass with `mv`, and pin the digest (`--digest`) when
  spending while the owner may change the pass;
- network file systems where `flock` is unreliable;
- what happens inside a long step after a tool has asked (revocation takes
  effect at the next question).

More in [docs/DESIGN.md](docs/DESIGN.md), "Residual risks".

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --no-default-features
cargo test --release --features test-clock
cargo test --release --test cli release_build_ignores_the_test_clock
python3 docs/conformance/check.py
cargo doc --no-deps
```

The integration tests set the clock with `HALLPASS_UNSAFE_TEST_CLOCK`,
which only debug builds and `--features test-clock` honour. Every test
points `XDG_STATE_HOME` and `HOME` (or the library's `StateDir`) at a
temporary directory, so the suite never touches your real witnesses.

## Retaining and checking history

For lost spend replies, historical endpoint audits and ledger backup comparison, see [Reading accounting evidence](docs/EVIDENCE.md).

Create a private archive directory, then retain the exact approved pass bytes
with the owner's signature, and keep the checked target with each spend:

```sh
mkdir -m 700 approval-archive
hallpass verify-approval engagement.pass.toml --signature engagement.pass.toml.sig \
  --allowed-signers trusted_signers --principal owner@example.org --archive approval-archive
hallpass spend engagement.pass.toml calls --to 192.0.2.10:5060/udp --record-target
hallpass audit-receipts engagement.pass.toml approval-archive \
  --allowed-signers trusted_signers --principal owner@example.org
hallpass --format json ledger engagement.pass.toml
hallpass retrieve approval-archive "$reviewed_digest" --output reviewed-pass.toml
hallpass --format json checkpoint engagement.pass.toml > checkpoint.json
```

Use the full pass digest from the ledger entry as `reviewed_digest`.
`--output FILE` creates the file with mode 0600 and refuses an existing file or a link; a `>` redirect would use your umask, and under `umask 002` the 0664 file is one `diff` and `archive` refuse.
Retain the checkpoint separately with the report. `retrieve` in text mode writes
exact original UTF-8 bytes, including comments and the original ending; JSON
mode instead emits metadata and a JSON string. The archive is user-owned and
may contain sensitive approval text. Its directory must be private and its
entries private regular files. Archive retention is opt-in and ordinary spends
do not depend on it. A matching digest identifies bytes, not who approved them.
`hallpass archive engagement.pass.toml approval-archive` stores the bytes
without a signature: an audit then puts every debit decided under them in an
`approval-unverified` gap and is not `complete`. The audit verifies each
recorded signature again only with `--allowed-signers` and a trusted signers
file you control; without it no audit is `complete`. That file decides whose
keys count. `--principal` decides who must have approved: name the owner, or
the audit is not `complete` either, because each record names its own
principal. An audit verifies each signature as of the time its revision was
first used, so a key that expired later still counts. Signing is in
[Signing and verifying an approval](docs/INTEGRATING.md#signing-and-verifying-an-approval),
and what an audit proves is in [EVIDENCE.md](docs/EVIDENCE.md#what-an-audit-proves).

In a separate account, verify a ledger without creating a witness:

```sh
hallpass --format json verify-checkpoint engagement.pass.toml.ledger checkpoint.json
```

`exact` and `extended` exit 0; `mismatch` exits 2; malformed inputs, missing
files or damaged ledgers exit 1. Verification trusts the supplied checkpoint:
a checkpoint copied from the same rewritten files does not establish independent
provenance. Keep it outside the ledger's administrative control.

When restoring an older ledger, inspect its carry-forward before recording the
recovery. The preview creates no ledger or witness; its token represents a
snapshot that may become stale:

```sh
hallpass --format json adopt engagement.pass.toml --preview
hallpass adopt engagement.pass.toml --reason 'restored from backup' --token "$reviewed_token"
```

A stale token is refused. Obtain and review a fresh preview. If a witness update
fails after an adoption was appended, inspect the ledger before retrying: the
adoption is already recorded.
