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
| Review an owner's signed approval or proposed scope edits | `verify-approval`, `diff --examples --at TIMESTAMP` |
| Check whether a consumer covers every restriction | `consumer-coverage` |
| See where a sequence of debits would first exceed a budget | `rehearse` |
| Reconcile a lost spend reply or replay a receipt against its approval | `receipt`, `audit-receipts` |
| Find backups containing the last witnessed ledger entry | `compare-backups` |

## Two-minute example

```sh
hallpass init engagement.pass.toml      # commented template, mode 0600, approves nothing
$EDITOR engagement.pass.toml            # copy in the owner's written approval
hallpass check engagement.pass.toml     # lists every problem, with what to do
```

A filled-in pass (documentation addresses):

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

During the window:

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
Ledger: none yet (nothing spent)

$ hallpass permits engagement.pass.toml --to 192.0.2.10:5060/udp
ALLOWED: 192.0.2.10:5060/udp by destination sip-edge of pass example-2026-11 (…)

$ hallpass permits engagement.pass.toml --to 192.0.2.11:5060/udp; echo $?
REFUSED: 192.0.2.11:5060/udp: 192.0.2.11 is not in any destination of this pass; do not touch it. …
2

$ hallpass permits web.pass.toml --to 198.51.100.7:443/tcp --name other.example.org; echo $?
REFUSED: 198.51.100.7:443/tcp as other.example.org: … is not approved for the name other.example.org, only for: web (app.example.com). …
2

$ hallpass spend engagement.pass.toml calls --to 192.0.2.10:5060/udp --note "first call"
RECORDED: 1 calls for 192.0.2.10:5060/udp by destination sip-edge (1 of 6 spent, 5 left; ledger entry 1)

$ hallpass ledger engagement.pass.toml
Ledger of pass example-2026-11 (engagement.pass.toml.ledger)
    seq  time                  counter                 n  digest               note
      1  2026-11-20T09:00:00Z  calls                   1  sha256:789b8599fd63  first call
Totals:
  calls            1 spent of 6
Ledger: 1 line(s) after the header, chain verified, the witness matches
Current pass digest: sha256:…
```

`spend --to` decides the destination, the window and the ceiling in one
step and records nothing when any of them refuses; without `--to` it checks
only the window and the ceiling.
The sixth `spend` of `calls` succeeds and the seventh is refused (exit 2),
whether the seven spends come from one process, seven commands, or two
terminals at once. Set `revoked = true` in the pass and the next `spend` or
`permits` from any tool is refused.

If the ledger goes missing (left behind in a copy, deleted by a cleanup),
hallpass does not start again from 0:

```text
$ hallpass status engagement.pass.toml
hallpass status: error: the ledger engagement.pass.toml.ledger for pass `example-2026-11` is missing, but the witness ~/.local/state/hallpass/example-2026-11.witness says hallpass recorded 1 ledger line(s) for this pass id (spent: calls 1); the ledger was last seen at … Put the ledger back beside the pass …; if it is really lost, run `hallpass adopt engagement.pass.toml --reason "..."` …

$ hallpass adopt engagement.pass.toml --reason "ledger lost when the laptop was reimaged"
ADOPTED: engagement.pass.toml.ledger for pass example-2026-11 (the ledger was missing; a new one was started). Recorded as ledger entry 1 … Carried from the witness: calls 1. Spent now: calls 1.
```

Exit codes: **0** ok or allowed, **2** refused by the pass, **1** any other
error (unreadable or invalid pass, damaged, lost or changed ledger, bad
arguments). Every
command takes `--format json` and then prints one JSON object on standard
output; [docs/spec.md](docs/spec.md) lists the fields.

From Rust:

```rust
let loaded = hallpass::load(path)?;
let target: hallpass::Target = "192.0.2.10:5060/udp".parse().map_err(hallpass::Error::Usage)?;
match loaded.pass.permits(&target, now, hallpass::time::Duration::ZERO) {
    hallpass::Decision::Allowed { label } => { /* go, and record `label` and `loaded.digest` */ }
    hallpass::Decision::Refused(refusal) => { /* do not send; show refusal.message */ }
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
- **Testing outside the window or after revocation**: `permits` and `spend`
  check the window and the `revoked` marker each time; `spend` re-reads the
  pass from disk under its lock.
- **Ceilings that only hold per command**: the ledger beside the pass makes
  a ceiling hold across commands and concurrent processes.
- **A pass that changed mid-run**: the digest identifies the exact file;
  `spend --digest` refuses if it changed.
- **Damaged state**: an unreadable pass or a damaged ledger permits
  nothing. It is never treated as empty.
- **A lost, replaced or rewound ledger**: a small witness in
  `~/.local/state/hallpass/` (or `$XDG_STATE_HOME/hallpass/`) records each
  ledger's last line. A ledger lost in a copy or a `git clean`, a pass
  moved without its ledger, an older copy put back, or an edited last line
  is refused until it is restored or adopted with
  `hallpass adopt FILE --reason TEXT`, which is recorded in the ledger and
  keeps the count.
- **Link tricks**: the pass and the ledger are never read through a
  symbolic link; a pass owned by anyone except the effective user or root, a pass writable by group/others, and a ledger readable by others
  are refused.

What it does not guard against:

- a tool that does not ask, or ignores the answer;
- a determined operator: they own the pass, the ledger and the witness,
  and can edit or delete all of them consistently. The witness catches
  accidents and casual edits, not a deliberate cheat;
- the same pass used from two machines or user accounts (each has its own
  witness);
- a wrong system clock (the window uses the decision clock; status and spends warn if it is strictly earlier than the last ledger event);
- network file systems where `flock` is unreliable;
- what happens inside a long step after a tool has asked (revocation takes
  effect at the next question).

More in [docs/DESIGN.md](docs/DESIGN.md), "Residual risks".

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```

The integration tests set the clock with `HALLPASS_UNSAFE_TEST_CLOCK`,
which only debug builds and `--features test-clock` honour. Every test
points `XDG_STATE_HOME` and `HOME` (or the library's `StateDir`) at a
temporary directory, so the suite never touches your real witnesses.

### Retaining and checking history

For lost spend replies, historical endpoint audits and ledger backup comparison, see [Reading accounting evidence](docs/EVIDENCE.md).

Create a private archive directory, then retain the exact approved pass bytes:

```sh
mkdir -m 700 approval-archive
hallpass archive engagement.toml approval-archive
hallpass --format json ledger engagement.toml
hallpass retrieve approval-archive sha256:REPLACE_WITH_FULL_LEDGER_DIGEST > reviewed-pass.toml
hallpass --format json checkpoint engagement.toml > checkpoint.json
```

Retain the checkpoint separately with the report. `retrieve` in text mode writes
exact original UTF-8 bytes, including comments and the original ending; JSON
mode instead emits metadata and a JSON string. The archive is user-owned and
may contain sensitive approval text. Its directory must be private and its
entries private regular files. Archive retention is opt-in and ordinary spends
do not depend on it. A matching digest identifies bytes, not who approved them.

In a separate account, verify a ledger without creating a witness:

```sh
hallpass --format json verify-checkpoint engagement.toml.ledger checkpoint.json
```

`exact` and `extended` exit 0; `mismatch` exits 2; malformed inputs, missing
files or damaged ledgers exit 1. Verification trusts the supplied checkpoint:
a checkpoint copied from the same rewritten files does not establish independent
provenance. Keep it outside the ledger's administrative control.

When restoring an older ledger, inspect its carry-forward before recording the
recovery. The preview creates no ledger or witness; its token represents a
snapshot that may become stale:

```sh
hallpass --format json adopt engagement.toml --preview
hallpass adopt engagement.toml --reason 'restored from backup' --token 'v1:sha256:REPLACE_WITH_PREVIEW_TOKEN'
```

A stale token is refused. Obtain and review a fresh preview. If a witness update
fails after an adoption was appended, inspect the ledger before retrying: the
adoption is already recorded.
