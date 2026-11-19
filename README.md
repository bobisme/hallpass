# hallpass

A pass is the written permission slip for an authorized test: who approved
it, which literal network destinations may be touched, from when until
when, and how much. hallpass reads a pass, says whether something is
permitted right now, and keeps count of what has been spent, across
processes.

It is a Rust library and a command line tool (`hallpass`). Rust tools use
the library; other tools run the command with `--format json`.

The whole project in one page: [docs/spec.md](docs/spec.md). The file
format: [docs/PASS-FORMAT.md](docs/PASS-FORMAT.md). Why it is built this
way: [docs/DESIGN.md](docs/DESIGN.md).

## Build

```sh
cargo build --release
cp target/release/hallpass ~/.local/bin/   # or run it from target/release
```

Linux and other Unix systems only (it relies on Unix file modes and
`flock`).

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

$ hallpass permits engagement.pass.toml --to 192.0.2.10:5060/udp
ALLOWED: 192.0.2.10:5060/udp by destination sip-edge of pass example-2026-11 (…)

$ hallpass permits engagement.pass.toml --to 192.0.2.11:5060/udp; echo $?
REFUSED: 192.0.2.11:5060/udp: 192.0.2.11 is not in any destination of this pass; do not touch it. …
2

$ hallpass spend engagement.pass.toml calls --note "first call"
RECORDED: 1 calls (1 of 6 spent, 5 left; ledger entry 1)

$ hallpass ledger engagement.pass.toml
Ledger of pass example-2026-11 (engagement.pass.toml.ledger)
    seq  time                  counter                 n  digest               note
      1  2026-11-20T09:00:00Z  calls                   1  sha256:789b8599fd63  first call
Totals:
  calls            1 spent of 6
Chain verified: 1 entries, every line follows the one before it.
Current pass digest: sha256:…
```

The sixth `spend` of `calls` succeeds and the seventh is refused (exit 2),
whether the seven spends come from one process, seven commands, or two
terminals at once. Set `revoked = true` in the pass and the next `spend` or
`permits` from any tool is refused.

Exit codes: **0** ok or allowed, **2** refused by the pass, **1** any other
error (unreadable or invalid pass, damaged ledger, bad arguments). Every
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
  authorization, an IPv4 address hidden in IPv6 (`::ffff:192.0.2.1`), "any"
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
- **Link tricks**: the pass and the ledger are never read through a
  symbolic link; a pass writable by others and a ledger readable by others
  are refused.

What it does not guard against:

- a tool that does not ask, or ignores the answer;
- someone with write access to the engagement directory: they can edit the
  pass, delete the ledger (which resets the count), or rewrite it
  consistently;
- a wrong system clock (the window uses the caller's clock);
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
which only debug builds and `--features test-clock` honour.
