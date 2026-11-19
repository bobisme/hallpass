# hallpass specification

This page describes what hallpass does at the current commit. Anything not
yet built is marked **planned**. The exact file format is in
[PASS-FORMAT.md](PASS-FORMAT.md); the reasons behind the decisions are in
[DESIGN.md](DESIGN.md).

## Purpose

An authorized test needs a written permission from the owner of what is
tested. hallpass turns that permission into a file that tools can check: it
reads the file, decides whether a given destination is permitted at a given
time, and counts what has been spent against the owner's ceilings, so that
a ceiling holds across commands and concurrent processes.

It is protocol-neutral. A tool that sends SIP, HTTP or anything else asks
the same questions.

### Non-goals

- **Enforcement.** hallpass is advisory. It answers tools that ask; it does
  not stop a tool that does not ask, and it sees no traffic.
- **Name resolution.** hallpass never resolves a host name and never
  accepts one as authorization.
- **Storing secrets.** A pass holds no credentials.
- **Signing or proving approval.** A pass records the reference to the
  written approval; it is not cryptographic proof of it.
- **Managing many passes.** One file is one approval.

## Concepts

- **Pass**: a TOML file recording one approval: id, name, approval,
  destinations, ceilings.
- **Owner**: the person or organization that approved the test and owns the
  destinations (`approval.owner`). The **operator** is who runs the test;
  the **reference** says where the written approval is.
- **Window**: the interval from `valid_from` (inclusive) to `valid_until`
  (exclusive), plus the `revoked` marker that ends it early.
- **Destination**: one labelled entry allowing a literal IP address or CIDR
  network, one protocol (`tcp` or `udp`), and a set of ports.
- **Target**: what a tool is about to touch: one address, one port, one
  protocol (`192.0.2.10:5060/udp`, `[2001:db8::1]:443/tcp`).
- **Ceiling**: a named counter with a total (`calls = 6`). Each tool
  defines its own units.
- **Ledger**: the append-only file beside the pass that records every
  spend.
- **Digest**: `sha256:` plus the SHA-256 of the pass file's exact bytes.

## The pass file (summary)

```toml
format = 1
id = "example-2026-11"            # the ledger belongs to this id
name = "Example voice edge"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z  # RFC 3339, offset required
valid_until = 2026-11-20T17:00:00Z
revoked = false                    # required; revoked_reason optional

[[destination]]                    # one or more
label = "sip-edge"
address = "192.0.2.10"             # or network = "192.0.2.0/28"
protocol = "udp"
ports = [5060, "10000-10100"]
hostname = "sip.example.net"       # informational; grants nothing

[ceilings]                         # optional
calls = 6
```

Validation rules, all reported together with field paths
([PASS-FORMAT.md](PASS-FORMAT.md) has the full list):

- unknown keys are errors in every table;
- addresses in canonical spelling only; refused: host names, IPv4 leading
  zeros and shortened forms, zones, non-canonical IPv6, IPv6 forms carrying
  IPv4 (mapped, compatible, NAT64), unspecified, multicast, broadcast,
  `240.0.0.0/4`, link-local; networks with host bits set or overlapping any
  refused range; loopback only when listed;
- networks broader than /24 (IPv4) or /64 (IPv6) need
  `whole_network_approved = true`; broader than /8 or /32 is always refused;
- ports 1-65535, ranges `"start-end"`; protocols `tcp`, `udp`;
- ceiling names `[a-z][a-z0-9_-]{0,31}`, totals 0 to 10^12, at most 64;
- the file: UTF-8, at most 1 MiB, regular file, not a symbolic link, not
  writable by group or others.

## Decision rules

All decisions take `now` from the caller.

### Window state

Evaluated in this order:

1. `revoked = true` → **revoked** (with `revoked_reason` if recorded).
2. `now < valid_from` → **not-yet-valid**, with the time until it opens.
3. `now >= valid_until` → **expired**, with the time since it ended.
4. otherwise → **valid**, with the time remaining (`valid_until - now`).

`check_window(now, needed)` permits only the valid state, and additionally
refuses **window-too-short** when `needed > 0` and the time remaining is
`<= needed`.

### `permits(target, now, needed)`

In this order, stopping at the first refusal:

1. the window, as `check_window(now, needed)`: `revoked`, `not-yet-valid`,
   `expired`, `window-too-short`;
2. a target address that is an IPv6 form carrying IPv4 (mapped, compatible,
   NAT64) → `embedded-ipv4` (ask with the IPv4 address);
3. the first destination, in file order, whose network contains the
   address, whose protocol matches and whose ports contain the port →
   **allowed**, naming that destination's label;
4. some destination contains the address but none with this protocol and
   port → `port-not-listed` (the message lists what is allowed for it);
5. otherwise → `address-not-listed`.

### `spend(pass, counter, n, note, expected digest, needed, now)`

1. Request checks, before any file is touched: `n` from 1 to 10^12, note one
   line of at most 500 characters. Failure is a usage error.
2. Load and validate the pass. Create the ledger with its header if it does
   not exist.
3. Open the ledger (not a link, mode exactly private: no group or other
   bits) and take an exclusive lock.
4. Under the lock: load and validate the pass again from disk; read and
   verify the whole ledger.
5. Refuse, recording nothing, in this order: `pass-changed` (an expected
   digest was given and differs), the window rules (`revoked`,
   `not-yet-valid`, `expired`, `window-too-short`), `unknown-counter` (not
   in `[ceilings]`), `ceiling-reached` (spent + n > total).
6. Otherwise append one entry (time, counter, n, digest of the pass as just
   read, note, sequence number, hash of the previous line), sync it to disk,
   and release the lock. The spend is confirmed only after the sync.

Two processes spending at once never together exceed the total.

### When the pass is edited

- The spent amount of a counter is the sum of all ledger entries with that
  counter name, whatever digest they carry. A raised total takes effect at
  once; a lowered total leaves `max(0, total - spent)`; no edit resets the
  count.
- A counter removed from the pass can no longer be spent; `status` lists
  its earlier spends under `unlisted_spends`.
- A changed `id` makes the ledger foreign: every spend and `status` fails
  with `ledger-foreign` until the id is restored or a new pass file is used.
- The digest changes with any byte; a caller that passed `--digest` gets
  `pass-changed`.

### Fail-closed cases

Each of these is an error (exit 1), permits nothing, and records nothing:

| Case | Code |
|---|---|
| the pass or ledger file is missing, unreadable, or fails to write | `io` |
| the pass or ledger path is a symbolic link (also if swapped in while opening) | `symlink` |
| the path is not a regular file | `not-regular-file` |
| the pass is larger than 1 MiB | `too-large` |
| the pass is writable by group or others; the ledger has any group or other bit | `insecure-permissions` |
| the pass does not validate (every problem listed) | `invalid-pass` |
| the ledger is empty, has a cut last line, an unreadable line, a sequence gap, a broken hash chain, an invalid field, or sums beyond 10^12 | `ledger-corrupt` |
| the ledger's pass id differs from the pass's | `ledger-foreign` |
| `init` target already exists (also a dangling link) | `exists` |
| bad arguments: malformed `--to`, `--digest`, `--n 0`, a bad note, a malformed test clock | `usage` |

A missing ledger is not an error: it means nothing was spent.

## Command line

```text
hallpass [--format text|json] <command>
  init FILE
  check FILE
  status FILE
  permits FILE --to ADDR:PORT/PROTO [--duration SECONDS]
  spend FILE COUNTER [--n N] [--note TEXT] [--digest DIGEST] [--duration SECONDS]
  digest FILE
```

Exit codes: **0** ok or allowed; **2** refused by the pass; **1** any other
error, including command-line usage errors. Text output goes to standard
output, except errors, which go to standard error. With `--format json`
every command prints one JSON object on standard output, errors included,
except command-line parse errors (unknown command, missing argument), which
print the parser's text on standard error with exit 1.

| Command | Exit 0 | Exit 2 | Exit 1 |
|---|---|---|---|
| `init` | template written (mode 0600; it does not validate until filled in) | never | file exists, write failed |
| `check` | the pass validates | never | any problem |
| `status` | the window is valid | not-yet-valid, expired or revoked | invalid pass, ledger error |
| `permits` | allowed | refused | invalid pass or target |
| `spend` | recorded | refused, nothing recorded | any error, nothing recorded |
| `digest` | printed | never | invalid pass |

`check` does not judge the window; `status` does.

### JSON fields

Every object has `command` and `result` (`ok`, `allowed`, `refused`,
`error`) and `file`.

- **error** (any command): `error` `{code, message}`, `problems` (list of
  `{field, message}`, empty unless `invalid-pass`).
- **init**: no more fields.
- **check**: `digest`, `pass_id`, `problems` (empty).
- **status**: `digest`, `now`, `test_clock`, `pass` `{id, name, owner,
  reference, operator}`, `window`, `destinations` (list of `{label, kind`
  (`address` or `network`)`, destination, protocol, ports` (list of `{start,
  end}`)`, ports_text, hostname, whole_network_approved}`), `counters` (list
  of `{name, total, spent, remaining}`), `unlisted_spends` (list of `{name,
  spent}`), `refusal` (`{code, message}` or null).
- **permits**: `digest`, `pass_id`, `now`, `test_clock`, `target`
  (normalized), `label` (or null), `refusal` (or null), `window`.
- **spend**: `digest`, `pass_id`, `now`, `test_clock`, `counter`, `n`,
  `total` (null for an unknown counter), `spent` (after the spend if
  recorded, else current), `remaining` (or null), `seq` (the new entry's
  sequence number, or null), `note`, `refusal` (or null).
- **digest**: `digest`, `pass_id`.

`window` is `{state, valid_from, valid_until, seconds_remaining,
seconds_until_open, seconds_since_end, revoked_reason}`; `state` is
`not-yet-valid`, `valid`, `expired` or `revoked`; the three `seconds_*`
fields are null except the one that applies. Times are UTC, whole seconds,
`YYYY-MM-DDTHH:MM:SSZ`.

Refusal codes: `not-yet-valid`, `expired`, `revoked`, `window-too-short`,
`embedded-ipv4`, `address-not-listed`, `port-not-listed`,
`unknown-counter`, `ceiling-reached`, `pass-changed`.

### Test clock

`HALLPASS_UNSAFE_TEST_CLOCK=<RFC 3339>` replaces "now" for `status`,
`permits` and `spend`, only in debug builds and builds with the
`test-clock` feature. When used, a warning goes to standard error and
`test_clock` is `true`. Release builds ignore it and say so on standard
error.

## Library API

Crate `hallpass` (re-exports `time`):

| Item | Purpose |
|---|---|
| `load(path) -> Result<LoadedPass, Error>` | read (no links, mode checks), validate, digest |
| `LoadedPass { pass, digest, path }` | |
| `Pass { id, name, approval, destinations, ceilings }` | validated pass; `Pass::parse(text)` returns all `Problem`s |
| `Pass::window_at(now) -> WindowState` | window state |
| `Pass::check_window(now, needed) -> Result<(), Refusal>` | window rule |
| `Pass::permits(&Target, now, needed) -> Decision` | `Allowed { label }` or `Refused(Refusal)` |
| `Pass::destination_for(ip, port, protocol)` | the matching destination, window not checked |
| `spend(path, &SpendRequest, now) -> Result<SpendOutcome, Error>` | atomic spend; `SpendOutcome.refusal` is `None` when recorded |
| `tally(&LoadedPass) -> Result<Tally, Error>` | spent per counter, under a shared lock |
| `ledger_path(path)` | `<pass>.ledger` |
| `write_template(path)`, `TEMPLATE` | `init` |
| `parse_address`, `parse_network`, `embedded_ipv4`, `Target` (`FromStr`), `Network`, `Protocol`, `PortSet` | strict parsing |
| `Digest` (`Display`/`FromStr` as `sha256:<hex>`), `Refusal`, `RefusalCode`, `WindowState`, `Problem`, `Error` (with `code()`) | value types |
| `stamp`, `span` | time formatting used in messages |
| constants: `FORMAT_VERSION`, `IPV4_CAP`, `IPV6_CAP`, `IPV4_FLOOR`, `IPV6_FLOOR`, `MAX_CEILING`, `MAX_COUNTERS`, `MAX_DESTINATIONS`, `MAX_NOTE`, `MAX_PASS_BYTES` | documented limits |

The library is Unix-only.

Cargo features: `cli` (on by default) builds the `hallpass` binary and is
the only user of clap. A program that uses only the library depends on
hallpass with `default-features = false` (playpen does). `test-clock` is
described under "Test clock"; it affects only the binary.

## Threat model and known limits

hallpass protects against mistakes and drift in the approval record and
its use: typos (unknown keys), ambiguous or smuggled addresses, names used
as authorization, over-broad networks, offset-less times, testing outside
the window or after revocation, ceilings that only hold per command, a pass
changed mid-run (digest), damaged state (fail closed) and link tricks on
the pass and ledger.

It does not protect against: a tool that does not ask or ignores the
answer; anyone who can write the engagement directory (they can edit the
pass, delete or rewrite the ledger; deleting the ledger or moving the pass
resets the count; the last ledger entry can be altered undetected); a wrong
system clock; unreliable `flock` on network file systems; symbolic links in
parent directories; directed broadcast addresses inside a listed network;
relay-embedding IPv6 (6to4, Teredo); and work already running when a pass
is revoked. [DESIGN.md](DESIGN.md) explains each.

## Not yet built (planned)

- **Consumers.** Built: the playpen egress guard consumes passes through
  the library (`playpen run --pass FILE`). It loads the pass with `load`,
  refuses to start unless `check_window(now, 0)` passes, allows exactly the
  destinations (optionally narrowed by label), ends the run at
  `valid_until`, and re-reads the pass every few seconds to stop the
  command when it is revoked, expired, unreadable, invalid or a destination
  in use changes. playpen does not spend: it limits where packets go, not
  how many. Planned: the SIP assessment toolbox calling `hallpass ...
  --format json` before each send and `spend` per call; the web tester
  using the library per request.
- **A ledger inspection command** (planned): listing entries; today read
  the JSON Lines file directly.
- **Protocols beyond tcp and udp**, and link-local destinations with an
  interface field: would need a new format version; not planned in detail.
