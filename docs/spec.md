# hallpass specification

This page describes what hallpass does at the current commit. Anything not
yet built is marked **planned**. The exact file format is in
[PASS-FORMAT.md](PASS-FORMAT.md); the reasons behind the decisions are in
[DESIGN.md](DESIGN.md).

## Approval review

`hallpass diff OLD NEW` is read-only and compares declared fields, printing
both byte digests. It normalizes port ranges, distinguishes informational
`hostname` from enforced `names`, reports destination additions/removals and
order changes, and flags uncertain containment for owner review. It never
authorizes a spend. `hallpass lint PASS` reports named rules overlapping
nameless rules for the same address family, protocol, and ports; each claimed
effective allowance is replayed through `permits_named` at the supplied time.
Lint reports at most 256 findings and indicates when it truncated the list.

`diff OLD NEW --examples --at TIMESTAMP` adds a bounded sample of changed
destination decisions using the ordinary evaluator at the supplied offset
timestamp. The report retains the field diff and review flags. Each
`examples.rows` entry includes the target, optional name, instant and
before/after label or refusal code. `examples.candidates` counts visits,
`evaluated` counts distinct requests, and `truncated` signals omitted work.
Sampling ends after 512 visits or 64 changed rows.

`consumer-coverage PASS --can CAPABILITY` compares the full validated approval
with declared checks for literal endpoints, names, time and revocation, and
each charged counter. The response identifies its `pass_id`, `digest`,
`declared` features and individual `findings`. The operator supplies the
declaration. Live decisions and charges happen independently.

`verify-approval` uses OpenSSH detached signatures under the fixed namespace
`hallpass-approval-v1`. A verified result includes the expected principal,
pass ID and digest of the exact bytes supplied to the verifier. The operator
provisions the trust file and selects the principal. See the signing and
digest-pinning workflow in the [integration guide](INTEGRATING.md).

`hallpass test-pass PASS SUITE` checks up to 1,024 ordered cases offline.
Exit 0 means all cases matched, 2 means an expectation differed, and 1 means
invalid input or an error. See the [example suite](review-suite.toml).

`check` and `status` report exact declared address-space unions separately for
IPv4 and IPv6. Duplicate and nested service rules count once. One IPv4 `/8`
and one IPv6 `/64` are documented consumer comparison points; they are
advisory only and do not change existing validation caps.

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
- **Issuing approvals.** The owner creates the written approval and distributes
  their public key through an independent trust channel. The optional offline
  `verify-approval` command verifies a detached SSH signature over a pass.
  Ordinary loading and live decisions use the pass and any supplied digest pin.
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
  spend (and every adoption).
- **Witness**: a small record per pass id in the user's state directory,
  outside the pass directory: the ledger's last sequence number, the hash
  of its last line, the totals, and where the ledger was. It lets hallpass
  notice a lost, replaced or rewound ledger.
- **State directory**: `$XDG_STATE_HOME/hallpass/`, or
  `$HOME/.local/state/hallpass/` when `XDG_STATE_HOME` is unset, empty or
  not an absolute path. Created mode 0700; witness and lock files 0600.
- **Adoption**: an operator's recorded acknowledgment, with a reason, of a
  ledger that was lost, changed outside hallpass, or had no witness.
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
  IPv4 (mapped, compatible, NAT64, and the transition forms 6to4, Teredo,
  ISATAP, SIIT-translated), unspecified, multicast, broadcast,
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

### `permits(target, now, needed)` and `permits_named(target, name, now, needed)`

`permits` is `permits_named` with no name.

In this order, stopping at the first refusal:

1. the window, as `check_window(now, needed)`: `revoked`, `not-yet-valid`,
   `expired`, `window-too-short`;
2. a target address that is an IPv6 form carrying IPv4 (mapped, compatible,
   NAT64, 6to4 `2002::/16`, Teredo `2001::/32`, an ISATAP interface
   identifier `…:0:5efe:a.b.c.d` or `…:200:5efe:a.b.c.d` under any prefix,
   SIIT-translated `::ffff:0:0:0/96`) → `embedded-ipv4`; the message names
   the IPv4 address (for Teredo, the client's);
3. the network address or the all-ones (directed broadcast) address of a
   listed IPv4 network of /30 or broader → `network-or-broadcast`, unless
   some destination lists that address on its own (`address`, or a /32
   network); /31 and /32 networks have no such addresses;
4. the first destination, in file order, whose network contains the
   address, whose protocol matches and whose ports contain the port →
   and which either lists no `names` or lists the query's name →
   **allowed**, naming that destination's label;
5. some destination matches the address, protocol and port, but each one
   lists `names` and none lists the query's name → `name-required` when the
   query has no name, `name-not-listed` when it has one (the message lists
   the approved names);
6. some destination contains the address but none with this protocol and
   port → `port-not-listed` (the message lists what is allowed for it);
7. otherwise → `address-not-listed`.

A name never grants: it is looked at only after the address, protocol and
port matched. Names compare in canonical form (ASCII lower case, no
trailing dot); the pass must spell them that way, a query need not.

### `spend(pass, counter, n, note, expected digest, needed, target, name, now)`

With a target, one spend answers "may I send this much to this destination
now, and count it". On a pass with `require_target_v1 = true`, every debit
must supply at least one target. The request name follows the destination rules.

1. Request checks, before any file is touched: `n` from 1 to 10^12, note one
   line of at most 500 characters with no control character (newline, tab,
   escape, C1 controls), no Unicode line or paragraph separator (U+2028,
   U+2029) and no bidirectional control (U+061C, U+200E, U+200F,
   U+202A-U+202E, U+2066-U+2069). Failure is a usage error. (Reading a
   ledger accepts notes that only avoid control characters, the 0.1 rule.)
   A name without a target, a negative `needed`, and a `now` outside the
   years 0001 to 9999 in UTC are usage errors too.
2. Load and validate the pass. Find the state directory, create it if
   needed (0700), check that it is a private directory and writable, and
   take an exclusive lock on `<pass id>.lock` in it. Read the witness.
3. If the ledger does not exist: when the witness records any line,
   `ledger-missing` (nothing is created); otherwise create the ledger with
   its header.
4. Open the ledger (not a link, mode exactly private: no group or other
   bits) and take an exclusive lock.
5. Under both locks: load and validate the pass again from disk (its id
   must not have changed); read and verify the whole ledger; compare it with
   the witness (see "The witness"). A ledger that does not hold the
   witnessed line is `ledger-changed`. When there was no witness, or the
   witness saw the ledger at another path or fewer lines ago, write the
   witness now, with a warning.
6. Refuse, recording nothing in the ledger, in this order: `pass-changed`
   (an expected digest was given and differs), the window rules (`revoked`,
   `not-yet-valid`, `expired`, `window-too-short`), when a target was given
   every refusal of `permits` for it, with the name and `needed`
   (`embedded-ipv4`, `network-or-broadcast`, `address-not-listed`,
   `port-not-listed`, `name-required`, `name-not-listed`),
   `target-required` (an owner-required destination was omitted),
   `required-counter-missing` (the debit omitted an owner-required charge),
   `unknown-counter` (not in `[ceilings]`), `ceiling-reached` (spent + n >
   total). The destination is decided against the pass as read under the
   locks, the same reading the entry's digest names.
7. Otherwise append one entry (time, counter, n, digest of the pass as just
   read, note, sequence number, hash of the previous line), sync it to disk,
   then replace the witness (written aside, synced, renamed), and release
   both locks. The spend is confirmed only after both. If the witness cannot
   be written after the entry was, the result is `witness-not-updated`: the
   spend counts, but the caller is told not to proceed.

Two processes spending at once never together exceed the total. Writers
always lock the witness first and the ledger second; readers take only a
shared lock on the ledger and read the witness, which is replaced
atomically.

### The witness

After every recorded spend or adoption the witness for the pass id holds
the ledger's last sequence number, the SHA-256 of its last line, the totals
per counter, the ledger's resolved path and the time. Every command that
reads the ledger (`status`, `permits`, `spend`, `ledger`, `adopt`) compares:

| Ledger | Witness | Result |
|---|---|---|
| missing | none, or no lines recorded | nothing spent (`fresh`) |
| missing | records lines | **error `ledger-missing`**, naming the witnessed totals, where the ledger was last seen and when, and what to do |
| present | none | accepted with a warning (`missing`); `spend` records a witness |
| present | its line `seq` hashes to the witnessed hash, and nothing follows | `matches` |
| present | the witnessed line is there, and `k` lines follow | accepted with a warning (`extended`): a run stopped between the ledger and the witness, or a hallpass without witnesses added lines; they count |
| present | the witnessed line is not there (a different line at that position, or fewer lines) | **error `ledger-changed`**, saying which, and naming another ledger of the same id if one exists where the witness saw it |
| present | could not be read (no state directory, damaged, not private) | `spend` and `adopt`: **error `witness-unavailable`**. `status`, `permits`, `ledger`: answered, with a warning and `not-checked` |

The path in the witness is informational: identity is the hash chain. A
pass moved with its ledger is accepted with a warning and the witness
follows it; the copy left behind is then `ledger-changed` (only one copy
can be spent from). A second pass file that reuses an id and has no ledger
is `ledger-missing`, not a fresh count.

### `adopt(pass, reason, now)`

`hallpass adopt FILE --reason TEXT` acknowledges a ledger that would
otherwise be refused or warned about, and records the acknowledgment in
the ledger as a line in the hash chain (`event: "adopt"`, the reason, the
pass digest, the witness's previous record, and `carried`):

- ledger missing, witness records lines: a new ledger is started; `carried`
  is the witness's totals;
- ledger changed: `carried` is, per counter, what the witness recorded
  beyond what the ledger holds;
- no witness: `carried` is empty.

Carried amounts count as spent. An adoption never lowers a count below
what the witness recorded; there is no reset to zero (a new budget is a
raised ceiling in the pass, or a new pass). Then the witness records the
new last line. The reason follows the note rules and is required. With
nothing to adopt (the ledger matches its witness, or there is neither a
ledger nor a witnessed spend) it is a usage error. A damaged ledger
(`ledger-corrupt`) is not adopted: repair it, or move it aside and adopt
the loss. The window is not checked: an adoption permits nothing.

### When the pass is edited

- The spent amount of a counter is the sum of all ledger entries with that
  counter name, whatever digest they carry. A raised total takes effect at
  once; a lowered total leaves `max(0, total - spent)`; no edit resets the
  count.
- A counter removed from the pass can no longer be spent; `status` lists
  its earlier spends under `unlisted_spends`.
- A changed `id` makes the ledger foreign: every spend and `status` fails
  with `ledger-foreign` until the id is restored or a new pass file is used.
  A new id also has its own witness.
- The digest changes with any byte; a caller that passed `--digest` gets
  `pass-changed`.

### Fail-closed cases

Every error below exits 1. The caller must stop. An append or witness failure can leave a debit on disk.

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
| the ledger is missing but its witness recorded lines | `ledger-missing` |
| the ledger does not hold the line its witness recorded | `ledger-changed` |
| `spend`, `adopt`: no state directory, or it is not a private writable directory, or the witness is damaged or not private | `witness-unavailable` |
| the spend exhausted its optional writer lock wait budget before appending | `lock-timeout` |
| the append or its sync failed and the caller must reconcile the ledger before retrying | `ledger-append-uncertain` |
| the spend was recorded but the witness could not be updated afterwards (the spend counts; do not proceed) | `witness-not-updated` |
| `init` target already exists (also a dangling link) | `exists` |
| bad arguments: malformed `--to`, `--digest`, `--n 0`, a bad note or reason, nothing to adopt, a malformed test clock | `usage` |

A missing ledger is not an error when no witness records lines for the
pass id: it means nothing was spent.

## Command line

```text
hallpass [--format text|pretty|json] <command>
hallpass help [COMMAND]
hallpass version
```

Use `hallpass help --format json` for the installed command directory and
`hallpass help COMMAND --format json` for arguments, usage, examples and
workflow. The global format option works on either side of the command,
before the argument separator `--`. An explicit format overrides `FORMAT`.
With neither set, terminals select pretty and pipes select text. Operational
commands use their established plain output in both modes. The help command
uses a compact listing in text and the expanded listing in pretty.

Exit **0** indicates success, **1** indicates a usage, file or accounting
error, and **2** indicates a policy refusal, verification mismatch or coverage gaps. Text
errors go to stderr. In JSON mode every command emits one object on stdout,
including usage errors, help and version. Parser failures also print their
diagnostic to stderr and return `error.code = "usage"` with null `command`
and `file`. Help and version requests return their own command name and
`result = "ok"`. Counted work requires a successful spend reply. See the
[caller contract](INTEGRATING.md).

| Command | Exit 0 | Exit 2 | Exit 1 |
|---|---|---|---|
| `init` | template written (mode 0600; it does not validate until filled in) | never | file exists, write failed |
| `check` | the pass validates | never | any problem |
| `status` | the window is valid | not-yet-valid, expired or revoked | invalid pass, ledger error (also missing or changed per the witness) |
| `permits` | allowed | refused | invalid pass or target, ledger error (as `status`) |
| `spend` | recorded (with `--to`: and the destination is permitted) | refused by the window, the destination or the ceiling; nothing recorded | error; inspect recording state before retry |
| `digest` | printed | never | invalid pass |
| `diff` | field comparison completed, including any requested sample | never | invalid pass, instant or usage |
| `consumer-coverage` | `covered` | `gaps` | invalid declaration or pass |
| `verify-approval` | `verified` | `unverified` | invalid pass, unavailable verifier or input |
| `ledger` | listed (also when there is no ledger yet) | never | invalid pass, ledger error (as `status`), bad `--counter` |
| `adopt` | adoption recorded | never | invalid pass, damaged ledger, nothing to adopt, missing reason, unusable state directory |

`check` does not judge the window; `status` does.

`permits` reads the ledger and its witness too (read-only, shared lock):
a damaged, lost or changed record is an error there as everywhere.

Warnings (no witness yet, a ledger extended past its witness or moved, a
witness that could not be checked) go to standard error as
`hallpass: warning: ...` in text output, and into `warnings` in JSON.

`ledger` is read-only. It takes the same shared lock as `status`, verifies
the whole chain, compares it with the witness, and lists each entry
(sequence number, time, counter, amount, the pass digest it was made
under, note) and each adoption (with what it carried and its reason), then
the total per counter. `--counter NAME` shows one counter. A pass without a ledger says
so and exits 0. In text output every operator-supplied string (notes, and
pass text in `status`) is shown with control characters, line separators
and bidirectional controls escaped as `\u{...}` and a backslash as `\\`,
so a note can neither forge a line of output nor send a terminal escape
sequence. JSON output carries the exact text.

### JSON fields

Every object has `command`, a command-specific `result`, `warnings` (strings)
and `advice` (objects with `level`, `type` and `message`). Both arrays can
be empty. Commands that report a pass path use `file`.

- **help** includes `topic` (null for root), `commands`, `usage`, `arguments`,
  `examples`, `workflow` and `exit_codes`. Argument metadata describes
  unconditional requirements. Consult the usage forms for conditional ones.
- **version** returns the package version in `version`.

- **error** (any command): `error` `{code, message, line}` (`line` is the
  1-based ledger line for `ledger-corrupt`, else null), `problems` (list of
  `{field, message}`, empty unless `invalid-pass`).
- **init**: no more fields.
- **check**: `digest`, `pass_id`, `require_target`, `problems` (empty).
- **status**: `digest`, `now`, `test_clock`, `pass` `{id, name, owner,
  reference, operator}`, `window`, `destinations` (list of `{label, kind`
  (`address` or `network`)`, destination, protocol, ports` (list of `{start,
  end}`)`, ports_text, hostname, names, whole_network_approved}`), `counters` (list
  of `{name, total, spent, remaining}`), `require_target`, `unlisted_spends` (list of `{name,
  spent}`), `ledger` `{path, exists, entries, adoptions, witness,
  moved_from}` (`witness` is `fresh`, `matches`, `extended`, `missing` or
  `not-checked`; `moved_from` the path the witness last saw, or null),
  `refusal` (`{code, message}` or null).
- **permits**: `digest`, `pass_id`, `now`, `test_clock`, `target`
  (normalized), `name` (normalized, or null), `label` (or null), `refusal` (or null), `window`.
- **spend**: `digest`, `pass_id`, `now`, `test_clock`, `counter`, `n`,
  `total` (null for an unknown counter), `spent` (after the spend if
  recorded, else current), `remaining` (or null), `seq` (the new entry's
  sequence number, or null), `note`, `target` and `name` (normalized, null
  without `--to` or `--name`), `label` (the permitting destination when
  recorded with `--to`, else null), `refusal` (or null).
- **digest**: `digest`, `pass_id`.
- **ledger**: `ledger` (its path), `exists`, `pass_id`, `digest` (of the
  pass now), `counter` (the `--counter` filter or null), `verified` (always
  `true` on success: a chain that does not verify is an error), `entries`
  (list of `{seq, time, counter, n, digest, note}`; `digest` is the pass
  digest the spend was decided against, `note` null when none),
  `adoptions` (list of `{seq, time, reason, digest, carried, previous}`;
  `carried` is an object of counter name to amount, `previous` is `{ledger,
  seq, totals, updated}` or null), `witness`, `moved_from` (as in
  `status`), `totals`
  (list of `{name, spent, total, remaining}` for every counter of the pass
  and every counter in the ledger, sorted by name; `total` and `remaining`
  null for a counter the pass no longer has). `spent` includes carried
  amounts.
- **adopt**: `ledger`, `pass_id`, `digest`, `now`, `test_clock`, `case`
  (`ledger-missing`, `ledger-changed` or `no-witness`), `created` (a new
  ledger was started), `seq`, `reason`, `carried` and `totals` (objects of
  counter name to amount), `previous` (as in `ledger`, or null).

`window` is `{state, valid_from, valid_until, seconds_remaining,
seconds_until_open, seconds_since_end, revoked_reason}`; `state` is
`not-yet-valid`, `valid`, `expired` or `revoked`; the three `seconds_*`
fields are null except the one that applies. Times are UTC, whole seconds,
`YYYY-MM-DDTHH:MM:SSZ`.

Refusal codes: `not-yet-valid`, `expired`, `revoked`, `window-too-short`,
`embedded-ipv4`, `network-or-broadcast`, `address-not-listed`, `port-not-listed`, `name-required`, `name-not-listed`,
`required-counter-missing`, `unknown-counter`, `ceiling-reached`, `pass-changed`.

### Test clock

`HALLPASS_UNSAFE_TEST_CLOCK=<RFC 3339>` replaces "now" for `status`,
`permits`, `spend` and `adopt`, only in debug builds and builds with the
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
| `Pass::permits_named(&Target, Option<&HostName>, now, needed) -> Decision` | the same for a request that carries a host name; needed when the destination lists `names` |
| `HostName` | a canonical DNS name; `str::parse` normalizes a query, `HostName::canonical` requires the pass spelling |
| `Pass::destination_for(ip, port, protocol)` | the matching destination, window and `names` not checked |
| `SpendRequest::new(counter, amount)` | a request; set `note`, `expect_digest`, `needed`, `target`, `name` as needed (the struct is `non_exhaustive`: fields may be added) |
| `spend(path, &SpendRequest, now) -> Result<SpendOutcome, Error>` | atomic spend with the witness in `StateDir::from_env()`; with `target` set it also decides the destination; `SpendOutcome.refusal` is `None` when recorded; `SpendOutcome.label`, `SpendOutcome.warnings` |
| `spend_in(path, &SpendRequest, now, &StateDir)` | the same with an explicit state directory |
| `adopt(path, reason, now, &StateDir) -> Result<AdoptOutcome, Error>` | record an adoption (`AdoptOutcome { case: AdoptCase, adoption: Adoption, ledger, created, pass_id, totals }`) |
| `tally(&LoadedPass) -> Result<Tally, Error>` | spent per counter, under a shared lock; reads the ledger only, without the witness (as in 0.1) |
| `read_ledger(&LoadedPass, &StateDir) -> Result<LedgerView, Error>` | every entry (`LedgerEntry { seq, time, counter, amount, digest, note }`), every `Adoption`, the tally, the `WitnessStatus`, `moved_from` and `warnings`; chain verified under a shared lock; read-only |
| `StateDir` (`from_env()`, `new(path)`, `path()`, `witness_path(id)`), `Witnessed`, `totals_text` | the state directory and witness records |
| `display_safe(text) -> Cow<str>` | operator text escaped for one terminal line |
| `ledger_path(path)` | `<pass>.ledger` |
| `write_template(path)`, `TEMPLATE` | `init` |
| `parse_address`, `parse_network`, `embedded_ipv4`, `ipv6_transition` (`Ipv6Transition`), `Target` (`FromStr`), `Network` (with `is_network_or_broadcast(ip)`), `Protocol`, `PortSet` | strict parsing |
| `Digest` (`Display`/`FromStr` as `sha256:<hex>`), `Refusal`, `RefusalCode`, `WindowState`, `Problem`, `Error` (with `code()`; `LedgerMissing` boxes a `MissingLedger`) | value types |
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
changed mid-run (digest), damaged state (fail closed), link tricks on
the pass and ledger, and accidents to the ledger as a whole: a ledger lost
in a copy or a `git clean`, a pass moved without its ledger, an older copy
of the ledger put back, an editor that rewrote the last line (the
witness).

It does not protect against: a tool that does not ask or ignores the
answer; anyone determined to cheat with write access to their own files
(they can edit the pass, and delete or rewrite both the ledger and the
witness consistently; the witness catches accidents and casual edits, not
that); a pass used from two machines or users, whose witnesses do not see
each other; a wrong system clock; unreliable `flock` on network file
systems; symbolic links in parent directories; the network or broadcast
address of a listed IPv6 network or of an IPv4 network whose real size is
larger than listed; IPv6 transition prefixes chosen by a provider (6rd,
MAP, NAT64 network-specific prefixes); and work already running when a
pass is revoked. [DESIGN.md](DESIGN.md) explains each.

## Not yet built (planned)

- **Consumers.** Built: the playpen egress guard consumes passes through
  the library (`playpen run --pass FILE`). It loads the pass with `load`,
  refuses to start unless `check_window(now, 0)` passes, allows exactly the
  destinations (optionally narrowed by label), ends the run at
  `valid_until`, and re-reads the pass every few seconds to stop the
  command when it is revoked, expired, unreadable, invalid or a destination
  in use changes. playpen does not spend: it limits where packets go, not
  how many. Planned: the SIP assessment toolbox calling `hallpass
  --format json spend --to ...` before each call ([INTEGRATING.md](INTEGRATING.md)); the web tester
  using the library per request.
- **Protocols beyond tcp and udp**, and link-local destinations with an
  interface field: would need a new format version; not planned in detail.


## Caller decision contract (0.2)

Use `hallpass --version` for the binary version. Readers should accept extra
JSON fields. Stable refusal/error codes and on-disk format versions are
separate contracts. The CLI samples the live clock after evidence verification for status, permits
and previews, and after preparatory witness writes under writer locks immediately
before spend policy evaluation. Explicit-time Rust APIs use the instant supplied
by their caller. Status and spend warn when that instant is strictly earlier than
the latest ledger event; equal instants do not warn.

The optional `permits --digest` precondition uses the byte digest and gives
exit 2 / `pass-changed` on a mismatch after ledger verification. For permits
and spend, repeat `--to ADDR:PORT/PROTO[@NAME]` up to 64 times. IPv6 uses
brackets. A separate `--name` requires exactly one target without a suffix.
All targets use one loaded pass. `targets` preserves input order and
`refused_target` is a one-based index or null. Existing scalar target and
label fields describe the first endpoint.

`spend --dry-run` returns 0 / `would-allow`, 2 / `refused` or 1 / `error`.
It reads a snapshot, checks observable write access and leaves the ledger
and witness untouched. A positive preview has a null sequence, current spent
and remaining amounts, and `projected_spent`. Concurrent changes and later
filesystem failures can change the result of the real spend.

| State evidence | permits | status / ledger | spend and spend preview |
|---|---|---|---|
| Fresh pass, no previous spend | evaluate policy | report fresh | evaluate policy |
| Ledger without a witness | evaluate with warning | report missing witness | evaluate; only a real spend can establish the witness |
| Unusable witness state | evaluate with warning | report not-checked | error |
| Missing or divergent witnessed history | error | error | error |

On a committing spend, `--lock-timeout-ms N` gives both writer locks one
shared monotonic wait budget. Zero requests one nonblocking attempt per lock.
Omitting the option uses blocking locks. A timeout exits 1 with
`error.code = "lock-timeout"` and `error.recording = "not-recorded"`.
The budget covers lock acquisition. It places no deadline on a subsequent
append or sync. An external process timeout can leave the outcome unknown.

After `witness-not-updated`, `error.recording` is `recorded` and the JSON
error contains `seq` and `ledger`. A `ledger-append-uncertain` error includes
the ledger path and `recording = "uncertain"`. Both exit 1. Inspect the
ledger and reconcile before retrying.

### Recovery preview and checkpoints

`adopt --preview` is a read-only snapshot of an adoptable ledger, reporting its
case, present totals, carry and projected totals, prior witness and a versioned
opaque token. It checks observable ledger, directory and witness write access
without creating files; later permission changes and I/O failures can still prevent
application. `adopt --reason TEXT --token TOKEN` rechecks that snapshot under
the writer's witness and ledger locks; a stale token is an error (exit 1) and
requires a new preview. An adoption already appended before a subsequent witness
write failure still counts; inspect the ledger before retrying.

`checkpoint` exports a versioned pass ID, sequence and exact-line hash, plus
whether a local witness corroborates the history. Sequence zero identifies the
header. `verify-checkpoint` validates the supplied ledger and reports `exact`
or `extended` (exit 0), `mismatch` (exit 2), or an input/error condition (exit
1). Verification uses the supplied checkpoint as its trust input and does not
read or create a witness. Retain checkpoints separately from the ledger.

The guard coordinates hallpass writers through their locks. Programs that edit
pass or ledger files without taking those locks can change them after a reviewed
snapshot; the missing-ledger decision uses the validated pass snapshot held at
publication time.

### Atomic accounting

One unit can debit multiple named budgets. The same policy decision checks
the pass digest, active window, requested destinations, and every ceiling
under the writer locks. A successful commit syncs one ledger sequence and
updates the witness with every resulting balance. Refusal leaves every
counter balance unchanged. Positive previews return projected_spent for each
charge while leaving the reported current balances and the ledger unchanged. Historical
scalar debits and adoption carry-forward remain valid, and tallying counts
a multi-charge unit once while adding each charge to its counter.

The versioned debit can retain an explicitly supplied caller reference and,
when requested, the approved targets and matched destination labels. The
reference correlates the caller's own run record with the digest and
sequence. An older incompatible reader fails closed on a versioned debit.
Charges remain monotone through restoration and adoption. Callers commit
at first send and reconcile ambiguous append outcomes against the ledger.

### Rehearsing a budget

Run `hallpass --format json rehearse docs/required-counters.toml docs/rehearse.toml`
to project three ordered debits of 40 bytes against a 100-byte ceiling. The first
two steps leave 20 bytes. The third returns `simulation-refused` (exit 2) and
preserves both balances. A complete projection returns `simulated` (exit 0).
Submit each actual unit with `spend` to check the current approval and balances.

A local UTF-8 TOML scenario has `version = 1` and 1–128 ordered `[[step]]`
tables. Each table supplies a unique pass-style identifier `id`, a quoted RFC
3339 `at` instant and an ordered list of `charges = [{counter = "bytes", n = 40}]`.
Instants may be equal and must be nondecreasing. Optional `duration` is an
unsigned 32-bit count of seconds. Optional `targets` lists up to 64 literal
endpoints in spend's `ADDR:PORT/PROTO[@NAME]` syntax. Each step has 1–64
distinct positive charges. The scenario file limit is 256 KiB.

The command reads one validated pass and compares its ledger with the witness.
The result identifies the pass digest, witness status and starting totals,
including historical charges and adoption carry. Each evaluated step reports
the before and after totals for its requested counters, remaining budget,
matched labels or refusal evidence. Following steps report `unevaluated`.
Every projection stays in memory. A subsequent live debit reads current state.

### Projecting an amendment against live balances

`hallpass diff CURRENT PROPOSED --budget-impact --json` reads one verified summary from CURRENT. Both digests identify the files compared. The projection gives the witness status and verified ledger tip (null before the first ledger). Each counter row shows the two limits, mandatory-charge flags and remaining amounts against the same historical spend, including adoption carry. A missing ceiling is null. For eight calls spent and a proposed ceiling of six, proposed_remaining is zero and over_proposed is two. This is a completed review (exit 0). Different pass IDs make a projection inapplicable (exit 2). Unusable accounting evidence exits 1. A proposal can change after review and concurrent spends can change these balances.

### Proving endpoint containment

`hallpass diff OLD NEW --containment --at TIMESTAMP` compares zero-duration endpoint admission at one explicit instant. Both validated revisions must have the same pass ID and open windows. Each proposed rule must fit within a single old rule's address range, protocol, ports and name domain. Every previously excluded IPv4 network or broadcast edge within a proposed destination must still be excluded for this proof. IPv6 transition exclusions apply identically to both revisions.

The result `contained` (exit 0) certifies that every endpoint/name pair admitted by NEW at that instant was admitted by OLD. The proof compares at most 16,384 rule pairs. When the proof fails, the existing bounded example search can establish `expanded` (exit 2) by exhibiting a new allowance. Otherwise the result is `inconclusive` (exit 2), with a reason such as a work limit or coverage that would require combining old rules. Invalid input exits 1. Label attribution, other instants, costs and scope duration are outside this certificate. See the accompanying declared-field diff for those edits.
