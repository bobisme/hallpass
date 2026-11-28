# hallpass specification

This page describes what hallpass does at the current commit. Anything not
yet built is marked **planned**. The exact file format is in
[PASS-FORMAT.md](PASS-FORMAT.md); the reasons behind the decisions are in
[DESIGN.md](DESIGN.md). How a tool calls hallpass is in
[INTEGRATING.md](INTEGRATING.md); the evidence commands are in
[EVIDENCE.md](EVIDENCE.md). A runnable first-shift walkthrough is
[WALKTHROUGH.md](WALKTHROUGH.md), run by `tests/walkthrough.rs`. A complete
caller is in [reference-caller/](reference-caller/README.md), run by
`tests/reference_caller.rs`.

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
- **Debit**: the record of one unit of work in the ledger. It charges one
  or more counters, each by a positive amount.
- **Ledger**: the append-only file beside the pass that records every
  spend (and every adoption and reference reconciliation).
- **Witness**: a small record per pass id in the user's state directory,
  outside the pass directory: the ledger's last sequence number, the hash
  of its last line, the totals, and where the ledger was. It lets hallpass
  notice a lost, replaced or rewound ledger.
- **State directory**: `$XDG_STATE_HOME/hallpass/`, or
  `$HOME/.local/state/hallpass/` when `XDG_STATE_HOME` is unset, empty or
  not an absolute path. A relative `XDG_STATE_HOME` is ignored with a warning that names it and the directory used instead. Created mode 0700; witness and lock files 0600.
- **Adoption**: an operator's recorded acknowledgment, with a reason, of a
  ledger that was lost, changed outside hallpass, or had no witness.
- **Reference reconciliation**: an operator's recorded statement, with a
  reason, of which caller references may be in the lines an adoption lost.
- **Digest**: `sha256:` plus the SHA-256 of the pass file's exact bytes.

## The pass file (summary)

```toml
format = 1
id = "example-2026-11"            # the ledger belongs to this id
name = "Example voice edge"
# require_target_v1 = true         # optional: every debit must check a destination
# required_counters_v1 = ["calls"] # optional: every debit must charge these

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
- text fields (`name`, `owner`, `reference`, `operator`, `revoked_reason`)
  hold no control character, line or paragraph separator or Unicode format
  character (the characters a note refuses), and the problem names the
  character; new after 0.2.0;
- addresses in canonical spelling only; refused: host names, IPv4 leading
  zeros and shortened forms, zones, non-canonical IPv6, IPv6 forms carrying
  IPv4 (mapped, compatible, NAT64, and the transition forms 6to4, Teredo,
  ISATAP, SIIT-translated), unspecified, multicast, broadcast,
  `240.0.0.0/4`, link-local; networks with host bits set or overlapping any
  refused range; loopback only when listed;
- networks broader than /24 (IPv4) or /64 (IPv6) need
  `whole_network_approved = true`; broader than /8 or /32 is always refused;
- ports 1-65535, ranges `"start-end"`, no port listed twice in one
  destination (new after 0.2.0); protocols `tcp`, `udp`;
- labels unique ignoring ASCII letter case (new after 0.2.0);
- ceiling names `[a-z][a-z0-9_-]{0,31}`, totals 0 to 10^12, at most 64;
- the file: UTF-8, at most 1 MiB, regular file, not a symbolic link, not
  writable by group or others, ending with a newline (new after 0.2.0);
  anywhere in it, comments included, none of the characters a text field
  refuses and no control character but a tab and a line end, each named
  with its line and column (new after 0.2.0);
- a file whose modification time is less than 0.25 s old (2.25 s when the
  time has no fraction of a second) is read again 0.25 s (2.25 s) after that
  time, or after that long if the time is in the future, and is
  `invalid-pass` unless its bytes, size and modification time are
  unchanged (new after 0.2.0).

## Decision rules

All decisions take `now` from the caller. The CLI samples the live clock
after evidence verification for status, permits and previews, and after
preparatory witness writes under writer locks immediately before spend
policy evaluation. Explicit-time Rust APIs use the instant supplied by their
caller. Status and spend warn when that instant is strictly earlier than the
latest ledger event; equal instants do not warn.

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

The CLI `permits` reads the ledger and its witness too (read-only, shared
lock): a damaged, lost or changed record is an error there as everywhere.
The optional `permits --digest` precondition uses the byte digest and gives
exit 2 / `pass-changed` on a mismatch after ledger verification.

For permits and spend, repeat `--to ADDR:PORT/PROTO[@NAME]` up to 64 times.
IPv6 uses brackets. A separate `--name` requires exactly one target without
a suffix. All targets use one loaded pass. One refused target refuses the
whole unit. `targets` preserves input order and `refused_target` is a
one-based index or null. Existing scalar target and label fields describe
the first endpoint.

### `spend(pass, counter, n, note, expected digest, needed, target, name, now)`

With a target, one spend answers "may I send this much to this destination
now, and count it". On a pass with `require_target_v1 = true`, every debit
must supply at least one target. Without that term, an allowed or previewed
debit with no target has a warning that no destination was checked. The
request name follows the destination rules.

1. Request checks, before any file is touched: `n` from 1 to 10^12, note one
   line of at most 500 characters with no control character (newline, tab,
   escape, C1 controls), no Unicode line or paragraph separator (U+2028,
   U+2029) and no Unicode format character: general category Cf of Unicode
   16.0 and the whole Tags block U+E0000-U+E007F. These include the
   bidirectional controls (U+061C, U+200E, U+200F, U+202A-U+202E,
   U+2066-U+2069), the zero-width characters (U+200B-U+200D, U+2060,
   U+FEFF), the soft hyphen (U+00AD) and the interlinear annotation
   controls (U+FFF9-U+FFFB). The note may not hold any other
   default-ignorable code point of Unicode 16.0 either: the combining
   grapheme joiner (U+034F), the Hangul fillers (U+115F, U+1160, U+3164,
   U+FFA0), U+17B4 and U+17B5, the variation selectors (U+180B-U+180F,
   U+FE00-U+FE0F, U+E0100-U+E01EF) and the reserved U+2065,
   U+FFF0-U+FFF8 and U+E0000-U+E0FFF. Nor may it hold a space other than
   the ASCII space (general category Zs: U+00A0, U+1680, U+2000-U+200A,
   U+202F, U+205F, U+3000). Failure is a usage error that names the
   character. (Reading a ledger accepts notes that only avoid control
   characters, the 0.1 rule.)
   A name without a target, a negative `needed`, and a `now` outside the
   years 0001 to 9999 in UTC are usage errors too.
2. Load and validate the pass. Find the state directory, create it if
   needed (0700), check that it is a private directory and writable, and
   take an exclusive lock on `<pass id>.lock` in it. Read the witness.
3. If the ledger does not exist: when the witness records any line,
   `ledger-missing`, or `ledger-elsewhere` when the ledger is intact where
   the witness last saw it (nothing is created); otherwise create the
   ledger with its header.
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
   `not-yet-valid`, `expired`, `window-too-short`), with the reference
   guard `duplicate-reference` or `reference-inconclusive` (see "Caller
   references and receipts"), when a target was given every refusal of
   `permits` for it, with the name and `needed` (`embedded-ipv4`,
   `network-or-broadcast`, `address-not-listed`, `port-not-listed`,
   `name-required`, `name-not-listed`), `target-required` (an
   owner-required destination was omitted), `unknown-counter` (a charged
   name is not in `[ceilings]`; checked before the required counters, so a
   typo is named as unknown), `required-counter-missing` (the debit omitted
   an owner-required charge), `ceiling-reached` (spent + n > total). The destination is
   decided against the pass as read under the locks, the same reading the
   entry's digest names.
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

#### Several charges in one debit

One unit can debit multiple named budgets. Each counter may occur once in a
unit. The same policy decision checks the pass digest, active window,
requested destinations, and every ceiling under the writer locks. A
successful commit syncs one ledger sequence and updates the witness with
every resulting balance. Refusal leaves every counter balance unchanged.
Positive previews return projected_spent for each charge while leaving the
reported current balances and the ledger unchanged. Historical scalar debits
and adoption carry-forward remain valid, and tallying counts a multi-charge
unit once while adding each charge to its counter.

#### Several referenced units in one atomic batch

The Rust library can reserve a compound call with
`spend_charges_batch*`. A `SpendChargesBatchRequest` holds 1 to 1024
`SpendChargesRequest` units. Every unit has exactly one charge of amount 1,
all units charge the same counter, each supplies a distinct caller reference
with `require_new_ref = true`, and each has either no target or one checked
and retained target. Lock-wait options belong to the batch. Invalid input is
rejected before a ledger is created.

Hallpass takes the witness and ledger locks once, verifies every reference,
applies every unit's digest, window and target policy, and advances a
prospective tally in request order. The first refusal names its one-based
unit and records none of them. Thus an aggregate ceiling shortage cannot
leave a paid prefix. Its refusal text keeps actual and prospective accounting
separate: it reports the durable spend before the batch, the full-batch
projection, the first unit that would exceed the ceiling, and that zero units
committed.

Success appends and syncs one `debit-batch` JSON line. Its units are ordinary
logical debits with contiguous, distinct sequences and receipts; `ledger`,
`receipt`, audits and reference guards expose them like scalar versioned
debits. The line hash is the checkpoint for the last sequence, and the
witness records that sequence and all resulting totals. Sequence counts are
therefore logical entry counts, not physical JSON-line counts. An older
Hallpass does not recognize `debit-batch` and fails closed at that line.

This single-line encoding is the partial-I/O boundary. A write of zero bytes
commits no unit, the complete newline-terminated line commits every unit, and
every strict byte prefix is an incomplete final line that forms no paid
prefix and makes the ledger fail closed. The caller must not perform the
external work after any append or witness error. After a synced line and a
failed witness update, each ordinary receipt lookup supplies the unique
sequence needed to reconcile the caller's durable run record.

#### Preview

`spend --dry-run` returns 0 / `would-allow`, 2 / `refused` or 1 / `error`.
It reads a snapshot, checks observable write access and leaves the ledger
and witness untouched. A positive preview has a null sequence, current spent
and remaining amounts, and `projected_spent`. Concurrent changes and later
filesystem failures can change the result of the real spend.

#### Caller references and receipts

The versioned debit can retain an explicitly supplied caller reference and,
when requested, the approved targets and matched destination labels. The
reference correlates the caller's own run record with the digest and
sequence. An older incompatible reader fails closed on a versioned debit.
Charges remain monotone through restoration and adoption. Callers commit
at first send and reconcile ambiguous append outcomes against the ledger.

With `spend --require-new-ref --caller-ref TEXT`, the verified writer scan
checks that exact reference under both locks across all digests of the pass
ID. Digest and window refusals take precedence. A duplicate exits 2 with
`refusal.code=duplicate-reference`, `seq: null`, and `reference_evidence`
containing `caller_ref`, `match_count`, the first 64 `sequences` in ledger
order, and `truncated`. The scan verifies the rest of the chain after a
match, including entries after the witness. A reference that a reference
reconciliation lists (see `reconcile-references` below) is a duplicate too,
also when no debit in the ledger carries it: `reference_evidence` then adds
`reconciled_at`, the first 64 sequences of the reconciliations that list
it, and the message names the first one and its adoption.

An absent reference exits 2 with `reference-inconclusive` and empty match
details when the ledger may lack lines that hallpass recorded:

- **After an adoption that may have lost lines.** An adoption that records
  a previous witness of at least one line, or carries any amount, accepted
  a ledger without lines hallpass had recorded: a missing ledger started
  anew with the witnessed totals, or a changed ledger with what the witness
  recorded beyond it. References on those lines may be gone even when
  nothing was carried. This lasts until a reference reconciliation follows
  the latest such adoption (see `reconcile-references` below); an adoption
  that loses nothing does not end it. Check the reference against the
  caller's run record, and spend without `--require-new-ref` only if that
  record shows the unit was never submitted. The message names the latest
  such adoption and the `hallpass reconcile-references` command that ends
  this.
- **Without a local witness.** A ledger with at least one line and no
  witness may be a partial copy. A guarded refusal records no witness. If
  the ledger is the complete history (for example it moved with the pass
  to another machine or state directory), `hallpass adopt FILE --reason
  TEXT` records one, and the message says so.

An adoption without a witness appends to the ledger as it stands: the hash
chain still holds every earlier line, and the adoption records no previous
witness and carries nothing. It loses no reference, so after it the guard
checks new references again. An adoption whose previous witness recorded
only the header loses none either. Adopt a ledger without a witness only
when it is the complete history: hallpass cannot tell a partial copy from
a complete one, and neither the count nor the guard sees lines missing
from it. Every adoption record already has the `witness` and `carried`
fields that tell the kinds apart, so the adoption line is unchanged.

A new caller reference is nonblank, at most 128 characters, without
leading or trailing spaces, and made only of ASCII characters with no
control character: two references that differ only in a combining mark, a
look-alike letter or hyphen (Cyrillic е, U+2010) or an invisible or
look-alike-space character could look the same. Reading a
ledger, and looking a reference up with `receipt` or a `reconcile`
manifest, applies the earlier rule (nonblank, at most 128 characters, no
control character, line separator or bidirectional control), so a
reference recorded before the new rule still reads and can be found.
Missing or invalid caller references are usage errors. A dry run applies
the same rules and reports observed matches without a reservation. The
guard coordinates cooperating guarded writers on the same local history.
External execution requires a separate record. The Rust option is
`SpendChargesRequest::require_new_ref`.

For a compound call, `SpendChargesBatchRequest` requires that option and a
distinct reference on every unit. One duplicate or inconclusive reference
refuses the whole batch; `refused_unit` and `reference_evidence` identify the
first one in request order. On success each
`SpendChargesBatchUnitOutcome` supplies its sequence and retained receipt.

#### Damaged ledger advice

A chain break at line N says that line N does not follow line N-1: one of the
two was changed, or a line between them was removed or moved. When N is the last line of the file (`error.last_line` is
true) and the line has no line end, the message names `hallpass repair FILE
--drop-torn-tail --preview` and, for a line that is whole and lacks only its line end, `hallpass repair FILE --restore-final-newline --preview` ([Dropping a cut-short last line](#dropping-a-cut-short-last-line)).
In every other case it advises restoring the ledger from a backup, finding
the good copy with `hallpass compare-backups`, and not editing lines by hand. It
then names the last resort for when there is no backup: move the ledger aside and
`adopt` it as `ledger-missing` (the receipts of the moved ledger are lost from
the chain).
The error code stays `ledger-corrupt`.

#### Lock wait

Every command that takes the ledger lock accepts `--lock-timeout-ms N`:
`spend` (with `--dry-run` too), `adopt` (with `--preview` too), `repair`,
`reconcile-references`, `permits`, `status`, `doctor`, `ledger`, `capacity`,
`rehearse`, `receipt`, `audit-receipts`, `audit-charges`, `reconcile`,
`compare-backups`, `checkpoint`, `verify-checkpoint`, and `diff` with
`--budget-impact`. A read takes a shared lock on the ledger, so it waits only
while a writer holds the ledger lock: a spend, an adoption, a reference
reconciliation, or another process. A writer takes the witness lock and then
the ledger lock, both exclusive.

N is one monotonic wait budget for every lock the command takes: on a
committing spend, both writer locks; on a read, the ledger lock (and the lock
of each candidate, for `compare-backups`). Only time spent waiting is
counted, not time spent reading. Zero requests one nonblocking attempt per
lock. Omitting the option uses blocking locks and waits without limit,
except for `doctor`, which then waits 3 seconds. A
timeout exits 1 with `error.code = "lock-timeout"` and
`error.recording = "not-recorded"`. For `compare-backups`, a timeout on any
candidate fails the whole command; it is not reported as a row. The budget
covers lock acquisition. It places no deadline on a subsequent append or
sync. An external process timeout can leave the outcome unknown.

`doctor` reports a lock still held after its wait as `blocked` with problem
`lock-timeout` (exit 2), naming the holder's process when it is known and
saying how to wait longer; it does not fail with an error.

Before it reads, `doctor` also tries the writer lock and the ledger lock
once each, without waiting (a probe that takes a lock lets go of it at
once, and no lock file is created). A lock another process holds is
reported as `needs-action` with code `lock-held`, naming the holder's
process when it is known (else `fuser PATH`) and saying that a hung writer
can be stopped, which frees the lock. It is `needs-action`, not `blocked`,
because a lock is often held for moments by a healthy spend; run doctor
again if it clears. A held ledger lock means doctor does not read the
ledger (a read would wait), and says so in a finding.

A preflight (`permits` before each further address) should pass
`--lock-timeout-ms`. Then a writer that stopped while it held the lock (a
`SIGSTOP`, a hung disk, a debugger) makes the worker fail with
`lock-timeout`, instead of making it wait with no end.

The locks are operating-system file locks (`flock`). The system releases one
when its holder exits or crashes, so a stale lock never needs removing; a
`lock-timeout` means a live process holds it. The message ends with the next
step: retry, or find and stop that process (`fuser PATH`).

After about two seconds of waiting for one lock, the CLI writes one line to
**stderr** (in text and JSON mode alike; it is never put in `warnings`, so
stdout stays one JSON object and the result is unchanged):

```
hallpass: waiting for the writer lock on PATH, held by process PID. Nothing is recorded yet; press Ctrl-C to give up, or use --lock-timeout-ms to stop waiting.
hallpass: waiting for the writer lock on PATH, held by process PID. Nothing is recorded yet; giving up in 500 ms (--lock-timeout-ms); press Ctrl-C to stop sooner.
```

The first form is for a command without `--lock-timeout-ms`; the second is
for one with it, and the number is the time left of the limit (the budget is
shared by every lock the command takes). `writer` becomes `ledger` for the
shared lock of a read. Where the holder cannot be found (it is found on Linux
from `/proc/locks`), `held by process PID` reads `held by another process;
find it with fuser PATH`. A command that gets the lock sooner prints nothing,
and so does a command whose `--lock-timeout-ms` ends first. The library never prints: set
`SpendRequest::on_lock_wait`, or pass a function to `with_lock_wait`, that
receives a `LockWait` (`path`, `holder_pid`, `shared`, `give_up_in`) to report the wait
yourself.

The library's reads have no request to carry a limit, so
`with_lock_wait(lock_timeout, on_lock_wait, f)` sets one around the call `f`:
every ledger and witness lock that the library takes in `f`, on the calling
thread, shares the budget `lock_timeout`, with the meaning above. A
`SpendRequest` whose own `lock_timeout` or `on_lock_wait` is set uses that
field instead. A preview (`preview_spend_in`, a dry-run `SpendChargesRequest`,
`capacity_in`) uses its request's `lock_timeout` for the shared lock; that
was a usage error before.

### The witness

After every recorded spend, adoption or reference reconciliation the
witness for the pass id holds the ledger's last sequence number, the
SHA-256 of its last line, the totals per counter, the ledger's resolved
path and the time. Every command that reads the ledger (`status`,
`permits`, `spend`, `ledger`, `adopt`, `reconcile-references`) compares:

| Ledger | Witness | Result |
|---|---|---|
| missing | none, or no lines recorded | nothing spent (`fresh`) |
| missing | records lines | **error `ledger-missing`**, naming the witnessed totals, where the ledger was last seen and when, and what to do |
| missing | records lines, and the ledger where the witness last saw it is another file that is intact (it holds the witnessed line, with or without entries after it) | **error `ledger-elsewhere`**, naming that ledger, its current totals and the pass file beside it, and how to apply a revision |
| present | none, and no copy (`<pass id>.recorded`) | accepted with a warning (`missing`); `spend` records a witness |
| present or missing | none, but its copy records lines | the witness was lost here: as for a witness that could not be read (the last row), with the adoption described below |
| present | its line `seq` hashes to the witnessed hash, and nothing follows | `matches` |
| present | the witnessed line is there, and `k` entries follow | accepted with a warning (`extended`): a run stopped between the ledger and the witness, or a hallpass without witnesses added entries; they count |
| present | the witnessed line is not there (a different line at that position, or fewer lines) | **error `ledger-changed`**, saying which, and naming another ledger of the same id if one exists where the witness saw it |
| present | the witnessed line is there, but the witness's totals are not the ledger's verified totals at that sequence (a counter added, removed or changed; a counter at 0 counts as absent) | the witness is damaged: as in the next row |
| present | the witnessed line is not at the witnessed sequence, but the line the witness's hash names is in the verified ledger at another sequence (a line records its own sequence, so the witness's sequence was changed) | the witness is damaged: as in the next row |
| present | could not be read (no state directory, damaged, not private) | `spend` and `adopt`: **error `witness-unavailable`**. `status`, `permits`, `ledger`: answered, with a warning and `not-checked` |

The same evidence, by command:

| State evidence | permits | status / ledger | spend and spend preview |
|---|---|---|---|
| Fresh pass, no previous spend | evaluate policy | report fresh | evaluate policy |
| Ledger without a witness | evaluate with warning | report missing witness | evaluate; a real spend without `--require-new-ref`, or `adopt`, establishes the witness |
| Unusable witness state, or a lost one (its copy is there) | evaluate with warning | report not-checked | error |
| Missing or divergent witnessed history | error | error | error |

The totals are compared at the witnessed sequence, not at the end of the
ledger, so a ledger ahead of its witness (a crash between the append and
the witness update) is still checked. `compare-backups` warns when a
candidate holds the witnessed line with other totals.

Beside the witness, hallpass keeps two notes that only choose words and
never decide a count or a refusal, and two that only add a refusal. A missing or damaged note changes only a
message, or gives the behaviour of earlier releases. `<pass id>.forks` records where an adoption that replaced the
witnessed history put its line (`ledger-missing` and `ledger-changed`
adoptions; the latest 16). A ledger that holds the line before such an
adoption and a different line where it is, is `ledger-changed` with "a
different history from sequence N" instead of "an older copy".
`<pass id>.pass-file` is described under "When the pass is edited", and
`<pass id>.witness-damage` (which does decide a refusal: an adoption from a
witness it names) under `adopt`.

`<pass id>.recorded` is a copy of the witness, written (private, not
synced) after each write of the witness. It differs from the witness only in
its version key (`hallpass_recorded`), so that it is never read as one.
While the witness file is missing and the copy reads as a copy for this pass
id that records at least one line, the witness was lost from this state
directory: it is not an arrival. `spend`, `repair`, `checkpoint` and
`reconcile-references` refuse with `witness-unavailable`, naming both files;
`status`, `permits` and `ledger` answer with `not-checked`. Nothing else in
the state directory shows a spend from it: `<pass id>.pass-file` is also
written by `permits` and `status`, and `<pass id>.lock` by a guarded spend
refused for want of a witness, which records nothing. A missing, damaged or
foreign copy is ignored, and a ledger without a witness is then an arrival,
as before; a state directory last written by an earlier release has no copy
until its next witness write. `adopt` reads the copy in place of the lost
witness: a ledger that holds the copy's line is adopted as a ledger without
a witness (`no-witness`, carrying nothing, keeping references conclusive);
a ledger that does not is `ledger-changed`, and a missing one
`ledger-missing`, each carrying what the copy records beyond the ledger,
with the copy as the adoption's previous witness, so guarded spends are
`reference-inconclusive` until the references are reconciled. Doctor names
the adoption preview.

The path in the witness is informational: identity is the hash chain. A
pass moved with its ledger is accepted with a warning and the witness
follows it; the copy left behind is then `ledger-changed` (only one copy
can be spent from) when it shares that witness (the same state directory).
A copy on another machine or account has a witness of its own and is not
refused: it stays live until its ledger is moved away there, and it is then
`ledger-missing`. The warning says both. A second pass file that reuses an id and has no ledger
is never a fresh count.

When the ledger beside the pass is missing and the witness last saw it at
another path, hallpass opens the file there under the rules for any ledger
(not a link, a regular file, private), verifies its whole chain, and checks
that it belongs to the pass id and holds the line the witness recorded (same
sequence number and hash). Entries after that line are allowed, as for
`extended`: the witness lags the ledger after a spend that stopped before
its witness update, or after spends from another state directory. If all of
that holds, the ledger is not lost, and the error is `ledger-elsewhere`. The
message gives that ledger's current sequence number and totals, not the
witness's, and says how many entries follow the witnessed line. This is the usual case of
an amended approval saved as a second file with the same id, or of a pass
moved without its ledger. The message names the intact ledger and the pass
file beside it, if there is one. To apply a revision, copy the new file into
that pass file's directory, rename the copy over it (`mv`), and spend from
it; the count carries on.
If the old file is being retired, or there is none, move the ledger beside
the new file instead. Do not adopt: adoption would start a second ledger
for the id. If the file cannot be opened, does not verify, belongs to
another id, or does not hold the witnessed line, the error is
`ledger-missing`, as for a lost ledger. Either way nothing is counted from
that file or created.

Only a command that records moves the witness forward: a spend from the
pass file beside the live ledger accepts the extra entries and records its
own witness. `status`, `permits`, `ledger` and the refusals above write
nothing, so a lagging witness stays as it is until then. That does not
open a window: the refusal and the adoption check use the live ledger's
own chain, whatever the witness lags.

### `adopt(pass, reason, now)`

`hallpass adopt FILE --reason TEXT` acknowledges a ledger that would
otherwise be refused or warned about (an adoption that carries an amount or
may lose lines also needs `--token`, see below), and records the acknowledgment in
the ledger as a line in the hash chain (`event: "adopt"`, the reason, the
pass digest, the witness's previous record, and `carried`):

- ledger missing, witness records lines: a new ledger is started; `carried`
  is the witness's totals;
- ledger changed: `carried` is, per counter, what the witness recorded
  beyond what the ledger holds;
- no witness: `carried` is empty;
- with `--checkpoint`, a ledger behind a retained checkpoint: `carried`
  rises, per counter, to what the checkpoint records beyond the ledger
  lines it proves are its own
  (see [After a whole-machine restore](#after-a-whole-machine-restore)).
  The line then also has `checkpoint` (`version`, `pass_id`, `seq`, `hash`
  and `totals`, without `latest` and `anchors`); a hallpass before the one
  that added `checkpoint` does not read such a line and stops with
  `ledger-corrupt`.

In the first two cases the ledger cannot confirm the carried totals: the
ledger is missing, or it does not hold the witnessed line. They come from
the witness alone. `adopt --preview` says so in `warnings` when it would
carry an amount. A witness edited, or damaged without becoming unreadable,
while its ledger was still there is refused by every command that compares
them (see "The witness"). The command that finds it notes what it saw in
`<pass id>.witness-damage`: the digest of the witness file's bytes, the
witnessed sequence, and both sets of totals. While the witness still has
those bytes, `adopt` and `adopt --preview` refuse (`witness-unavailable`)
to carry its totals, and advise putting the ledger or a backup back. If no
copy is left, `adopt --carry-noted-totals` carries, per counter, the higher
of the witness's total and the verified total noted, so the note never
lowers a count; the flag is an error when no note applies. Without a note,
adoption is as before. A witness damaged after the ledger was lost, with no
command in between, can only be checked against the operator's run
records.

The first two may have lost lines and their caller references, so later
guarded spends refuse new references as `reference-inconclusive`; the third
keeps every line (see "Caller references and receipts"). A reference
reconciliation (`reconcile-references`, below) ends that refusal. Carried amounts
count as spent. An adoption never lowers a count below
what the witness recorded; there is no reset to zero (a new budget is a
raised ceiling in the pass, or a new pass). The one exception is a witness
that counts only a rehearsal, adopted with `--drop-rehearsal FILE`
when the rehearsal ledger FILE proves it (see
[Test-clock lines](#test-clock-lines)): a rehearsal spent nothing real. Then the witness records the
new last line. The reason follows the note rules and is required.
(Reading a ledger accepts a recorded reason under the earlier rule, which
refused line separators and bidirectional controls but not the other
format characters, invisible characters or look-alike spaces.) With
nothing to adopt (the ledger matches its witness, or there is neither a
ledger nor a witnessed spend) it is a usage error. A damaged ledger
(`ledger-corrupt`) is not adopted: repair it, or move it aside and adopt
the loss (the last resort when a counted last line is damaged and there is
no backup: the new ledger carries the witness totals, but the receipts of
the moved ledger are no longer in the chain). A ledger that is missing, or
that does not hold the witnessed line (`ledger-changed`, such as an older
copy), is not adopted either while the ledger where the witness last saw it,
at another path, is intact (also when it has entries after the witness):
`adopt` and `adopt --preview` both fail with `ledger-elsewhere` and record
nothing, because the adoption would fork the history. When a file is at
that path that hallpass did not read (a link, not private, or not readable
by this user), it may still be the intact ledger, so `adopt` and `adopt
--preview` refuse too: `insecure-permissions` with the `chmod 600` to run
for a file others can read, else `io`, saying to put the real ledger there
or make it readable, then run the command again. When hallpass read the
file and found it is not this pass's intact ledger (damaged, for another
id, not a regular file), the adoption is allowed, and `adopt --preview`
names the file in `warnings`: the witness may be behind it, so its carried
totals may be too low. A lock on that file held past the lock-wait budget
is `lock-timeout`. There is no flag to force it. If that ledger really is to be
abandoned, move it away from the path the witness names; the case is then
`ledger-missing`. The window is not checked: an adoption permits nothing.

When the adoption would carry an amount or record a previous witness of
at least one line, `adopt --preview` warns in `warnings` that every later
guarded spend (`--require-new-ref`) on this ledger is refused as
`reference-inconclusive` until the references that may be in the lost lines
are reconciled with `hallpass reconcile-references`. `adopt` repeats the
warning when it records the adoption.

`adopt --preview` is a read-only snapshot of an adoptable ledger, reporting its
case, present totals, carry and projected totals, prior witness and a versioned
opaque token. It checks observable ledger, directory and witness write access
without creating files; later permission changes and I/O failures can still prevent
application. `adopt --reason TEXT --token TOKEN` rechecks that snapshot under
the writer's witness and ledger locks; a stale token is an error (exit 1) and
requires a new preview. An adoption that carries an amount from the witness
or a checkpoint, or records a previous witness of at least one line (the
adoptions that make guarded spends `reference-inconclusive`), is refused
without `--token`, with a `usage` error that names the preview command and
records nothing. A plain adoption, with nothing carried and nothing lost (a
ledger that moved with its pass and has no witness), needs no token. The
library's `adopt_guarded*` functions keep the optional token. An adoption already appended before a subsequent witness
write failure still counts; inspect the ledger before retrying.

The guard coordinates hallpass writers through their locks. Programs that edit
pass or ledger files without taking those locks can change them after a reviewed
snapshot; the missing-ledger decision uses the validated pass snapshot held at
publication time.

### Dropping a cut-short last line

A failed append is rolled back ([Fail-closed cases](#fail-closed-cases)), so
hallpass itself leaves a cut-short line only when the rollback fails too, or
when an older hallpass wrote the ledger. `hallpass repair FILE
--drop-torn-tail --preview` shows what would be removed and prints a token
(`tail1:sha256:...`); `hallpass repair FILE --drop-torn-tail --token TOKEN`
removes it. Both refuse (exit 1, `usage`, nothing changed) unless all of
these hold:

- the ledger does not end with a line end, and it has at least one
  complete line (the header);
- every complete line verifies, for this pass;
- the witness exists and its line is one of the complete lines, so the
  witness never counted the cut-short line;
- the cut-short bytes start as hallpass starts the next line,
  `{"seq":N,` with N one past the last complete line, or are a shorter
  start of that.

A complete last line that is invalid is never removed. The repair takes
both writer locks and checks the token again; a stale token requires a new
preview. Before the ledger is cut, the removed bytes are written to a new
private file beside it, `LEDGER.torn-N` (`LEDGER.torn-N.2` and on when that
exists), and synced. The repair records no ledger line and does not change
the witness: the ledger then ends with the line the witness recorded, or
with lines after it. In Rust: `preview_drop_torn_tail` and `drop_torn_tail`,
which return a `TornTail`.

When the cut-short last line is whole and the witness counted it, the
repair above refuses, and `hallpass repair FILE --restore-final-newline
--preview` applies instead. It prints a token (`newline1:sha256:...`) that
`hallpass repair FILE --restore-final-newline --token TOKEN` takes. Both
refuse (exit 1, `usage`, nothing changed) unless all of these hold:

- the ledger does not end with a line end, and it has a complete header;
- the ledger with a line end added verifies, for this pass: the last line
  parses and chains to the line before it;
- the witness exists, and the hash of that last line is the tail the
  witness recorded at the last sequence number of the ledger.

The repair takes both writer locks, checks the token again, appends one
`\n` byte and syncs. It changes and removes no line, records no ledger line
and does not change the witness. The JSON reply has `repair`
`"restore-final-newline"`, `result` (`preview` or `repaired`), `seq`,
`length` (the length before the line end) and `token`. In Rust:
`preview_restore_final_newline` and `restore_final_newline`, which return a
`FinalNewline`.

### `reconcile-references(pass, adoption, references, reason, now)`

After an adoption that may have lost lines, every guarded spend is
`reference-inconclusive` (see "Caller references and receipts"). Putting
the old ledger back is `ledger-changed`, so the way back is a statement
from the operator, recorded in the ledger:

```text
hallpass reconcile-references FILE --adoption SEQ --references LIST --reason TEXT
```

`LIST` is a JSON file, at most 8 MiB:
`{"version": 1, "pass_id": "ID", "references": ["REF", ...]}`. It names
every caller reference that may be in the lines the adoption lost: in
practice, every reference that the run records of every caller on this pass
used. Each reference follows the caller reference rules, each appears once,
and a list holds at most 10,000. Record a longer list in parts of at most 10,000, one reconciliation after another with the same `--adoption`; each adds to the earlier ones, and until the last is recorded a reference not yet listed is accepted as new, so spend only after it. An empty list states that no reference was
lost. `--adoption` names the latest adoption that may have lost lines: the
sequence that the `reference-inconclusive` message and
`ledger --format json` (`unreconciled_adoption`) give. The reason follows
the note rules and is required.

The reconciliation is a line in the hash chain, like an adoption:

```text
{"seq":5,"time":"…","event":"reconcile-references","adoption":3,"reason":"every reference in the shift 17 journals","digest":"sha256:…","references":["unit-1","unit-2"],"prev":"sha256:…"}
```

From that line on, a guarded spend decides in this order:

1. a debit in the ledger carries the reference: `duplicate-reference`;
2. a reconciliation lists it: `duplicate-reference`, with `reconciled_at`;
3. an adoption that may have lost lines has no reconciliation after it:
   `reference-inconclusive`;
4. the ledger has lines but no local witness: `reference-inconclusive`;
5. otherwise the reference is new.

A reconciliation covers the adoption it names and every earlier one. A
second reconciliation of the same adoption adds its references. A later
adoption that may lose lines makes references inconclusive again until it
is reconciled too; the lists of earlier reconciliations that are still in
the chain keep refusing their references. A reconciliation permits nothing,
changes no count, and does not check the window. Under both writer locks it
compares the ledger with the witness as a spend does, appends the line and
syncs it, then updates the witness.

Nothing is recorded, and the error is `usage`, when the reason or the list
breaks these rules, the ledger has no adoption that may have lost lines,
`--adoption` is not the latest one (the message names it), or the ledger
has lines but no witness (hallpass cannot tell a partial copy from the
whole history: adopt it as it stands first). With no ledger, it is `usage`,
or `ledger-missing` (or `ledger-elsewhere`) when the witness recorded lines.
A changed ledger is `ledger-changed`, and the state directory errors are
those of `spend`. When the line was appended and only the witness update
failed, the error is `witness-unavailable` with a null `recording`, and the
reconciliation stands; the next command accepts the ledger, since it only
adds to what the witness recorded.

The ledger accepts the line only where hallpass writes it: after an
adoption that may have lost lines, naming the latest such adoption, with
distinct valid references and a valid reason. Anything else is
`ledger-corrupt` at that line.

**Why this is safe.** The guard's promise is that a reference already used
on this pass is refused. After a lossy adoption, hallpass cannot keep it
alone, because the lost lines are gone. The reconciliation keeps it with
the operator's run records, and only by a statement recorded in the ledger:
a reference that was used in a lost line is accepted as new only when an
operator recorded a reconciliation, with a reason, whose list leaves it
out. Until then every reference stays inconclusive. The line names the
adoption it covers, and the command refuses a list made for an earlier
adoption, so a list never silently covers a loss it was not made for. Every
reference it lists stays a duplicate for as long as the line is in the
chain. A second loss starts the refusal again. A loss that takes the
reconciliation with it is itself an adoption that may have lost lines.

A listed reference is refused, whatever its prefix, rather than accepted
under a new prefix or epoch: a prefix proves nothing about references
that callers outside the operator's control used, and an exact list can be
audited line by line against the run records. A caller that owns a prefix
should still list every reference it used.

**Compatibility.** The line is a new kind; the ledger version stays 1. The
line has the field `references`, which no earlier line shape accepts, and
lacks the fields that identify a spend, debit or adoption (`counter`,
`charges`, `carried`). A hallpass from before this line decodes no shape
from it, so every command of it that reads the ledger (`status`, `permits`,
`spend`, `capacity`, `rehearse`, `ledger`, `adopt`, `receipt`,
`audit-receipts`, `audit-charges`, `reconcile`, `checkpoint`,
`verify-checkpoint`, `compare-backups` for that candidate, and `diff
--budget-impact`) fails with `ledger-corrupt` at that line, and nothing
more can be spent there. It never counts around the line or skips it. Use
a hallpass that reads the line; do not remove it. This hallpass, too,
reports a complete line whose `event` it does not know as `ledger-corrupt`,
and says that a newer hallpass may have written it.

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
- Replace the pass file at its path: write the new version to a file in the
  same directory, `chmod 600` it, and `mv` it over the old one, so that no
  command reads a save in progress. `spend`, `permits` and `status` note the
  pass file they read (device, inode, birth time where the file system
  records one, and the digest) in `<pass id>.pass-file` in an existing state
  directory. When a later one reads the same file with other contents, it
  warns that the pass was changed in place and recommends `mv` and
  `--digest`. It warns once per change and never refuses. A touch (same
  contents) and a replacement by `mv` (a new file) are not warned about. The
  warning comes after the change, so it does not stop a read of a save in
  progress; it tells the operator that their way of saving is exposed. A
  revision kept as a second file with
  the same id has no ledger beside it, and is refused as `ledger-elsewhere`
  while the first file's ledger is intact (see "The witness").

### Fail-closed cases

Every error below exits 1. The caller must stop. An append or witness failure can leave a debit on disk.

Every file a command reads is opened the way a pass is: never through a
symbolic link, only a regular file, and without blocking. That covers the
pass, the ledger, the witness and lock files, and every input: a scenario, a
case suite, a checkpoint, a backup candidate, a manifest, a reference list,
a signature, a trusted signers file and the archived files. A FIFO in place of
any of them is refused at once with `not-regular-file`.
`compare-backups` refuses the whole comparison when a candidate is not a
regular file, before it reads any; a link, a missing file or a damaged copy
is still reported in that candidate's row.

| Case | Code |
|---|---|
| the pass or ledger file is missing, unreadable, or fails to write | `io` |
| the pass or ledger path, or any other file a command reads except a trusted signers file (`--allowed-signers`), is a symbolic link (also if swapped in while opening) | `symlink` |
| the path of a file a command reads is not a regular file: a FIFO, a device, a socket or a directory (also if swapped in while opening; the open never waits for a FIFO's writer) | `not-regular-file` |
| the pass is larger than 1 MiB | `too-large` |
| `spend` (not `--dry-run`), `adopt` (not `--preview`) or `reconcile-references`, when the directory that holds the pass can be written by others and lacks the sticky bit | `shared-directory` |
| the pass, or a trusted signers file (`--allowed-signers`), is writable by group or others; the ledger has any group or other bit; a directory above the file that a trusted signers link resolves to is writable by group or others without the sticky bit | `insecure-permissions` |
| the pass, or a trusted signers file (or a directory above the file that its link resolves to), belongs to a user other than the effective user or root | `untrusted-owner` |
| the pass does not validate (every problem listed), changed while it was read, or does not end with a newline | `invalid-pass` |
| the ledger is empty, has a cut last line, an unreadable line, a sequence gap, a broken hash chain, an invalid field, or sums beyond 10^12 | `ledger-corrupt` |
| the ledger's pass id differs from the pass's | `ledger-foreign` |
| `spend`, `adopt`, `reconcile-references`: the command runs under the test clock and the ledger holds a line written at the real time, or it runs on the real clock and the ledger holds a line written under the test clock ([Test-clock lines](#test-clock-lines)) | `ledger-clock-mix` |
| the ledger is missing but its witness recorded lines | `ledger-missing` |
| the ledger is missing (or, for `adopt`, does not hold the witnessed line), but the ledger the witness last saw at another path is intact, perhaps with entries after the witness (a second pass file with the same id, or a pass moved without its ledger) | `ledger-elsewhere` |
| the ledger does not hold the line its witness recorded | `ledger-changed` |
| `spend`, `adopt`, `reconcile-references`: no state directory, or it is not a private writable directory, or the witness is damaged or not private | `witness-unavailable` |
| the command used up its `--lock-timeout-ms` (or `lock_timeout`) waiting for a ledger or witness lock, before it read or recorded anything | `lock-timeout` |
| writing the line failed, and the ledger was cut back to its length before the write and synced, under the lock and before the witness was updated: nothing was recorded | `ledger-append-failed` |
| the line was written but its sync failed, or a failed write could not be rolled back; the caller must reconcile the ledger before retrying | `ledger-append-uncertain` |
| the spend was recorded but the witness could not be updated afterwards (the spend counts; do not proceed) | `witness-not-updated` |
| `init` target already exists (also a dangling link) | `exists` |
| an archived entry's bytes do not match its digest, or a signature record or its `.sig` file is damaged (the archive was changed or is broken) | `archive-corrupt` |
| bad arguments: malformed `--to`, `--digest`, `--n 0`, a bad note or reason, nothing to adopt, a bad reference list or nothing to reconcile, a malformed test clock | `usage` |

A missing ledger is not an error when no witness records lines for the
pass id: it means nothing was spent.

A JSON error says in `error.recording` what the failed command left in the
ledger. After `witness-not-updated`, `error.recording` is `recorded` and the
JSON error contains `seq` and `ledger`. A `ledger-append-uncertain` error
includes the ledger path and `recording = "uncertain"`. Both exit 1. Inspect
the ledger and reconcile before retrying.

Every append happens under both writer locks, before the witness is
updated. An append that would take the ledger past the process's file size
limit (`RLIMIT_FSIZE`, `ulimit -f`) is refused before anything is written,
because the kernel ends a process that writes past it with `SIGXFSZ`;
hallpass checks the same limit before it writes a new ledger, a witness or
a repair copy. When the write fails (for example a short write on a full
disk, or that refusal), hallpass cuts the ledger back to its length before
the write and syncs it. When that works and the length reads back as before,
the ledger holds exactly its previous bytes, since an append only adds bytes
at the end: the error is `ledger-append-failed` with the ledger path and
`recording = "not-recorded"`, and the command can be run again once the cause
is fixed. `recording` is `uncertain` in two cases. First, the rollback
failed: the ledger may end with a cut-short line, which `repair
--drop-torn-tail` can remove. Second, the whole line was written but its
sync failed: after a failed sync the page cache no longer tells what is on
disk, and a later sync can report success without writing the line, so
hallpass leaves the line in place. If it is there, it counts. `lock-timeout` and
`witness-unavailable`, `shared-directory` and `archive-corrupt` have `recording = "not-recorded"`: the attempt appended
no entry to the ledger. So does every `usage` error, whether clap or hallpass
found it, because arguments are checked before any write. So does every error
of a command that never appends to a ledger (for example `ledger`, `check`,
`receipt`, `reconcile`, `capacity`): an `io` error from `ledger` has
`recording = "not-recorded"`. The exception is an `adopt` whose adoption was
appended before the witness update failed: its `witness-unavailable` error has a
null `recording`, and the adoption counts. The same holds for a
`reconcile-references` whose reconciliation was appended. `recording` is null
only for an error of a command that can append (`spend`, `adopt`,
`reconcile-references`, `status`) that is not a usage error and not named
above, such as an `io` error: hallpass cannot say whether the write happened.

## Budget questions

Neither command below writes a ledger or a witness, and neither reserves
budget. Each live unit still needs a successful spend.

### `capacity`

Run `hallpass --format json capacity PASS` with the same unit syntax as spend,
using a positional counter with optional `--n` or repeated `--charge`.
`--to`, `--name`, `--duration` and `--digest` apply the same debit policy at
one instant. Each counter's capacity is `floor(remaining / n)`. The minimum
is the overall `units`, and `limiting_counters` lists every tied counter in
request order. The `counters` rows include `counter`, `n`, `total`, `spent`,
`remaining`, that counter's `units` and `remaining_after` the overall count.
A valid unit yields `result=capacity` and exit 0, including at zero with
`unit_refusal` describing the first exhausted budget. An invalid unit policy
yields exit 2, `result=refused`, `units: null`, `refusal` and a one-based
`refused_target` when applicable. A usage or evidence error exits 1. Capacity
writes no ledger or witness and reserves no budget.

### `rehearse`

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

## Approval review

These commands read passes and, for `--budget-impact`, the verified ledger.
None of them authorizes a spend.

### Comparing revisions

`hallpass diff OLD NEW` is read-only and compares declared fields, printing
both byte digests. It normalizes port ranges, distinguishes informational
`hostname` from enforced `names`, reports destination additions/removals and
order changes, and flags uncertain containment for owner review. It never
authorizes a spend. In `diff`, `before` and `after` are JSON strings, numbers
or null (absent); text prints absent values as `none`. A network change is
named `destination[LABEL].network`, or `.address` when both sides are single
hosts.

An introduced or removed destination prints its full grant on one line,
`introduced destination: LABEL grants address|network VALUE PROTOCOL ports
PORTS, any name|names LIST [review required]`, and the JSON carries the same
values in `introduced_grants` and `removed_grants`. When a new destination
lets another destination's `names` list have no effect (the `check`
name-restriction overlap), text adds a `WARNING:` line and JSON lists it in
`name_restriction_overlaps` and `warnings`, as `check` does; overlaps
already present in OLD are not repeated.

Comments and layout are part of the signed and digested bytes, so two
files can have different digests and the same declared fields.
`same_declared_fields` is true when no field, destination, destination
order or approval ID differs. When it is true and the digests differ, text
adds one line, `The digests differ, but no declared field does: the files
differ only in ...`, and JSON lists each kind of change in `text_changes`:
`comments` (added, removed, changed or moved), `layout` (whitespace, line
breaks, key order, or the form of a table or list) and `value-spelling` (a
value written another way, such as a time with another offset or a list in
another order). `comment_changes` lists each comment that only one file
has, as `{change, line, text}`: `change` is `removed` (only OLD has it, and
`line` is in OLD) or `added` (only NEW has it, and `line` is in NEW), and
`text` runs from `#` to the end of the line. A changed comment is one
removed and one added. Text prints each as `Comment removed (OLD line N):
"TEXT"` or `Comment added (NEW line N): "TEXT"`, escaped like every other
value. Both lists are empty otherwise.

`diff OLD NEW --examples --at TIMESTAMP` adds a bounded sample of changed
destination decisions using the ordinary evaluator at the supplied offset
timestamp. The report retains the field diff and review flags. Each
`examples.rows` entry includes the target, optional name, instant and
before/after label or refusal code. `examples.candidates` counts visits,
`evaluated` counts distinct requests, and `truncated` signals omitted work.
Sampling ends after 512 visits or 64 listed rows. Each row has `change`:
`newly-allowed` (refused to allowed), `changed` (any other change) or
`refusal-code-only` (refused before and after, only the code differs). Rows
are ordered newly allowed first, then changed, then refusal-code-only; text
prints a heading per kind. Refusal-code-only changes are noise for a
reviewer looking for new permissions, so they are counted in
`examples.refusal_code_changes` and not listed unless `--refusal-changes` is
given (`examples.refusal_code_changes_listed` says which). `--at` takes an RFC 3339
timestamp with an offset; `now` is refused.

A nameless destination that NEW adds or changes can open an address and
port that another destination, in OLD or NEW, restricts to names. The
sample tries those requests first: one address and one port for each such
pair and shared port range, once without a name and once with an
`example.net` name the named destination does not list (at most 64
requests). When the decision for one of them changes and NEW allows it,
its row names the bypassed destination in `bypasses_names_of`, and text
adds `, bypassing the names list of LABEL`. These rows come first in their
kind, so a newly allowed one comes before every other newly allowed row.
`bypasses_names_of` is null in every other row.

### Projecting an amendment against live balances

`hallpass diff OLD NEW --budget-impact --json` reads one verified summary from the live ledger. In the documented flow OLD is an archived copy with no ledger and NEW is the live pass, so the ledger beside NEW is used; the ledger beside OLD is used only when NEW has none. When neither has one and the witness names an intact live ledger for the id, with its pass file beside it, that ledger is read, read only, and the text says `Ledger used: PATH (the live ledger, named by the witness).`; if the live ledger has no pass file beside it, the command fails and says to give the live pass file as OLD. `budget_impact.ledger` is the path read and `budget_impact.ledger_source` is `new`, `old`, `live` or `none` (neither exists; the projection then starts from zero spend, or fails when the witness records spends). Text prints the same as `Ledger used:`. A read-only command never advises `hallpass adopt`; its ledger and witness errors say only that nothing was changed, and recovery advice appears from `status`, `spend` and `adopt`. Both digests identify the files compared. The projection gives the witness status and verified ledger tip (null before the first ledger). Each counter row shows the two limits, mandatory-charge flags and remaining amounts against the same historical spend, including adoption carry. A missing ceiling is null. For eight calls spent and a proposed ceiling of six, proposed_remaining is zero and over_proposed is two. This is a completed review (exit 0). `budget_impact.counter_substitution` is `{dropped, added}` when NEW drops a ceiling and adds one under a new name, and null otherwise. Text then warns that a new counter starts with nothing spent, so spend on a dropped counter does not count against it. Different pass IDs make a projection inapplicable (exit 2). Unusable accounting evidence exits 1. A proposal can change after review and concurrent spends can change these balances.

### Proving endpoint containment

`hallpass diff OLD NEW --containment --at TIMESTAMP` compares zero-duration endpoint admission at every instant. A request is admitted when the window is open, the pass is not revoked, and a destination rule matches the request. The rule match does not depend on the instant, so the endpoint proof compares the destination rules alone, and the window and revocation are judged as their own terms (see `loosenings` below). The verdict is therefore the same for every `--at`. Both validated revisions must have the same pass ID. When NEW is revoked it admits nothing at any instant (a window is never empty), and the endpoint result is `contained` with reason `new-admits-nothing`. Otherwise every request a proposed rule admits must be admitted by the old rules taken together, whether or not either window holds `--at`. The proof is exact. It splits the proposed rule's addresses at every start and end of an old rule with the same protocol, and for each piece merges the ports of the old rules that hold it. A proposed rule with `names` is checked once for each of its names, against the old rules that have no `names` or list that name. A proposed rule without `names` admits every name and none, so only old rules without `names` count for it. So two port ranges merged into one, two networks merged into the one that holds them, and a names list that two old rules give together are all `contained`. The IPv4 network and broadcast addresses that NEW excludes are left out of its rules, because NEW refuses them whatever the rules say. Every previously excluded IPv4 network or broadcast edge within a proposed destination must still be excluded for this proof. IPv6 transition exclusions apply identically to both revisions. Before this proof used the union of the old rules, each proposed rule had to fit within a single old rule, and these consolidations were `inconclusive` with reason `single-rule-coverage-unproved`.

The endpoint proof gives `containment.endpoint_result`: `contained` certifies that every endpoint/name pair NEW's rules admit is admitted by OLD's rules; with no window or revocation loosening, every request NEW admits at any instant OLD admits at that instant. `containment.compared_pairs` counts the proposed and old rule pairs the proof compared. The proof spends at most 4,194,304 units of work: one for each rule pair, address piece and port range it merges. Past that the endpoint result is `inconclusive` with reason `work-limit` (before, the limit was 16,384 rule pairs, with reason `pair-limit`). When the proof finds a request that no old rule admits, the reason is `union-coverage-unproved` until a replay shows it. When the proof fails, the existing bounded example search can establish `expanded` by exhibiting a new allowance; the requests the proof found uncovered are replayed after it, one for each NEW destination and port range the old rules do not cover, and one for each IPv4 edge that OLD excludes and NEW does not. The search replays requests through the ordinary decision procedure at `--at` when NEW's window holds it, and otherwise at NEW's `valid_from`; `containment.replayed_at` gives that instant (null when no search ran). OLD is replayed with NEW's window and revocation state, so a row differs only by the destination rules. Text says so when the instant is not `--at`. Every new allowance lies in a widened class: a NEW destination and port range that the OLD destinations together do not cover, or an IPv4 network or broadcast address that OLD excludes and NEW does not. A bypassed names list (see `--examples`) is a class of its own, once without a name and once with an unlisted name. `containment.counterexamples` lists up to eight new allowances, in the order of `examples.rows` and then the replayed uncovered requests, each in a class that no earlier one is in; so the bypassed names lists come first. `more_counterexamples` is true when the list is not empty and some widened class has no counterexample in it: the eight were not enough, a class holds no sampled allowance (a bypassed names list may hold none, and an uncovered request in an IPv6 transition range is refused by both revisions), or a work limit (4,194,304 units of work, 64 names-list requests) leaves the classes unknown. False means every widened class has a counterexample listed.
`containment.example` keeps the first of them. Otherwise the endpoint result is `inconclusive`, with a reason such as `work-limit`, `union-coverage-unproved` or `ipv4-edge-coverage-unproved`.

The overall verdict, `result` at the top level and `containment.result`, also covers the rest of the pass. `containment.loosenings` lists each non-endpoint change that gives NEW more authority, as `{field, before, after}` with the field named as in `changes`: a later `approval.valid_until`, an earlier `approval.valid_from`, a higher `ceilings.NAME`, a new `ceilings.NAME` unless NEW requires every debit to charge both it and a counter OLD had, a counter substitution (below), a counter dropped from `required_counters_v1`, `require_target_v1` turned off, `approval.revoked` turned off, and any change of `approval.owner` or `approval.operator`. A change that only narrows is not listed.

Ceilings are compared by counter name, because the ledger counts spend by name. A counter new to the pass starts with nothing spent, even when its work was charged to another counter before. So:

- A counter without a ceiling cannot be spent (`unknown-counter`), so a ceiling removed alone narrows.
- A new ceiling loosens unless NEW requires every debit to charge both it and a counter OLD had. Requiring the new counter alone is not enough: a debit can charge it and none of OLD's counters, so it is counted from zero outside every ceiling OLD set. When NEW also requires a counter OLD had, every debit still charges that counter and its spend so far.
- A counter substitution loosens: NEW drops an OLD ceiling and adds a ceiling under a name OLD did not have. Each dropped ceiling is listed as `ceilings.OLD` with `code` `counter-substitution` and `replaced_by` (the new names), whether or not NEW requires the new counters and whatever their amounts. A rename that keeps the amount, one ceiling split into two, and two ceilings merged into one are all substitutions. Applied mid-engagement, a rename of `requests = 3` (all spent) to `calls = 3` lets 3 more units go out. Text adds `renamed or replaced by "NEW" (counter-substitution)` to the `Loosened:` line. Other loosenings have no `code`.
- Adding a counter to `required_counters_v1` narrows; dropping one loosens.

Before this rule, a rename to a counter that NEW required, and a new counter that only NEW required, were `contained`.

The overall verdict is `contained` (exit 0) only when the endpoint result is `contained` and `loosenings` is empty. It is `expanded` when the endpoint result is `expanded`, and `widened` when `loosenings` is not empty and the endpoints are not shown to be expanded; an `inconclusive` endpoint result with no loosenings stays `inconclusive`. Every verdict other than `contained` exits 2, so a gate can rely on the exit code alone. A pure revocation is therefore `contained` (exit 0), while a revocation that also raises a ceiling is `widened`. An un-revoke compares the rules and is `widened` by the `approval.revoked` loosening. A revision that only narrows the window is `contained` at every `--at`. Text ends `Overall verdict: RESULT.` and one reason: for a contained revoked NEW, that it admits nothing at any instant; otherwise what contained means. Before this proof was independent of the instant, a NEW whose window did not hold `--at` was `contained (new-admits-nothing)` whatever its rules, and OLD closed with NEW open was `inconclusive (old-closed-new-open)`; neither reason is given now. Before this verdict covered the whole pass, `result` and `containment.result` reported the endpoint result only: a revision that kept the endpoints could be `contained` while it extended the window or raised a ceiling. Read `endpoint_result` for the old meaning. Invalid input exits 1. Label attribution and costs are outside the endpoint proof. See the accompanying declared-field diff for every edit.

### Name overlaps and declared breadth

`hallpass lint PASS` reports named rules overlapping nameless rules for the
same address family, protocol, and ports; each claimed effective allowance
is replayed through `permits_named` at the supplied time. Lint reports at
most 256 findings and indicates when it truncated the list. The finding code
is `name-restriction-overlap`. `check` and `status` also warn about each
such pair, in text and in `warnings` and `name_restriction_overlaps`. The
pass stays valid and `check` exits 0.

Lint also gives a `wide-port-grant` finding, after the overlaps, for each
destination that grants more than 1,024 ports or every port, as `{code,
label, protocol, ports, port_count, message}`; `ports` is sorted and
merged, as `1-65535`. The first line of the text report counts what the
report gives: `N advisory finding(s) and M warning(s) for ID`. The
findings are the lines that follow it and the rows of `findings`; the
warnings are the `hallpass: warning:` lines on standard error and the
entries of `warnings` (an unmatched acknowledgement, the window warnings
and the approval text warnings of `approval-id`).

The owner may accept one overlap in the pass: the named destination lists the
label of the nameless destination in `overlap_acknowledged`. That is advice
only and never changes a decision. `status` then prints one `Note:` line
instead of a warning on every call, and marks the pair `acknowledged` in
`name_restriction_overlaps`; `check`, `lint` and `diff` still show the full
overlap, marked as acknowledged, and `diff` lists a changed list as
`destination[LABEL].overlap_acknowledged` with review required. A label that
names no destination, the destination itself, a destination that has `names`,
or an acknowledgement on a destination without `names` makes the pass
invalid. A well-formed acknowledgement of a pair that does not overlap (the
addresses, protocol or ports are apart) is not an error, because it can hide
nothing; `check`, `status` and `lint` warn that it covers nothing
(`overlap-acknowledgement-unmatched`). That warning is skipped when `lint`
cut its list at 256 findings. A pass that uses the key is refused by a
hallpass that predates it, as any unknown key is.

`check` and `status` report exact declared address-space unions separately for
IPv4 and IPv6. Duplicate and nested service rules count once. One IPv4 `/8`
and one IPv6 `/64` are documented consumer comparison points; they are
advisory only and do not change existing validation caps.

### Window warnings

The window is the owner's decision, so an implausible one is a warning and never a refusal; exit codes do not change. `check`, `status` and `lint` warn, each with a code in `window_warnings` (list of `{code, message}`; each message is also in `warnings`):

- `window-too-long`: `valid_until` is more than 90 days after `valid_from`. A security-test engagement runs for days or weeks and a quarter is the longest ordinary one, so a longer window is more often a typo (`2062` for `2026`) than a plan. This needs no clock.
- `window-ended`: the clock is at or after `valid_until`, so every request is refused as `expired`. Skipped for a revoked pass.
- `window-starts-far-ahead`: `valid_from` is more than 30 days after the clock. Skipped for a revoked pass.

`status` and `lint` use the decision clock. `check` uses the same clock: the real time, or in a debug build (or one with the `test-clock` feature) the time in `HALLPASS_UNSAFE_TEST_CLOCK`. `check` reports it as `now` and `test_clock`. `diff` lists the same warnings for NEW as `new_window_warnings`, each message also in `warnings` with the prefix `NEW revision:`; it knows no clock, so `window-ended` and `window-starts-far-ahead` appear only with `--at`, judged at that instant, and `window-too-long` always appears. A warning that a window is long is judged on the window alone, not on a change: it shows even when the diff did not touch the window.


### Consumer coverage

`consumer-coverage PASS --can CAPABILITY` compares the full validated approval
with declared checks for literal endpoints, names, time and revocation, and
each charged counter. The response identifies its `pass_id`, `digest`,
`declared` features and individual `findings`. The operator supplies the
declaration. Live decisions and charges happen independently. Capabilities
are `endpoints`, `names`, `live-window`, `target-on-every-debit` and
`charge:COUNTER`, or `none` alone. Finding codes are `missing-endpoints`,
`missing-names`, `missing-live-window`, `missing-target-on-every-debit` and
`missing-counter`.

### Signed approvals

`verify-approval` uses OpenSSH detached signatures under the fixed namespace
`hallpass-approval-v1`. A verified result includes the expected principal,
pass ID and digest of the exact bytes supplied to the verifier. The operator
provisions the trust file and selects the principal. It verifies as of now,
or as of `--at TIME`: a key that the trust file limits with `valid-after` or
`valid-before` counts only inside that window, and outside it the reason is
`key-not-valid-at-time`. A key whose line has a `namespaces=` option
without `hallpass-approval-v1` gives `key-not-permitted-for-namespace`. With `--archive`, the
verified bytes, the signature and a record of the verification are retained
(see "Archives and evidence").

A verified result also names the key that made the signature: `key`, its
fingerprint as `ssh-keygen` printed it (`Good "hallpass-approval-v1"
signature for PRINCIPAL with TYPE key SHA256:...`), or null when it printed
none. `principal_match` says how the trust file matched the principal:
`named` when a line that holds the key names it without a pattern (alone, or
in a list of names), `pattern` when only a line whose principals use `*`,
`?` or `!` does, and `certificate` for a certificate trusted through a
`cert-authority` line, whose certificate `ssh-keygen` checked names the
principal. A `pattern` line trusts its key for everyone it matches, so it
does not say that the key is the principal's: the result is still
`verified`, with a warning, unless `--allow-pattern-principals` is given.
To tell the two apart when the trust file has a pattern line, hallpass
verifies a plain key again with only the lines that name their principals.
`--signer-key SHA256:...` requires the signature to be made with that key:
another key is `unverified` with reason `signer-key-mismatch` and the key
that made it, and nothing is archived.

The trusted signers file decides whose keys count, so it follows the pass
file's rule wherever hallpass reads it (`verify-approval` and the audits'
`--allowed-signers`): owned by the effective user or root, and writable by
neither group nor others. Otherwise the command stops with
`untrusted-owner` or `insecure-permissions` and the `chmod 600` to run.

The trusted signers file is read only, so it may be a symbolic link, as a
Kubernetes `ConfigMap` or `Secret` mount or a link under `/etc` is. hallpass
resolves the link, applies the rule to the file it reaches, and requires each
directory above that file to be owned by the effective user or root and not
writable by group or others (a directory with the sticky bit is allowed).
Messages name the resolved path. A link whose target fails the rule is
refused as a file that fails it would be. A path that is not a link is
checked as before, and no other input may be a link.

hallpass trusts the `ssh-keygen` it runs: it is the absolute path in
`HALLPASS_SSH_KEYGEN` when that is set, else `ssh-keygen` on `PATH`. A
`HALLPASS_SSH_KEYGEN` that is not an absolute path is a `usage` error.
Whoever controls hallpass's environment controls its verifier either way;
set `HALLPASS_SSH_KEYGEN` to pin it, for example to `/usr/bin/ssh-keygen`,
when not every directory on `PATH` is yours. See the signing and
digest-pinning workflow in the [integration guide](INTEGRATING.md#signing-and-verifying-an-approval).

### Case suites

`hallpass test-pass PASS SUITE` checks up to 1,024 ordered cases offline.
Exit 0 means all cases matched, 2 means an expectation differed, and 1 means
invalid input or an error. See the [example suite](review-suite.toml).
The opt-in `--strength` mode first checks the baseline, then evaluates up to 64
in-memory mutations that only loosen the pass: remove destination name
restrictions, extend a port range by one adjacent valid port, widen a network
by one bit (a single address becomes a /31 or /127), add the other transport,
and move `valid_from` one second earlier and `valid_until` one second later.
It reports the first case that distinguishes each edit or marks the edit as
surviving. A mutation that would not validate, and every ceiling change
(cases cannot spend), has status `skipped` with a `reason`; `mutations_skipped`
counts them and `mutations_tested` does not. Work is capped at
4,096 total case evaluations; incomplete analysis exits 2 and is explicitly
truncated. Survivors are review prompts, never instructions to change the
approval.

## Accounting history

### Checkpoints

`checkpoint` exports a versioned pass ID, sequence and exact-line hash, plus
whether a local witness corroborates the history. JSON `witness.relation` is
`matches`, `lags` or `absent`, observed under the same lock as the export, with
`witnessed_seq` and `exported_seq`. Only `lags` and `absent` add a warning.
`local_corroboration` is true for `matches` and `lags`. A pass with no ledger and
no witnessed spend has nothing to commit to. `checkpoint` then exits 2 with
`result = "empty"`, `checkpoint = null` and empty text output. A witnessed spend
with a missing ledger is still an error. `verify-checkpoint` validates the supplied ledger and reports `exact`
or `extended` (exit 0), `mismatch` (exit 2), or an input/error condition (exit
1). Its JSON `relation` refines `result` with the words `compare-backups` uses:
`exact`, `extended`, `shorter` (the ledger is of the same pass but ends before
the checkpointed line, as an older copy does; `result` is still `mismatch`),
`foreign` (another pass) or `mismatch`. Only the length is checked for
`shorter`: the checkpoint cannot show that the copy is a true prefix. Verification uses the supplied checkpoint as its trust input and does not
read or create a witness. Retain checkpoints separately from the ledger.

The checkpoint object also has `totals`: per counter, what the ledger
counted through the checkpointed line (carried amounts included). The hash
does not cover them. A checkpoint without `totals` (from an earlier
hallpass) is still read; `verify-checkpoint` refuses `totals` that are not
counter names with whole numbers from 0 to the largest ceiling.

It also has `latest` and `anchors`, which place a shorter ledger (see
[After a whole-machine restore](#after-a-whole-machine-restore)).
`latest` is the latest time on any line through the checkpointed one (RFC
3339; absent when no line has a time). `anchors` maps a sequence to the hash
of the line that ends there, for the 16 lines just before the checkpointed
one and for the lines a power of two after the header or before the
checkpointed one (at most 144; none inside a debit batch line, which ends at
a later sequence). A checkpoint without them (from an earlier hallpass) is
still read; `verify-checkpoint` refuses a `latest` that is not an RFC 3339
time, and `anchors` with more than 256 entries, a sequence of 0 or not
below the checkpoint's own, or a hash that is not one.

### After a whole-machine restore

A restore of both the ledger and the state directory from an older copy
leaves a ledger and witness that agree, so only a checkpoint retained
elsewhere shows the loss. `doctor FILE --checkpoint CHECKPOINT` reads the
checkpoint exactly as `verify-checkpoint` does (a file it would refuse is
doctor's own error, exit 1) and compares it with the ledger, read only:

- the ledger holds the checkpointed line (`exact`, `extended`): finding
  `checkpoint-holds`;
- an adoption in the ledger acted on this checkpoint: finding
  `checkpoint-adopted`;
- the ledger ends before the line (`shorter`), or reaches its sequence
  with another line there (`mismatch`): **blocked** `checkpoint-behind`,
  naming `adopt FILE --checkpoint CHECKPOINT --preview`; with a checkpoint
  without `totals` it names no command;
- either of those, but the lines the checkpoint proves are its own count
  more of some counter than the checkpoint records (counts only grow, so
  its totals do not belong to its line hashes): **blocked**
  `checkpoint-fork`, with no command: hallpass does not merge two
  histories;
- the checkpoint is for another pass: **blocked** `checkpoint-foreign`.

A shorter ledger is not always an older copy of the checkpointed history.
After a whole-machine restore a worker may spend before anyone runs
doctor, and then the ledger's last entries are new spends at the sequences
the lost entries had. When the worker spends more often than the restore
lost entries, the ledger reaches the checkpoint's sequence with a new line
there (`mismatch`). So hallpass places either ledger by the checkpoint:

- **shared**: the ledger's lines through the last anchor whose hash the
  ledger has at that sequence, taken in order up to the first it does not
  have, are the checkpointed history's own (each line hash covers every
  line before it). Only the header is shared when there is no such anchor,
  and always for a checkpoint without `anchors`.
- **new**: the ledger's line at the first anchor it does not have, and
  every later line, are not checkpointed ones; nor is a line whose time is
  later than `latest`, or any line after it. For a ledger that reaches the
  checkpoint's sequence, the checkpoint's own `hash` is one more anchor it
  does not have.
- the lines between are not placed: the checkpoint has no hash for them.

The doctor finding and the preview say which lines are which. The headline
says entries `ledger_seq + 1` to the checkpoint's sequence are missing only
when every ledger line is shared; otherwise it says checkpointed entries
after the last shared line are missing. When no anchor is shared, or the
checkpoint has no `anchors`, no line is shared and every ledger line counts
as new: the carry may be too high, never too low, so hallpass names the
adoption and says so rather than leaving no step.

Times never prove a line shared: a restored machine's clock may run behind
the one that wrote the lost entries, so a spend since the restore can carry
an earlier time than `latest`. A time later than `latest` does prove a line
new, whatever any clock did, because no checkpointed line has a later time.
A clock that ran ahead before the restore only makes `latest` later, so
fewer lines are proved new; the carry does not depend on times.

`adopt FILE --checkpoint CHECKPOINT` (with `--preview`, then `--reason` and
`--token`) acts only on `checkpoint-behind` with `totals`, for a `shorter`
or a `mismatch` ledger alike. Every other
relation is a usage error that names the next step. The adoption carries,
per counter, what the checkpoint's totals record beyond what the shared
lines count, and so counts every other ledger line as new: the result is at
least the checkpoint's totals plus every spend since the restore. A line
that is not placed but was in fact an older copy of a checkpointed one
counts twice, which is on the safe side for spending; with a checkpoint
without `anchors`, every ledger line counts so. When the ledger has changed
between the comparison and the adoption's lock, the adoption refuses and
names doctor again. When
the witness also calls for an adoption (`ledger-missing`,
`ledger-changed`, `no-witness`), it carries per counter the higher of the
two, so no count goes down. Its case is `checkpoint-behind` when the ledger
and witness agree or there is neither. The line records the checkpoint
(`checkpoint`, as exported but without `latest` and `anchors`), so it is
not adopted twice; its sequence may be below the adoption line's own.
`verify-checkpoint` still says `mismatch` after the adoption: the lost
lines are not back. The token covers
the checkpoint. `--checkpoint` cannot be used with `--drop-rehearsal`.

The checkpoint proves that a ledger of the pass once reached its sequence
with the line it commits to, and which
ledger lines are its own as far as its anchors reach. It cannot show what
the missing entries were, and nothing authenticates its totals beyond the
operator who kept it. A higher count is the safe side for spending; a total
edited lower would carry too little. `adopt --preview` says this in
`warnings`. An adoption from a checkpoint always may have lost caller
references, so guarded spends are `reference-inconclusive` until
`reconcile-references` follows it.

### Archives and evidence

`archive PASS DIR` retains the exact validated pass bytes in a private
directory, and `retrieve DIR DIGEST` prints them again by their full digest.
`retrieve DIR DIGEST --output FILE` writes them to a new file instead, with
mode 0600 whatever the umask; it refuses a path where anything exists (a file
or a link, a dangling link included) and removes a file it could not finish
writing. Redirecting the output with `>` gives the file the shell's umask
mode, 0664 under the common `umask 002`, which `diff` and `archive` refuse
because the group could change it.
`verify-approval --archive DIR` retains them too, after the owner's signature
verified, and keeps the signature (`DIGEST.sig`) and a record of the
verification (`DIGEST.approval`) beside them. The record is one JSON line
with `version`, `digest`, `namespace`, `principal`, `allowed_signers`,
`signature` and, in `version` 2, `key`, the fingerprint of the key that made
the signature. A `version` 1 record has no `key`; it still reads, with the
key unknown. Each archived digest therefore
has a provenance: `signature-recorded`, `unsigned` (archived without a
signature record, as by `archive` or an older version) or `missing`. Archive
files are created once and never replaced, so `archive` never upgrades or
downgrades a digest; only `verify-approval --archive` adds a record. Reading
a record does not verify its signature, and anyone who can write the archive
can write one.
`receipt`, `audit-receipts`, `audit-charges`, `reconcile` and
`compare-backups` read the ledger under shared locks and report historical
evidence. None of these commands writes the ledger or the witness. Both
audits report every revision the ledger used with its provenance. With
`--allowed-signers FILE` they run `ssh-keygen -Y verify` again over each
recorded revision's archived bytes and signature with FILE, as of the time
the revision was first used (`--signatures-as-of now` for the current time),
and report it `signature-verified` or `signature-rejected`. FILE decides
whose keys count; `--principal`, which can be repeated, decides who must have
approved. Without `--principal`, each signature is verified for the principal
its record names, and a revision that verifies is a `signer-not-pinned` gap.
So the audits are `complete` only when every revision used is
`signature-verified` for a principal named with `--principal`, and never
without `--allowed-signers` and `--principal`. Archived bytes are never
edited, so a revision whose bytes match their digest but break a pass rule
added since it was archived is a `revision-unparsable` gap, not an error, and
its signature is still verified. They run `ssh-keygen` after they release
the ledger lock, over copies of the bytes they read under it.
[EVIDENCE.md](EVIDENCE.md) gives their results, exit codes and fields.

## Command line

```text
hallpass [--format text|pretty|json] <command>
hallpass help [COMMAND]
hallpass version
```

Use `hallpass help --format json` for the installed command directory and
`hallpass help COMMAND --format json` for arguments, usage, examples and
workflow. The global format option works on either side of the command,
before the argument separator `--`. An explicit format overrides the `HALLPASS_FORMAT` environment variable
(`text`, `pretty` or `json`); an invalid value is a usage error that names
it. The unprefixed `FORMAT` variable is ignored, with a warning when
`HALLPASS_FORMAT` is not set. `--json` means `--format json`. Repeating
it, or giving it with `--format json`, is fine. `--json` together with
`--format text` or `--format pretty` is a usage error that names both flags;
its JSON object is printed because `--json` was given.
With neither set, terminals select pretty and pipes select text. Operational
commands use their established plain output in both modes. The help command
uses a compact listing in text and the expanded listing in pretty.

Use `hallpass --version` for the binary version. Readers should accept extra
JSON fields. Stable refusal/error codes and on-disk format versions are
separate contracts.

Exit **0** indicates success, **1** indicates a usage, file or accounting
error, and **2** indicates a policy refusal, verification mismatch, coverage
gaps or inconclusive evidence. Text
errors go to stderr. In JSON mode every command emits one object on stdout,
including usage errors, help and version. In JSON mode a parser failure prints
nothing to stderr. Its object has `error.code = "usage"`, `file` null,
`error.recording = "not-recorded"`, and `command` set to the subcommand when
it was recognized (null otherwise). Help and version requests return their own command name and
`result = "ok"`. Counted work requires a successful spend reply. See the
[caller contract](INTEGRATING.md).

A text error starts with a short headline:
`hallpass COMMAND: error: CODE: WHAT IS WRONG`. When there is one next
step, the second line is `Next: STEP`. The full message follows, indented
by two spaces; it says the same as `error.message` in JSON. A long message
is one step per line: its first sentence, then each later sentence or
alternative on its own `- ` line, indented two spaces more. An error with
no headline of its own (`io`, `usage`, `untrusted-owner`,
`archive-corrupt`) puts the first line of its message after the code.
`doctor` prints its verdict the same way: `BLOCKED: CODE: HEADLINE` (or
`NEEDS ACTION:`), then `Next:` and the step, then `Details:` with the
rest of the explanation, then `Also:` with the other findings. Details
and findings are broken into steps the same way, and so are a refusal and
the long lines of `adopt`, `reconcile-references` and `repair`. Only white
space changes: the words are those of the JSON message. Text output shows a
path under the current directory relative to it, so a command it names runs
as written in that directory; other paths stay absolute (never `../`). On a
terminal (standard output and standard error both), long lines wrap at 100
columns, or `COLUMNS` when that is smaller, and a command in backticks is
never broken; otherwise there is no wrapping. JSON keeps absolute paths and
one-line messages. Callers read the JSON, not this text.

| Command | Exit 0 | Exit 2 | Exit 1 |
|---|---|---|---|
| `help` | the command directory, or one command's page | never | unknown topic |
| `version` | the version | never | bad arguments |
| `init` | template written (mode 0600; it does not validate until filled in) | never | file exists, write failed |
| `check` | the pass validates (warnings can still be present) | never | any problem |
| `status` | the window is valid | not-yet-valid, expired or revoked | invalid pass, ledger error (also missing or changed per the witness) |
| `doctor` | `healthy`: nothing blocks a spend and nothing needs doing | `needs-action` or `blocked`, with the one next command | a pass path that cannot be read or is not a regular file, an unusable archive directory, a `--checkpoint` file that `verify-checkpoint` would refuse |
| `permits` | allowed | refused, also `pass-changed` with `--digest` | invalid pass or target, ledger error (as `status`) |
| `spend` | recorded (with `--to`: and the destination is permitted); with `--dry-run`, `would-allow` | refused by the digest, the window, the reference guard, the destination or the ceiling; nothing recorded | error; inspect recording state before retry |
| `capacity` | budget count, including zero | invalid unit policy | usage, pass or accounting error |
| `rehearse` | `simulated`: every step fits | `simulation-refused`: a step is refused | invalid scenario or pass, accounting error |
| `digest` | printed | never | invalid pass |
| `ledger` | listed (also when there is no ledger yet) | never | invalid pass, ledger error (as `status`), bad `--counter` |
| `adopt` | adoption recorded, or the `--preview` snapshot | never | invalid pass, damaged ledger, nothing to adopt, the ledger is intact elsewhere, missing reason, stale token, unusable state directory, a `--checkpoint` that does not show the ledger behind it |
| `repair` | the cut-short last line was removed, or the `--preview` | never | invalid pass, no ledger, nothing safe to remove (a complete last line, damage before it, no witness, a line the witness counted), stale token |
| `reconcile-references` | reconciliation recorded | never | invalid pass, list or reason, damaged, missing or changed ledger, no adoption to reconcile, not the latest such adoption, no witness, unusable state directory |
| `archive` | the exact bytes are retained | never | invalid pass, unusable archive directory |
| `retrieve` | the exact bytes are printed | never | malformed digest, missing or unusable archive entry |
| `receipt` | `found` | `absent`, `ambiguous` | the reference, pass, ledger or witness could not be checked |
| `audit-receipts` | `complete`: and `--allowed-signers` verified a signature over every revision used again, for a `--principal` | `incomplete`, `mismatch` | unusable ledger, archive entry, signature record or trusted signers file; `ssh-keygen` cannot run for a recorded signature, or does not accept `-O verify-time` |
| `audit-charges` | `complete`: and `--allowed-signers` verified a signature over every revision used again, for a `--principal` | `incomplete`, `mismatch`, `empty` | unusable ledger, archive entry, signature record or trusted signers file; `ssh-keygen` cannot run for a recorded signature, or does not accept `-O verify-time` |
| `reconcile` | `match` | `discrepancy` | invalid manifest, pass or history |
| `compare-backups` | `preserved` | `no-match`, `ambiguous`, `inconclusive` | `partial-error` (a candidate failed), invalid pass, a candidate that is not a regular file, `lock-timeout` |
| `checkpoint` | exported | `empty`: nothing recorded yet | invalid pass, ledger error (as `status`) |
| `verify-checkpoint` | `exact` or `extended` | `mismatch` | malformed checkpoint, missing or damaged ledger |
| `verify-approval` | `verified` | `unverified` | invalid pass, unavailable verifier or input |
| `diff` | field comparison completed, including any requested sample or projection; with `--containment`, overall `contained` | `--containment`: `expanded`, `widened` or `inconclusive`; `--budget-impact`: different pass IDs | invalid pass, instant or usage, unusable accounting evidence |
| `consumer-coverage` | `covered` | `gaps` | invalid declaration or pass |
| `lint` | the report, with or without findings | never | invalid pass |
| `test-pass` | every case matched; with `--strength`, `complete` | a mismatch; with `--strength`, survivors, partial analysis or a failed baseline | invalid pass or suite |
| `approval-id` | the ID is printed | never | bad arguments, including an owner or reference that a pass could not hold (the text rules of PASS-FORMAT.md) |

`check` does not judge the window; `status` does.

`doctor` runs the checks the other commands run (the pass and its file
mode, the directory that holds it, the ledger chain, the witness and its
totals, a ledger elsewhere, a cut-short last line, rehearsal and live
lines, an in-place edit, the window, with `--archive DIR` whether the
archive holds this revision, and with `--checkpoint CHECKPOINT` how the
ledger relates to a retained checkpoint) and names exactly one next command with the
real paths, or nothing to do. It uses the library's own errors and advice:
`ledger-corrupt` with a last line that lacks only its line end, which the
witness recorded, names `repair --restore-final-newline --preview`; a
cut-short last line that the repair preview accepts names
`repair --drop-torn-tail --preview`; other damage and `ledger-changed`
name `compare-backups`, and with no other ledger for the pass id in sight their step also gives the last resort for a pass with no backup (move the ledger aside, then adopt, with the exact commands and the warning that the moved ledger's receipts leave the chain), and `compare-backups` with no copy that holds the witnessed line gives the move as `last-resort` advice with its `argv`, so following the named commands ends; `ledger-elsewhere` names the `mv` of the live ledger
(or a `diff` with the live pass file when one is beside it), and
`ledger-missing` names `adopt --preview`. It never names `adopt` while the
ledger may be intact elsewhere: when a file is still where the witness last
saw the ledger, it names `compare-backups` on that file instead. Doctor
reads only: it writes no witness, note or lock file and does not create the
state directory. A lagging witness beside its ledger needs nothing (the
next spend catches it up). No witness is a finding while the ledger has no
entries; with entries, a spend with `--require-new-ref` is refused as
`reference-inconclusive`, so doctor reports `needs-action` and names
`adopt --preview`, for a ledger that is the complete history. A damaged
witness beside a verifying ledger names the `mv` of the witness aside, and
then that adoption. Doctor checks with `access(2)`, without writing, that
a spend can write the state directory, its lock file and the ledger (or
the directory a first spend creates the ledger in); when one cannot be
written it reports `blocked` with the `chmod` to run, or, for a path
another user owns, no command (for a state directory that a spend would
create under such a directory, it says to set `XDG_STATE_HOME` instead). When every ceiling
is reached, every spend is refused, and doctor reports `blocked` with
`ceiling-reached`. A `ledger-changed` ledger whose witness last saw
another ledger file for the pass id names `compare-backups` on both.
`healthy` means that the next spend, with or without `--require-new-ref`,
does not fail for the state of the pass, its ledger or its witness.

Warnings (no witness yet, a ledger extended past its witness or moved, a
witness that could not be checked, a debit that checked no destination, a
decision clock earlier than the latest ledger event, a directory holding the pass that group or others can write without the sticky bit (see below), a destination whose
`names` another destination defeats, declared breadth beyond a comparison
point) go to standard error as
`hallpass: warning: ...` in text output, and into `warnings` in JSON.

**Shared directory.** Someone who can write the directory that holds the
pass, and so its ledger and lock file, can `rename` or delete files there
without writing to them, which the file-mode checks do not see. This includes
putting the operator's own older revision of the pass over the current one:
it has the right owner and mode and the same id, so an unpinned spend would
run under the older approval. When the directory has a group or other write
bit and no sticky bit (mode 1000):

- If others can write it (`o+w`), `spend` (not `--dry-run`), `adopt` (not
  `--preview`) and `reconcile-references` are refused with error
  `shared-directory` before anything is recorded (`recording =
  "not-recorded"`). The fix is `chmod o-w DIR`, or `chmod +t DIR` if the
  directory must stay shared. This is a new refusal (compatibility change).
- Every other command that reads the pass (`check`, `status`, `ledger`,
  `permits`, `spend --dry-run`, `adopt --preview`) warns, and so does every
  command, writing or not, when only the group can write (`chmod go-w DIR`).
  A group-writable directory is common under `umask 002`, so it is not
  refused. Group write counts whoever the group's members are, as for a pass
  file.

A directory with the sticky bit (`/tmp`, mode 1777) raises neither. Only the
directory that holds the pass is checked, not its parents. The state directory
is not covered by this rule: it is already refused unless it has no group or
other bit (`witness-unavailable`, fix `chmod 700`).

`ledger` is read-only. It takes the same shared lock as `status`, verifies
the whole chain, compares it with the witness, and lists each entry
(sequence number, time, counter, amount, the pass digest it was made
under, note) and each adoption (with what it carried and its reason) and
reference reconciliation (with its adoption, its number of references, the
first ten of them quoted, and its reason last), then the total per counter.
While an adoption that may have lost lines is not reconciled, text adds a
`References:` line that says so. `--counter NAME` shows one counter.
`--tail N` shows only the last N entries and `--since SEQ` only entries with
sequence number >= SEQ. Both are applied to the output only: the whole chain
is verified and compared with the witness first (a damaged earlier line still
fails), and the totals and balances cover the whole ledger. Given together,
they select the intersection: first entries with seq >= SEQ, then the last N
of those. Both apply after `--counter` (adoptions and reference
reconciliations always count as entries).
`--tail 0` shows no entries but still verifies and prints the totals; a
`--since` beyond the last entry shows none. A slice is marked: text output
has a line `Showing entries A to B of T in the ledger (...)`, and JSON has
`shown`. A pass without a ledger says
so and exits 0. In text output every operator-supplied string (notes,
reasons, caller references, and pass text in `status`) is shown with
control characters, line and paragraph separators and Unicode format
characters escaped as `\u{...}` and a backslash as `\\`, so a note can
neither forge a line of output nor send a terminal escape sequence, and a
value recorded earlier with an invisible character shows it. A value that
text output quotes is in double quotes, with a `"` inside written as `\"`
and each character escaped once, so it cannot end its quotes early and
read as more fields: a caller reference (in `spend`, `ledger`, `receipt`
and `reconcile`), a receipt's target, name and label (in `spend` and
`ledger`), a value that `reconcile` says differs, a reason after "with the
reason", a signer principal (in `archive`, `audit-receipts` and
`audit-charges`) and the pass name in `status`. Error messages already
carry their own escapes, so their backslashes are printed once, as
written. The same rule holds for every message in text output: errors,
warnings, `REFUSED:` lines and advice. A message puts text from the
caller, the pass or an archive in as a quoted value (as `display_quoted`
writes it), and is printed with control, line-separator, bidi and format
characters escaped and its own backslashes left alone, so each escape
shows once. `verify-approval` quotes the principal in the same way. JSON
output carries the exact text.

### JSON fields

Every object has `command`, a command-specific `result`, `warnings` (strings)
and `advice` (objects with `level`, `type` and `message`, and `argv` for a
suggested help command). Both arrays can be empty. Commands that report a
pass path use `file`. A `refusal` is `{code, message}` or null.

- **help** includes `topic` (null for root), `description`, `commands`
  (list of `{name, description}`), `usage`, `arguments`, `examples`,
  `workflow` and `exit_codes`. Argument metadata describes unconditional
  requirements. Consult the usage forms for conditional ones.
- **version** returns the package version in `version`.

- **error** (any command): `error` `{code, message, headline, next, line,
  recording, seq, ledger, last_line}` (`headline` is one short sentence that
  says what is wrong, the first line of the text output after the code, or
  the first line of `message` for an error with none of its own; `next` is
  the one next step in words, or null; `line` is the 1-based ledger line for
  `ledger-corrupt`, else null; `last_line` is true when that line is the last
  in the file, so the damage may be a final line cut short, false when it is
  earlier, and null for other errors; `recording`, `seq` and `ledger` as in "Fail-closed cases", null when
  they do not apply; parser failures carry them too, with `recording`
  `not-recorded`), `problems` (list of
  `{field, message}`, empty unless `invalid-pass`).
- **init**: no more fields.
- **check**: `digest`, `pass_id`, `require_target`, `required_counters`
  (sorted list, empty when none are required), `problems` (empty),
  `breadth` `{ipv4, ipv6}` (declared address counts as decimal strings),
  `now`, `test_clock`, `window_warnings` (see "Window warnings"),
  `name_restriction_overlaps` (list of `{code, named_label, unnamed_label,
  acknowledged, message}`, one per pair that `lint` reports, and one with
  code `overlap-acknowledgement-unmatched` for each acknowledgement that
  names no overlap; each message is also in `warnings`, including those of
  acknowledged pairs).
- **status**: `digest`, `now`, `test_clock`, `pass` `{id, name, owner,
  reference, operator}`, `window`, `destinations` (list of `{label, kind`
  (`address` or `network`)`, destination, protocol, ports` (list of `{start,
  end}`)`, ports_text, hostname, names, whole_network_approved,
  overlap_acknowledged}`), `breadth`
  (as in `check`), `counters` (list of `{name, total, spent, remaining, over_ceiling, over_by}`; when the owner lowers a ceiling below what is spent, `over_ceiling` is true, `over_by` is the excess, `remaining` is 0, and text shows `OVER by N`),
  `required_counters`, `require_target`, `unlisted_spends` (list of `{name,
  spent}`), `ledger` `{path, exists, entries, adoptions, witness,
  moved_from}` (`witness` is `fresh`, `matches`, `extended`, `missing` or
  `not-checked`; `moved_from` the path the witness last saw, or null),
  `window_warnings` (as in `check`), `name_restriction_overlaps` (as in `check`, but `warnings` leaves out the
  messages of acknowledged pairs), `refusal`.
- **permits**: `digest`, `pass_id`, `now`, `test_clock`, `target`
  (normalized, the first target), `name` (normalized, or null), `label` (or
  null), `targets` (list of `{target, name, label}` in request order),
  `refused_target` (one-based, or null), `refusal`, `window`.
- **spend**: every reply (`allowed`, `would-allow` or `refused`) has the
  same keys, whatever the flags. `file`, `digest`, `pass_id`, `now`,
  `test_clock`, `charges` (list of `{counter, n, total, spent, remaining,
  projected_spent}` in request order, one entry for a positional COUNTER;
  `total` and `remaining` null for an unknown counter, `spent` after the
  spend if recorded, else current, `projected_spent` the projected total
  of a positive `--dry-run`, else null), `counter`, `n`, `total`, `spent`,
  `remaining` and `projected_spent` (the same values as the only charge
  when the unit charges one counter, all null when it charges several),
  `seq` (the new entry's sequence number, or null), `note`, `targets` (list
  of `{target, name, label}` in request order), `refused_target`
  (one-based, or null), `target` and `name` (of the first target,
  normalized, null without `--to` or `--name`), `label` (the destination
  that permits the first target when the spend is or would be allowed,
  else null), `receipt`
  (`{caller_ref, targets}` retained by a committed debit that asked for
  one, else null; `caller_ref` is null without `--caller-ref`, `targets`
  is empty without `--record-target`, and each entry is `{target, name,
  label}` with `name` null for an unnamed endpoint), `refusal`,
  `reference_evidence` (`{caller_ref, match_count, sequences, truncated}`
  for `duplicate-reference` and `reference-inconclusive`, else null;
  `match_count` and `sequences` count debits only, and `reconciled_at`,
  the first 64 sequences of the reference reconciliations that list the
  reference, is present only when one does). The
  ledger line keeps its own, shorter encoding.
- **capacity**: `digest`, `pass_id`, `now`, `test_clock`, `targets`,
  `units`, `limiting_counters`, `counters` and `unit_refusal`, as in
  "Budget questions"; a refusal adds `refusal` and `refused_target`.
- **rehearse**: `digest`, `pass_id`, `witness`, `ceilings`,
  `starting_spent`, `projected_spent`, `steps` (each with `id`, `at`,
  `duration`, `charges`, `targets`, `status`, `balances`, `labels` and
  `refusal`) and `stopped_at` (the refused step, or null).
- **digest**: `digest`, `pass_id`.
- **doctor**: `result` (`healthy`, `needs-action` or `blocked`), `file`,
  `pass_id` (null when the pass does not load), `problem` (the error or
  refusal code a spend would fail with, or null), `headline` (one short
  sentence: the verdict line of the text output), `message` (what is wrong,
  or that nothing is), `next` (the one command to run, as an argv array
  with real paths, or null), `next_step` (what to do, in words) and
  `findings` (list of `{code, message}`: other problems and warnings).
- **ledger**: `ledger` (its path), `exists`, `pass_id`, `digest` (of the
  pass now), `counter` (the `--counter` filter or null), `verified` (always
  `true` on success: a chain that does not verify is an error), `shown`
  (null without `--tail` or `--since`, else `{from, to, of}`: the first and
  last sequence number shown, null when none is, and `of`, the number of
  entries, adoptions and reference reconciliations included, in the whole
  ledger), `entries`
  (list of `{seq, time, counter, n, digest, note, test_clock}` for a scalar
  spend, or `{seq, time, event, version, charges, digest, note, receipt,
  test_clock}` with `event` `debit` for a versioned debit; `digest` is the
  pass digest the spend was decided against, `note` null when none,
  `test_clock` true for a line written under the test clock),
  `adoptions` (list of `{seq, time, reason, digest, carried, previous,
  may_have_lost_references, checkpoint, test_clock}`; `checkpoint` is the
  checkpoint an `adopt --checkpoint` acted on, or null; `carried` is an object of counter name to
  amount, `previous` is `{ledger, seq, totals, updated, test_clock}` or null
  (`test_clock` true when that witness showed a rehearsal),
  `may_have_lost_references` is true for an adoption that records a
  previous witness of at least one line, carries an amount, or acted on a
  checkpoint),
  `reference_reconciliations` (list of `{seq, time, adoption, reason,
  digest, references, test_clock}`; `adoption` is the sequence of the adoption it
  reconciles, `references` the whole list), `unreconciled_adoption` (the
  latest adoption that may have lost lines when no reconciliation follows
  it, so guarded spends are `reference-inconclusive`; else null),
  `test_clock_from` (the sequence of the first line written under the test
  clock, or null: see [Test-clock lines](#test-clock-lines)), `witness`,
  `moved_from` (as in
  `status`), `totals`
  (list of `{name, spent, total, remaining, over_ceiling, over_by}` for every counter of the pass
  and every counter in the ledger, sorted by name; `total` and `remaining`
  null for a counter the pass no longer has; `over_ceiling` is false and `over_by` null there). `spent` includes carried
  amounts.
- **adopt**: `ledger`, `pass_id`, `digest`, `now`, `test_clock`, `case`
  (`ledger-missing`, `ledger-changed`, `no-witness` or
  `checkpoint-behind`), `created` (a new
  ledger was started), `seq`, `reason`, `carried` and `totals` (objects of
  counter name to amount), `previous` (as in `ledger`, or null),
  `rehearsal` (null, or `{units, carried, proof}`: see
  [Test-clock lines](#test-clock-lines)), `checkpoint` (the checkpoint
  acted on with `--checkpoint`, as the adoption line records it, or null). A preview
  has `result = "preview"`, `case`, `pass_id`, `seq`, `present`, `carried`,
  `totals`, `previous`, `rehearsal`, `checkpoint` and `token`.
- **repair**: `result` (`preview` or `repaired`), `ledger`, `pass_id`,
  `seq` (the last complete line, kept), `witness_seq`, `kept_bytes`,
  `removed_bytes`, `token` and `copy` (the file that holds the removed
  bytes, null in a preview).
- **reconcile-references**: `ledger`, `pass_id`, `digest`, `now`,
  `test_clock`, `seq` (of the new line), `adoption`, `reason` and
  `references` (the list recorded).
- **archive**: `digest`, `provenance` (`signature-recorded` or
  `unsigned`) and `approval` (the kept signature record `{principal,
  namespace, allowed_signers, signature, key}`, or null; `key` is null in a
  record that an older hallpass wrote). **retrieve**: `digest`
  and `bytes` (the exact pass text); with `--output FILE`, `digest`, `output`
  (the path), `mode` (`0600`) and `length` (bytes written) instead of `bytes`.
- **receipt**, **audit-receipts**, **audit-charges**, **reconcile**,
  **compare-backups**: see [EVIDENCE.md](EVIDENCE.md). **receipt** has
  `reconciled_at` (the first 64 sequences of the reference reconciliations
  that list the reference, empty when none does). **reconcile** has
  `pass_id`, `witness`, `adoption_count` and `rows` (list of `{caller_ref,
  result, reason, candidate_count, sequences, truncated, differences,
  reconciled_at}` in manifest order; `reason` is `targets-unrecorded` for an
  `incomplete` row and null otherwise; each entry of `differences` is
  `{sequence, field, expected, recorded}`, where `expected` and `recorded`
  are numbers for `charge.<counter>` and `targets.count`, strings for the
  other fields, and null when that side has none; `reconciled_at` as in
  `receipt`).
- **checkpoint**: `checkpoint` (`{version, pass_id, seq, hash, totals,
  latest, anchors}`, or null when `result` is `empty`; `totals` is an
  object of counter name to amount, `latest` an RFC 3339 time (absent when
  no line has one), `anchors` an object of sequence to line hash: see
  [Checkpoints](#checkpoints)), `local_corroboration`, `witness` `{relation,
  witnessed_seq, exported_seq}` (`relation` is `matches`, `lags` or
  `absent`; `witnessed_seq` is null for `absent`, `exported_seq` null for
  `empty`).
- **verify-checkpoint**: `relation` (`exact`, `extended`, `shorter`,
  `foreign` or `mismatch`), `added` (entries after the checkpoint) and
  `trust_input` (`supplied-checkpoint`).
- **verify-approval**: `principal` (or `expected_principal` when
  unverified), `reason` and `next_step` when unverified (`reason` is `wrong-namespace`, `bytes-do-not-match`, `malformed-signature`, `untrusted-key`, `wrong-principal`, `key-not-valid-at-time`, `key-not-permitted-for-namespace` or `unknown`, read from ssh-keygen's output, or `signer-key-mismatch`; the result and exit code do not change), `key` (the fingerprint of the key that made the signature, or null when ssh-keygen did not name it or the signature did not verify), `principal_match` when verified (`named`, `pattern` or `certificate`), `pass_id` and `digest` when verified, `namespace`, `verify_time` (the `--at` instant, or null for now), `archive`, `provenance`
  (`signature-recorded` when verified with `--archive`, `signature-not-stored`
  when an earlier, different record was kept and this signature was not
  stored, else null) and
  `approval` (the signature record now in the archive, as in `archive`, or
  null; when an earlier, different record was kept, a warning says so, the
  provenance is `signature-not-stored`, and the exit status is 2, when the kept
  record names another principal).
- **diff**: `old`, `new`, `old_pass_id`, `new_pass_id`, `old_digest`,
  `new_digest`, `approval_id_changed`, `changes` (list of `{field, before,
  after, review_required}`; `before` and `after` are a JSON string, number
  or null), `introduced` and `removed` (labels), `introduced_grants` and
  `removed_grants` (one `{label, scope, network, protocol, ports, names,
  hostname, whole_network_approved, overlap_acknowledged}` per introduced or removed destination;
  `scope` is `address` or `network`; empty `names` means any name),
  `new_window_warnings` (as `window_warnings` in `check`, for NEW),
  `name_restriction_overlaps` (as in `check`, limited to overlaps that
  NEW introduces; their messages are also in `warnings`, acknowledged or
  not, so the reviewer sees what the owner accepted),
  `order_changed`, `review_required`, `same_declared_fields`,
  `text_changes` and `comment_changes` (each `{change, line, text}`; see
  "Comparing revisions"); `examples`, `budget_impact` or `containment` when
  requested. Each row of `examples.rows` and `containment.counterexamples`
  is `{target, name, at, before, after, change, bypasses_names_of}`.
- **consumer-coverage**: `pass_id`, `digest`, `declared`,
  `require_target`, `findings` (each with its `code`).
- **lint**: `digest`, `findings` (`name-restriction-overlap` rows, then
  `wide-port-grant` rows `{code, label, protocol, ports, port_count,
  message}`; see "Name overlaps and declared breadth"), `truncated`,
  `window_warnings` (as in "Window warnings").
- **test-pass**: `cases` (the suite path), `digest`, `results`,
  `mismatches`; `mutation_strength` with `--strength`.
- **approval-id**: `id`, `owner`, `reference`. When `--owner` or
  `--reference` holds text that `approval.owner` or `approval.reference`
  may not hold, the usage error lists each problem under `problems` as
  `{field, message}`, as `check` does. When it holds a combining mark or
  two or more spaces in a row, the ID is printed and `warnings` says the
  ID depends on those exact characters; `check` and `lint` give the same
  warning for the pass.

`window` is `{state, valid_from, valid_until, seconds_remaining,
seconds_until_open, seconds_since_end, revoked_reason}`; `state` is
`not-yet-valid`, `valid`, `expired` or `revoked`; the three `seconds_*`
fields are null except the one that applies. `seconds_remaining` and
`seconds_since_end` round down and `seconds_until_open` rounds up, so none
promises more time than the decision allows; text says "less than 1 s left"
for a part second in an open window. Window times (`valid_from`,
`valid_until`) are UTC, whole seconds, `YYYY-MM-DDTHH:MM:SSZ`.

Recorded ledger times follow one rule in every command that reports them
(`ledger`, `receipt`, `reconcile`, `audit-receipts`, `audit-charges`): JSON
gives the time exactly as the ledger line records it, in UTC with its full
fractional seconds when a real clock wrote it (for example
`2026-11-23T16:36:15.36549262Z`), because the ledger is evidence and
truncating a time loses the order of debits within a second. Text output may
print whole seconds, in every one of those commands (`audit-receipts` text
included). The whole-second rule above is about window times only.

### Refusal codes

`not-yet-valid`, `expired`, `revoked`, `window-too-short`, `embedded-ipv4`,
`network-or-broadcast`, `address-not-listed`, `port-not-listed`,
`name-required`, `name-not-listed`, `target-required`,
`required-counter-missing`, `unknown-counter`, `ceiling-reached`,
`pass-changed`, `duplicate-reference`, `reference-inconclusive`.

### Test clock

`HALLPASS_UNSAFE_TEST_CLOCK=<RFC 3339>` replaces "now" for `status`,
`doctor`, `check`, `permits`, `spend`, `capacity`, `adopt`, `reconcile-references` and
`lint`, the commands that read the clock, only in debug builds and builds
with the `test-clock` feature. When used, a warning goes to standard
error and `test_clock` is `true`. Release builds ignore it and say so on
standard error. Lines written under it are marked: see
[Test-clock lines](#test-clock-lines).

### Test-clock lines

Every ledger line written under the test clock (a spend, a debit, a debit
batch, an adoption or a reference reconciliation) carries
`"test_clock":true` just before `prev`, so the marker is in the hash chain.
A line without it was written at the real time. hallpass never writes
`"test_clock":false`; a line that has it is `ledger-corrupt`.

A ledger holds lines of one kind. Under the test clock, `spend` (also with
`--dry-run`), `adopt` (also with `--preview`) and `reconcile-references`
refuse a ledger that holds a real-clock line. On the real clock, they refuse
a ledger that holds a test-clock line. Both fail with `ledger-clock-mix` and
record nothing. A release binary has no test clock, so it never writes the
marker and cannot add to a rehearsal ledger, but it still reads one. A
library caller marks its own lines with `with_test_clock`.

`ledger` shows `test_clock` on each entry, adoption and reconciliation, and
`test_clock_from` for the ledger. `receipt` shows `test_clock` on each match.
`audit-receipts` and `audit-charges` report every marked line as the gap
`test-clock-entry`, so the audit of a rehearsal ledger is never `complete`.
Both audits also report a line whose time is more than 5 minutes later than
the audit's own clock as `entry-in-future`; smaller skew between hosts is
allowed.

The witness shows a rehearsal too: when every entry of the ledger it
records was written under the test clock and no adoption in it carried an
amount, it has `"test_clock":true` (hallpass never writes `false`, and a
witness with it is damaged). A witness without the field reads as before.
A hallpass from before the field calls such a witness damaged.

A rehearsal run by mistake on the live pass has a way back. A spend on the
real clock fails `ledger-clock-mix`, and the message and `doctor` name the
recovery: move the rehearsal ledger aside and keep it (`mv -n
PASS.ledger PASS.ledger.rehearsal`), then `adopt --preview
--drop-rehearsal PASS.ledger.rehearsal`. The mark is only a hint: it
makes an adoption on the real clock from that witness (`ledger-missing` or
`ledger-changed`) a usage error that names the units as rehearsal units,
and it chooses the words of the advice and of `doctor`. It never lowers a
count. The adoption must choose:

- `--drop-rehearsal FILE` carries nothing from the witness, once FILE
  proves the rehearsal. hallpass opens FILE under the rules for any ledger
  (not a link, a regular file, private), verifies its whole chain, and
  checks that it is a ledger of this pass id other than the one beside the
  pass, that its last line has the sequence number and hash the witness
  recorded, that every entry is a test-clock line, that no adoption in it
  carried an amount (which may be live work), and that its totals are the
  witness's. Any failure is a usage error that names it, and nothing is
  recorded; there is no fallback to the mark. This is sound because a
  real-clock write is never added to a ledger of test-clock lines: the
  witnessed count is the rehearsal's, and it spent nothing real. The
  adoption line records the witness with `"test_clock":true`, and it does
  not make guarded spends `reference-inconclusive`: rehearsal references
  are not live ones. A hallpass from before this field fails closed
  (`ledger-corrupt`) on that line.
- `--carry-rehearsal` carries the units as before, and the reply names
  them as rehearsal units. It is a usage error when the witness has no
  mark.

`--drop-rehearsal` is refused with `--carry-noted-totals`, since a witness
found damaged proves nothing. Without the rehearsal ledger, the totals stay
counted: adopt without the flag, or use a pass with a new id. Under the
test clock an adoption carries a rehearsal's units without a flag, as any
totals. The replies have `rehearsal`: null, or `{units, carried, proof}`
with the witness's totals, whether they were carried, and the file that
proved the rehearsal (null with `--carry-rehearsal`).

Ledgers written before the marker existed have no marked lines and read as
before. A test-clock line written by such a version cannot be told from a
real one. A hallpass from before the marker fails closed on a marked line
with `ledger-corrupt`.

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
| `permits_in`, `permits_with_clock_in`, `NamedTarget`, `PermitOutcome`, `TargetRefusal`, `MAX_TARGETS` | several targets of one unit against the file, with the ledger and witness verified |
| `SpendRequest::new(counter, amount)` | a request; set `note`, `expect_digest`, `needed`, `target`, `name` as needed (the struct is `non_exhaustive`: fields may be added) |
| `spend(path, &SpendRequest, now) -> Result<SpendOutcome, Error>` | atomic spend with the witness in `StateDir::from_env()`; with `target` set it also decides the destination; `SpendOutcome.refusal` is `None` when recorded; `SpendOutcome.label`, `SpendOutcome.warnings` |
| `spend_in(path, &SpendRequest, now, &StateDir)` | the same with an explicit state directory |
| `spend_with_clock_in`, `preview_spend_in`, `preview_spend_with_clock_in` | the same with the clock sampled under the locks, and read-only previews |
| `spend_charges`, `spend_charges_in`, `spend_charges_with_clock_in`, `SpendChargesRequest`, `SpendChargesOutcome`, `Charge`, `ChargeOutcome` | one debit with several charges, an optional caller reference, receipt and reference guard |
| `spend_charges_batch`, `spend_charges_batch_in`, `spend_charges_batch_with_clock_in`, `SpendChargesBatchRequest`, `SpendChargesBatchOutcome`, `SpendChargesBatchUnitOutcome`, `MAX_DEBIT_BATCH_UNITS` | 1 to 1024 distinct guarded caller-reference debits, each one unit of the same counter and with one optional retained target, decided under one lock and committed as one all-or-none ledger line |
| `adopt(path, reason, now, &StateDir) -> Result<AdoptOutcome, Error>` | record an adoption (`AdoptOutcome { case: AdoptCase, adoption: Adoption, ledger, created, pass_id, totals }`) |
| `preview_adopt`, `adopt_guarded`, `AdoptPreview` | the adoption preview and its token |
| `preview_restore_final_newline`, `restore_final_newline`, `FinalNewline` | the repair of a whole last ledger line that lacks only its line end ([Dropping a cut-short last line](#dropping-a-cut-short-last-line)) |
| `preview_drop_torn_tail`, `drop_torn_tail`, `TornTail` | the repair of a cut-short last ledger line, and its preview and token ([Dropping a cut-short last line](#dropping-a-cut-short-last-line)) |
| `reconcile_references(path, adoption, &[String], reason, now, &StateDir) -> Result<ReconcileReferencesOutcome, Error>`, `read_reference_list(path, pass_id)`, `ReferenceReconciliation`, `MAX_RECONCILED_REFERENCES`, `MAX_REFERENCE_LIST_BYTES` | record a reference reconciliation (`ReconcileReferencesOutcome { reconciliation, ledger, pass_id, warnings }`) and read its list |
| `tally(&LoadedPass) -> Result<Tally, Error>` | spent per counter, under a shared lock; reads the ledger only, without the witness (as in 0.1) |
| `read_ledger(&LoadedPass, &StateDir) -> Result<LedgerView, Error>` | every entry (`LedgerEntry { seq, time, counter, amount, digest, note }`), every `Adoption` and `ReferenceReconciliation`, `unreconciled_adoption`, the tally, the `WitnessStatus`, `moved_from` and `warnings`; chain verified under a shared lock; read-only |
| `read_summary` | the tally and witness status without the entries |
| `LedgerView::latest_time`, `LedgerView::clock_warning(now)` | the latest time on any logical entry of the ledger and the sequence number of the first entry with it; the warning for a decision clock before it |
| `with_test_clock(f)` | mark every ledger line the library calls in `f` write on this thread as written under a test clock; writes refuse to mix marked and unmarked lines in one ledger (`Error::LedgerClockMix`, [Test-clock lines](#test-clock-lines)) |
| `with_lock_wait(lock_timeout, on_lock_wait, f)`, `LockWait { path, holder_pid, shared, give_up_in }` | bound every ledger and witness lock wait of the library calls in `f` on this thread, and hear about a long wait ([Lock wait](#lock-wait)) |
| `open_input(path)` | open a file to read as a pass is opened: not through a link, only a regular file, never blocking on a FIFO |
| `export_checkpoint_observed` (`CheckpointExport`, `WitnessRelation`), `export_checkpoint`, `verify_checkpoint` (`Checkpoint`, `CheckpointStatus`) | checkpoints |
| `read_checkpoint(path)`, `MAX_CHECKPOINT_BYTES`, `compare_checkpoint(&LoadedPass, &Checkpoint)` (`CheckpointCover`, `CheckpointGap`) | read a retained checkpoint as `verify-checkpoint` does, and what it shows about the ledger beside a pass (`doctor --checkpoint`) |
| `preview_adopt_checkpoint`, `adopt_guarded_checkpoint` | `adopt --checkpoint` ([After a whole-machine restore](#after-a-whole-machine-restore)) |
| `archive_pass`, `archive_pass_bytes`, `retrieve_pass` | the private archive of exact pass bytes |
| `archive_provenance` (`Provenance`, `SignedApproval`), `archive_verified_signature` (`ArchivedSignature`), `APPROVAL_NAMESPACE`, `MAX_SIGNATURE_BYTES` | signature records beside archived bytes; recording one does not verify anything |
| modules `capacity`, `scenario`, `evidence`, `review` | budget questions, accounting evidence, and approval review |
| `evidence::audit_receipts`, `evidence::audit_charges` (`ReceiptAudit`, `ChargeAudit`) | replay the ledger against the archived revisions; signature records are read, not verified again, so the result is never `complete` |
| `evidence::audit_receipts_with`, `evidence::audit_charges_with`, `Reverify { allowed_signers, principals, as_of, check }`, `AsOf` (`FirstUse`, `Instant(time)`), `SignatureToCheck`, `Recheck`, `SignatureCheck` | the same audits, verifying each recorded signature again. `check` runs after the ledger lock is released, once per digest and principal tried, and gets a `SignatureToCheck { digest, bytes, signature, approval, principal, as_of }` with the archived bytes and signature as read under the lock (bytes, not paths), and the instant to verify as of: the revision's first use, or the `AsOf::Instant`. With `principals`, it tries the record's principal first when it is named, then the others in order, until one verifies. It returns `Recheck::Verified` or `Recheck::Rejected(reason)`; an error ends the audit. Without a `Reverify`, or with empty `principals`, an audit is never `complete`. `SignatureCheck` (the reply's `signatures`) says whether the audit verified again, against which `allowed_signers` digest, for which `principals` and as of when |
| `StateDir` (`from_env()`, `new(path)`, `path()`, `witness_path(id)`), `Witnessed`, `totals_text` | the state directory and witness records |
| `display_safe(text) -> Cow<str>` | operator text escaped for one terminal line |
| `display_quoted(text) -> String` | operator text as one double-quoted value, each character escaped once |
| `ledger_path(path)` | `<pass>.ledger` |
| `write_template(path)`, `TEMPLATE` | `init` |
| `parse_address`, `parse_network`, `embedded_ipv4`, `ipv6_transition` (`Ipv6Transition`), `Target` (`FromStr`), `Network` (with `is_network_or_broadcast(ip)`), `Protocol`, `PortSet` | strict parsing |
| `Digest` (`Display`/`FromStr` as `sha256:<hex>`), `Refusal`, `RefusalCode`, `WindowState`, `Problem`, `Error` (with `code()`; `LedgerMissing` boxes a `MissingLedger`, `LedgerElsewhere` an `ElsewhereLedger`) | value types |
| `stamp`, `span` | time formatting used in messages |
| constants: `FORMAT_VERSION`, `IPV4_CAP`, `IPV6_CAP`, `IPV4_FLOOR`, `IPV6_FLOOR`, `MAX_CEILING`, `MAX_COUNTERS`, `MAX_DESTINATIONS`, `MAX_NOTE`, `MAX_PASS_BYTES` | documented limits |

The library is Unix-only.

Cargo features: `cli` (on by default) builds the `hallpass` binary and is
the only user of clap. A program that uses only the library depends on
hallpass with `default-features = false` (playpen does). playpen is a separate tool: an egress guard that consumes passes through this library. `test-clock` is
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

## Consumers

- **playpen** (built): the playpen egress guard consumes passes through
  the library (`playpen run --pass FILE`). It loads the pass with `load`,
  refuses to start unless `check_window(now, 0)` passes, allows exactly the
  destinations (optionally narrowed by label), ends the run at
  `valid_until`, and re-reads the pass every few seconds to stop the
  command when it is revoked, expired, unreadable, invalid or a destination
  in use changes. playpen does not spend: it limits where packets go, not
  how many.
- **Planned**: the SIP assessment toolbox calling `hallpass
  --format json spend --to ...` before each call ([INTEGRATING.md](INTEGRATING.md)); the web tester
  using the library per request.
- **Protocols beyond tcp and udp**, and link-local destinations with an
  interface field: would need a new format version; not planned in detail.
