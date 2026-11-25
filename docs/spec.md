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
leading or trailing spaces, and holds no control character and none of the
characters a note refuses (line separators, Unicode format characters,
other invisible characters and spaces other than the ASCII space): two
references that differ only in those could look the same. Reading a
ledger, and looking a reference up with `receipt` or a `reconcile`
manifest, applies the earlier rule (nonblank, at most 128 characters, no
control character, line separator or bidirectional control), so a
reference recorded before the new rule still reads and can be found.
Missing or invalid caller references are usage errors. A dry run applies
the same rules and reports observed matches without a reservation. The
guard coordinates cooperating guarded writers on the same local history.
External execution requires a separate record. The Rust option is
`SpendChargesRequest::require_new_ref`.

#### Damaged ledger advice

A chain break at line N says that line N does not follow line N-1: one of the
two was changed, or a line between them was removed or moved. The message
advises removing a final line that was cut short only when N is the last line
of the file (`error.last_line` is true). When N is earlier, it advises
restoring the ledger from a backup, finding the good copy with `hallpass
compare-backups`, and not editing lines by hand. The error code stays
`ledger-corrupt`.

#### Lock wait

On a committing spend, `--lock-timeout-ms N` gives both writer locks one
shared monotonic wait budget. Zero requests one nonblocking attempt per lock.
Omitting the option uses blocking locks. A timeout exits 1 with
`error.code = "lock-timeout"` and `error.recording = "not-recorded"`.
The budget covers lock acquisition. It places no deadline on a subsequent
append or sync. An external process timeout can leave the outcome unknown.

The locks are operating-system file locks (`flock`). The system releases one
when its holder exits or crashes, so a stale lock never needs removing; a
`lock-timeout` means a live process holds it. The message ends with the next
step: retry, or find and stop that process (`fuser PATH`).

A spend with no timeout waits without limit. After about two seconds of
waiting, the CLI writes one line to **stderr** (in text and JSON mode alike;
it is never put in `warnings`, so stdout stays one JSON object and the
result is unchanged): `waiting for the writer lock on PATH, held by process
PID` where the holder can be found (Linux, `/proc/locks`), otherwise
`held by another process; find it with fuser PATH`. A spend that gets the
lock sooner prints nothing. The library never prints: set
`SpendRequest::on_lock_wait` to a function that receives a `LockWait`
(`path`, `holder_pid`) to report the wait yourself.

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
| missing | records lines, and the ledger where the witness last saw it is another file that is intact | **error `ledger-elsewhere`**, naming that ledger and the pass file beside it, and how to apply a revision |
| present | none | accepted with a warning (`missing`); `spend` records a witness |
| present | its line `seq` hashes to the witnessed hash, and nothing follows | `matches` |
| present | the witnessed line is there, and `k` lines follow | accepted with a warning (`extended`): a run stopped between the ledger and the witness, or a hallpass without witnesses added lines; they count |
| present | the witnessed line is not there (a different line at that position, or fewer lines) | **error `ledger-changed`**, saying which, and naming another ledger of the same id if one exists where the witness saw it |
| present | could not be read (no state directory, damaged, not private) | `spend` and `adopt`: **error `witness-unavailable`**. `status`, `permits`, `ledger`: answered, with a warning and `not-checked` |

The same evidence, by command:

| State evidence | permits | status / ledger | spend and spend preview |
|---|---|---|---|
| Fresh pass, no previous spend | evaluate policy | report fresh | evaluate policy |
| Ledger without a witness | evaluate with warning | report missing witness | evaluate; a real spend without `--require-new-ref`, or `adopt`, establishes the witness |
| Unusable witness state | evaluate with warning | report not-checked | error |
| Missing or divergent witnessed history | error | error | error |

The path in the witness is informational: identity is the hash chain. A
pass moved with its ledger is accepted with a warning and the witness
follows it; the copy left behind is then `ledger-changed` (only one copy
can be spent from). A second pass file that reuses an id and has no ledger
is never a fresh count.

When the ledger beside the pass is missing and the witness last saw it at
another path, hallpass opens the file there under the rules for any ledger
(not a link, a regular file, private), verifies its whole chain, and checks
that it belongs to the pass id and ends with exactly the line the witness
recorded (same sequence number and hash). If all of that holds, the ledger
is not lost, and the error is `ledger-elsewhere`. This is the usual case of
an amended approval saved as a second file with the same id, or of a pass
moved without its ledger. The message names the intact ledger and the pass
file beside it, if there is one. To apply a revision, replace the content
of that pass file with the new one and spend from it; the count carries on.
If the old file is being retired, or there is none, move the ledger beside
the new file instead. Do not adopt: adoption would start a second ledger
for the id. If the file cannot be opened, does not verify, belongs to
another id, or does not end with the witnessed line (also when it has grown
past it), the error is `ledger-missing`, as for a lost ledger. Either way
nothing is counted from that file or created.

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

The first two may have lost lines and their caller references, so later
guarded spends refuse new references as `reference-inconclusive`; the third
keeps every line (see "Caller references and receipts"). A reference
reconciliation (`reconcile-references`, below) ends that refusal. Carried amounts
count as spent. An adoption never lowers a count below
what the witness recorded; there is no reset to zero (a new budget is a
raised ceiling in the pass, or a new pass). Then the witness records the
new last line. The reason follows the note rules and is required.
(Reading a ledger accepts a recorded reason under the earlier rule, which
refused line separators and bidirectional controls but not the other
format characters, invisible characters or look-alike spaces.) With
nothing to adopt (the ledger matches its witness, or there is neither a
ledger nor a witnessed spend) it is a usage error. A damaged ledger
(`ledger-corrupt`) is not adopted: repair it, or move it aside and adopt
the loss. A missing ledger that is intact where the witness last saw it
is not adopted either: `adopt` and `adopt --preview` both fail with
`ledger-elsewhere` and record nothing, because the adoption would fork the
history. There is no flag to force it. If that ledger really is to be
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
requires a new preview. An adoption already appended before a subsequent witness
write failure still counts; inspect the ledger before retrying.

The guard coordinates hallpass writers through their locks. Programs that edit
pass or ledger files without taking those locks can change them after a reviewed
snapshot; the missing-ledger decision uses the validated pass snapshot held at
publication time.

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
and a list holds at most 10,000. An empty list states that no reference was
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
  command reads a save in progress. A revision kept as a second file with
  the same id has no ledger beside it, and is refused as `ledger-elsewhere`
  while the first file's ledger is intact (see "The witness").

### Fail-closed cases

Every error below exits 1. The caller must stop. An append or witness failure can leave a debit on disk.

| Case | Code |
|---|---|
| the pass or ledger file is missing, unreadable, or fails to write | `io` |
| the pass or ledger path is a symbolic link (also if swapped in while opening) | `symlink` |
| the path is not a regular file | `not-regular-file` |
| the pass is larger than 1 MiB | `too-large` |
| `spend` (not `--dry-run`), `adopt` (not `--preview`) or `reconcile-references`, when the directory that holds the pass can be written by others and lacks the sticky bit | `shared-directory` |
| the pass is writable by group or others; the ledger has any group or other bit | `insecure-permissions` |
| the pass belongs to a user other than the effective user or root | `untrusted-owner` |
| the pass does not validate (every problem listed), changed while it was read, or does not end with a newline | `invalid-pass` |
| the ledger is empty, has a cut last line, an unreadable line, a sequence gap, a broken hash chain, an invalid field, or sums beyond 10^12 | `ledger-corrupt` |
| the ledger's pass id differs from the pass's | `ledger-foreign` |
| the ledger is missing but its witness recorded lines | `ledger-missing` |
| the ledger is missing, but the ledger the witness last saw at another path is intact (a second pass file with the same id, or a pass moved without its ledger) | `ledger-elsewhere` |
| the ledger does not hold the line its witness recorded | `ledger-changed` |
| `spend`, `adopt`, `reconcile-references`: no state directory, or it is not a private writable directory, or the witness is damaged or not private | `witness-unavailable` |
| the spend exhausted its optional writer lock wait budget before appending | `lock-timeout` |
| the append or its sync failed and the caller must reconcile the ledger before retrying | `ledger-append-uncertain` |
| the spend was recorded but the witness could not be updated afterwards (the spend counts; do not proceed) | `witness-not-updated` |
| `init` target already exists (also a dangling link) | `exists` |
| bad arguments: malformed `--to`, `--digest`, `--n 0`, a bad note or reason, nothing to adopt, a bad reference list or nothing to reconcile, a malformed test clock | `usage` |

A missing ledger is not an error when no witness records lines for the
pass id: it means nothing was spent.

A JSON error says in `error.recording` what the failed command left in the
ledger. After `witness-not-updated`, `error.recording` is `recorded` and the
JSON error contains `seq` and `ledger`. A `ledger-append-uncertain` error
includes the ledger path and `recording = "uncertain"`. Both exit 1. Inspect
the ledger and reconcile before retrying. `lock-timeout` and
`witness-unavailable` and `shared-directory` have `recording = "not-recorded"`: the attempt appended
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

`hallpass diff OLD NEW --budget-impact --json` reads one verified summary from the live ledger. In the documented flow OLD is an archived copy with no ledger and NEW is the live pass, so the ledger beside NEW is used; the ledger beside OLD is used only when NEW has none. `budget_impact.ledger` is the path read and `budget_impact.ledger_source` is `new`, `old` or `none` (neither exists; the projection then starts from zero spend, or fails when the witness records spends). Text prints the same as `Ledger used:`. A read-only command never advises `hallpass adopt`; its ledger and witness errors say only that nothing was changed, and recovery advice appears from `status`, `spend` and `adopt`. Both digests identify the files compared. The projection gives the witness status and verified ledger tip (null before the first ledger). Each counter row shows the two limits, mandatory-charge flags and remaining amounts against the same historical spend, including adoption carry. A missing ceiling is null. For eight calls spent and a proposed ceiling of six, proposed_remaining is zero and over_proposed is two. This is a completed review (exit 0). Different pass IDs make a projection inapplicable (exit 2). Unusable accounting evidence exits 1. A proposal can change after review and concurrent spends can change these balances.

### Proving endpoint containment

`hallpass diff OLD NEW --containment --at TIMESTAMP` compares zero-duration endpoint admission at one explicit instant. Both validated revisions must have the same pass ID. When NEW admits nothing at the instant (it is revoked, or its window does not cover the instant), the endpoint result is `contained` with reason `new-admits-nothing`: every endpoint NEW admits, none, is admitted by OLD, whether or not OLD is open. When OLD admits nothing and NEW is open, containment cannot be shown and the endpoint result is `inconclusive` with reason `old-closed-new-open`. Otherwise both windows are open and each proposed rule must fit within a single old rule's address range, protocol, ports and name domain. Every previously excluded IPv4 network or broadcast edge within a proposed destination must still be excluded for this proof. IPv6 transition exclusions apply identically to both revisions.

The endpoint proof gives `containment.endpoint_result`: `contained` certifies that every endpoint/name pair admitted by NEW at that instant was admitted by OLD. The proof compares at most 16,384 rule pairs. When the proof fails, the existing bounded example search can establish `expanded` by exhibiting a new allowance. Every new allowance lies in a widened class: a NEW destination and port range that no single OLD destination covers, or an IPv4 network or broadcast address that OLD excludes and NEW does not. A bypassed names list (see `--examples`) is a class of its own, once without a name and once with an unlisted name. `containment.counterexamples` lists up to eight new allowances, in the order of `examples.rows`, each in a class that no earlier one is in; so the bypassed names lists come first. `more_counterexamples` is true when the list is not empty and some widened class has no counterexample in it: the eight were not enough, a class holds no sampled allowance (it may hold none at all, for example when two OLD rules together cover it), or a work limit (16,384 rule pairs, 64 names-list requests) leaves the classes unknown. False means every widened class has a counterexample listed.
`containment.example` keeps the first of them. Otherwise the endpoint result is `inconclusive`, with a reason such as a work limit or coverage that would require combining old rules.

The overall verdict, `result` at the top level and `containment.result`, also covers the rest of the pass. `containment.loosenings` lists each non-endpoint change that gives NEW more authority, as `{field, before, after}` with the field named as in `changes`: a later `approval.valid_until`, an earlier `approval.valid_from`, a higher `ceilings.NAME`, a new `ceilings.NAME` for a counter NEW does not require every debit to charge (a counter without a ceiling cannot be spent, so removing a ceiling narrows), a counter dropped from `required_counters_v1`, `require_target_v1` turned off, `approval.revoked` turned off, and any change of `approval.owner` or `approval.operator`. A change that only narrows is not listed. The overall verdict is `contained` (exit 0) only when the endpoint result is `contained` and `loosenings` is empty. It is `expanded` when the endpoint result is `expanded`, and `widened` when `loosenings` is not empty and the endpoints are not shown to be expanded; an `inconclusive` endpoint result with no loosenings stays `inconclusive`. Every verdict other than `contained` exits 2, so a gate can rely on the exit code alone. A pure revocation is therefore `contained` (exit 0), while a revocation that also raises a ceiling is `widened`. Before this verdict covered the whole pass, `result` and `containment.result` reported the endpoint result only: a revision that kept the endpoints could be `contained` while it extended the window or raised a ceiling. Read `endpoint_result` for the old meaning. Invalid input exits 1. Label attribution, other instants and costs are outside the endpoint proof. See the accompanying declared-field diff for every edit.

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
`key-not-valid-at-time`. With `--archive`, the
verified bytes, the signature and a record of the verification are retained
(see "Archives and evidence"). See the signing and
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
verification (`DIGEST.approval`) beside them. Each archived digest therefore
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
without `--allowed-signers` and `--principal`. They run `ssh-keygen` after
they release the ledger lock, over copies of the bytes they read under it.
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

| Command | Exit 0 | Exit 2 | Exit 1 |
|---|---|---|---|
| `help` | the command directory, or one command's page | never | unknown topic |
| `version` | the version | never | bad arguments |
| `init` | template written (mode 0600; it does not validate until filled in) | never | file exists, write failed |
| `check` | the pass validates (warnings can still be present) | never | any problem |
| `status` | the window is valid | not-yet-valid, expired or revoked | invalid pass, ledger error (also missing or changed per the witness) |
| `permits` | allowed | refused, also `pass-changed` with `--digest` | invalid pass or target, ledger error (as `status`) |
| `spend` | recorded (with `--to`: and the destination is permitted); with `--dry-run`, `would-allow` | refused by the digest, the window, the reference guard, the destination or the ceiling; nothing recorded | error; inspect recording state before retry |
| `capacity` | budget count, including zero | invalid unit policy | usage, pass or accounting error |
| `rehearse` | `simulated`: every step fits | `simulation-refused`: a step is refused | invalid scenario or pass, accounting error |
| `digest` | printed | never | invalid pass |
| `ledger` | listed (also when there is no ledger yet) | never | invalid pass, ledger error (as `status`), bad `--counter` |
| `adopt` | adoption recorded, or the `--preview` snapshot | never | invalid pass, damaged ledger, nothing to adopt, the ledger is intact elsewhere, missing reason, stale token, unusable state directory |
| `reconcile-references` | reconciliation recorded | never | invalid pass, list or reason, damaged, missing or changed ledger, no adoption to reconcile, not the latest such adoption, no witness, unusable state directory |
| `archive` | the exact bytes are retained | never | invalid pass, unusable archive directory |
| `retrieve` | the exact bytes are printed | never | malformed digest, missing or unusable archive entry |
| `receipt` | `found` | `absent`, `ambiguous` | the reference, pass, ledger or witness could not be checked |
| `audit-receipts` | `complete`: and `--allowed-signers` verified a signature over every revision used again, for a `--principal` | `incomplete`, `mismatch` | unusable ledger, archive entry, signature record or trusted signers file; `ssh-keygen` cannot run for a recorded signature, or does not accept `-O verify-time` |
| `audit-charges` | `complete`: and `--allowed-signers` verified a signature over every revision used again, for a `--principal` | `incomplete`, `mismatch`, `empty` | unusable ledger, archive entry, signature record or trusted signers file; `ssh-keygen` cannot run for a recorded signature, or does not accept `-O verify-time` |
| `reconcile` | `match` | `discrepancy` | invalid manifest, pass or history |
| `compare-backups` | `preserved` | `no-match`, `ambiguous`, `inconclusive` | `partial-error` (a candidate failed), invalid pass |
| `checkpoint` | exported | `empty`: nothing recorded yet | invalid pass, ledger error (as `status`) |
| `verify-checkpoint` | `exact` or `extended` | `mismatch` | malformed checkpoint, missing or damaged ledger |
| `verify-approval` | `verified` | `unverified` | invalid pass, unavailable verifier or input |
| `diff` | field comparison completed, including any requested sample or projection; with `--containment`, overall `contained` | `--containment`: `expanded`, `widened` or `inconclusive`; `--budget-impact`: different pass IDs | invalid pass, instant or usage, unusable accounting evidence |
| `consumer-coverage` | `covered` | `gaps` | invalid declaration or pass |
| `lint` | the report, with or without findings | never | invalid pass |
| `test-pass` | every case matched; with `--strength`, `complete` | a mismatch; with `--strength`, survivors, partial analysis or a failed baseline | invalid pass or suite |
| `approval-id` | the ID is printed | never | bad arguments, including an owner or reference that a pass could not hold (the text rules of PASS-FORMAT.md) |

`check` does not judge the window; `status` does.

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

- **error** (any command): `error` `{code, message, line, recording, seq,
  ledger, last_line}` (`line` is the 1-based ledger line for
  `ledger-corrupt`, else null; `last_line` is true when that line is the last
  in the file, so the damage may be a final line cut short, false when it is
  earlier, and null for other errors; `recording`, `seq` and `ledger` as in "Fail-closed cases", null when
  they do not apply; parser failures carry them too, with `recording`
  `not-recorded`), `problems` (list of
  `{field, message}`, empty unless `invalid-pass`).
- **init**: no more fields.
- **check**: `digest`, `pass_id`, `require_target`, `problems` (empty),
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
- **ledger**: `ledger` (its path), `exists`, `pass_id`, `digest` (of the
  pass now), `counter` (the `--counter` filter or null), `verified` (always
  `true` on success: a chain that does not verify is an error), `shown`
  (null without `--tail` or `--since`, else `{from, to, of}`: the first and
  last sequence number shown, null when none is, and `of`, the number of
  entries, adoptions and reference reconciliations included, in the whole
  ledger), `entries`
  (list of `{seq, time, counter, n, digest, note}` for a scalar spend, or
  `{seq, time, event, version, charges, digest, note, receipt}` with
  `event` `debit` for a versioned debit; `digest` is the pass
  digest the spend was decided against, `note` null when none),
  `adoptions` (list of `{seq, time, reason, digest, carried, previous,
  may_have_lost_references}`; `carried` is an object of counter name to
  amount, `previous` is `{ledger, seq, totals, updated}` or null,
  `may_have_lost_references` is true for an adoption that records a
  previous witness of at least one line or carries an amount),
  `reference_reconciliations` (list of `{seq, time, adoption, reason,
  digest, references}`; `adoption` is the sequence of the adoption it
  reconciles, `references` the whole list), `unreconciled_adoption` (the
  latest adoption that may have lost lines when no reconciliation follows
  it, so guarded spends are `reference-inconclusive`; else null), `witness`,
  `moved_from` (as in
  `status`), `totals`
  (list of `{name, spent, total, remaining, over_ceiling, over_by}` for every counter of the pass
  and every counter in the ledger, sorted by name; `total` and `remaining`
  null for a counter the pass no longer has; `over_ceiling` is false and `over_by` null there). `spent` includes carried
  amounts.
- **adopt**: `ledger`, `pass_id`, `digest`, `now`, `test_clock`, `case`
  (`ledger-missing`, `ledger-changed` or `no-witness`), `created` (a new
  ledger was started), `seq`, `reason`, `carried` and `totals` (objects of
  counter name to amount), `previous` (as in `ledger`, or null). A preview
  has `result = "preview"`, `case`, `pass_id`, `seq`, `present`, `carried`,
  `totals`, `previous` and `token`.
- **reconcile-references**: `ledger`, `pass_id`, `digest`, `now`,
  `test_clock`, `seq` (of the new line), `adoption`, `reason` and
  `references` (the list recorded).
- **archive**: `digest`, `provenance` (`signature-recorded` or
  `unsigned`) and `approval` (the kept signature record `{principal,
  namespace, allowed_signers, signature}`, or null). **retrieve**: `digest`
  and `bytes` (the exact pass text); with `--output FILE`, `digest`, `output`
  (the path), `mode` (`0600`) and `length` (bytes written) instead of `bytes`.
- **receipt**, **audit-receipts**, **audit-charges**, **reconcile**,
  **compare-backups**: see [EVIDENCE.md](EVIDENCE.md). **receipt** has
  `reconciled_at` (the first 64 sequences of the reference reconciliations
  that list the reference, empty when none does). **reconcile** has
  `pass_id`, `witness`, `adoption_count` and `rows` (list of `{caller_ref,
  result, candidate_count, sequences, truncated, differences,
  reconciled_at}` in manifest order; each entry of `differences` is
  `{sequence, field, expected, recorded}`, where `expected` and `recorded`
  are numbers for `charge.<counter>` and `targets.count`, strings for the
  other fields, and null when that side has none; `reconciled_at` as in
  `receipt`).
- **checkpoint**: `checkpoint` (`{version, pass_id, seq, hash}`, or null
  when `result` is `empty`), `local_corroboration`, `witness` `{relation,
  witnessed_seq, exported_seq}` (`relation` is `matches`, `lags` or
  `absent`; `witnessed_seq` is null for `absent`, `exported_seq` null for
  `empty`).
- **verify-checkpoint**: `relation` (`exact`, `extended`, `shorter`,
  `foreign` or `mismatch`), `added` (lines after the checkpoint) and
  `trust_input` (`supplied-checkpoint`).
- **verify-approval**: `principal` (or `expected_principal` when
  unverified), `reason` and `next_step` when unverified (`reason` is `wrong-namespace`, `bytes-do-not-match`, `malformed-signature`, `untrusted-key`, `wrong-principal`, `key-not-valid-at-time` or `unknown`, read from ssh-keygen's output; the result and exit code do not change), `pass_id` and `digest` when verified, `namespace`, `verify_time` (the `--at` instant, or null for now), `archive`, `provenance`
  (`signature-recorded` when verified with `--archive`, else null) and
  `approval` (the signature record now in the archive, as in `archive`, or
  null; when an earlier, different record was kept, a warning says so).
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
`check`, `permits`, `spend`, `capacity`, `adopt`, `reconcile-references` and
`lint`, the commands that read the clock, only in debug builds and builds
with the `test-clock` feature. When used, a warning goes to standard
error and `test_clock` is `true`. Release builds ignore it and say so on
standard error.

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
| `adopt(path, reason, now, &StateDir) -> Result<AdoptOutcome, Error>` | record an adoption (`AdoptOutcome { case: AdoptCase, adoption: Adoption, ledger, created, pass_id, totals }`) |
| `preview_adopt`, `adopt_guarded`, `AdoptPreview` | the adoption preview and its token |
| `reconcile_references(path, adoption, &[String], reason, now, &StateDir) -> Result<ReconcileReferencesOutcome, Error>`, `read_reference_list(path, pass_id)`, `ReferenceReconciliation`, `MAX_RECONCILED_REFERENCES`, `MAX_REFERENCE_LIST_BYTES` | record a reference reconciliation (`ReconcileReferencesOutcome { reconciliation, ledger, pass_id, warnings }`) and read its list |
| `tally(&LoadedPass) -> Result<Tally, Error>` | spent per counter, under a shared lock; reads the ledger only, without the witness (as in 0.1) |
| `read_ledger(&LoadedPass, &StateDir) -> Result<LedgerView, Error>` | every entry (`LedgerEntry { seq, time, counter, amount, digest, note }`), every `Adoption` and `ReferenceReconciliation`, `unreconciled_adoption`, the tally, the `WitnessStatus`, `moved_from` and `warnings`; chain verified under a shared lock; read-only |
| `read_summary` | the tally and witness status without the entries |
| `export_checkpoint_observed` (`CheckpointExport`, `WitnessRelation`), `export_checkpoint`, `verify_checkpoint` (`Checkpoint`, `CheckpointStatus`) | checkpoints |
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
