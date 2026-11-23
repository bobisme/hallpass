# A first shift, from written approval to handoff

> **Build note.** This page, as written, needs a debug build (`cargo build`,
> or a release build with `--features test-clock`). It pins the date with
> `HALLPASS_UNSAFE_TEST_CLOCK` and passes `--rehearsal` to the reference
> caller, and only those builds honour the clock. A default release binary
> ignores the variable, prints "HALLPASS_UNSAFE_TEST_CLOCK is set but
> ignored" and uses the real date. The window of 2026-11-20 is then over, so
> the first preview is refused. To run it live with a release binary, make
> these changes and nothing else:
>
> 1. Leave out the `export HALLPASS_UNSAFE_TEST_CLOCK=...` line.
> 2. In both pass files (steps 2 and 5), set `valid_from` before now and
>    `valid_until` after now. In the amended pass, keep `valid_until` earlier
>    than in the first pass, as the page narrows it.
> 3. Leave out `--rehearsal` from the three `caller.py run` commands.
> 4. The digests change with the window. In the `retrieve` command, use the
>    digest that `pin` printed for the first pass. The output blocks on this
>    page then no longer match: they show the rehearsal dates and digests.

This page takes one operator through one shift. It starts with the owner's
email and ends with a handoff that the next operator can check. Each step
uses the [reference caller](reference-caller/README.md) and the `hallpass`
command line.

The shift is a rehearsal. Every command runs in a fresh temporary directory
and touches no network. `tests/walkthrough.rs` runs the `sh` blocks of this
page in order, in one shell, and compares each output block that follows
them.

## Before you start

Run `cargo build` in the checkout root and put `target/debug` first on your
`PATH`. Then, from the checkout root, create the work directory and pin the
rehearsal clock:

```sh
repo=$PWD
caller="$repo/docs/reference-caller/caller.py"
work=$(mktemp -d)
cd "$work"
umask 077
export XDG_STATE_HOME="$work/state"
export HALLPASS_UNSAFE_TEST_CLOCK=2026-11-20T09:00:00Z
```

The rehearsal happens at 09:00 UTC on 2026-11-20. A debug build of hallpass
honours `HALLPASS_UNSAFE_TEST_CLOCK` and marks every reply with
`test_clock: true`. The reference caller accepts those replies only with
`--rehearsal`. `XDG_STATE_HOME` keeps the witness inside the work directory.

For a live shift, use a release build, enter the real window, unset
`HALLPASS_UNSAFE_TEST_CLOCK` and leave out `--rehearsal`. Keep
`XDG_STATE_HOME` and `HOME` the same for the whole engagement.

## 1. The written approval

The owner sends this email the day before:

```text
From: Pat Owner <pat@example.org>
Date: 2026-11-19
Subject: Approval: web edge test

Sam, you may test app.example.org at 192.0.2.10, TCP port 443, on
2026-11-20 from 08:00 to 17:00 UTC. Send at most 5 requests and 100 bytes
in total. Count both for every request, and name the endpoint each time.
```

## 2. The pass

Start from the template. It approves nothing.

```sh
hallpass init engagement.pass.toml
```

```text
Wrote engagement.pass.toml (mode 0600). It approves nothing: fill it in from the owner's written approval, then run `hallpass check engagement.pass.toml`.
```

The template has two commented lines for owners who put conditions on every
debit. "Name the endpoint each time" becomes `require_target_v1 = true`: a
debit without `--to` is refused. "Count both for every request" becomes
`required_counters_v1 = ["requests", "bytes"]`: a debit that leaves out
either counter is refused. Each required counter needs a ceiling. The host
name goes in `names`, so a request must carry it.

Copy the email into the template. The finished pass:

```sh
cat > engagement.pass.toml <<'PASS'
# Copied from Pat Owner's email of 2026-11-19.
format = 1
id = "web-2026-11"
name = "Web edge"
require_target_v1 = true
required_counters_v1 = ["requests", "bytes"]

[approval]
owner = "Pat Owner"
reference = "email of 2026-11-19"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[ceilings]
requests = 5
bytes = 100
PASS
hallpass check engagement.pass.toml
```

```text
engagement.pass.toml: OK, pass web-2026-11 with 1 destination(s) and 2 ceiling(s). Declared breadth: IPv4 1, IPv6 0. The window is checked by `hallpass status`.
Digest: sha256:87d2830137b2c9dc893dfeda671aaff3bd71e3999c07cd33fc80a63ce3f6faf0
Every debit requires a checked destination.
```

Every key is described in [the pass format](PASS-FORMAT.md#top-level). For
an approval ID that stays stable across revisions, see
[Mapping written approvals](INTEGRATING.md#mapping-written-approvals-and-practice-runs).

## 3. Archive and pin the reviewed bytes

Read the pass against the email once more. Then archive the exact bytes and
pin their digest:

```sh
mkdir -m 700 approval-archive
python3 "$caller" pin shift.jsonl engagement.pass.toml approval-archive
```

```text
pinned web-2026-11 sha256:87d2830137b2c9dc893dfeda671aaff3bd71e3999c07cd33fc80a63ce3f6faf0
```

`pin` runs `hallpass archive`, checks that the file did not change while it
was archived, and appends a `pin` record to the journal `shift.jsonl`. Every
later unit sends this digest with `--digest`. If the pass changes, hallpass
refuses the unit. The archive keeps the reviewed text for later audits:
[Retaining and checking history](../README.md#retaining-and-checking-history).

## 4. Preview, then spend once

A preview shows what would fit. It records nothing and reserves nothing.

```sh
hallpass spend --dry-run --charge requests=1 --charge bytes=24 \
    --to 192.0.2.10:443/tcp@app.example.org -- engagement.pass.toml
```

```text
WOULD ALLOW: no debit recorded
  1 requests (0 spent, 5 left)
  24 bytes (0 spent, 100 left)
```

Now run the first unit:

```sh
python3 "$caller" run shift.jsonl engagement.pass.toml shift-1/unit-1 --rehearsal \
    --to 192.0.2.10:443/tcp@app.example.org --charge requests=1 --charge bytes=24 --duration 60
```

```text
shift-1/unit-1: debit seq 1 verified, unit sent, completion recorded
```

The caller did this, in order:

1. It journaled the intent: the reference, the pinned digest, the target
   and name, and the charges.
2. It ran `hallpass --format json spend` with `--digest`, `--caller-ref`,
   `--require-new-ref` and `--record-target`.
3. It checked the reply with `inspect_reply` from
   [the reference decoder](conformance/check.py). Only a verified debit
   reaches the callback.
4. It journaled the debit and `callback-start`, ran the callback, and
   journaled `callback-done`. The callback stands in for real traffic: it
   writes one line to `outbox.jsonl`.

Each journal record is on disk before the next step starts. The reply
contract is in [Rules for a command-line caller](INTEGRATING.md#rules-for-a-command-line-caller).

## 5. The owner narrows the approval

Mid-shift, the owner writes again:

```text
From: Pat Owner <pat@example.org>
Date: 2026-11-20
Subject: Re: Approval: web edge test

Please finish by 12:00 UTC today, and keep the total to 60 bytes.
```

Copy the change into the pass. Edit this file in place rather than save a
second file with the same ID: that file would have no ledger beside it, and
hallpass would refuse it as `ledger-elsewhere`. Keep the ID and the
reference, so the ledger and its totals carry on:

```sh
cat > engagement.pass.toml <<'PASS'
# Copied from Pat Owner's email of 2026-11-19.
# Narrowed by the reply of 2026-11-20: end at 12:00, at most 60 bytes.
format = 1
id = "web-2026-11"
name = "Web edge"
require_target_v1 = true
required_counters_v1 = ["requests", "bytes"]

[approval]
owner = "Pat Owner"
reference = "email of 2026-11-19"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T12:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.org"]

[ceilings]
requests = 5
bytes = 60
PASS
```

The journal still pins the first revision. The next unit is refused, and
nothing is recorded or sent:

```sh
python3 "$caller" run shift.jsonl engagement.pass.toml shift-1/unit-2 --rehearsal \
    --to 192.0.2.10:443/tcp@app.example.org --charge requests=1 --charge bytes=24 --duration 60 \
    || echo "exit $?"
```

```text
shift-1/unit-2: refused pass-changed, nothing sent
exit 2
```

The journal records the refusal and its code. The reference `shift-1/unit-2`
is now used: the caller never submits a reference twice, so the next unit
gets a new one. A reference must be unique for the pass, so include the
shift or run name in it.

## 6. Review the revision and pin it

Retrieve the bytes of the first pin from the archive and compare them with
the new pass:

```sh
hallpass --format text retrieve approval-archive \
    sha256:87d2830137b2c9dc893dfeda671aaff3bd71e3999c07cd33fc80a63ce3f6faf0 > reviewed-1.toml
hallpass diff --containment --at 2026-11-20T09:00:00Z reviewed-1.toml engagement.pass.toml
hallpass status engagement.pass.toml
```

```text
OLD pass web-2026-11 digest: sha256:87d2830137b2c9dc893dfeda671aaff3bd71e3999c07cd33fc80a63ce3f6faf0
NEW pass web-2026-11 digest: sha256:27c3a869c61aab46b652d0b378fb969c1834c23e6d4798947ec1941ef64a3bdb
approval.valid_until: 2026-11-20T17:00:00Z -> 2026-11-20T12:00:00Z [review required]
ceilings.bytes: 100 -> 60 [review required]
Endpoint scope at 2026-11-20T09:00:00Z: contained (rules-and-ipv4-edges-covered). Compared 1 rule pairs.
Overall verdict: contained. Contained means the endpoints and every other term only narrow.
Pass web-2026-11 "Web edge" (engagement.pass.toml)
Approved by: Pat Owner (reference: email of 2026-11-19)
Operator: Sam Tester
Window: VALID, 3 h 0 min left (2026-11-20T08:00:00Z to 2026-11-20T12:00:00Z)
Destinations:
  web              192.0.2.10               tcp 443  [only as: app.example.org]
Required on every debit: bytes, requests
Every debit requires a checked destination.
Ceilings:
  bytes            60 total, 24 spent, 36 left
  requests         5 total, 1 spent, 4 left
Digest: sha256:27c3a869c61aab46b652d0b378fb969c1834c23e6d4798947ec1941ef64a3bdb
Declared breadth: IPv4 1, IPv6 0.
Ledger: 1 line(s) after the header, chain verified, the witness matches
```

The diff shows the two narrowed terms. The overall verdict covers the
endpoints, the window, the ceilings and the requirements, and it is
contained, so the revision only narrows. The status shows the new window and what is left.
For more review tools, see
[Review and case suites](INTEGRATING.md#review-and-case-suites).

Pin the reviewed revision:

```sh
python3 "$caller" pin shift.jsonl engagement.pass.toml approval-archive
```

```text
pinned web-2026-11 sha256:27c3a869c61aab46b652d0b378fb969c1834c23e6d4798947ec1941ef64a3bdb
```

## 7. Run a permitted unit

```sh
python3 "$caller" run shift.jsonl engagement.pass.toml shift-1/unit-3 --rehearsal \
    --to 192.0.2.10:443/tcp@app.example.org --charge requests=1 --charge bytes=24 --duration 60
```

```text
shift-1/unit-3: debit seq 2 verified, unit sent, completion recorded
```

## 8. Hand off the shift

The handoff puts each caller reference beside the ledger. It runs
`hallpass reconcile` with a manifest built from the journal's intents, and
counts the other debits on the ledger without judging them. It exits 0 when
nothing needs attention and 2 when something does.

```sh
python3 "$caller" handoff shift.jsonl engagement.pass.toml
```

```text
Handoff for web-2026-11 (engagement.pass.toml) from shift.jsonl
shift-1/unit-1  sent                  debit seq 1  ok: debited and sent
shift-1/unit-2  refused pass-changed  no debit     ok: refused, nothing debited or sent
shift-1/unit-3  sent                  debit seq 2  ok: debited and sent
Ledger: 2 debits, witness matches. Spent: bytes 48 of 60, requests 2 of 5.
Nothing needs attention.
```

Each line rests on different records:

| Line | Substantiated by | Where |
|---|---|---|
| A refusal (`shift-1/unit-2`) | The journal's `spend` record with `"outcome": "refused"` and its code. hallpass records nothing for a refusal, so `reconcile` reports the reference `absent`. | `shift.jsonl` |
| Each debit (`debit seq 1`, `debit seq 2`) | The ledger entry whose receipt holds the reference, the pinned digest, the charges and the checked target. | `engagement.pass.toml.ledger`, `approval-archive` |
| Each completed callback (`sent`) | The journal's `callback-start` and `callback-done` records. A record kept by the target, here `outbox.jsonl`, can confirm it. hallpass cannot. | `shift.jsonl`, the target's own records |

Look up one debit by its reference, and replay every recorded target against
the archived revision it was spent under:

```sh
hallpass receipt engagement.pass.toml --caller-ref shift-1/unit-3
hallpass audit-receipts engagement.pass.toml approval-archive
```

```text
Receipt found for "shift-1/unit-3". 1 matches. Witness matches. Adoptions 0.
  #2 2026-11-20T09:00:00Z sha256:27c3a869c61aab46b652d0b378fb969c1834c23e6d4798947ec1941ef64a3bdb  charges=[{"counter":"requests","n":1},{"counter":"bytes","n":24}] targets=[{"label":"web","name":"app.example.org","target":"192.0.2.10:443/tcp"}]
Receipt audit complete. Witness matches.
corroborated 2
  #1 target 1 at 2026-11-20T09:00:00Z 192.0.2.10:443/tcp name app.example.org: recorded label web confirmed
  #2 target 1 at 2026-11-20T09:00:00Z 192.0.2.10:443/tcp name app.example.org: recorded label web confirmed
mismatches 0
```

The journal holds four records for a completed unit. Times are the caller's
own clock:

```text
{"at": "…", "ref": "shift-1/unit-3", "event": "intent", "pass": "engagement.pass.toml", "pass_id": "web-2026-11", "digest": "sha256:…", "targets": [{"target": "192.0.2.10:443/tcp", "name": "app.example.org"}], "charges": [{"counter": "requests", "n": 1}, {"counter": "bytes", "n": 24}], "rehearsal": true}
{"at": "…", "ref": "shift-1/unit-3", "event": "spend", "outcome": "debited", "seq": 2}
{"at": "…", "ref": "shift-1/unit-3", "event": "callback-start"}
{"at": "…", "ref": "shift-1/unit-3", "event": "callback-done"}
```

### Missing execution evidence

A debit proves that hallpass admitted a unit. It does not prove that the
unit ran. The handoff marks every debit without a recorded completion:

```text
lost-reply     unknown      debit seq 1  ATTENTION: debited, never sent; the debit stands
no-completion  unconfirmed  debit seq 2  ATTENTION: completion not recorded; check the target, do not repeat
by-hand        no record    debit seq 3  ATTENTION: no journal record; find the run record of this debit
```

- `unknown` with a debit: the caller stopped before it recorded the reply.
  No `callback-start` was written, so the callback never ran. The debit
  stands. Run any further work as a new unit with a new reference.
- `unconfirmed`: `callback-start` is in the journal and `callback-done` is
  not. The unit may have run. Check the target's own records. The caller
  never repeats the callback by itself.
- `no record`: the ledger has a debit with a reference that this caller owns
  (the `--ref-prefix` given to `handoff`) and this journal does not explain
  it. Find the run record that made it. Debits by other callers on the same
  ledger are only counted, not judged.

`tests/reference_caller.rs` produces each of these lines by interrupting
the caller. Run `handoff` after any interruption, before more units. For the
underlying contracts, see
[Reconcile a lost spend response](EVIDENCE.md#reconcile-a-lost-spend-response)
and [Reconcile a run manifest](EVIDENCE.md#reconcile-a-run-manifest).

Hand over the journal, the outbox, the pass with its ledger, the archive and
the handoff output. For a copy of the ledger state that a second account can
verify, add a checkpoint:
[Retaining and checking history](../README.md#retaining-and-checking-history).
