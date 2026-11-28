# Reference caller

[`caller.py`](caller.py) performs one unit of work at a time under a pass.
It journals what it intends and what it did, asks hallpass for a debit, and
calls the unit's callback only after a verified debit. Copy it and replace
`send_unit` with your own work.

It needs Python 3.9 or later, the standard library only, and `hallpass` on
`PATH`. It checks every spend reply with `inspect_reply` from
[the reference decoder](../conformance/check.py). Nothing touches the
network: the callback writes one line to a local file, `outbox.jsonl` by
default. [The walkthrough](../WALKTHROUGH.md) uses it for a whole shift.

The hallpass ledger is the authority for debits. The journal is the
authority for what the caller did. Neither one can stand in for the other.

## Commands

```text
caller.py pin     JOURNAL PASS ARCHIVE [--require-signature PRINCIPAL --allowed-signers FILE [--signature FILE]]
caller.py run     JOURNAL PASS REF --to ADDR:PORT/PROTO[@NAME] --charge COUNTER=N
                  [--to ...] [--charge ...] [--duration S] [--outbox FILE] [--rehearsal]
caller.py handoff JOURNAL PASS [--ref-prefix PREFIX] [--since SEQ] [--all]
caller.py reconcile-references JOURNAL PASS --reason TEXT [--also JOURNAL ...] [--rehearsal]
```

| Command | What it does | Exit |
|---|---|---|
| `pin` | Archives the reviewed pass with `hallpass archive` and journals its ID and digest. Later units pin this digest. With `--require-signature`, pins only a signed revision: see below. | 0 pinned, 1 error |
| `run` | Performs one unit: see below. | 0 sent, 2 refused, 1 unknown or usage error |
| `handoff` | Puts each reference in the journal beside the ledger, through `hallpass reconcile`, in manifests of at most 1,024 rows (hallpass's limit for one); a longer journal is asked in chunks and the rows are merged, so the output is the same as for one run. Other debits are counted, not judged: see below. | 0 nothing needs attention, 2 something does, 1 error |
| `reconcile-references` | After an adoption that may have lost lines, records every reference in the journals with `hallpass reconcile-references`, so that guarded spends resume: see below. | 0 recorded, or nothing to reconcile; 1 error |

The journal records each pass by its ID, its digest and its resolved path.
`run`, `handoff` and `reconcile-references` match records to the pass by the ID
that hallpass reports, so `e.pass.toml`, `./e.pass.toml` and the absolute path
are one pass, and so is a pass that moved with its journal and ledger. If
records name another file than the one given, `handoff` prints a `Note:` line
with the old path: after a move that is expected; otherwise it may be a second
copy of the pass, so find out which file is the pass. The spend reply still
compares the file as written, so use one spelling within a run.

## Pinning a signed revision

Plain `pin` pins whatever is on disk when it runs. If an approval is signed
(see [Signing and verifying an
approval](../INTEGRATING.md#signing-and-verifying-an-approval)), an unsigned
edit made after `verify-approval` would be pinned and spent under without a
word. It would show up only at audit time, as an `approval-unverified` gap.
Ask `pin` to rest on the signature instead:

```text
caller.py pin JOURNAL PASS ARCHIVE --require-signature owner@example.org \
  --allowed-signers /etc/hallpass/trusted_signers [--signature PASS.sig]
```

`--signature` defaults to `PASS.sig`. `--allowed-signers` is the operator's
own trust file, kept apart from the pass and the signature. With
`--require-signature` the caller:

1. runs `hallpass verify-approval` itself with that signers file and the
   principal, and publishes the verified bytes and their signature to
   `ARCHIVE`. Anything but `result = "verified"` for that principal stops the
   pin;
2. runs `hallpass archive` on the file as it is now. The reply must have
   `provenance = "signature-recorded"`, the same principal in its `approval`
   record, and the digest that `verify-approval` verified. A pass edited
   between the two calls archives as another digest, so the pin is refused;
3. checks `hallpass digest` as before, and journals the pin with
   `signed_by`.

The pin rests on the signature that was verified, never on a record in the
archive: anyone who can write the archive can write a record. Nothing is
journaled on a refusal. Sign the new bytes and run `pin` again. A signature
pin is about the bytes: the pass window and the ceilings are still decided at
each `run`. `--allowed-signers` and `--signature` without
`--require-signature` are refused, so a typo cannot drop the check.

## One unit

`run` refuses a reference that is already in its journal. A reference is
used once, whatever its outcome. The check and the write of the intent are
one step under the journal lock, so of several runs that start with the same
reference at once, one writes its intent and the others refuse. Then it:

1. journals `intent`: the reference, the pass, the pinned ID and digest, the
   targets with their names, and the charges;
2. runs `hallpass --format json spend` with `--digest`, `--caller-ref REF`,
   `--require-new-ref`, `--record-target`, `--duration` and every `--to` and
   `--charge`;
3. passes the reply to `inspect_reply`. On a verified debit it journals
   `spend` with `"outcome": "debited"` and the `seq`, then `callback-start`,
   calls `send_unit`, and journals `callback-done`;
4. on a refusal (exit 2, `result = "refused"`, no sequence) journals `spend`
   with `"outcome": "refused"` and the refusal code;
5. on anything else journals `spend` with `"outcome": "unknown"` and the exit
   code. It sends nothing and does not retry. This includes exit 1 with an empty
   reply: hallpass could not write it, and its stderr says what is recorded.

Each record is a JSON line, appended and synced to disk before the next step.
A crash can cut off the last line. The caller ignores a last line without a
newline: it never acted on a record that was not on disk. The next record is
appended under a lock on the journal. If the file does not end in a newline,
the fragment is cut off first, and the caller prints the cut bytes on stderr.
It is cut rather than ended with a newline so that the journal holds no
unreadable line: nothing depends on the fragment, and every later `run` and
`handoff` stays possible. Any other line that is not a JSON object is damage.
The caller refuses to read the journal, names the line, and says to keep a
copy and fix or remove that line; it does not print a traceback. The minimal
caller keeps no journal, so it has nothing to tear.

## After an interruption

Run `handoff`. For each reference it shows what the journal says the caller
did, what the ledger holds for that reference, and a verdict. It also compares
the pass on disk with the last digest pinned in the journal. If they differ, it
prints an `ATTENTION` line with both digests, says that the ceilings shown come
from the file on disk, and exits 2.

It also reads the journal's pins for the pass. If the last pin has no
`signed_by` but an earlier pin did, it prints an `ATTENTION` line naming both
digests and the signer, and exits 2. A signed pin refuses an unsigned edit,
but a plain `pin` afterwards is accepted by the journal. Units spent on that
unsigned revision show at audit time as `approval-unverified`. The journal
does not forbid the plain pin; `handoff` makes it visible. Have the signer
sign the pass, then run `pin --require-signature` again, or restore the signed
bytes. A journal that was never signed is not flagged.

| Journal | Ledger | Verdict |
|---|---|---|
| `sent` | debit | ok |
| `refused CODE` | no debit | ok |
| `unconfirmed`: `callback-start` without `callback-done` | debit | attention: the unit may have run. Check the target's own records. |
| `not sent` or `unknown`: no `callback-start` | debit | attention: the debit stands and nothing was sent |
| `unknown` | no debit | attention: nothing was debited or sent |
| `refused CODE` | debit | attention: another run used this reference |
| no record | debit with your `--ref-prefix` | attention: the journal does not explain this debit |
| `sent` | reconciled: no debit, and a reference reconciliation lists the reference | ok: the debit is missing from the adopted ledger |
| `refused CODE` | reconciled | ok |
| `unconfirmed` | reconciled | attention: the unit may have run. Check the target's own records. |
| `not sent` or `unknown` | reconciled | attention: nothing was sent, and the debit, if there was one, is missing from the adopted ledger |
| any but `refused CODE` | no debit, while `unreconciled_adoption` is set | attention: the unit may be in the lines the adoption lost. Run `reconcile-references` first, then `handoff` again. It is never reported as "not debited". |

While an adoption waits for its reference reconciliation, `handoff` prints a
`Pending:` line after its ledger line. A reference with more than one
`intent` record (older runs that raced) is flagged, and `handoff` judges it by
the run that debited, not by the first record.

### A ledger that other callers share

Several workers often spend from one pass, each with its own journal.
`handoff` judges only the units in the journal it is given. It never gives a
verdict on a debit that the journal does not mention, and it does not set the
exit code for one. It prints one line instead, for example `333 other debits
by other callers or without a reference, not judged; use --all to list them.`

- `--ref-prefix PREFIX`: the references this caller owns (for example
  `shift-17-`). A debit with that prefix and no journal record is a lost or
  stray unit of this caller, so it is an `ATTENTION` row (`no record`) and
  sets exit 2. Give every worker a prefix of its own and always pass it.
  Without it, a debit that carries your reference but is missing from your
  journal is not flagged. The prefix must not be empty.
- `--since SEQ`: look only at ledger debits from sequence number `SEQ` on
  (it uses `hallpass ledger --since`). It bounds the other-debit count and
  the prefix check. Units in the journal are always judged, whatever their
  sequence number.
- `--all`: list the other debits, as `other: not judged` rows.

## Handing a pass to another account

`handoff` output and the journal can be copied. The ledger must be moved,
not copied: a copy on an account with another state directory has no
witness, so every `run` there is refused as `reference-inconclusive` until
`hallpass adopt`, and the old copy would stay spendable as a second budget.
After a move, the old account is refused and must not run `adopt` or spend.
[Step 9 of the walkthrough](../WALKTHROUGH.md#9-hand-the-pass-to-another-account)
shows the commands and what they print.

## After a lost ledger

When the ledger is lost or replaced and an operator adopts it, the lost
lines may have held this caller's references. hallpass then refuses every
`run` as `reference-inconclusive`, and nothing is sent. To let the caller
spend again:

```text
caller.py reconcile-references JOURNAL PASS --reason TEXT [--also JOURNAL ...]
```

It reads `unreconciled_adoption` from `hallpass ledger` (with none, it says
there is nothing to do and exits 0). It lists every reference in the
journal for `PASS`, and in each `--also` journal, whatever the unit's
outcome, and runs `hallpass reconcile-references` with that list and the
reason. The ledger records both. hallpass then refuses each listed
reference as `duplicate-reference` and accepts new ones. The caller
journals a `reconcile-references` record with the adoption, the new ledger
sequence and the number of references.

A reference that is left off the list would be accepted as new. Pass the
journal of every caller that spent on this pass, in one command: the guard
resumes as soon as the line is recorded. The adoption carried the totals
that hallpass had counted. If the debits that the journals show add up to
less than that for a counter, a journal is probably missing: the caller
warns on standard error, names the shortfall, and records nothing unless you
pass `--accept-shortfall` (use it when a caller with no journal made the
debit). A unit whose outcome is unknown (a crash after the spend, or a spend
whose reply was lost) counts as possibly debited, so an ordinary crash does
not trip the check; the caller reports how many such units it counted. A
recorded debit that the ledger already holds is not counted. hallpass takes at most 10,000 references in a
list, so the caller splits a longer list into parts and records them in
order, one `reconcile-references` record in the journal for each part. Until
the last part is recorded, a reference not yet listed is accepted as new, so
nothing should spend in between. If another adoption loses lines
later, run it again. `--rehearsal` keeps `HALLPASS_UNSAFE_TEST_CLOCK`, as for
`run`.

After it, `handoff` shows a unit whose debit was lost as `reconciled seq N`
(see the table above).

## Cost

Every `hallpass` call verifies the whole ledger, and this caller makes one
spend per unit, so it is meant for units that are not very frequent. For
many small units, spend once for a group of them, and when to split an
engagement across passes, read [Cost per call and batching](../INTEGRATING.md#cost-per-call-and-batching).

The caller never repeats a callback by itself, and `handoff` changes
nothing. To do the work of an interrupted unit, decide by hand, then run a
new unit with a new reference. For the ledger side, see
[Reconcile a lost spend response](../EVIDENCE.md#reconcile-a-lost-spend-response)
and [Reconcile a run manifest](../EVIDENCE.md#reconcile-a-run-manifest).

## Rehearsals and tests

A live caller removes `HALLPASS_UNSAFE_TEST_CLOCK` from the environment of
every hallpass command. With `--rehearsal`, `run` keeps it and accepts a
reply with `test_clock: true`; `inspect_reply` checks the rest of the reply
as usual. Use `--rehearsal` only with a debug build in a practice directory.

A release build ignores the variable and spends live. `--rehearsal` refuses
that case. Before it journals anything, `run` checks that the `permits` reply
says `test_clock: true`, and it stops with a message that names the release
build. If a spend reply still says `false` in a rehearsal, `run` journals the
debit but does not run the callback, says the debit is live, and exits 1;
`handoff` then shows it as debited and never sent. Without `--rehearsal`, a
reply with `test_clock: true` is refused in the same way.

`REFERENCE_CALLER_INTERRUPT=after-spend` makes `run` exit with status 3
after hallpass replies and before the reply is journaled.
`REFERENCE_CALLER_INTERRUPT=after-callback` makes it exit with status 3
after the callback and before `callback-done`. `tests/reference_caller.rs`
uses both.
