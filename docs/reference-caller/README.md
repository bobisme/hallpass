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
caller.py pin     JOURNAL PASS ARCHIVE
caller.py run     JOURNAL PASS REF --to ADDR:PORT/PROTO[@NAME] --charge COUNTER=N
                  [--to ...] [--charge ...] [--duration S] [--outbox FILE] [--rehearsal]
caller.py handoff JOURNAL PASS
```

| Command | What it does | Exit |
|---|---|---|
| `pin` | Archives the reviewed pass with `hallpass archive` and journals its ID and digest. Later units pin this digest. | 0 pinned, 1 error |
| `run` | Performs one unit: see below. | 0 sent, 2 refused, 1 unknown or usage error |
| `handoff` | Puts each reference in the journal beside the ledger, through `hallpass reconcile`, and lists ledger debits that the journal does not explain. | 0 nothing needs attention, 2 something does, 1 error |

Use the same `PASS` spelling for every command: the journal and the spend
reply compare it as written.

## One unit

`run` refuses a reference that is already in its journal. A reference is
used once, whatever its outcome. Then it:

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
   code. It sends nothing and does not retry.

Each record is a JSON line, appended and synced to disk before the next step.
A crash can cut off the last line. The caller ignores a last line without a
newline: it never acted on a record that was not on disk.

## After an interruption

Run `handoff`. For each reference it shows what the journal says the caller
did, what the ledger holds for that reference, and a verdict.

| Journal | Ledger | Verdict |
|---|---|---|
| `sent` | debit | ok |
| `refused CODE` | no debit | ok |
| `unconfirmed`: `callback-start` without `callback-done` | debit | attention: the unit may have run. Check the target's own records. |
| `not sent` or `unknown`: no `callback-start` | debit | attention: the debit stands and nothing was sent |
| `unknown` | no debit | attention: nothing was debited or sent |
| `refused CODE` | debit | attention: another run used this reference |
| no record | debit | attention: the journal does not explain this debit |

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

`REFERENCE_CALLER_INTERRUPT=after-spend` makes `run` exit with status 3
after hallpass replies and before the reply is journaled.
`REFERENCE_CALLER_INTERRUPT=after-callback` makes it exit with status 3
after the callback and before `callback-done`. `tests/reference_caller.rs`
uses both.
