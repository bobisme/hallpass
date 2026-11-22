# Reading accounting evidence

These commands read local files under shared ledger locks. They produce historical evidence. Sending a unit of work still requires the caller's normal authorization and accounting decision.

## Reconcile a lost spend response

Before submitting a counted unit, persist its unique reference, reviewed pass digest, expected charges and endpoint list in your own durable run record. For example, suppose run `batch-42` records one request and four bytes to `192.0.2.10:443/tcp@app.example.com`. Its state is `debit-submitted`, and the caller has no spend response. The original spend used `--caller-ref batch-42 --record-target`. Find the debit using the current revision of the same pass.

```sh
hallpass --json receipt engagement.toml --caller-ref batch-42
```

If the result is `found`, compare the receipt's digest, charge names and amounts, and retained targets against that run record. Record the ledger sequence alongside the original request. Keep the external action's completion as a separate field and reconcile it against the caller's own execution record. Hallpass cannot determine whether the action ran. An empty target list means the debit retained no endpoint evidence.

| Result | Exit | Meaning |
| --- | --- | --- |
| `found` | 0 | Exactly one matching debit in this pass's available history. |
| `absent` | 2 | No exact match in the available history. |
| `ambiguous` | 2 | Multiple debits shared the reference. Preserve all candidate sequences for reconciliation. |
| `error` | 1 | The reference, pass, ledger or witness could not be checked. |

A reference is case-sensitive. Legacy scalar spends and reference-free debits supply no match. The command counts all matches and returns the first 64 in sequence order, setting `truncated` when more exist. Review `witness`, `warnings` and `adoption_count`. Adoption can carry spent totals after the original receipts were lost. A fresh pass returns `absent` with a `fresh` witness. A missing ledger with witnessed spending returns an error. A matching receipt alone cannot authorize another send, retry a debit or refund budget.

Use `--require-new-ref` with `--caller-ref` so cooperating workers on the same
local history submit a given reference at most once. Record the intended unit
and reference before submitting the guarded spend.

```sh
hallpass --format json spend engagement.toml \
  --charge requests=1 --charge bytes=4 \
  --to 192.0.2.10:443/tcp@app.example.com --record-target \
  --digest "$digest" --caller-ref batch-42 --require-new-ref
```

After a lost reply, use `receipt` and reconcile the debit with the saved unit
and your execution record. If another worker submits the same guarded
reference, the repeat exits 2 with `refusal.code=duplicate-reference` and
`seq: null`. Read `reference_evidence.sequences` for up to 64 historical
matches and use `receipt` to compare the recorded charges and targets. The
repeat provides no permission to send. An absent reference in a history
that contains an adoption or has events without a local witness returns
`reference-inconclusive`. A dry run reports the history it observes and
reserves nothing. Retain your own execution record to decide whether the
external action occurred. Calls that omit the guard can reuse references
for correlation.

## Replay historical endpoint decisions

```sh
mkdir -m 700 approval-archive
hallpass --json archive engagement.toml approval-archive
# Archive each reviewed revision before spending under it.
hallpass --json audit-receipts engagement.toml approval-archive
```

For each debit that retained targets, the audit reads the archived bytes for its digest, checks the pass ID and evaluates each ordered literal endpoint and optional request name at the stored instant with zero duration. Corroboration requires an allowed decision with the same destination label. Each detail has a ledger sequence and a one-based endpoint index. The current revision can have different labels, windows or revocation status.

| Result | Exit | Meaning |
| --- | --- | --- |
| `complete` | 0 | At least one endpoint was corroborated, and all available evidence was replayable without mismatch. |
| `incomplete` | 2 | No corroborated endpoints, or evidence gaps and no policy mismatch. |
| `mismatch` | 2 | At least one refusal or changed matched label. Other gaps are still listed. |
| `error` | 1 | Unusable input, such as a corrupt ledger or a digest-invalid archive entry. |

The `gaps` object groups affected sequences by reason. A legacy spend, debit without targets, adoption with carried balances or missing archived revision leaves a gap. Counts include every endpoint or affected record. The report retains the first 64 endpoint details per outcome and the first 64 sequences per gap reason. Each group marks its own truncation. The reader caches one parsed revision at a time. Review the independently reported witness status and warnings when interpreting the history. Replay establishes only the scope of recorded endpoints at the recorded instant. The requested duration, unrecorded endpoints, actual traffic and execution outcomes require other evidence.

## Compare ledger backups before restoring one

```sh
hallpass --json compare-backups engagement.toml copies/friday.ledger copies/saturday.ledger
```

Supply one to 32 explicit paths. The command captures the local witness once, then checks every candidate through its final line. The live ledger can be missing. A verified tip identifies the pass ID, sequence and hash. Candidates appear in input order. Equal `tip_group` values identify copies with the same verified tip.

| Relation | Meaning |
| --- | --- |
| `exact` | Tip equals the captured witness. |
| `extended` | The candidate contains the witnessed line at the witnessed sequence and additional valid lines. |
| `shorter` | The same pass ID has fewer lines than the anchor. Historical ancestry is unconfirmed. |
| `mismatch` | Same pass ID, but the candidate disagrees at the witnessed sequence. |
| `foreign` | A verified candidate belongs to another pass ID. |
| `unanchored` | The same pass ID has a verified tip, but the witness is missing or unreadable. |
| `error` | This file could not be verified. It supplies no tip. |

`preserved` exits 0 when an exact copy or one distinct extension preserves the witnessed prefix. Multiple distinct extension tips yield `ambiguous` even if one is longer. An independently verified prefix relationship or external records are needed to resolve their order. `no-match`, `ambiguous` and `inconclusive` exit 2. An unavailable witness yields `inconclusive`. Per-file failures yield `partial-error` and exit 1, retaining the assessment of valid files and the error code for each damaged or unreadable candidate.

After choosing and restoring a file by your normal recovery procedure, compare the restored path again and match its verified tip to the reviewed candidate. A different captured anchor requires another review. Then inspect the live ledger before resuming work.

```sh
hallpass --json compare-backups engagement.toml engagement.toml.ledger
hallpass --json ledger engagement.toml
```

The comparison performs no file discovery, restoration, adoption or witness update.
