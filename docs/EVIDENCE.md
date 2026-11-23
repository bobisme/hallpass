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
| `changed` | With `--ancestry`, an extended candidate changed between verification scans or failed the second full verification. Its `error.code` is `candidate-changed` or the verification error. |

`preserved` exits 0 when an exact copy or one distinct extension preserves the witnessed prefix. Multiple distinct extension tips yield `ambiguous` even if one is longer. An independently verified prefix relationship or external records are needed to resolve their order. `no-match`, `ambiguous` and `inconclusive` exit 2. An unavailable witness yields `inconclusive`. Per-file failures yield `partial-error` and exit 1, retaining the assessment of valid files and the error code for each damaged or unreadable candidate.

After choosing and restoring a file by your normal recovery procedure, compare the restored path again and match its verified tip to the reviewed candidate. A different captured anchor requires another review. Then inspect the live ledger before resuming work.

```sh
hallpass --json compare-backups engagement.toml engagement.toml.ledger
hallpass --json ledger engagement.toml
```

The comparison performs no file discovery, restoration, adoption or witness update.

### Comparing successive backups

By default distinct witnessed extensions are ambiguous, even when one extends
another. Opt in to full-file ancestry verification:

```sh
hallpass compare-backups engagement.toml --ancestry copies/friday.ledger copies/saturday.ledger
hallpass --json compare-backups engagement.toml --ancestry copies/friday.ledger copies/saturday.ledger
```

`ancestry.prefix_links` lists pairs of one-based tip groups where the first is
a verified prefix of the second; `maximal_groups` identifies the remaining
branch tips. Duplicate tips share a group. Every candidate is fully verified
again before its hashes are trusted; changed or corrupt candidates produce a
partial error. An absent witness remains inconclusive. This comparison does not
restore a backup or prove any external work.

Only candidates that extend the witness are compared. Candidates that equal or
precede the witness never appear in `ancestry`. Empty `prefix_links` therefore
means that no extended tip group is a prefix of another. It does not mean that
the backups are unrelated. Text output says this in words.

### Audit historical charges

```sh
hallpass audit-charges engagement.toml approval-archive
hallpass --json audit-charges engagement.toml approval-archive
```

Each scalar or atomic debit is checked against the exact archived revision and
pre-debit totals. Missing revisions leave gaps while recorded arithmetic still
advances. A report may contain both `archive-missing` gaps and confirmed
`mismatches`; mismatches take precedence in the result. Adoption carry advances
totals but is not a verified original debit. `empty` means no debit or carry was
available; `incomplete` means evidence is missing. The witness is reported
separately. This numerical audit does not establish endpoints or external work.

### Reconcile a run manifest

Create a JSON manifest with the pass ID and the reviewed digest returned by
`hallpass digest engagement.toml`. For example, save the following as
`manifest.json`, replacing the digest with the actual full digest:

```json
{
  "version": 1,
  "pass_id": "review-example",
  "units": [{
    "caller_ref": "run-42",
    "digest": "sha256:3ed8bc0c2b5ad53b4f397e4848a5a0beb05cb5557383d8c12883a5d678ed9542",
    "charges": [{"counter": "requests", "n": 1}],
    "targets": [{"target": "192.0.2.10:443/tcp", "name": "app.example.com"}]
  }]
}
```

```sh
hallpass spend engagement.toml --charge requests=1 --to 192.0.2.10:443/tcp@app.example.com --record-target --caller-ref run-42
hallpass reconcile engagement.toml manifest.json
hallpass --json reconcile engagement.toml manifest.json
```

Rows preserve manifest order. References must be distinct, charges positive and
unique by counter, and optional targets canonical and ordered. Omit `targets`
to avoid requiring endpoint evidence; supply it to require recorded targets.
The manifest is limited to 1,048,576 bytes and 1,024 rows. Candidate sequence
samples are capped at 64 while counts remain complete. `absent` means absent
from available history, and adoption can preserve totals without receipts.
A different digest, charge, target or name is a mismatch. Each row has a
`differences` list. Each entry has `sequence` (the candidate debit it
describes), `field`, `expected` (manifest) and `recorded` (ledger). A null
value means that side has none. Fields are `digest`, `charge.<counter>`,
`targets.count`, `target[n]` and `name[n]`. With several candidates, the list
holds the differences of each candidate within the sample cap, and `sequence`
tells them apart. Missing retained targets
are incomplete and duplicate references are ambiguous. The result only
reconciles recorded accounting; it does not establish external actions, retries
or refunds. Verification failures and malformed manifests exit 1, discrepancies
exit 2, and a complete match exits 0.

## Export and verify a checkpoint

```sh
hallpass --json checkpoint engagement.toml > checkpoint.json
hallpass --json verify-checkpoint engagement.toml.ledger checkpoint.json
```

`checkpoint` commits to the last verified line of the ledger. Its
`checkpoint` object holds `version`, `pass_id`, `seq` and `hash`. Retain it
outside the administrative control of the ledger. `verify-checkpoint` reads
only the ledger and the supplied checkpoint, and never reads or creates a
witness. `exact` means the ledger ends at the checkpoint line and
`extended` means `added` lines follow it; both exit 0. `mismatch` exits 2.
A malformed checkpoint or a missing or damaged ledger exits 1.

The `witness` object tells how the local witness relates to the exported
line. It is observed under the same lock as the export.

| `witness.relation` | Meaning |
| --- | --- |
| `matches` | The witness records the exported line. `witnessed_seq` equals `exported_seq`. |
| `lags` | The witness records an older line of the same verified ledger. `witnessed_seq` is lower than `exported_seq`, and a warning says so. |
| `absent` | There is no witness for this pass. `witnessed_seq` is null, and a warning says so. |

`local_corroboration` is true for `matches` and `lags`. A lagging witness
corroborates the history only up to `witnessed_seq`.

Before anything has been recorded there is no ledger and no witnessed
spend, so there is no line to commit to. `checkpoint` then exits 2 with
`result = "empty"`, `checkpoint = null`, `witness.relation = "absent"` and
both sequences null. In text mode stdout is empty. In JSON mode the object
holds no checkpoint. Either way a redirect such as the one above leaves no
valid checkpoint, and `verify-checkpoint` rejects the file with exit 1.
Check the exit code before you retain the output. A
missing ledger after a witnessed spend is an error (exit 1), not an empty
result.
