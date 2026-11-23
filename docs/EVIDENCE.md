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

A reference is case-sensitive. A spend recorded without `--caller-ref` supplies no match. The command counts all matches and returns the first 64 in sequence order, setting `truncated` when more exist. Review `witness`, `warnings` and `adoption_count`. Adoption can carry spent totals after the original receipts were lost. `reconciled_at` lists the first 64 sequences of the reference reconciliations that name the reference: the operator recorded that its debit may be in lines an adoption lost, so `absent` does not show that it was never debited, and a warning says so. A fresh pass returns `absent` with a `fresh` witness. A missing ledger with witnessed spending returns an error. A matching receipt alone cannot authorize another send, retry a debit or refund budget.

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
repeat provides no permission to send. An absent reference returns
`reference-inconclusive` in a history with events but no local witness, or
with an adoption that may have lost lines (it records a previous witness of
at least one line, or carries totals) and no reference reconciliation after
it. For a complete ledger without a witness, `hallpass adopt` records one
and the guard checks references again. After an adoption that lost lines,
list every reference your run records used on the pass and record the list
with `hallpass reconcile-references FILE --adoption SEQ --references LIST
--reason TEXT`: a listed reference is then a duplicate, with
`reference_evidence.reconciled_at`, and any other is checked against the
ledger again. Until then, spend without the guard only when your run record
shows the unit was never submitted. See [the
rule](spec.md#caller-references-and-receipts) and
[`reconcile-references`](spec.md#reconcile-referencespass-adoption-references-reason-now). A dry run reports the
history it observes and reserves nothing. Retain your own execution record
to decide whether the external action occurred. Calls that omit the guard
can reuse references for correlation.

## Replay historical endpoint decisions

Retain each revision the owner approves together with the signature that
approves it, and keep the checked target with each debit:

```sh
mkdir -m 700 approval-archive
hallpass --json verify-approval engagement.toml --signature engagement.toml.sig \
  --allowed-signers trusted_signers --principal owner@example.org --archive approval-archive
hallpass --json spend engagement.toml --charge requests=1 \
  --to 192.0.2.10:443/tcp@app.example.com --record-target
hallpass --json audit-receipts engagement.toml approval-archive
```

A plain `spend --to` checks its target but does not keep it, so the audit can
only count that debit as a `targets-unrecorded` gap. Add `--record-target` to
every spend whose endpoint you want to audit. It is not the default: a
wrapper that checks replies expects no `receipt` from a spend that did not ask
for one, a debit line with a target is longer than a scalar spend line and
every call verifies the whole ledger, and the kept endpoints and request names
can be read by anyone who can read the ledger and its copies.

For each debit that retained targets, the audit reads the archived bytes for its digest, checks the pass ID and evaluates each ordered literal endpoint and optional request name at the stored instant with zero duration. Corroboration requires an allowed decision with the same destination label. Each detail has a ledger sequence, a one-based endpoint index and the `provenance` of the revision it was replayed against. The current revision can have different labels, windows or revocation status.

| Result | Exit | Meaning |
| --- | --- | --- |
| `complete` | 0 | At least one endpoint was corroborated, all available evidence was replayable without mismatch, and a verified signature approved every revision the ledger used. |
| `incomplete` | 2 | No corroborated endpoints, or evidence gaps (a revision without a verified signature is one) and no policy mismatch. |
| `mismatch` | 2 | At least one refusal or changed matched label. Other gaps are still listed. |
| `error` | 1 | Unusable input, such as a corrupt ledger, a digest-invalid archive entry or a damaged signature record. |

A CI gate should require exit 0 and `result = "complete"`. An engagement
whose revisions were stored by `archive` alone is never `complete`: even when
the replay finds no mismatch, it is `incomplete` with an `approval-unverified`
gap. That gap means the archive holds no evidence that the owner approved
those bytes; it is not a pass.

The `gaps` object groups affected lines by reason. Counts include every endpoint or affected record. The report retains the first 64 endpoint details per outcome and the first 64 sequences per gap reason. Each group marks its own truncation.

| Gap | Lines | To close it next time |
| --- | --- | --- |
| `targets-unrecorded` | A spend or debit line that kept no target: a scalar spend line, which has no field for one, or a debit without `--record-target`. | Spend with `--to` and `--record-target`. |
| `archive-missing` | A debit with targets whose revision is not in the archive. | Archive each revision before spending under it. |
| `approval-unverified` | A spend or debit line decided under a revision that is not `signature-verified` in the archive. | Have the owner sign that revision, and record it with `verify-approval --archive`. |
| `adoption-carry` | An adoption that carried totals. Carried totals are not original debits. | Nothing: restore the original ledger if you have it. |

`targets-unrecorded` replaces the `legacy-spend` reason that earlier versions
gave a scalar spend line. Both gaps about a revision, `archive-missing` and
`approval-unverified`, also name the revision: `digests` lists each digest
with its own `count`, first 64 `sequences` and `truncated`, in order of first
use, up to 64 digests (`digests_truncated` marks more). Text output prints
them under the gap. For the other reasons `digests` is empty.

The reader caches one parsed revision at a time. Review the independently reported witness status and warnings when interpreting the history. Replay establishes only the scope of recorded endpoints at the recorded instant. The requested duration, unrecorded endpoints, actual traffic and execution outcomes require other evidence.

### What an audit proves

Text output says an endpoint is `confirmed` when the revision its debit was
decided under allows it at the recorded instant, by the destination label the
debit recorded, and that revision is `signature-verified`. Confirmed proves
that the recorded endpoint was in the scope of exact pass bytes for which the
archive holds a verified signature record. It does not prove that traffic went
there or only there, that the work ran, or that the record itself is genuine:
the audits read the record and do not run `ssh-keygen` again. An endpoint
under an `unsigned` revision is never confirmed. Text says that it matches the
archived revision, which no verified signature approved, and its JSON detail
has `provenance = "unsigned"`. `corroborated` counts both kinds; read each
detail's `provenance`.

### Revisions and their provenance

`archive` stores the exact pass bytes and nothing else.
`verify-approval --archive` stores them only after `ssh-keygen -Y verify`
accepted the owner's signature over exactly those bytes, and keeps two files
beside them: `DIGEST.sig`, the signature, and `DIGEST.approval`, one JSON line
with `version`, `digest`, `namespace`, `principal`, `allowed_signers` (the
digest of the trusted signers file it verified against) and `signature` (the
digest of `DIGEST.sig`). Every archive file is created once and never
replaced. Each digest has one provenance:

| `provenance` | Meaning |
| --- | --- |
| `signature-verified` | `verify-approval --archive` verified a signature over these bytes and recorded it. |
| `unsigned` | The bytes are archived without a signature record: `archive` stored them, or an older version wrote the archive. |
| `missing` | The archive does not hold these bytes. |

`archive` never upgrades a digest. Archiving bytes that already have a record
keeps the record, and `archive` then reports `signature-verified` with the
record as `approval`. Only `verify-approval --archive` adds a record, so
running it later over the bytes of an `unsigned` digest upgrades that digest.
A record is never replaced: a second, different verified signature over the
same bytes is not stored, and `verify-approval` says so in `warnings`.
Archives written by earlier versions hold no records, so every digest in them
reads `unsigned` until `verify-approval --archive` records its signature. A
record that does not parse, names another digest, or does not match its
`.sig` file is an error (exit 1).

Both audits list the digests the ledger's spend and debit lines used, in
`revisions`, in order of first use. Each entry has `digest`, `first_seq` and
`last_seq`, `lines` (how many lines used it), `provenance`, and `approval`
(the record, or null). `count` is the number of distinct digests and
`unverified` how many are not `signature-verified`. The first 64 are listed
and `truncated` marks more. Text output prints them after the gaps. To list
only the revisions:

```sh
hallpass --json audit-charges engagement.toml approval-archive | jq '.revisions'
```

To check a signature independently, verify the archived signature over the
archived bytes with a trusted signers file you hold:

```sh
ssh-keygen -Y verify -n hallpass-approval-v1 -I owner@example.org -f trusted_signers \
  -s "approval-archive/$digest.sig" < "approval-archive/$digest"
```

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
pre-debit totals. Missing revisions leave `archive-missing` gaps, which name
each missing digest with its sequences, while recorded arithmetic still
advances. A report may contain both gaps and found `mismatches`; mismatches
take precedence in the result. Adoption carry advances totals but is not a
verified original debit. Like `audit-receipts`, the charge audit reports
`revisions` and an `approval-unverified` gap for every debit decided under a
revision that is not `signature-verified`. `complete` (exit 0) means every
debit was checked without a mismatch and a verified signature approved every
revision used. `empty` means no debit or carry was available; `incomplete`
means evidence is missing, approval evidence included. The witness is reported
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
Each row has `reconciled_at`, the first 64 sequences of the reference
reconciliations that name its reference: its debit may be in lines an
adoption lost, so an `absent` row may still have been debited, and a warning
counts such rows.
A different digest, charge, target or name is a mismatch. Each row has a
`differences` list. Each entry has `sequence` (the candidate debit it
describes), `field`, `expected` (manifest) and `recorded` (ledger). A null
value means that side has none. Each value has the natural JSON type of its
field: a number for `charge.<counter>` and `targets.count`, a string for
`digest`, `target[n]` and `name[n]`. (Before this change every value was a
string, such as `"5"`.) Fields are `digest`, `charge.<counter>`,
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
