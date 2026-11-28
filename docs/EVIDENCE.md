# Reading accounting evidence

Before any recovery below, run `hallpass doctor PASS`. It reads only. It
says whether anything blocks a spend, names the one next command (for
example `hallpass repair PASS --drop-torn-tail --preview`,
`hallpass compare-backups PASS LEDGER` or `hallpass adopt PASS --preview`)
with the real paths, and lists other findings. In JSON, read `result`,
`problem`, `next` (an argv array) and `findings`. It never names `adopt`
while the ledger may be intact elsewhere. Run the named command, then
doctor again, until `result` is `healthy`. When `compare-backups` finds no
copy that holds the line the witness recorded, a spend fails with
`ledger-changed` or `ledger-corrupt`, every other candidate was read and no
other ledger for the pass id is in sight, its `advice` has an entry of type
`last-resort` whose `argv` moves the ledger aside (`mv LEDGER
LEDGER.damaged`). Run it only when no other backup copy exists; doctor then
names the adoption preview.

These commands read local files under shared ledger locks. They produce historical evidence. Sending a unit of work still requires the caller's normal authorization and accounting decision. The audits release the lock before they verify signatures, so a spend never waits for `ssh-keygen`.

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

A reference is case-sensitive. A spend recorded without `--caller-ref` supplies no match. The command counts all matches and returns the first 64 in sequence order, setting `truncated` when more exist. Review `witness`, `warnings` and `adoption_count`. Adoption can carry spent totals after the original receipts were lost. `reconciled_at` lists the first 64 sequences of the reference reconciliations that name the reference: the operator recorded that its debit may be in lines an adoption lost, so `absent` does not show that it was never debited, and a warning says so. A fresh pass returns `absent` with a `fresh` witness. A missing ledger with witnessed spending returns an error. Each match has `test_clock`, true for a debit written under the test clock; such a match is a rehearsal, text marks it `TEST CLOCK`, and a warning says so. A matching receipt alone cannot authorize another send, retry a debit or refund budget.

The Rust `spend_charges_batch*` API gives every member of a committed atomic
batch its own logical sequence and ordinary receipt, even though all members
occupy one physical ledger line. Look up and compare each caller reference
exactly as above. All receipts are present or none is a valid debit prefix;
after any API error the caller still sends nothing and reconciles the whole
saved reference set.

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
ledger again. A list holds at most 10,000 references: record a longer one in
parts, back to back, before any spend. Until then, spend without the guard only when your run record
shows the unit was never submitted. See [the
rule](spec.md#caller-references-and-receipts) and
[`reconcile-references`](spec.md#reconcile-referencespass-adoption-references-reason-now). A dry run reports the
history it observes and reserves nothing. Retain your own execution record
to decide whether the external action occurred. Calls that omit the guard
can reuse references for correlation.

## Recover from a failed write

`hallpass doctor PASS` tells the cases below apart and names the step.

A spend whose ledger write fails (a full disk, a file size limit) is rolled
back under the lock: the ledger is cut back to its length before the write.
The reply is then `error.code = "ledger-append-failed"` with
`error.recording = "not-recorded"`: nothing was debited or permitted, and the
same unit can be spent again once the cause is fixed. With
`ledger-append-uncertain`, stop and reconcile as above; `receipt` shows
whether the debit is in the ledger.

If the rollback failed too, or an older hallpass wrote the ledger, the
ledger can end with a line cut short, and every command then fails
`ledger-corrupt` at that line with `error.last_line` true. Do not edit the
ledger by hand. Preview the repair, review it, and apply it with its token:

```sh
hallpass --json repair engagement.toml --drop-torn-tail --preview
hallpass --json repair engagement.toml --drop-torn-tail --token "$token"
```

The repair removes only a last line with no line end, and only when the
witness recorded one of the complete lines before it, so the witness
proves the cut-short line was never counted. It keeps the removed bytes in
`engagement.toml.ledger.torn-N` (named in `copy`). It refuses anything else,
such as a complete last line that is invalid, damage before the last line or
a missing witness: restore the ledger from a backup instead, as below.

A last line that is whole (it parses and follows the line before it) and
that the witness recorded as its last line, but that has no line end, is
the one case where the witness counted the line. Dropping it would lower
the count, so `--drop-torn-tail` refuses. Add the line end instead:

```sh
hallpass --json repair engagement.toml --restore-final-newline --preview
hallpass --json repair engagement.toml --restore-final-newline --token "$token"
```

This appends one `\n` byte. No line is changed or removed, and no receipt is
lost. It refuses, and changes nothing, when the last line does not parse or
chain, when the witness is missing, or when the hash of that line is not the
tail the witness recorded.
If the witness counted the damaged last line, the repair always refuses,
because removing the line would lower the count. With no backup, the last
resort is to move the ledger aside (keep it, it holds the receipts) and run
`hallpass adopt engagement.toml --preview`, then `hallpass adopt
engagement.toml --reason "..." --token TOKEN`. The pass is then
`ledger-missing`, and the adoption starts a new ledger that carries the
witness totals. The receipts in the moved ledger are not in the new chain. See
[Dropping a cut-short last line](spec.md#dropping-a-cut-short-last-line).

### A lost witness

Each time hallpass writes the witness, it also writes a copy of it,
`<pass id>.recorded`, in the same state directory. If the witness is missing
but the copy is there, the witness was lost from this state directory (a
cleanup, a partial restore). It is not a pass arriving from another machine,
user or state directory. A spend is then refused with
`error.code = "witness-unavailable"`, and the message names both files.
Without this refusal, an older copy of the ledger put back with it would
count less than was spent. `status`, `permits` and `ledger` still answer,
with the witness `not-checked`.

If a backup of the state directory holds the witness, put it back. If not,
run `hallpass doctor engagement.toml`: it names
`hallpass adopt engagement.toml --preview`. The adoption checks the ledger
against the copy:

- The ledger holds the line the copy records: the case is `no-witness`. The
  adoption carries nothing and keeps every line, and guarded spends go on.
- The ledger does not hold that line (an older copy): the case is
  `ledger-changed`. The adoption carries what the copy records beyond the
  ledger, so the count is not lowered, and it may have lost lines: guarded
  spends are `reference-inconclusive` until you reconcile the references.
- The ledger is missing too: the case is `ledger-missing`, and the adoption
  starts a new ledger that carries the copy's totals.

A state directory where the pass was only checked (`permits`, `status`, a
guarded spend refused for want of a witness) holds `<pass id>.pass-file` and
`<pass id>.lock` but no copy, so a ledger there is still an arrival. A copy
that does not read as one (damaged, or for another pass id) is ignored. A
state directory last written by an earlier release has no copy until the
next write of the witness.

## Replay historical endpoint decisions

Retain each revision the owner approves together with the signature that
approves it, and keep the checked target with each debit. Audit with your own
trusted signers file and the owner's principal, so that the audit verifies
each signature again and requires the owner's:

```sh
mkdir -m 700 approval-archive
hallpass --json verify-approval engagement.toml --signature engagement.toml.sig \
  --allowed-signers trusted_signers --principal owner@example.org --archive approval-archive
hallpass --json spend engagement.toml --charge requests=1 \
  --to 192.0.2.10:443/tcp@app.example.com --record-target
hallpass --json audit-receipts engagement.toml approval-archive \
  --allowed-signers trusted_signers --principal owner@example.org
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
| `complete` | 0 | At least one endpoint was corroborated, all available evidence was replayable without mismatch, and this audit verified again, with `--allowed-signers`, a signature over every revision the ledger used, for a principal named with `--principal`, by a key that the trusted signers file names for that principal or a certificate (not only through a pattern, unless `--allow-pattern-principals`). |
| `incomplete` | 2 | No corroborated endpoints, or evidence gaps and no policy mismatch. A revision without a signature this audit verified is a gap, and so is a line written under the test clock. |
| `mismatch` | 2 | At least one refusal or changed matched label. Other gaps are still listed. |
| `error` | 1 | Unusable input, such as a corrupt ledger, a digest-invalid archive entry, a damaged signature record or an unreadable `--allowed-signers` file, or an `ssh-keygen` that cannot run when a recorded signature needs verifying. |

A CI gate should run the audit with `--allowed-signers`, a trusted signers
file the auditor controls, and `--principal` with the owner's principal, and
require exit 0 and `result = "complete"`:

```sh
hallpass --json audit-receipts engagement.toml approval-archive \
  --allowed-signers trusted_signers --principal owner@example.org > audit.json
jq -e '.result == "complete"' audit.json
```

A gate that also runs `hallpass diff --containment` on each proposed pass
fails every renewal under the same id, because a later `valid_until` is
`widened`. See [Renewing or extending an approval](PASS-FORMAT.md#renewing-or-extending-an-approval)
for what a reviewer does, and for how the audits treat the renewed revision.

`--allowed-signers` may name a symbolic link, such as a Kubernetes
`ConfigMap` or `Secret` mount or a link under `/etc`. hallpass resolves the
link and checks the file it reaches (owned by you or root, not writable by
group or others) and each directory above that file (owned by you or root,
not writable by group or others unless it is sticky). A message names the
resolved path, and a target that fails a check is refused.

The two options answer different questions. The trusted signers file decides
*whose* keys count. `--principal` decides *who* must have approved. A signers
file for a whole organization trusts many people, for example the owner and
the consultant who runs the work. Without `--principal`, each signature is
verified for the principal its record names, and whoever writes the archive
picks that principal. A consultant who widens the pass, signs it with their
own trusted key and records it would then pass. So an audit without
`--principal` still verifies every signature, but is never `complete`: a
revision whose signature verifies is a `signer-not-pinned` gap, which names
the principal each record chose. Repeat `--principal` for an owner with
several principals, for example after a key change: each revision must then
verify for one of them.

`complete` cannot be reached without `--allowed-signers`. A signature record
in the archive is only a file: anyone who can write the archive can copy
another revision's `.sig` and write a record that names any digest, with no
key. So an audit that only reads the records reports each one as
`signature-recorded`, with a `signature-not-reverified` gap, and is
`incomplete`. A gate keyed on exit 0 or on `complete` alone therefore fails
when the flag is missing, instead of accepting records that anyone could have
written. The reply's `signatures.reverified` says which mode ran. An
engagement whose revisions were stored by `archive` alone is never `complete`
either: it is `incomplete` with an `approval-unverified` gap, because the
archive holds no signature for those bytes.

The `gaps` object groups affected lines by reason. Counts include every endpoint or affected record. The report retains the first 64 endpoint details per outcome and the first 64 sequences per gap reason. Each group marks its own truncation.

| Gap | Lines | To close it next time |
| --- | --- | --- |
| `targets-unrecorded` | A spend or debit line that kept no target: a scalar spend line, which has no field for one, or a debit without `--record-target`. | Spend with `--to` and `--record-target`. |
| `archive-missing` | A debit with targets whose revision is not in the archive. | Archive each revision before spending under it. |
| `revision-unparsable` | A debit with targets (`audit-receipts`), or a spend or debit line (`audit-charges`), whose archived revision matches its digest but breaks a pass rule that this hallpass has and the one that recorded the work did not. The audit cannot replay it. | Nothing in the archive: never edit archived bytes. Run the audit with the hallpass version that recorded the work, or accept the gap. |
| `approval-unverified` | A spend or debit line decided under a revision with no signature record in the archive (`unsigned` or `missing`). | Have the owner sign that revision, and record it with `verify-approval --archive`. |
| `signature-not-reverified` | A spend or debit line decided under a revision with a signature record that this audit did not verify, because it ran without `--allowed-signers`. | Run the audit with `--allowed-signers` and your own trusted signers file. |
| `signature-rejected` | A spend or debit line decided under a revision whose recorded signature `ssh-keygen -Y verify` rejected with the `--allowed-signers` file, for every `--principal` given. | Check the `reason`. Supply the right trusted signers file or principal. If the archived signature is wrong, or the record names another principal (`wrong-principal`), move `DIGEST.sig` and `DIGEST.approval` aside (a record is never replaced), have the owner sign that revision, and record it with `verify-approval --archive`. |
| `signer-not-pinned` | A spend or debit line decided under a revision whose recorded signature verified, but for the principal its record names, because the audit ran without `--principal`. | Run the audit with `--principal` and the owner's principal. |
| `signer-matched-by-pattern` | A spend or debit line decided under a revision whose recorded signature verified for a principal named with `--principal`, but the trusted signers file holds its key for that principal only on a line whose principals use a pattern (`*`, `?` or `!`). | Give each owner key a line that names its principal. If pattern lines are what you intend, run the audit with `--allow-pattern-principals`. |
| `adoption-carry` | An adoption that carried totals. Carried totals are not original debits. | Nothing: restore the original ledger if you have it. |
| `test-clock-entry` | Any line written under the test clock (`HALLPASS_UNSAFE_TEST_CLOCK` in a debug build): it carries `"test_clock":true`. It is a rehearsal, and its time is not the real time. | Record live work with a release build, in a ledger of its own. |
| `entry-in-future` | Any line whose time is more than 5 minutes later than the audit's own clock (the real time where the audit runs); smaller skew between hosts is allowed. The clock that recorded it was set ahead, or the audit's clock is behind. | Check both clocks. Do not take the recorded time as when the work happened. |

`targets-unrecorded` replaces the `legacy-spend` reason that earlier versions
gave a scalar spend line. The seven gaps about a revision, `archive-missing`,
`revision-unparsable`, `approval-unverified`, `signature-not-reverified`,
`signature-rejected`, `signer-not-pinned` and `signer-matched-by-pattern`,
also name the revision:
`digests` lists each digest with its own `count`, first 64 `sequences` and
`truncated`, in order of first use, up to 64 digests (`digests_truncated`
marks more). A `signature-rejected` entry also has `reason`, the code
`verify-approval` uses: `wrong-namespace`,
`bytes-do-not-match`, `malformed-signature`, `untrusted-key`,
`wrong-principal`, `key-not-valid-at-time`, `key-not-permitted-for-namespace`
or `unknown`, read from `ssh-keygen`'s output, or `recorded-key-mismatch`:
the signature verified, but the record names another key than the one that
made it, so `verify-approval` did not write that record.
`key-not-permitted-for-namespace` means that the key is in the trusted
signers file for that principal, but its `namespaces=` option leaves out
`hallpass-approval-v1`. `key-not-valid-at-time` means that the key is in the
trusted signers file for that principal, but its `valid-after` or
`valid-before` window does not hold the time the signature was verified as
of. It is never reported as `untrusted-key`. With several `--principal`
values, the reason is that of the first one tried: the record's principal
when it is among them. A `signer-not-pinned` entry also has `principal`, the
principal its record names, which the signature verified for. A
`signer-matched-by-pattern` entry has `principal`, the principal it verified
for, and `signer_key`, the key that made the signature. A
`revision-unparsable` entry also has `problems`, the first 4 problems that
this hallpass finds in the archived bytes, each `{field, message}` as `check`
gives them but without the advice to edit the file, and `problem_count`, how
many there are in all. Text output prints the digests under the gap, with the
reason and what it means, the principal, or the problems. For the other
reasons `digests` is empty.

Pass rules get stricter, and archived bytes are never edited. So a revision
that an older hallpass archived and spent under can break a rule of this one,
for example with a hidden character in a comment. Its bytes still match their
digest, so the archive is not damaged. The audit records a
`revision-unparsable` gap for the lines decided under it, goes on, and is not
`complete` (exit 2). To replay those lines, run the audit with the hallpass
version that recorded the work. Bytes that do not match their digest are
still an error (exit 1), and so is a revision whose `id`, when its TOML can
be read, names another pass.
The audit still verifies the signature of such a revision: a signature over
the exact bytes still shows who approved them. So the revision has its
provenance and its approval gap as any other does. When its signature
verified for a principal you named, `revision-unparsable` is its only gap.

The reader caches one parsed revision at a time. Review the independently reported witness status and warnings when interpreting the history. Replay establishes only the scope of recorded endpoints at the recorded instant. The requested duration, unrecorded endpoints, actual traffic and execution outcomes require other evidence.

### What an audit proves

An audit has two modes, and they prove different things.

- **Without `--allowed-signers`** the audit replays the ledger against the
  archived bytes and reports which revisions have a signature record. It
  shows whether the recorded endpoints (`audit-receipts`) or charges
  (`audit-charges`) fit those exact bytes. It proves nothing about who
  approved them: a record is a file that anyone who can write the archive
  can write. Text says "signature record present (not re-verified)", JSON
  says `signature-recorded`, and the audit is never `complete`.
- **With `--allowed-signers FILE` and `--principal`** the audit also runs
  `ssh-keygen -Y verify` again for each revision that has a record: over the
  archived bytes, with the archived signature, in the `hallpass-approval-v1`
  namespace, for a principal you named, against FILE, as of the time the
  revision was first used. A revision it accepts is `signature-verified`: a
  key that FILE trusted at that time for that principal signed those exact
  bytes. The proof is only as good as FILE and the principals you name, so
  keep them under your own control. The reply gives FILE's digest in
  `signatures.allowed_signers` and the principals in
  `signatures.principals`. A revision it rejects is `signature-rejected`,
  with a `reason`.
- **Which key signed.** A line of FILE can give its key to principals by a
  pattern, such as `*@example.org`, so a signature can verify for the owner's
  principal with another person's key. Each `signature-verified` revision
  therefore reports `signer_key`, the fingerprint of the key that made the
  signature, as `ssh-keygen` printed it when it verified the signature in
  this audit, and `principal_match`, how FILE matched the principal:
  `named` when a line that holds the key names the principal without a
  pattern (alone, or in a list of names), `pattern` when only a line whose
  principals use `*`, `?` or `!` does, and `certificate` when the key is a
  certificate trusted through a `cert-authority` line. A `pattern` revision
  is a `signer-matched-by-pattern` gap, because such a line does not say
  that the key is the owner's, so the audit is not `complete`; with
  `--allow-pattern-principals` it is accepted. A `certificate` is accepted:
  `ssh-keygen` checked that the certificate names the principal, so the
  authority vouched for the key. To tell `named` from `pattern`, the audit
  verifies a plain key again with only the lines of FILE that name their
  principals, when FILE has a pattern line. The key in the record is not
  trusted: anyone who can write the archive can write it. A record that
  names another key than the one that made the signature is
  `signature-rejected` with reason `recorded-key-mismatch`.
- **With `--allowed-signers FILE` alone** the audit verifies each signature
  for the principal its record names. A revision it accepts is
  `signature-verified`, which shows whose key signed it. But whoever wrote
  the archive chose that principal, so each such revision is a
  `signer-not-pinned` gap, and the audit is never `complete`.

Text output says an endpoint is `confirmed` when the revision its debit was
decided under allows it at the recorded instant, by the destination label the
debit recorded, and that revision is `signature-verified` for a principal you
named with `--principal`, and not only through a pattern principal (a
`signer-matched-by-pattern` gap). Confirmed proves that the recorded endpoint was in
the scope of exact pass bytes that a key in your trusted signers file signed
for that principal. It does not prove that traffic went there or only there,
or that the work ran. An endpoint under any other revision is never
confirmed, and text says why: the revision matches but no verified signature
approved it (`unsigned`), it has a signature record that was not re-verified
(`signature-recorded`), its recorded signature failed re-verification
(`signature-rejected`), or its signature verified only for the principal its
record names, because no `--principal` was given. `corroborated` counts every
kind; read each detail's `provenance`.

#### The time a signature is verified as of

A trusted signers file can limit a key to a window with `valid-after` and
`valid-before`, for example when the owner changes keys. The audits verify
each signature as of the time the revision was first used: the time of the
first ledger line decided under it, which is its `first_time`. They give
`ssh-keygen` that time with `-O verify-time`, to the second. So a key that
has expired since still approves the revisions first used before it expired,
and a past audit keeps its result. A key outside its window at that time does
not approve the revision, and the reason is `key-not-valid-at-time`: a key
that had already expired, or one that was not yet valid. So a key added
later cannot approve work done before.
Keep a retired key's line in the file, with `valid-before` set, so that the
revisions it signed still verify. An `ssh-keygen` that does not accept
`-O verify-time` is an error (exit 1), not a rejected signature.

`--signatures-as-of now` verifies every signature as of the current time
instead, by the system clock (the test clock does not apply). Use it to ask
whether every key is still valid today. It is not the default, because a key
that expired after an approval does not undo that approval. Each revision
reports the time used as `verify_time`, and `signatures.as_of` is
`first-use` or the instant used. Text output gives the time in each
revision's line.

With `--allowed-signers`, each digest is verified once, however many lines
used it. The audit reads the ledger under the shared ledger lock, and with it
the archived bytes of each revision used, its record and the `.sig` file the
record names, checked against each other. It keeps these bytes in memory and
releases the lock. Then it runs `ssh-keygen`, so spends on the pass do not
wait for it. The audit reads FILE once, before it reads the ledger.
`ssh-keygen` reads the archived bytes on standard input, and copies of the
signature and of FILE from a private (0700) temporary directory, which the
audit writes from the bytes it read and removes afterwards. So `ssh-keygen`
verifies exactly the bytes that the audit reports, against the FILE whose
digest `signatures.allowed_signers` gives, even if a file changes on disk
meanwhile. The result describes the archive and FILE as the audit read them.
A missing or unreadable FILE is an error (exit 1). So is a FILE that
another user could change: FILE follows the pass file's rule, owned by you
or root and writable by neither group nor others, because whoever can write
it can add a key for the owner's principal (`insecure-permissions` or
`untrusted-owner`, with the `chmod 600` to run). So is a temporary
directory that cannot be created (set `TMPDIR` to a directory you can
write), and an `ssh-keygen` that cannot run, or that prints its usage instead
of verifying, when a revision has a record to verify: an unusable verifier
is never a pass.

The audits trust what `ssh-keygen` says. They run the one that
`HALLPASS_SSH_KEYGEN` names when it is set (an absolute path), else the one
on `PATH`. Set the variable, for example to `/usr/bin/ssh-keygen`, when not
every directory on `PATH` is yours.

### Revisions and their provenance

`archive` stores the exact pass bytes and nothing else.
`verify-approval --archive` stores them only after `ssh-keygen -Y verify`
accepted the owner's signature over exactly those bytes. It reads the
signature and the trusted signers file once, and `ssh-keygen` verifies
private copies of those bytes, so what it records is what was verified. It
keeps two files beside the bytes: `DIGEST.sig`, the signature, and
`DIGEST.approval`, one JSON line with `version`, `digest`, `namespace`,
`principal`, `allowed_signers` (the digest of the trusted signers file it
verified against), `signature` (the digest of `DIGEST.sig`) and `key` (the
fingerprint of the key that made the signature, such as `SHA256:...`, as
`ssh-keygen` printed it). That is `version` 2. A `version` 1 record has no
`key`: an older hallpass wrote it, or `ssh-keygen` did not name the key. It
still reads, and its key is unknown (`key` is null in `approval`). Every
archive file is created once and never replaced. Each digest has one provenance:

| `provenance` | Meaning |
| --- | --- |
| `signature-recorded` | The archive holds a signature record and the signature it names, as `verify-approval --archive` writes them after the signature verified. Reading the record does not verify the signature again, and anyone who can write the archive can write a record. |
| `unsigned` | The bytes are archived without a signature record: `archive` stored them, or an older version wrote the archive. |
| `missing` | The archive does not hold these bytes. |

The audits report the same words, except for a revision with a record when
they run with `--allowed-signers`: it is `signature-verified` when
`ssh-keygen` accepted its signature again, and `signature-rejected` when it
did not. Only an audit with `--allowed-signers` reports `signature-verified`.

`archive` never upgrades a digest. Archiving bytes that already have a record
keeps the record, and `archive` then reports `signature-recorded` with the
record as `approval`. Only `verify-approval --archive` adds a record, so
running it later over the bytes of an `unsigned` digest upgrades that digest.
A record is never replaced: a second, different verified signature over the
same bytes is not stored (for the same principal this is still exit 0, with
`signature-recorded`). `verify-approval` then says so in `warnings`, reports
`provenance` `signature-not-stored` and exits 2 when the kept record names a
DIFFERENT principal, so a step that archives
approvals fails. To record the new signature, move `DIGEST.sig` and
`DIGEST.approval` aside and run `verify-approval --archive` again.
Archives written by earlier versions hold no records, so every digest in them
reads `unsigned` until `verify-approval --archive` records its signature. A
record that does not parse, names another digest, or does not match its
`.sig` file is an error (exit 1), and so is a version 2 record without a
`key` or a version 1 record with one. An older hallpass reads a version 2
record as damaged.

Both audits list the digests the ledger's spend and debit lines used, in
`revisions`, in order of first use. Each entry has `digest`, `first_seq` and
`last_seq`, `first_time` (the time of its first line), `lines` (how many
lines used it), `provenance`, `approval` (the record, or null), `reason` (for
`signature-rejected`, else null), `verify_time` (the instant its signature
was verified as of, or null when this audit did not verify it) and
`verified_for` (the principal it verified for, for `signature-verified`,
else null), `signer_key` (the key that made the signature, from this audit's
verification, for `signature-verified`, else null) and `principal_match`
(`named`, `pattern` or `certificate`, for `signature-verified`, else null). `count` is the number of distinct digests and `unverified` how
many are not `signature-verified`. The first 64 are listed and `truncated`
marks more. Text output prints them after the gaps. Its first line counts
the revisions without a verified signature. Without `--principal` but with
`--allowed-signers`, it also counts the revisions not verified for a
principal named with `--principal`, which is all of them. To list only the
revisions:

```sh
hallpass --json audit-charges engagement.toml approval-archive \
  --allowed-signers trusted_signers --principal owner@example.org | jq '.revisions'
```

Both audits also report `signatures`: `reverified` (true when the audit ran
with `--allowed-signers`, so `ssh-keygen` checked every record it read),
`allowed_signers` (the digest of that file, or null), `principals` (the
`--principal` values, each once; empty when none was given, so that each
signature was verified for the principal its record names) and `as_of`
(`first-use`, the instant `--signatures-as-of now` used, or null without
`--allowed-signers`). With `--allowed-signers`, text output ends the
revisions with a line that names the file's digest, the time and the
principals.

`--allowed-signers` runs, for each recorded revision, the check you can also
make by hand with a trusted signers file you hold. Here `$first_used` is the
revision's `first_time` written as `YYYYMMDDHHMMSSZ`:

```sh
ssh-keygen -Y verify -n hallpass-approval-v1 -I owner@example.org -f trusted_signers \
  -O verify-time="$first_used" -s "approval-archive/$digest.sig" < "approval-archive/$digest"
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

`preserved` exits 0 when an exact copy or one distinct extension preserves the witnessed prefix. Multiple distinct extension tips yield `ambiguous` even if one is longer. An independently verified prefix relationship or external records are needed to resolve their order. `no-match`, `ambiguous` and `inconclusive` exit 2. An unavailable witness yields `inconclusive`. Per-file failures yield `partial-error` and exit 1, retaining the assessment of valid files and the error code for each damaged or unreadable candidate. A candidate that is not a regular file (a FIFO, a device or a directory) is a wrong argument, not a damaged copy: the whole command fails with `not-regular-file` before it reads any candidate. A lock that is still held when `--lock-timeout-ms` runs out fails the whole command with `lock-timeout`; run it again.

After choosing and restoring a file by your normal recovery procedure, compare the restored path again and match its verified tip to the reviewed candidate. A different captured anchor requires another review. Then inspect the live ledger before resuming work.

```sh
hallpass --json compare-backups engagement.toml engagement.toml.ledger
hallpass --json ledger engagement.toml
```

The comparison performs no file discovery, restoration, adoption or witness update.

A candidate that holds the line the witness names, but at another sequence
than the witness records, proves the witness damaged (its sequence was
changed): the warning says so, as for a candidate that holds the witnessed
line with other totals.

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

Candidates that extend the witness, equal it or lie behind it (`shorter`) are
compared. This is sound for a copy behind the witness too: each line holds the
hash of the line before it, so a verified copy whose tip hash is found at the
same sequence in another verified copy is a prefix of it. With the ledger lost
and every backup older than the last spend, the copies still show which lie on
one line and which is a fork, and the newest copy on each branch. This only
reads: the relations, the assessment and the adoption advice do not change. A
copy behind the witness that is a prefix of no other copy may still be an
older copy of the ledger hallpass wrote; the copies given are all that is
compared. A candidate that `mismatch`es, is foreign or is unreadable never
appears in `ancestry`. Empty `prefix_links` therefore means that no tip group
is a prefix of another. It does not mean that the backups are unrelated. Text
output leads with the conclusion: "Nothing to compare" when only one tip group
is compared, and that the groups split when two or more are compared and none
is a prefix of another.

A candidate that holds the witnessed line but has other totals there than
the witness records shows that the witness is damaged; `warnings` says so.
Adoption from a missing ledger carries the witness's totals, which then
come from the witness alone: check them against your run records.

Before you adopt, make sure the ledger is really lost. When the witness
last saw the ledger at another path and the ledger there is intact,
hallpass refuses the pass as `ledger-elsewhere` and refuses to adopt. This
holds also when that ledger has entries after the witness (a spend that
stopped before its witness update, or spends from another state
directory); the message then gives that ledger's current totals. If the file
there is a link, not private, or not readable, hallpass does not read it,
and it refuses to adopt until you fix it (the message gives the `chmod` to
run). If it read the file and found it damaged or for another pass,
`adopt --preview` names it in `warnings`: the witness may be behind it, so
check it before you adopt.

### Audit historical charges

```sh
hallpass audit-charges engagement.toml approval-archive \
  --allowed-signers trusted_signers --principal owner@example.org
hallpass --json audit-charges engagement.toml approval-archive \
  --allowed-signers trusted_signers --principal owner@example.org
```

Each scalar or atomic debit is checked against the exact archived revision and
pre-debit totals. Missing revisions leave `archive-missing` gaps, which name
each missing digest with its sequences, and revisions that break a newer pass
rule leave `revision-unparsable` gaps, while recorded arithmetic still
advances. A report may contain both gaps and found `mismatches`; mismatches
take precedence in the result. Adoption carry advances totals but is not a
verified original debit. Like `audit-receipts`, the charge audit takes
`--allowed-signers`, `--principal` and `--signatures-as-of`, and reports
`revisions`, `signatures` and a gap for every debit decided under a revision
that is not `signature-verified` for a principal you named. `complete` (exit
0) means every debit was checked without a mismatch and this audit verified
again a signature over every revision used, for a principal you named. `empty` means no debit or carry was available; `incomplete`
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
are incomplete, with `reason` `targets-unrecorded` (null on every other row),
and duplicate references are ambiguous. The result only
reconciles recorded accounting; it does not establish external actions, retries
or refunds. Verification failures and malformed manifests exit 1, discrepancies
exit 2, and a complete match exits 0.

## Export and verify a checkpoint

```sh
hallpass --json checkpoint engagement.toml --output checkpoint.json
hallpass --json verify-checkpoint engagement.toml.ledger checkpoint.json
```

`--output FILE` creates the file with mode 0600, whatever the umask, and
refuses an existing file or a link; give each export a new name, such as one
with the date. A `>` redirect uses the umask instead, and under `umask 002`
the file is 0664. `verify-checkpoint`, `doctor --checkpoint` and
`adopt --checkpoint` apply the `--allowed-signers` rule to the checkpoint
file: it must be owned by you or root, and not writable by group or others,
or the command refuses it (`insecure-permissions`, exit 1) and says to run
`chmod 600`. They refuse rather than warn because the checkpoint is the
trust input against a rollback: whoever can write it can swap in an older one
so that the check says `exact`. A symbolic link is allowed (a mount from
another host, say); hallpass checks the file it reaches and each directory
above it.

`checkpoint` commits to the last verified line of the ledger. Its
`checkpoint` object holds `version`, `pass_id`, `seq`, `hash`, `totals`
(per counter, what the ledger counted through that line, carried amounts
included), `latest` (the latest time on any line through it) and `anchors`
(the hashes of some earlier lines, by sequence: the 16 just before it and
those a power of two after the header or before it). The hash covers the
line, and so the history before it; it does not cover `totals`, which are
what the exporter wrote. `latest` and `anchors` let a later shorter ledger
be placed against the checkpointed history (see
[After a restore](#after-a-restore)). A checkpoint from a hallpass before
`totals`, `latest` or `anchors` were exported has none, and still verifies. Retain it
outside the administrative control of the ledger. `verify-checkpoint` reads
only the ledger and the supplied checkpoint, and never reads or creates a
witness. `exact` means the ledger ends at the checkpoint line and
`extended` means `added` entries follow it (a `debit-batch` line counts once per unit); both exit 0. `mismatch` exits 2.
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

### After a restore

A restore of the whole machine (a VM snapshot rolled back, a home-directory
backup put back) restores the ledger and the witness together. They agree
with each other, so `status` says "the witness matches" and `spend` goes on
without a warning, while every spend made since the snapshot is gone. With a
ceiling of 3, five units can be spent across the two histories. hallpass
cannot see this from this machine's files. A checkpoint kept elsewhere can.

Export a checkpoint now and then, and keep it where a snapshot or backup of
this machine does not reach (another host, a password manager, a ticket):

```sh
hallpass --json checkpoint engagement.toml --output checkpoint.json
```

A checkpoint stored inside the snapshot is rolled back with everything else
and proves nothing. After any restore, before the next spend:

1. Fetch the newest checkpoint from the outside copy.
2. Run `hallpass --json verify-checkpoint engagement.toml.ledger checkpoint.json`.
   `exact` or `extended` (exit 0): the ledger still holds the exported line.
   `mismatch` (exit 2): the ledger was rolled back or replaced, and spends
   after the checkpoint may be lost.
   `hallpass doctor engagement.toml --checkpoint checkpoint.json` makes the
   same comparison, read only, and names the next step.
3. On `mismatch`, do not spend. If a newer copy of the ledger exists
   (`verify-checkpoint` says `exact` or `extended` for it), put it back: it
   keeps the receipts. Otherwise follow what doctor names, as below.

What doctor does with each relation:

| `verify-checkpoint` relation | `doctor --checkpoint` | Next step |
| --- | --- | --- |
| `exact`, `extended` | finding `checkpoint-holds` | Nothing: the ledger holds the line. |
| `shorter` or `mismatch` | **blocked** `checkpoint-behind` | `adopt --checkpoint --preview`, below. |
| `shorter` or `mismatch`, checkpoint without `totals` | **blocked** `checkpoint-behind` | Put back a copy that holds the line, or have the owner decide. |
| `shorter` or `mismatch`, the lines the checkpoint proves its own count more than it records | **blocked** `checkpoint-fork` | Put back a copy that holds the line, or stop and have the owner decide: hallpass does not merge two histories. |
| `foreign` | **blocked** `checkpoint-foreign` | Give the checkpoint of this pass. |
| `shorter` or `mismatch`, already adopted | finding `checkpoint-adopted` | Nothing more for the checkpoint. |

When the ledger is behind the checkpoint and no copy is left, record the
loss with the checkpoint:

```sh
hallpass --json adopt engagement.toml --checkpoint checkpoint.json --preview
hallpass --json adopt engagement.toml --checkpoint checkpoint.json \
  --reason 'whole-machine restore; checkpoint from the ticket' --token "$token"
```

A shorter ledger is not always an older copy of the checkpointed history.
An automated worker may spend after the restore and before anyone runs
doctor; its spend takes the sequence a lost entry had. After more spends
than the restore lost, the ledger reaches the checkpoint's sequence with a
new line there, and `verify-checkpoint` says `mismatch`; doctor and the
adoption treat it the same way. hallpass places the
ledger by the checkpoint's `anchors`: the ledger lines through the last
anchor it holds (taken in order, up to the first it does not hold) are
shared, the checkpointed history's own. A line at an anchor the ledger
does not hold, a line with a time later than `latest`, and every line after
either are new; for a ledger that reaches the checkpoint's sequence, so is
its line there and every later one. Other lines are not placed. Doctor and the preview say
which lines are which, and doctor's headline names missing entries by
number only when every ledger line is shared.

The adoption (case `checkpoint-behind`) carries, per counter, what the
checkpoint's `totals` record beyond what the shared lines count. Every
other ledger line counts as new on top, so every count rises to at least
the checkpoint's totals plus every spend since the restore; nothing is ever
lowered. A line that is not placed but was an older copy of a checkpointed
one counts twice, which is on the safe side. With a checkpoint from a
hallpass before `anchors`, or one whose anchors the ledger holds none of,
no line is shared, and every ledger line counts so: the count may be too
high, never too low. Export checkpoints with this hallpass. Times never prove a line shared,
because a restored clock may run behind; a later time proves a line new
whatever any clock did. The adoption line records the checkpoint, so
doctor then says `checkpoint-adopted`, and a second `adopt --checkpoint`
with it is refused. `verify-checkpoint` still says `mismatch`: the lost
lines are not back.

For example: two spends, a snapshot, two more spends, a checkpoint at
sequence 4 with `totals` 4, then the snapshot put back and one more spend.
The ledger has 3 lines and counts 3. The checkpoint's anchors prove lines 1
and 2 shared and line 3 new, so the adoption carries 4 - 2 = 2, and the
count is 5: the four before the restore and the one after. With three
spends after the restore instead, the ledger has 5 lines and its line 4 is
not the checkpointed one (`mismatch`); the anchors still prove lines 1 and
2 shared, the adoption still carries 2, and the count is 7.

Know what the checkpoint proves. It proves that a ledger of this pass once
reached the checkpointed sequence with the line it commits to, and which ledger lines are its own as far as its
anchors reach. It does not show what the missing entries were. The totals are what the checkpoint
file says, and nothing authenticates them beyond the place you kept it. A
total raised by mistake only spends budget; one lowered would carry too
little, so keep the checkpoint where it cannot be edited. Compare the
preview's carry with your run records before you adopt. hallpass refuses
the adoption when the shared lines count more of a counter than the
checkpoint records (counts only grow, so its totals do not belong to its
line hashes), when the checkpoint
records no totals, and for `exact` and `extended`.

The receipts of the lost entries are gone, so the adoption may have lost
caller references: from it on, a spend with `--require-new-ref` is refused
as `reference-inconclusive` until `reconcile-references` records the
references your run records show for the lost entries. Doctor names that
command next, and is healthy after it.

A restore older than your newest checkpoint is caught. One newer than it is
not, so export often enough that the gap is a loss you accept.
