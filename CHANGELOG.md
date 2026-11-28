# Changelog

## Unreleased

Changes since commit d70c09f.

### Compatibility

- **Atomic debit batches add a ledger line shape.** A successful
  `spend_charges_batch*` writes `event: "debit-batch"`. Older Hallpass
  builds stop at that line with `ledger-corrupt`, so they fail closed. One
  physical batch line owns a contiguous logical sequence range; status and
  missing-ledger messages now describe logical entries rather than equating
  the final sequence with a physical JSON-line count.

- **Every spend reply has the same keys.** Scalar and `--charge` replies,
  allowed, `would-allow` and refused, now all have `charges`, `receipt`,
  `reference_evidence` and the scalar fields `counter`, `n`, `total`,
  `spent`, `remaining` and `projected_spent`. The scalar fields repeat the
  only charge of a one-counter unit and are null when a unit charges
  several counters. A `receipt` always has `caller_ref` and `targets`, and
  each target has `name` (null for an unnamed endpoint). A decoder copied
  from the previous `docs/conformance/check.py` stops (fails closed) on
  every `--charge` reply, because the scalar keys are now present. Update
  it from the current `check.py`, which tests the values instead.
- **`diff` values changed type.** `changes[].before` and `after` are a JSON
  string, number or null (absent), not always a string. A ceiling is a
  number. An absent ceiling, `hostname` or `revoked_reason` is null instead
  of the text `None`. Ports read `5060, 10000-10100`. A network change is
  labelled `destination[LABEL].network`. It was `.address`, which now
  remains only when both sides are single hosts.
- **Library:** `review::FieldChange.before` and `after` changed from
  `String` to `serde_json::Value`.
- **`checkpoint` has an empty result.** With no ledger and no witnessed
  spend, `checkpoint` exits 2 with `result = "empty"`, `checkpoint = null`
  and empty text output. It was an `io` error (exit 1).
- **Error text no longer doubles backslashes.** Text-mode error messages
  print the escapes they carry (`\"`, `\\`, `\u{...}`) once. JSON
  `error.message` is unchanged.
- **`witness-unavailable` errors carry `error.recording = "not-recorded"`**
  (it was null). An `adopt` whose adoption was appended before the witness
  update failed still has a null `recording`.
- **`test-pass --strength` tries more mutations.** It also widens each
  network by one bit, adds the other transport, and moves each end of the
  window by one second. A suite with no survivors before can now report
  survivors and exit 2.
- **The default output format comes from `HALLPASS_FORMAT`.** The
  unprefixed `FORMAT` variable is ignored, with a warning when
  `HALLPASS_FORMAT` is unset. An invalid `HALLPASS_FORMAT` is a usage error
  that names the variable. A caller that set `FORMAT=json` must set
  `HALLPASS_FORMAT=json`.
- **Argument parse errors have the full error shape.** In JSON mode they
  now carry `command` (when the subcommand was recognized), `file`,
  `problems`, and `error.ledger`, `error.recording` (`"not-recorded"`) and
  `error.seq`, and nothing is printed to standard error.
- **Read-only commands no longer advise `hallpass adopt`.** A missing or
  changed ledger, or a damaged witness, reported by `diff`, `ledger`,
  `receipt`, `reconcile`, `checkpoint`, the audits and the other read-only
  commands now says the command changed nothing and points to `hallpass
  status`. `spend`, `adopt` and `status` keep the advice.
- **`diff --budget-impact` reads the live ledger.** It uses the ledger
  beside NEW, or beside OLD only when NEW has none, and reports
  `budget_impact.ledger` and `budget_impact.ledger_source`.
- **Guarded spends after an adoption.** `--require-new-ref` checks new
  references again after an adoption that kept every line (for example a
  ledger moved to a new machine and adopted there). An adoption that lost
  witnessed lines or carried totals still makes new references
  `reference-inconclusive`. Both inconclusive refusals now name the next
  step.
- **Audit archives.** `audit-charges` and `audit-receipts` report a
  missing, non-directory or world-readable archive directory as an error
  (exit 1) instead of an `archive-missing` gap (exit 2).
- **Library:** `Error::Insecure` has a new `advice` field, and
  `AddressError` has a new `NonStandardIpv4` variant.
- **`ledger-elsewhere`: a second pass file for a live ledger.** A pass
  file with no ledger beside it, whose id has an intact ledger where the
  witness last saw it (an amended approval saved as a second file, or a
  pass moved without its ledger), is refused as `ledger-elsewhere` instead
  of `ledger-missing`. The message names the live ledger and its pass file
  and says to replace that file's content with the revision. `adopt` and
  `adopt --preview` refuse, because adopting would fork the history. A
  last-seen ledger that cannot be read or verified, or disagrees with the
  witness, is still `ledger-missing`. The exit code (1) is unchanged.
- **`ledger --json` times keep their fractional seconds.** Entry, debit and
  adoption `time` values are now exactly as recorded (for example
  `2026-11-23T16:36:15.36549262Z`), as `receipt` and `audit-receipts`
  already gave them, so debits within one second keep their order. Ledgers
  written with whole seconds are unchanged.
- **`unknown-counter` comes before `required-counter-missing`.** A debit
  that names a counter the pass does not have is refused as
  `unknown-counter`, even when it also misses a required counter.
- **`window.seconds_until_open` rounds up.** `seconds_remaining` and
  `seconds_since_end` still round down. No value promises more time than
  the decision allows.
- **`diff` JSON `warnings` is no longer always empty.** It repeats the
  message of each name-restriction overlap that NEW introduces.
- **The reference caller's `handoff` judges only its own journal.** Debits
  by other callers on a shared ledger are counted and never set the exit
  code. A caller that relied on `handoff` flagging every unrecorded debit
  must pass `--ref-prefix` with the references it owns.
- **Text output:** multi-counter debits in the `ledger` table print one
  row per charge. `verify-checkpoint` adds the relation when it differs
  from the result.
- **Library:** `CheckpointStatus` has new variants `Shorter` and `Foreign`
  (a ledger of another pass is now `Foreign`, not `Mismatch`).
  `Error::LedgerCorrupt` has a new field `last`. New items: `LockWait`,
  `SpendRequest::on_lock_wait`, `rfc3339`, `span_left`, `span_until` and
  `whole_seconds_up`.

- **`diff --containment` judges the whole pass.** `result` and
  `containment.result` are now an overall verdict. A revision that keeps the
  endpoints but loosens anything else returns the new value `widened`, with
  exit 2, instead of `contained` with exit 0. Loosening means a later window
  end, an earlier window start, a higher ceiling, a new ceiling on a counter
  that is not required, a dropped required counter, `require_target_v1`
  turned off, an un-revoke, or a changed owner or operator.
  `containment.endpoint_result` keeps the old endpoint-only verdict. A CI
  gate keyed on the exit code used to accept such revisions.
- **Audits need a verified signature.** `audit-receipts` and
  `audit-charges` return `incomplete` (exit 2) when any revision the ledger
  used has no signature record in the archive. This includes archives
  written only with `archive` or by older versions: run
  `verify-approval --archive` for each signed revision. The `legacy-spend`
  gap code is gone; plain spend lines count under `targets-unrecorded`.
- **Pass files.** A pass whose last line does not end with a newline is
  `invalid-pass`; add the newline. Text fields (`name`, `owner`,
  `reference`, `operator`, `revoked_reason`) refuse Unicode line or
  paragraph separators and bidirectional controls, as `--note` does. The
  first read of a pass within 250 ms of a write to it waits up to 250 ms
  (2.25 s on file systems that keep whole seconds).
- **New pass key and ledger line.** An older hallpass refuses a pass with
  `overlap_acknowledged` (unknown key), and reports `ledger-corrupt` on a
  ledger with a `reconcile-references` line. Both fail closed.
- **JSON values:** `reconcile` `differences[].expected` and `recorded` are
  numbers for `charge.<counter>` and `targets.count` (they were strings).
  `error.recording` is `not-recorded`, not null, for every `usage` error and
  for every error of a command that never appends to a ledger.
- **Usage:** `--json` together with a non-JSON `--format` is a usage error
  (exit 1); it used to output JSON silently.
- **Messages:** `ledger-elsewhere` is several short lines in text, with each
  path once; JSON `error.message` holds the same lines joined. Scripts that
  matched the old wording break.

- **Audits without `--allowed-signers` are never `complete`.** Anyone who can
  write the archive can write a signature record, so `audit-receipts` and
  `audit-charges` no longer trust one they did not check: a recorded signature
  reads as `signature-recorded` with a `signature-not-reverified` gap, and the
  audit exits 2. Run the audits with `--allowed-signers FILE`. The unreleased
  provenance value `signature-verified` now means only that this audit
  verified the signature again; `archive` and `verify-approval` report
  `signature-recorded`, and the library's `Provenance::SignatureVerified` is
  renamed `SignatureRecorded`.
- **`verify-approval`** with an ssh-keygen that prints its usage text now
  exits 1 with an error, not 2 with `untrusted-key`.
- **Shared pass directories:** `spend`, `adopt` and `reconcile-references`
  refuse with the new error `shared-directory` (nothing recorded) when the
  directory that holds the pass is writable by any user and lacks the sticky
  bit. There another user could put the operator's own older, wider revision
  back over the pass, and the owner and mode checks would accept it. Fix with
  `chmod o-w DIR`, or `chmod +t DIR` if the directory must stay shared.
- **Unicode format characters:** a pass whose `name`, `owner`, `reference`,
  `operator`, `revoked_reason` or `hostname` holds a Unicode format character
  (zero-width characters, BOM, soft hyphen, interlinear annotation, tag
  characters and the rest of category Cf) no longer loads, and the problem
  names the character. New caller references also refuse leading and trailing
  spaces. New notes, adoption and reconciliation reasons and reference lists
  refuse format characters too, also through the library. Ledgers written
  earlier still read, and `receipt` and `reconcile` still find their
  references.
- **`diff --containment`:** when NEW is revoked or its window does not cover
  the instant, the endpoint result is `contained` (reason
  `new-admits-nothing`), so a pure revocation exits 0. Other loosenings still
  make the overall verdict `widened`. The reason `both-windows-must-be-open`
  is replaced by `new-admits-nothing` and `old-closed-new-open`.

- **Invisible characters and look-alike spaces:** a pass whose text fields
  hold a default-ignorable character (for example U+034F, the Hangul fillers
  U+115F, U+1160, U+3164 and U+FFA0, variation selectors, and the reserved
  U+2065, U+FFF0–FFF8 and U+E0000–E0FFF) or a space other than U+0020 (U+00A0,
  U+1680, U+2000–200A, U+202F, U+205F, U+3000) no longer loads; `check` names
  the field and the character. New caller references, notes, adoption and
  reconciliation reasons and reference lists refuse the same characters.
  Ledgers written earlier still read, and their references can still be looked
  up.
- **`approval-id`** refuses an owner or reference that a pass could not hold:
  empty, over 200 characters, surrounding spaces, or any character a pass
  refuses. It is a usage error (exit 1) with `problems` as in `check`, and no
  id is printed. Library: `review::approval_id` returns `Result<String,
  Vec<Problem>>`.
- **Signature verification works on the bytes read:**
  `audit-receipts`/`audit-charges --allowed-signers` and `verify-approval`
  read the signature and the trusted signers file once and give `ssh-keygen`
  private copies in a new 0700 directory under `TMPDIR`, so they need a
  writable `TMPDIR`. A file that changes during verification is no longer an
  error; the result describes the bytes read, and `verify-approval --archive`
  records exactly those. `verify-approval` refuses a signature over 64 KiB.
  Library: `evidence::SignatureToCheck::signature` is the signature's bytes,
  not a path, and `Reverify::check` runs after the ledger lock is released,
  once per digest in order of first use.
- **Message quoting:** messages put caller-, pass- and archive-supplied values
  in as quoted values: the principal in `verify-approval` text, witness and
  state-directory paths, the revoked reason in the revoked-pass refusal, pass
  labels in problem messages and scenario step ids. Scripts that matched the
  old wording break; JSON keys are unchanged.

- **Audits need `--principal` to be `complete`.** With `--allowed-signers` but
  no `--principal`, an audit still verifies every signature but records a
  `signer-not-pinned` gap naming each record's principal, and exits 2: the
  signers file decides whose keys count, `--principal` decides who must have
  approved. `--principal` is repeatable. JSON `signatures.principal` is now
  `signatures.principals` (a list); library `Reverify.principals` and
  `Reverify.as_of`.
- **Audits verify signatures as of each revision's first use** in the ledger
  (`-Overify-time`), not now: a key that expired after first use still
  verifies, and one not yet valid then is rejected. A key outside its validity
  window is reported as `key-not-valid-at-time`, not `untrusted-key`. Audits
  need an ssh-keygen that accepts `-O verify-time`.
- **Hidden characters anywhere in a pass file:** comments, keys and whitespace
  refuse the characters text fields refuse, and every control character other
  than tab and a line end (LF or CRLF); a leading byte order mark too. The
  problem gives line, column and character. Delete it and get the pass
  re-approved.
- **Labels and ports:** labels that differ only in letter case are refused,
  and so is a port listed twice in one destination (`[443, 443]`, `[80,
  "1-1024"]`).
- **File inputs:** every file input (case suite, checkpoint, manifest,
  reference list, signature, allowed-signers file) is opened like a pass: a
  symbolic link is refused with `symlink`, and a FIFO, device or directory
  with `not-regular-file`. compare-backups refuses the whole command for such
  a candidate.
- **Containment counterexamples** are chosen one per widened class, so the
  list can change, and `more_counterexamples` now means some widened class has
  no counterexample listed or a limit was reached.
- **Wording and fields:** `lint`'s first line is `N advisory finding(s) and M
  warning(s) for ID`; the backwards-clock, `lock-timeout`, charge,
  adopt-preview and ledger-damage messages are reworded. Library:
  `Error::LedgerCorrupt.complete`, `LockWait.shared`,
  `review::LintReport.port_findings`.

- **Test-clock ledger lines are marked, and never mix with live lines.** A
  line written under `HALLPASS_UNSAFE_TEST_CLOCK` carries `"test_clock":true`
  in the hash chain; a hallpass from before this change refuses such a ledger
  as `ledger-corrupt`. Writing a test-clock line to a ledger with real-clock
  lines, or the reverse, is refused with the new code `ledger-clock-mix`
  (previews included). Audits report each marked line as `test-clock-entry`
  and a line dated more than 5 minutes after the audit's clock as
  `entry-in-future`, so neither is ever `complete`. `ledger` and `receipt`
  JSON gain `test_clock` fields, and `ledger` gains `test_clock_from`.
  Library: `test_clock` on `LedgerEntry`, `LedgerDebit`, `Adoption` and
  `ReferenceReconciliation`; `test_clock_from` on `LedgerView`.
- `verify-approval --archive` exits 2 with `provenance`
  `signature-not-stored` when the archive already held a record of a
  different principal, so this signature was not stored. A second signature
  by the same principal is still exit 0, `signature-recorded`.
- The reference caller's `handoff` exits 2 when the pass on disk differs from
  the last pinned digest.
- Clap value errors (for example `--n 1.5`) print in the usual
  `hallpass CMD: error:` format with "Nothing was permitted."; the exit status
  stays 1. `verify-checkpoint` text says "later entries", not "later lines".
  The batch ceiling refusal no longer repeats "Nothing was recorded".
  Library: `LockWait.give_up_in`.

- **Witness totals are checked.** A witness whose totals differ from the
  verified ledger at the witnessed sequence is damaged: `witness-unavailable`
  for spend, adopt and audits, and `not-checked` with a warning for status,
  permits and ledger. Proven damage is remembered in `<id>.witness-damage`, and
  `adopt` refuses to carry totals from that witness unless
  `--carry-noted-totals` is given. The witness format is unchanged.
- A failed ledger write that hallpass rolls back gives the new code
  `ledger-append-failed` with `recording: not-recorded` (it used to be
  `ledger-append-uncertain`); resubmitting the same unit is safe. The
  `ledger-corrupt` advice for a cut-short last line names `hallpass repair`
  instead of asking for a hand edit.
- CLI amounts and other numeric flags (`--n`, `--charge`, `--duration`,
  `--lock-timeout-ms`, `--tail`, `--since`, `--adoption`) refuse a leading
  zero. `diff --containment` calls a changed `approval.reference` `widened`.
- In a release build, an ignored `HALLPASS_UNSAFE_TEST_CLOCK` is a JSON
  `warnings` entry on every command. The reference and minimal callers under
  `--rehearsal` refuse a hallpass that ignores the test clock, and a live
  caller refuses one that reports a test clock.
- The reference caller matches journal records by pass ID, not by the path as
  typed; `reconcile-references` records carry `pass_id`.
- The `ledger-elsewhere` advice says to replace the live pass file by `mv`.
  Library: `AdoptPreview.from_note` (a new public field).

- A new caller reference must be printable ASCII. References holding any
  other character (accented letters, Cyrillic lookalikes, Unicode hyphens) are
  refused by `spend`, batches, library requests and `reconcile-references`; a
  ledger that already holds such references still reads, finds them with
  `receipt` and reconciles them.
- A repeated `--format` or `--json` is a usage error; the last one no longer
  wins silently.

- **`diff --containment` proves the endpoints for every instant.** The
  destination rules are compared whatever `--at` is, and the window and
  revocation are judged as their own loosenings. A revision whose rules widen
  is `expanded` (exit 2) even when `--at` is outside NEW's window; it used to
  be `contained`. `containment.reason` `new-admits-nothing` now means only that
  NEW is revoked, `old-closed-new-open` is no longer given, and the text line
  reads `Endpoint scope at every instant:`. New field `containment.replayed_at`.
- When hallpass cannot write its reply it exits 1 (or keeps its own status 2)
  instead of panicking with exit 101, and says on stderr whether anything was
  recorded. The reference decoder maps exit 1 with an empty stdout to
  `reconcile`. A closed pipe on a read-only command is silent.
- Archive damage (an archived entry that no longer matches its digest, or a
  damaged signature record) reports `archive-corrupt` instead of `usage`.

- A copy of a pass whose witness lags an intact ledger (after a spend killed
  between its append and its witness update, or spends from a second state
  directory) is `ledger-elsewhere`, with the live ledger's totals; it used to
  be `ledger-missing`. `adopt` and `adopt --preview` refuse it, and also refuse
  a `ledger-changed` copy while the ledger the witness last saw is intact.
  They refuse while that ledger is a link, not private or unreadable, until it
  is fixed. `ElsewhereLedger.seq` and `.totals` are the live ledger's; new
  fields `witness_seq`, `expected_exists`, `AdoptPreview.last_seen_unchecked`.
- A pass with `-0` or a quoted single port (`ports = "443"`) no longer loads.
  Write `0` or `443`; quoted strings are for ranges such as `"8000-8100"`.

### Added

- `hallpass doctor FILE [--archive DIR]`: a read-only diagnosis of a pass,
  its ledger, witness and state. It gives `healthy` / `needs-action` /
  `blocked`, the `problem` code a spend would fail with, exactly one `next`
  command with real paths, and `findings`. It never names `adopt` while the
  ledger may be intact. Library: `StateDir::read_only()`,
  `LedgerView::check_clock_kind()`.
- A pass whose modification time is in the future gives a warning in `spend`,
  `permits` and `status`.

- Library: `spend_charges_batch`, `spend_charges_batch_in`,
  `spend_charges_batch_with_clock_in`, `SpendChargesBatchRequest`,
  `SpendChargesBatchOutcome`, `SpendChargesBatchUnitOutcome` and
  `MAX_DEBIT_BATCH_UNITS`. They decide 1 to 1024 distinct guarded
  caller-reference debits of one unit each under one lock and commit them as
  one all-or-none ledger line, with one optional retained target and a unique
  logical sequence and receipt per unit.

- A warning when a debit checks no destination: an allowed or previewed
  `spend` without `--to`, on a pass without `require_target_v1`.
- A warning in `check` and `status` for each name-restriction overlap that
  `lint` reports, also listed in the new `name_restriction_overlaps` field.
  The pass stays valid and `check` still exits 0.
- `checkpoint` JSON has a `witness` object with `relation` (`matches`,
  `lags` or `absent`), `witnessed_seq` and `exported_seq`. Only `lags` and
  `absent` add a warning. Before, every export had a warning.
- `reconcile` rows have a `differences` list of `{sequence, field,
  expected, recorded}`.
- `test-pass --strength` reports ceiling changes and mutations that would
  not validate as `skipped`, with a `reason`, and counts them in
  `mutations_skipped`.
- docs/WALKTHROUGH.md, a runnable first-shift walkthrough for new
  operators, checked by `tests/walkthrough.rs`.
- docs/reference-caller/, a complete caller that journals each unit,
  gates its callback with `inspect_reply`, and reconciles interrupted
  units by reference without repeating them. `tests/reference_caller.rs`
  runs it.
- Library: `export_checkpoint_observed`, `CheckpointExport`,
  `WitnessRelation`, `review::name_overlap_warnings` and
  `review::NameOverlapWarning`.
- `diff` prints what an introduced or removed destination grants (address
  or network, protocol, ports, names or any name) with `[review required]`,
  and warns when a new destination makes another destination's `names` list
  have no effect. JSON adds `introduced_grants`, `removed_grants` and
  `name_restriction_overlaps`.
- `status` and `ledger` flag a counter spent past a lowered ceiling (`OVER
  by N`); JSON adds `over_ceiling` and `over_by`.
- A spend that waits more than about 2 s for the writer lock says so on
  stderr, naming the holder process where the system allows. stdout stays
  one JSON object.
- `verify-checkpoint` JSON has `relation`, with the words `compare-backups`
  uses; an older copy reads `shorter`.
- `verify-approval` says why a signature failed: JSON adds `reason`
  (`wrong-namespace`, `bytes-do-not-match`, `malformed-signature`,
  `untrusted-key`, `wrong-principal` or `unknown`) and `next_step`. The
  result and exit code are unchanged.
- A `ledger-corrupt` error has `error.last_line`.
- `adopt --preview` and `adopt` warn when the adoption makes later
  `--require-new-ref` spends `reference-inconclusive`. Library:
  `Error::LedgerElsewhere`, `ElsewhereLedger` and
  `makes_references_inconclusive()` on `AdoptPreview` and `Adoption`.
- A relative `XDG_STATE_HOME`, which is ignored, gives a warning that names
  the directory used instead.
- The reference caller's `handoff` takes `--ref-prefix`, `--since` and
  `--all`.
- docs/INTEGRATING.md "Cost per call and batching": when one spend per unit
  is fine, when to batch, and when to split an engagement across passes.

- `diff --containment` reports `containment.loosenings` and prints
  `Loosened:` and `Overall verdict:` lines.
- Signature provenance in the archive. `verify-approval --archive` keeps
  `DIGEST.sig` and a `DIGEST.approval` record (principal, namespace, trust
  file and signature digests) beside the bytes, after reading the signature
  and trust file before and after verification. `archive` never adds or
  upgrades a record. Both audits gain `revisions` (each digest used, its
  sequences and provenance) and an `approval-unverified` gap. Gaps gain
  `digests`, endpoint details gain `provenance`, and `archive` and
  `verify-approval` replies gain `provenance` and `approval`.
  docs/EVIDENCE.md says what an audit proves and gives the
  `ssh-keygen -Y verify` command for an independent check.
- `hallpass reconcile-references FILE --adoption SEQ --references LIST
  --reason TEXT` records the caller references that may be in lines a lossy
  adoption lost. Guarded spends then refuse those references as
  `duplicate-reference` (with `reference_evidence.reconciled_at`) and accept
  new ones. Before this step they stay `reference-inconclusive`, and a later
  lossy adoption needs its own reconciliation. `ledger` JSON gains
  `reference_reconciliations`, `unreconciled_adoption` and
  `adoptions[].may_have_lost_references`; `receipt` and `reconcile` rows gain
  `reconciled_at`. The reference caller has a matching `reconcile-references`
  subcommand, and `handoff` reports `reconciled` verdicts.
- `overlap_acknowledged = ["LABEL"]` on a destination with `names`
  acknowledges its overlap with one nameless destination. `status` then shows
  a one-line note instead of the warning, and `check`, `lint` and `diff`
  still show it in full. It never changes a decision. An acknowledgement
  that matches no overlap gives the warning
  `overlap-acknowledgement-unmatched`.
- `hallpass retrieve DIR DIGEST --output FILE` writes the file with mode
  0600, whatever the umask, and refuses an existing file or link.
- docs/minimal-caller/minimal_caller.py, a short integrator (preflight,
  spend before the work, strict reply check) that a test runs.

- `audit-receipts` and `audit-charges --allowed-signers FILE` (and optional
  `--principal`) verify each recorded signature again with `ssh-keygen -Y
  verify` over the archived bytes, once per digest. A rejection is a
  `signature-rejected` gap whose `reason` says why (`bytes-do-not-match`,
  `untrusted-key`, `wrong-principal`, `malformed-signature`,
  `wrong-namespace`). Both audits gain a top-level `signatures` object and
  `revisions.details[].reason`. docs/EVIDENCE.md shows how to move a rejected
  record aside and record a new one. Library: `audit_receipts_with`,
  `audit_charges_with` and the `Reverify` hook.
- Window warnings in `check`, `status` and `lint`: a window longer than 90
  days (`window-too-long`), one that has ended (`window-ended`) and one that
  opens more than 30 days ahead (`window-starts-far-ahead`), in
  `window_warnings` and `warnings`; exit codes are unchanged. `check` now
  reads the clock and adds `now` and `test_clock`; `diff` adds
  `new_window_warnings`.
- Warnings for a pass directory without the sticky bit: every command warns
  when it is group-writable, and the read-only commands (`check`, `status`,
  `ledger`, `permits`, `spend --dry-run`, `adopt --preview`) warn when it is
  world-writable.
- `hallpass::display_quoted`, which quotes a value for text output and escapes
  it once.
- docs/WALKTHROUGH.md step 9 hands a pass to another account: copy the
  journal, outbox, pass and archive, move the ledger, then `adopt` on the new
  account. A copy would be a second budget; the old account is refused because
  its witness remembers the ledger. INTEGRATING.md and the reference caller
  README link to it.

- `--lock-timeout-ms` on every command that takes the ledger lock, and a
  notice naming the holding process when a read waits more than 2 s. Library:
  `with_lock_wait`, `open_input`.
- Audits: `--signatures-as-of first-use|now`, per-revision `first_time`,
  `verify_time` and `verified_for`, `signatures.as_of`, and a
  `revision-unparsable` gap (with `problems` and `problem_count`) for an
  archived revision that breaks a pass rule added after it was archived.
  `verify-approval --at TIME`.
- `diff --examples` and `--containment` first try each address where a new
  nameless destination overlaps a names-restricted one, unnamed and with an
  unlisted name, marked `bypasses_names_of`. When the digests differ and no
  declared field does, `diff` says so, names the kind of change (`comments`,
  `layout`, `value-spelling`) and lists comments added and removed. Library:
  `review::text_changes`.
- `lint` gives a `wide-port-grant` finding for more than 1,024 ports or every
  port. `approval-id`, `check` and `lint` warn when the owner or reference
  holds a combining mark or a run of spaces, because the id depends on the
  exact characters.
- The reference caller's `pin --require-signature PRINCIPAL --allowed-signers
  FILE` verifies the signature itself and pins only a digest `verify-approval`
  and `archive` agree on. The minimal caller reads `HALLPASS_REVIEWED_DIGEST`.
  INTEGRATING.md shows the signed workflow end to end.
- `--json` is listed in `hallpass help` and every `<command> --help`.

- Library: `with_test_clock`, which marks the ledger lines written inside it
  as test-clock lines.

- `hallpass repair FILE --drop-torn-tail` (`--preview`, then `--token`), and in
  Rust `preview_drop_torn_tail`, `drop_torn_tail` and `TornTail`. It removes a
  cut-short last ledger line only when the witness proves the line was never
  counted, and keeps the removed bytes in `LEDGER.torn-N`.
- `adopt --carry-noted-totals`, which carries per counter the higher of the
  witness total and the verified total noted when the witness was found
  damaged; `preview_adopt_with`, `adopt_guarded_with`, and `from_note` in adopt
  results.
- A warning when a pass file is changed in place since the last `spend`,
  `permits` or `status` (`StateDir::observe_pass_file`, note `<id>.pass-file`).
- Spend and `capacity` warn when the ledger has spend on a counter the pass no
  longer has. `check` and `lint` warn when a destination repeats another.
- `adopt --preview` warns that carried totals come from the witness alone;
  `compare-backups` warns about a witness whose totals differ from a
  candidate.

### Changed

- `check` text names the counters required on every debit, or says none are
  required. Its JSON includes `required_counters` as a sorted array.
- An atomic batch ceiling refusal distinguishes the durable balance from its
  prospective units: it reports the actual pre-batch spend, full-batch
  projection, first refused unit and that zero batch units committed.
- Reconcile manifest errors name the row, `caller_ref`, field and escaped
  value, and the canonical form where one exists.
- The `lock-timeout` message says what to do next and that a crashed
  holder releases the lock on its own.
- A `ledger-corrupt` chain break names both lines. The advice to remove a
  cut-short final line appears only for the last line; damage before the
  end of the file gets advice to restore a backup found with
  `compare-backups`.
- Time left reads "less than 1 s" for a part second in an open window, and
  time until the window opens rounds up.
- The no-witness warning no longer says that the next spend records a
  witness: only an allowed spend does.
- Address and file error messages end with a next step.
- docs/spec.md describes parser failures as they behave, PASS-FORMAT.md
  says `hostname` must be a DNS name, `required_counters_v1` is explained
  as applying to every debit, and playpen is introduced where it is first
  mentioned.
- `ledger` takes `--tail N` and `--since SEQ` to show only recent
  entries, with a `shown` marker in text and JSON. The whole chain is still
  verified, and totals cover the whole ledger.
- `diff --containment` reports up to 8 counterexamples
  (`containment.counterexamples`, `more_counterexamples`);
  `containment.example` is kept. `diff --examples` lists newly allowed
  changes first, tags each row with `change`, and counts refusal-code-only
  changes (`refusal_code_changes`); `--refusal-changes` lists them.
- The reference caller takes each target's canonical spelling from
  `hallpass permits` before it journals an intent. An upper-case or
  uncompressed IPv6 target, or a name with a trailing dot, no longer ends in
  an unknown outcome and a failed handoff.
- The `window-too-short` refusal says the work would end at or after the
  window closes, matching the exclusive `valid_until`.
- A numeric IPv4 spelling with a `0x` part is named as non-standard IPv4,
  not as a host name. A ledger mode error gives ledger advice. Error
  messages end with a full stop.
- `audit-receipts`, `audit-charges`, `reconcile`, `compare-backups`, the
  `test-pass --strength` report and the receipt line of `spend` print
  readable text instead of JSON fragments. `receipt` prints times as
  `YYYY-MM-DDTHH:MM:SSZ`.
- A text-mode error ends with "Nothing was permitted." only for `spend`,
  `permits`, `check`, `rehearse`, `capacity` and `status`.
- A host name in `--to` gets advice for a query: resolve it, ask about the
  literal address, and give the name with `--name`. A host name in a pass
  gets advice for the file. The `Display` text of `AddressError::Hostname`
  no longer carries advice.
- A duplicate destination label is reported even when either destination
  has other problems.
- `diff --at now` is refused with a message that asks for an RFC 3339
  timestamp.
- Each call still verifies every ledger line, but about 3x faster: at
  10,000 lines a `permits` or `spend` call takes about 5 ms instead of
  about 16 ms. docs/DESIGN.md ("Cost per call") gives the measured costs,
  a practical ledger size and when to batch with `--n`.
  `tests/ledger_scale.rs` (ignored by default) measures them.
- Ledger lines whose notes or caller references hold non-ASCII text,
  quotation marks or backslashes are read directly instead of through
  `serde_json`, and every line reads faster. Each call still verifies every
  line. A call on receipt-bearing debits costs about 40% less: about 60 ms
  instead of 100 ms at 100,000 lines (49 MB). docs/DESIGN.md ("Cost per
  call") now gives the cost as about 1.2 ms per MB of ledger.
- docs/spec.md and docs/INTEGRATING.md are reorganized, and the spec's
  lists of refusal codes, error codes, commands and JSON fields are
  current.
- A pass that changed while hallpass read it is refused as `invalid-pass`,
  so a save in progress (truncate, then write in pieces) can no longer be
  read as a valid but wider prefix. A file modified in the last 250 ms is
  read again once 250 ms have passed and must be unchanged. In the
  evaluator's scenario, unnamed spends allowed fell from 72 of 278 to 0. A
  writer that pauses longer than 250 ms in the middle of a save is still a
  risk; pinning the digest closes it. The docs now say to replace a pass by
  writing `pass.toml.new`, running `chmod 600` and moving it over the old
  file, and the walkthrough does so.
- With no `--lock-timeout-ms`, waiting for the writer lock uses the
  blocking lock again, and the wait notice comes from a timer thread.
  Polling every 20 ms had made waits unfair: with 8 writers at 100,000
  lines, p99 falls from 3.7 s to 0.6 s at the same throughput.
  docs/DESIGN.md gives the numbers and advice on choosing
  `--lock-timeout-ms`.
- Recovery messages. Each cause of `witness-unavailable` gets only its own
  next step. The no-witness warning says correctly which spends record a
  witness. `adopt --token` says whether the token is malformed or stale,
  and to run `--preview` again.
- A negative or malformed `--n` says "N must be a positive integer".
  `capacity` refusals no longer say "Nothing was recorded". `audit-receipts`
  text times are whole seconds. The `ledger` text's last column is
  `details`, with labelled `receipt:` and `note:` parts.
- docs/WALKTHROUGH.md says which build it needs and how to run it live with
  a release binary. The docs show `--record-target` wherever audit evidence
  is wanted. `spend --to` still records no target by default, because a
  conforming wrapper refuses a reply that has a receipt it did not request.
- **Fixed:** `spend` and `ledger` text escaped a caller reference twice, so a
  crafted reference could read as an extra, out-of-scope receipt target;
  `receipt`, `archive` and the audits doubled backslashes. Text output now
  quotes each value once (`\"`, `\\`, `\u{…}`) and escapes every Unicode
  format character. Refusals name the character, for example U+200B.
- `status` on an over-ceiling ledger says more is spent than the ceiling
  allows and gives a lowered ceiling only as one possible cause. A pass or
  ledger path that is not a regular file gets advice for both. Evidence
  reports print each warning once. The missing-ledger refusal tells an account
  whose ledger was moved away on purpose not to adopt or spend. An empty name
  after `@` in `--to` says how to fix it. `docs/conformance/check.py` prints
  one line, "N cases passed". The minimal caller and the tests no longer write
  Python bytecode into the docs tree.
- The cost-per-call figures in INTEGRATING.md and DESIGN.md are measured on an
  ext4 NVMe disk: a spend takes about 15 ms, mostly fsync, so one process does
  about 60 a second; 8 writers do 62–71 a second on a small ledger and 12–13
  at 100,000 lines. The tmpfs figures are labelled as such, and the batching
  advice matches.
- **Fixed:** warnings, `REFUSED:` lines and `verify-approval` text no longer
  double backslashes that are already escapes (a principal `ops\lead` showed
  as `"ops\\\\lead"`). Messages are printed with control, separator, bidi,
  format and invisible characters escaped and their own backslashes left
  alone; spec.md states the rule.
- **Fixed:** a signature or trusted signers file swapped out and back during
  verification could make `ssh-keygen` check other bytes than the record
  names. Verification now uses private copies of the bytes read.
- With `--allowed-signers`, the audits run `ssh-keygen` after they release the
  shared ledger lock, so `spend` and `adopt` no longer wait for one
  `ssh-keygen` per digest.
- Text output escapes default-ignorable characters and non-ASCII spaces as
  `\u{…}`, messages included. A caller reference that starts or ends with a
  non-ASCII space is refused as containing "a look-alike space (U+…)".
- spec.md's library table lists the audit API (`audit_*_with`, `Reverify`,
  `SignatureToCheck`, `Recheck`, `SignatureCheck`), and its test-clock list
  includes `check`; tests/doc_lists.rs keeps that list in step with the code.
- **Fixed:** the documented audit CI gate accepted a widening that the
  operator signed with their own trusted key; audits broke once the owner's
  key expired and called it untrusted; an archived revision that broke a newer
  pass rule stopped an audit with advice to edit archived bytes.
- **Fixed:** read-only commands waited silently, without limit, on a held
  ledger lock; a FIFO argument hung `test-pass` and `verify-checkpoint`; the
  backwards-clock warning stopped after one spend (it now compares with the
  latest recorded time, and `permits` warns too).
- **Fixed:** a bidi override or zero-width character in a pass comment passed
  `check`; review examples never showed the address where a new destination
  bypasses a names list; `lint` said "0 advisory finding(s)" while printing a
  window warning; a doubled full stop in symlink, witness and `REFUSED:`
  messages.
- Charge errors name the charge and give the range (1 to 1000000000000);
  `adopt --preview` says why there is nothing to adopt; a complete but invalid
  ledger line names the field and advises a restore from backup, never
  removal.
- The lock-wait line says when it will give up when `--lock-timeout-ms` is
  set, instead of suggesting the flag; spec.md shows both lines.
- The clock-precedes warning shows sub-second times and the gap when the two
  times differ by under a second, and points callers who sampled `now` before
  the lock to `spend_charges_batch_with_clock_in`. INTEGRATING.md recommends
  that function for concurrent batch callers.
- A known top-level key written under a table says that top-level keys must
  come before the first `[table]` header.
- The `wrong-principal` audit advice and the reference caller's "no signature
  record" refusal say how to recover: move the archive's `DIGEST.sig` and
  `DIGEST.approval` aside, then run `verify-approval --archive` again.
- A debug build under `HALLPASS_UNSAFE_TEST_CLOCK` no longer adds unmarked
  debits to a live ledger, and audits no longer call such debits `complete`
  (bn-2mm).
- `verify-approval --archive` no longer says it retained a signature record
  for a signature it did not store (bn-1re).
- The reference caller's `handoff` no longer says "Nothing needs attention"
  when the pass on disk is not the pinned revision (bn-37z).
- `diff` marks a changed `approval.reference` `[review required]`.
- An integer too large for the TOML reader gets the field's own rule
  (`ceilings.*`, `destination[N].ports`, `format`) instead of "not valid TOML".
- A ledger from before an adoption is called "a different history from
  sequence N", not "an older copy"; `compare-backups --ancestry` leads with its
  conclusion; the adoption reference warning ends with a full stop.
- A one-digit witness edit followed by an adoption could allow an overspend
  (bn-2pm).
- A short write during an append no longer leaves a torn line that blocks
  every later command: the ledger is cut back and synced under the lock
  (bn-2pi).
- The reference caller no longer appends onto a torn journal record, and a
  damaged journal line is refused with its number instead of a traceback
  (bn-ykr). `handoff` no longer says "Nothing needs attention" when the pass
  path is spelled differently (bn-yi9). Rehearsal mode against a release build
  no longer debits live and runs the callback (bn-2kr).
- A file size limit (`ulimit -f`, RLIMIT_FSIZE) no longer kills hallpass with
  SIGXFSZ partway through a ledger line. Before each write, hallpass checks
  that the file stays within the limit and otherwise writes nothing, so a
  spend fails `ledger-append-failed` / `not-recorded` with a reply and an
  unchanged ledger. The check covers new ledgers, the witness and its notes,
  the repair copy, `init` / `retrieve --output`, archive files and the
  signature verifier's scratch files (bn-gr5).
- The reference caller's `handoff` flags a last pin without a signature that
  follows a signed pin for the same pass (bn-1kc).
- README, DESIGN, EVIDENCE and INTEGRATING name whole-machine restores (ledger
  and state directory rolled back together) as a residual risk, and show a
  periodic `checkpoint` kept off the machine plus `verify-checkpoint` after a
  restore (bn-2r2).
- Caller references that look alike are no longer accepted as distinct new
  references (bn-s33).
- An oversized `--n` states the limit (1 to 1000000000000) (bn-27g).
- `diff --containment` no longer certifies a widening revision as `contained`
  when `--at` falls outside the window (bn-3js).
- A recorded debit, adoption, reconciliation, repair or archive whose reply
  cannot be written says on stderr that it IS recorded, with its ledger entry
  and caller reference (bn-1yo).
- The moved-or-copied warning no longer promises that the other copy will be
  refused: a copy with its own witness (another machine, account or state
  directory) stays live until its ledger is moved away. PASS-FORMAT says
  "move" for a machine move. When a counted last line is damaged, the repair
  refusal, the `ledger-corrupt` advice and EVIDENCE name the last resort (move
  the ledger aside and adopt) (bn-2bg).
- Archive damage has its own error code (bn-3jb).
- A lagging witness no longer lets a copy of the pass adopt and spend the
  ceiling a second time (bn-37e).
- A future-dated pass is settled once, before the locks, instead of a second
  time under the writer lock: 8 concurrent spenders went from 10.8 s to 1.4 s
  (bn-134).
- `-0` was accepted although `+0` was refused; a quoted single port was
  accepted though not documented (bn-2ew).
