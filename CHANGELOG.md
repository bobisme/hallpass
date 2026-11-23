# Changelog

## Unreleased

Changes since commit d70c09f.

### Compatibility

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

### Added

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

### Changed

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
