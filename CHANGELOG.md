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

### Changed

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
