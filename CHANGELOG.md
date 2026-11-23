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
- docs/spec.md and docs/INTEGRATING.md are reorganized, and the spec's
  lists of refusal codes, error codes, commands and JSON fields are
  current.
