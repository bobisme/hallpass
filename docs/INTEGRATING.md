# Calling hallpass from another tool

## Review and case suites

Run `hallpass diff OLD NEW` to inspect the changed terms and both byte
digests. Run `hallpass lint NEW` to see where a second destination relaxes a
name restriction.

Try the owner example from the repository root with
`hallpass --format json test-pass docs/review-approval.toml docs/review-suite.toml`.
The suite checks a named allowance, a name refusal and both window boundaries.
Each case supplies an offset timestamp, target, and an expected outcome of
`allowed` or a stable refusal code. The version 1 TOML suite accepts up to
1,024 cases and 256 KiB. Exit 0 means every expectation matched, 2 means a
mismatch, and 1 means invalid input. The report includes the pass digest
and preserves input order. The command reads no accounting state.

## Mapping written approvals and practice runs

Keep the exact written reference in `approval.reference`. For a stable ID,
construct `hp1-` plus the first 52 lowercase hexadecimal characters of
SHA-256 over the namespace `hallpass/approval/v1`, owner identity, and the
exact reference string, separated by NUL bytes. If that ID already belongs to
different owner/reference material, append `-2`, `-3`, and so on. Revisions of
the same approval retain the ID; a different owner or reference is a new ledger
identity. An approval without a trustworthy start instant is incomplete:
request the actual approval time instead of guessing one.

For example, run `hallpass approval-id --owner "Pat Owner" --reference
"Change 9812 / Voice edge (approved)"` and copy the printed ID into the pass.
Keep the reference exactly as written when revising destinations or ceilings.
If that message omits the start instant, obtain it from the owner before
issuing the pass.

For a loopback practice run, allocate a fresh ID and explicit window and
ceilings for each separately approved start. For example, use `practice-` followed by a new UUIDv4 as the run ID, while retaining the reusable owner reference as
metadata. Persist that ID in the pass and keep the ordinary ledger and witness
locations. A restart in the same run reuses the same pass and ledger; a second
run gets a new ID and budget. Do not copy a pass without its ledger, use a reset
flag, or apply this recipe to routed rehearsals.

This page is for the author of a tool that sends traffic and wants hallpass
to decide whether it may. It covers the command line, the library, what a
"yes" guarantees and what it does not. The rules themselves are in
[spec.md](spec.md), the file format in [PASS-FORMAT.md](PASS-FORMAT.md).

## The one call

Before each unit of work (one call, one request), ask and count in one step:

```text
hallpass --format json spend --to ADDRESS:PORT/PROTOCOL [--name HOSTNAME] [--n N] [--duration SECONDS] [--digest DIGEST] [--note TEXT] -- PASS COUNTER
```

Before sending, require exit 0 and a production `spend` response with
`"result": "allowed"`, `"test_clock": false` and a positive recorded sequence.
Match the pass ID, digest, counter and amount to the request. The reference
decoder below exercises this contract with a callback.

`spend --to` decides the destination, the window, revocation and the
ceiling together, under one lock, against one reading of the pass file. If
any of them refuses, nothing is recorded. Without `--to`, `spend` checks only
the window and the ceiling; the caller must then have asked `permits` for
every destination itself.

| Exit | `result` | Meaning | What the caller does |
|---|---|---|---|
| 0 | `allowed` | recorded; the pass permits this now | send |
| 2 | `refused` | the pass says no; nothing was recorded | do not send; show `refusal.message` to the operator |
| 1 | `error` | invalid input, unavailable evidence or storage failure | stop and show `error.message`. Reconcile a recorded or uncertain append before retrying |
| other | none | hallpass did not run or crashed | do not send |

Every `refusal.message` and `error.message` ends with what to do next. The
`refusal.code` and `error.code` values are stable; the message texts are
for people and may change.

## A worked example

The test `tests/integrating.rs` writes the pass below as
`engagement.pass.toml`, runs every `$ hallpass` line of this section at
2026-11-20T09:00:00Z, and compares the exit code and the fields shown. The
real objects have more fields ([spec.md](spec.md), "JSON output"); a caller
must ignore fields it does not know.

```toml
format = 1
id = "example-2026-11"
name = "Example voice edge"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = [5060, "10000-10100"]

[ceilings]
calls = 2
```

At start, validate the pass and keep its digest. Passing the digest to every
later call makes hallpass refuse if the file changed since the operator
confirmed it.

```console
$ hallpass --format json check -- engagement.pass.toml
exit 0
{"result": "ok", "pass_id": "example-2026-11", "problems": []}
```

Before the first packet of the first call. The call may last two minutes, so
the window must stay open that long:

```console
$ hallpass --format json spend --to 192.0.2.10:5060/udp --duration 120 --note run-0001 -- engagement.pass.toml calls
exit 0
{"result": "allowed", "target": "192.0.2.10:5060/udp", "label": "sip-edge", "counter": "calls", "n": 1, "spent": 1, "total": 2, "remaining": 1, "seq": 1, "refusal": null}
```

The media address of that call is another destination question. It is not
another call, so ask without counting:

```console
$ hallpass --format json permits --to 192.0.2.10:10000/udp --duration 120 -- engagement.pass.toml
exit 0
{"result": "allowed", "label": "sip-edge", "refusal": null}
```

An address the owner did not list is refused, and the count does not move:

```console
$ hallpass --format json spend --to 192.0.2.11:5060/udp -- engagement.pass.toml calls
exit 2
{"result": "refused", "spent": 1, "seq": null, "label": null, "refusal": {"code": "address-not-listed"}}
```

The second call is the last one the owner approved:

```console
$ hallpass --format json spend --to 192.0.2.10:5060/udp -- engagement.pass.toml calls
exit 0
{"result": "allowed", "spent": 2, "remaining": 0, "seq": 2}
$ hallpass --format json spend --to 192.0.2.10:5060/udp -- engagement.pass.toml calls
exit 2
{"result": "refused", "spent": 2, "seq": null, "refusal": {"code": "ceiling-reached"}}
```

A command line that hallpass cannot read is an error object too, never
empty output:

```console
$ hallpass --format json spend --to sip.example.net:5060/udp -- engagement.pass.toml calls
exit 1
{"result": "error", "error": {"code": "usage"}}
$ hallpass --format json spend
exit 1
{"result": "error", "error": {"code": "usage"}}
```

What was counted, for the report:

```console
$ hallpass --format json status -- engagement.pass.toml
exit 0
{"result": "ok", "counters": [{"name": "calls", "total": 2, "spent": 2, "remaining": 0}], "ledger": {"entries": 2, "witness": "matches"}}
```

## Rules for a command-line caller

- **Judge by `result`, then by the exit code; require both.** `--help` or
  `-h` anywhere on the command line prints help and exits 0. Put every
  option first, then `--`, then the pass path and the counter, as above:
  nothing after `--` is read as an option, so a file named `-h` is a file.
  Never build the command line through a shell.
- **Give literal addresses.** hallpass never resolves a name. Resolve the
  name yourself, ask about the address you will connect to, and connect to
  exactly that address. `--name` narrows; it never grants.
- **Ask about every address you send to**: signalling, media (RTP and
  RTCP), redirects, a second address of the same host. One `spend --to` for
  the unit of work, `permits` for each further address.
- **Give `--duration`** the longest time the work can still send, in
  seconds. Without it the answer is for this instant only.
- **Count at first send.** Call `spend` immediately before the first packet
  of each unit, not for a whole plan at the start: hallpass has no way to
  give a spend back. A unit that was counted and then did not send stays
  counted; that errs towards less traffic.
- **Refuse `"test_clock": true`** outside your own tests. Debug builds of
  hallpass honour `HALLPASS_UNSAFE_TEST_CLOCK`; a release build does not
  and always reports `false`. Remove that variable from the environment you
  start hallpass with.
- **Show `warnings`** to the operator. They are not refusals, but they say
  things such as "the ledger was moved" or "the witness could not be
  checked".
- **Keep `HOME` and `XDG_STATE_HOME` stable.** The witness that notices a
  deleted or rolled-back ledger lives in `$XDG_STATE_HOME/hallpass` (or
  `~/.local/state/hallpass`). A caller that runs hallpass in a container or
  with a temporary home gives every run a new witness and loses that
  protection; `spend` then says so in `warnings`.
- **Keep the ledger beside the pass.** `PASS.ledger` is the count. Do not
  copy the pass elsewhere to "start fresh": the witness refuses that
  (`ledger-missing`), and `hallpass adopt` is the recorded way out.
- **`permits`, `status` and `ledger` are read-only and more forgiving than
  `spend`**: when the witness cannot be checked they still answer, with a
  warning and `"witness": "not-checked"`. Only a `spend` is the permission
  to send a counted unit.

## Preflight and follow-up checks

Use `spend --dry-run` with the same arguments as the counted operation. Its
positive result is `would-allow`, with the current balance, a projected
spent value and a null sequence. Another process may consume the balance
immediately. Only a subsequent recorded spend permits the counted operation.
Use `permits --digest DIGEST` for later uncounted destinations in the same
unit so a pass edit requires fresh review.

To check several known destinations together, repeat `--to` up to 64 times.
Attach a name to its endpoint as `--to 192.0.2.10:443/tcp@app.example.org`.
The separate `--name` form takes exactly one target. One refused target
refuses the whole unit and `refused_target` gives its one-based position.
The Rust path is `permits_in` with an ordered slice of `NamedTarget` values.

A spend error with `error.recording = "recorded"` identifies a durable debit
by `error.ledger` and `error.seq`. With `"uncertain"`, the append or sync
failed. Stop and inspect the ledger before deciding whether another spend is
appropriate. Never automatically retry either outcome.

### Test a subprocess wrapper

Run `python3 docs/conformance/check.py` from the checkout. The reference
decoder exercises a callback spy over a versioned JSON corpus. To test your
own wrapper, feed each case's exit status and raw stdout to its normal
decoder and compare the action, callback count and warnings. A null exit
denotes launch failure. Both stop and reconcile must invoke zero callbacks.
The integration suite also supplies real CLI output acquired with the
production clock. [Fixtures](conformance/cases.json) · [Reference decoder](conformance/check.py)

The reference adapter takes `expected` from the caller before invoking
hallpass. It contains the validated pass ID, byte digest, counter name and
positive integer amount under `pass_id`, `digest`, `counter` and `n`.
Pin the command with `--digest` and pass the exact counter and amount
to `spend`. The decoder requires all four response fields to match in
value and JSON type before it calls the send callback. Unknown response fields
remain compatible. The callback spy only counts calls.

This adapter covers scalar `spend PASS COUNTER [--n N]`. A multi-charge caller
should check the same pass identity and digest and validate its complete
requested `charges` array against the response before proceeding.

## Charge all known costs at the first send

Use positional COUNTER with optional --n for a scalar spend, or repeat
--charge COUNTER=N for the named costs of one unit. Each counter may occur
once. In JSON a successful debit has result "allowed", one seq, and a
charges array with counter, n, total, spent and remaining for each charge.
A refusal has result "refused", no sequence, and unchanged balances. Text
output shows the sequence and per-counter balances. The scalar command keeps
its existing JSON fields.

A read-only --dry-run returns "would-allow" when all costs fit at the check,
with current balances, projected_spent per charge and no sequence. An exit status of zero with result
"allowed" and a sequence authorizes that unit. The caller should send
immediately, using the exact destinations and scope it checked. A preview
never reserves capacity. A committed debit stands if the caller crashes
before sending. On ambiguous outcomes, inspect the ledger and avoid blind
retries. A witness-update failure reports the sequence that already synced.

For an isolated run with the debug binary, create a pass and charge it as
shown below. Both subprocesses use the same pass and witness. At most one
can consume the available request and bytes.

~~~sh
set -eu
hallpass_bin=$(command -v hallpass)
work=$(mktemp -d)
trap 'rm -r -- "$work"' EXIT
export HOME="$work/home"
export XDG_STATE_HOME="$work/state"
mkdir -m 700 "$HOME"
export HALLPASS_UNSAFE_TEST_CLOCK=2026-11-20T09:00:00Z
umask 077
pass="$work/example.toml"
cat >"$pass" <<'PASS'
format = 1
id = "multi-charge-example"
name = "Atomic debit example"

[approval]
owner = "Example approval owner"
operator = "Example operator"
reference = "Example approval"
valid_from = 2026-11-20T08:00:00Z
valid_until = 2026-11-20T17:00:00Z
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = 5060
names = ["sip.example.net"]

[[destination]]
label = "web"
network = "2001:db8::/120"
protocol = "tcp"
ports = 443
names = ["edge.example.net"]

[ceilings]
requests = 1
bytes = 100
PASS

digest=$("$hallpass_bin" --format json digest "$pass" | jq -er .digest)
spend() {
    "$hallpass_bin" --format json spend "$pass" \
        --charge requests=1 --charge "bytes=$1" \
        --to 192.0.2.10:5060/udp@sip.example.net \
        --to '[2001:db8::1]:443/tcp@edge.example.net' --digest "$digest" \
        --caller-ref "$2" --record-target
}
# A preview observes the current balances without reserving them.
"$hallpass_bin" --format json spend "$pass" --dry-run \
    --charge requests=1 --charge bytes=100 \
    --to 192.0.2.10:5060/udp@sip.example.net \
    --to '[2001:db8::1]:443/tcp@edge.example.net' \
    | jq -e '.result == "would-allow" and .seq == null'
test ! -e "$pass.ledger"

# This refusal charges neither counter and leaves the initial ledger header.
spend 101 run-81/too-large >"$work/refusal.json" || test "$?" -eq 2
cp "$pass.ledger" "$work/initial.ledger"

spend 100 run-81/unit-a >"$work/a.json" &
a=$!
spend 100 run-81/unit-b >"$work/b.json" &
b=$!
wait "$a" || test "$?" -eq 2
wait "$b" || test "$?" -eq 2

# Store the approved unit's sequence and digest alongside the caller reference.
jq -s -e 'map(select(.result == "allowed")) |
    if length == 1 then .[0] | {ref: .receipt.caller_ref, seq, digest, charges}
    else error("expected exactly one committed debit") end' \
    "$work/a.json" "$work/b.json"
"$hallpass_bin" status "$pass"
"$hallpass_bin" ledger "$pass" --counter bytes

# Deliberately restore the header-only copy to exercise adoption.
cp "$work/initial.ledger" "$pass.ledger"
"$hallpass_bin" adopt "$pass" --reason "restored example ledger"
"$hallpass_bin" ledger "$pass" --counter requests
~~~

The refused 101-byte request spends zero requests and zero bytes. The
successful 100-byte request leaves both counters at zero remaining. After
adoption the ledger records both charges as witness carry-forward. The
caller reference correlates the ledger receipt with a caller-run record.
The caller should include the pass id when references can span passes.
References are correlation data rather than idempotency keys. Before
opting in to --record-target, take into account who can read the ledger
and its exports. The option stores the literal, canonical request name
and matched label for each checked target.

## The library

For Rust callers the same decision is `hallpass::spend` with
`SpendRequest::target` set. Depend on the crate with
`default-features = false` to leave out the command-line parser. The clock
is an argument everywhere: the library never reads it.

```rust,no_run
use std::path::Path;

use hallpass::time::{Duration, OffsetDateTime};
use hallpass::{Digest, Error, SpendRequest, Target};

/// `Ok(None)`: counted, send now. `Ok(Some(why))`: the pass refuses, do not
/// send. `Err`: hallpass could not decide, do not send.
fn may_send_one_call(
    pass_file: &Path,
    confirmed: Digest,
    to: &str,
    longest_call: Duration,
) -> Result<Option<String>, Error> {
    let target: Target = to.parse().map_err(Error::Usage)?;
    let mut request = SpendRequest::new("calls", 1);
    request.target = Some(target);
    request.needed = longest_call;
    request.expect_digest = Some(confirmed);
    let outcome = hallpass::spend_with_clock_in(
        pass_file, &request, &hallpass::StateDir::from_env(), OffsetDateTime::now_utc,
    )?;
    for warning in &outcome.warnings {
        eprintln!("hallpass: {warning}");
    }
    Ok(outcome.refusal.map(|refusal| refusal.to_string()))
}

fn main() -> Result<(), Error> {
    let pass_file = Path::new("engagement.pass.toml");
    // Once, at start: validate, show the operator, keep the digest.
    let loaded = hallpass::load(pass_file)?;
    match may_send_one_call(
        pass_file,
        loaded.digest,
        "192.0.2.10:5060/udp",
        Duration::minutes(2),
    )? {
        None => println!("send"),
        Some(why) => println!("do not send: {why}"),
    }
    Ok(())
}
```

`Pass::permits` and `Pass::permits_named` are pure: they answer for a
`Pass` already in memory and read nothing. Use them for further addresses of
a unit that `spend` has counted, and load the pass again (`hallpass::load`)
when the answer must reflect an edit or a revocation; `spend` always reads
the file again.

## What an "allowed" guarantees

- The pass file validated in full at the moment of the decision: format
  version, every field, no unknown key, private file mode, not a link.
- The window was open at `now` and stays open for `--duration`; the pass
  was not marked revoked; `valid_until` is exclusive.
- The target is one literal address inside a listed destination, with a
  listed port and protocol, and is not the network or broadcast address of
  a listed IPv4 network. An IPv6 address that carries an IPv4 address
  (mapped, NAT64, 6to4, Teredo, ISATAP) is refused.
- When the destination lists `names`, the name given is one of them.
- The spend is in the ledger and on disk, the total was not exceeded, and
  this holds across processes: concurrent callers never together pass a
  ceiling.
- The ledger's hash chain verified, and the ledger agrees with the witness
  of this user on this machine.
- With `--digest`: the pass is byte for byte the one the digest was taken
  from.

## What it does not guarantee

- **That the packet goes where hallpass was asked about.** hallpass decides;
  it does not send or filter. The caller must send to exactly the address
  it asked about. playpen enforces a pass at the network level; hallpass
  alone does not.
- **That the approval is real.** A pass is a file the operator wrote.
  hallpass checks that it is complete and unambiguous, not that the owner
  agreed.
- **A correct clock.** The window is checked against the caller's clock. A
  spend warns if the decision instant precedes the most recent entry. An incorrect clock can still make the window appear open.
- **Protection from the operator's own account.** The ledger and the
  witness belong to the same user; someone who deletes both starts from
  zero. The witness catches accidents (a copied pass, a cleaned directory,
  a restored backup), not intent.
- **A count across machines or users.** Each user on each machine has its
  own witness; a pass and ledger copied to a second machine is accepted
  there with a warning on its first spend.
- **That a counted unit was sent.** A debit records admission for one unit.
  When you opt in to a receipt, it can also record a caller reference and
  the targets checked. Keep the returned `seq` and digest with your own run record.
- **Time after the decision.** The CLI samples its spend clock under the writer locks after preparatory witness writes and immediately before evaluating policy. Status, permits and spend previews sample after evidence verification. Time between return and the end of work must still fit the approved window. Rust callers using explicit-time `spend_in` supply their own decision instant.

## Reservations

A recorded spend is final under the current accounting rules. Complete local
preparation before spending and request the debit immediately before the first
send. If the process crashes after the debit, include that unit in the recorded
total. The approval-owner decision about introducing reservations and releases
is tracked in `bn-34a`.
