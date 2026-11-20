# Calling hallpass from another tool

This page is for the author of a tool that sends traffic and wants hallpass
to decide whether it may. It covers the command line, the library, what a
"yes" guarantees and what it does not. The rules themselves are in
[spec.md](spec.md), the file format in [PASS-FORMAT.md](PASS-FORMAT.md).

## The one call

Before each unit of work (one call, one request), ask and count in one step:

```text
hallpass --format json spend --to ADDRESS:PORT/PROTOCOL [--name HOSTNAME] [--n N] [--duration SECONDS] [--digest DIGEST] [--note TEXT] -- PASS COUNTER
```

Send only if the exit code is 0 **and** the JSON object on standard output
has `"result": "allowed"`. Anything else means: do not send.

`spend --to` decides the destination, the window, revocation and the
ceiling together, under one lock, against one reading of the pass file. If
any of them refuses, nothing is recorded. Without `--to`, `spend` checks only
the window and the ceiling; the caller must then have asked `permits` for
every destination itself.

| Exit | `result` | Meaning | What the caller does |
|---|---|---|---|
| 0 | `allowed` | recorded; the pass permits this now | send |
| 2 | `refused` | the pass says no; nothing was recorded | do not send; show `refusal.message` to the operator |
| 1 | `error` | hallpass could not decide (invalid pass, damaged ledger, unusable state directory, bad arguments) | do not send; show `error.message` |
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
- **That a counted unit was sent**, or that an entry says what it paid for:
  the ledger holds counter, amount, time, pass digest and the note, not the
  target. Put your own run reference in `--note` and keep the returned
  `seq`.
- **Time after the decision.** The CLI samples its spend clock under the writer locks. Time between return and the end of work must still fit the approved window. Rust callers using explicit-time `spend_in` supply their own decision instant.

## Not offered yet

These are needs of known callers that hallpass does not meet; each is a
bone in this repository (`bn list`):

- giving back a spend whose traffic never left (reserve, then release);
- practice passes whose id is reused in many directories;
- the target and a caller reference in the ledger entry;
- a limit on the total breadth of all destinations together.
