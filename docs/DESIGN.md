# Design decisions

hallpass is the protocol-neutral part of an earlier assessment toolbox's
safety model: nothing is sent unless the owner approved it in writing, to
literal addresses, inside a time window, under ceilings. That toolbox kept
the rules inside its SIP code and had one known gap: its ceilings counted
per process, so a ceiling of 6 calls held within one command but not across
six commands. hallpass closes that gap with the ledger.

## Shape

- **Library first, CLI second.** Rust tools call the library; other tools
  call `hallpass ... --format json`. The CLI is a thin layer over the same
  library calls. The CLI uses `permits_with_clock_in` to verify the ledger
  and witness before sampling the decision instant. Library clients can use
  the same entry point.
- **Pure decisions and live decisions.** `Pass::window_at`,
  `Pass::check_window` and `Pass::permits` evaluate caller-supplied data and
  time. Ledger-aware APIs handle local files and accept an explicit state
  directory. Writers evaluate live policy under the accounting locks.
- **Validated inputs.** Construct a pass with `load` and use the public
  address and target parsers. Library-produced structs such as `Pass` are
  `#[non_exhaustive]`.

## Validation

- The pass is parsed into a generic TOML table and walked by hand, not
  deserialized with serde's `deny_unknown_fields`. Serde stops at the first
  error; the walk reports every problem at once, each with its field path,
  which is what an operator filling in a pass needs.
- Every free-text field is one printable line, so nothing an operator
  writes can break a log line or the text output.
- Timestamps need an explicit offset. A local time would mean different
  instants on different machines.
- `valid_from` is inclusive and `valid_until` exclusive. At `valid_until`
  the pass is already expired.
- `revoked` is required (`false` must be written). A missing marker is a
  problem, not a silent "not revoked".

## Addresses

- One spelling per address (the canonical one). This is the earlier
  toolbox's rule (`str(ip_address(a)) == a`) applied to IPv6 too. It is
  stricter than needed for safety, but it means the reviewer and the tool
  read the same text.
- The standard library's IPv4 parser already refuses leading zeros and
  shortened forms; hallpass detects them first so the message says why.
- IPv6 forms that carry IPv4 (mapped, compatible, NAT64) are refused in a
  pass and refused in a `permits` query (`embedded-ipv4`). On a dual-stack
  socket, `::ffff:192.0.2.1` is 192.0.2.1; a list read only as IPv6 would
  miss that. The caller must ask with the IPv4 address.
- **Transition forms** are refused the same way (pass: an address problem
  naming the mechanism and the IPv4 address; query: `embedded-ipv4`). Each
  can carry traffic over IPv4 to an address the IPv6 list does not show,
  or broaden an approval to whatever sits behind a relay:
  - 6to4 `2002::/16`: tunnelled to the IPv4 router in bits 16-47;
  - Teredo `2001::/32`: tunnelled in UDP to the client's public IPv4
    address (the last 32 bits, inverted; named in the message); for a
    network, the Teredo server's address (bits 32-63) is named, since a
    network has no one client;
  - ISATAP interface identifiers (`0:5efe` or `200:5efe` followed by an
    IPv4 address, RFC 5214) under any prefix: tunnelled to that IPv4
    address. Refused as an address and as a network of /96 or longer
    (whose every address has that identifier). A /64 contains such
    addresses among ordinary ones and is accepted; the ISATAP-form ones are
    refused when asked about. A real host whose random interface identifier
    happens to start with `0:5efe` is refused too; the chance is about one
    in 2^30 for a random identifier;
  - SIIT IPv4-translated `::ffff:0:0:0/96` (RFC 2765): not refused before
    (the IPv4-mapped check needs `ffff` in the sixth group, this has it in
    the fifth); a translator delivers it to the IPv4 address.
  NAT64 `64:ff9b::/96` and the local-use `64:ff9b:1::/48` were already
  refused. The IPv4 address named for `64:ff9b:1::/48` is the last 32 bits,
  which is right for a /96 translation prefix inside it; a translator
  using a shorter prefix (RFC 6052 allows /32 to /96) puts it elsewhere, so
  the named address can be wrong even though the refusal is right.
  **Left alone**, because they cannot be recognized from the address: 6rd
  (RFC 5969) and MAP-E/MAP-T (RFC 7597, 7599), whose prefixes each provider
  chooses, and NAT64 network-specific prefixes. Also left: the old Teredo
  prefix `3ffe:831f::/32`, in the 6bone space that was returned in 2006 and
  is not routed.
- **Names narrow and never grant.** One address can answer for many
  parties (a CDN, shared hosting), and the host name a request carries
  decides which. A destination may list `names`; then `permits` allows it
  only for a query that carries one of them (`--name`,
  `Pass::permits_named`), and a query with no name is refused rather than
  assumed harmless. A name is looked at only after the address, protocol
  and port matched, hallpass never resolves one, and the informational
  `hostname` stays informational. Names are exact: a wildcard would approve
  names the owner never saw. A tool that does not speak names (a packet
  filter such as playpen) cannot honour the list and enforces the address
  only; the tool that writes the request is the one that must keep to it.
- **Network and broadcast addresses.** `permits` refuses the first and the
  last address of a listed IPv4 network of /30 or broader
  (`network-or-broadcast`): the last is the directed broadcast address,
  which can reach every host on the network (a classic amplification), and
  the first is the network itself, which some stacks also treat as a
  broadcast. /31 networks (RFC 3021 point-to-point) and /32 have no such
  addresses. An address that a destination lists on its own (`address`,
  or a /32 network) is permitted even when it is the edge of another listed
  network: the owner named that exact address, which is the strongest form
  of approval the format has, and it covers the case of an owner whose
  real network is larger than the piece listed. The rule is in
  `Pass::permits`, not in the pass: hallpass cannot tell from a pass alone
  how large the owner's real network is. `Network::is_network_or_broadcast`
  is public so a consumer (for example an egress filter) can apply the
  same rule. IPv6 has no broadcast; the subnet-router anycast address (the
  first address of an IPv6 network) reaches a router of that network, not
  all hosts, and is left alone.
- A `permits` query accepts any unambiguous spelling of an address
  (`2001:DB8::1` is the same address as `2001:db8::1`), but not host names,
  zones, shortened or leading-zero IPv4.
- Loopback is allowed when listed and never implied. Link-local is refused
  (no interface in the format; cloud metadata lives there).
- Breadth cap /24 and /64, raised per destination by
  `whole_network_approved = true`; hard floor /8 and /32. The earlier
  toolbox capped signaling networks at one /8 in total and warned above a
  /16; for a pass naming literal destinations a /24 (256 hosts) or one IPv6
  subnet is the largest shape that is usually one owner's service.
- Only `tcp` and `udp`: both have ports and every expected consumer maps
  onto them.

## Window state

`window_at` returns `revoked` before anything else, then `not-yet-valid`,
`expired`, `valid` with the time remaining. `check_window(now, needed)`
also refuses `window-too-short` when the caller's next piece of work (for
example a 40 s preflight) could run past `valid_until`, the earlier
toolbox's "the window must cover the latest possible end" rule. The CLI
exposes it as `--duration SECONDS` on `permits` and `spend`.

The earlier toolbox had an "unbound" mode (a run with no approval window,
with a warning). hallpass has none: every valid pass has a window. A tool
that runs without a pass is unbound, and should say so itself.

## One decision for a send

Until `spend` took a target, a caller asked `permits` and then `spend`: two
commands, two readings of the pass file, and only the caller's discipline
tied the count to the destination. A pass edited between the two could
count a call for a destination that had just been removed. `spend --to`
(`SpendRequest::target`) decides the destination inside the spend: after
the locks are taken and the pass is read again, in the order digest,
window, destination, counter, ceiling, and a refusal records nothing. It
reuses `permits_named` unchanged, so the two can never disagree. `spend`
without a target stays, for callers that count something with no single
destination; it can only be stricter to give one.

By default the ledger omits targets. Callers can opt into a debit receipt
with checked targets and labels using `--record-target`. The command line reports a line it cannot read as a JSON error
object when `--format json` is on it, because a caller that reads JSON and
gets empty output has to guess. What a caller may rely on is in
[INTEGRATING.md](INTEGRATING.md).

## Literals as written

TOML reads `0x1F90`, `8_080` and `+443` as numbers and
`"192.0.2.1\u0030"` as `192.0.2.10`. The value is right by TOML's rules,
but a reviewer reading the file sees something else. A pass is refused
unless every number is plain decimal and every string is written with the
characters it holds (`\"` and `\\` excepted). A window timestamp must also
fit the years 0001 to 9999 when read in UTC, and a host name whose last
label is a number (`app.example.123`, `0x7f.1`) is refused, because common
resolvers read such text as an IPv4 address.

## Digest

SHA-256 of the exact file bytes, not of a canonical form of the content.
It answers "which file was this run held to" without any doubt about
normalization. The cost is that a comment edit changes the digest; with
the ledger rule below that costs nothing but a `pass-changed` refusal for a
tool that pinned the old digest, which is the point.

## Ledger

- **Location**: `<pass file>.ledger`, beside the pass. The pass and its
  count travel together, the operator needs no configuration, and the pass
  directory is already where the engagement's private files live. Moving or
  renaming the pass file leaves the ledger behind (see residual risks).
- **Format**: JSON Lines with a header naming the pass id, then one entry
  per spend: `seq`, `time`, `counter`, `n`, `digest`, `note`, `prev`. Text
  that `grep` and `jq` can read, appended one `write` per entry.
- **Integrity**: consecutive `seq` plus `prev` (the SHA-256 of the previous
  line) detect a removed, reordered or edited line. A line without a final
  newline is a cut write. An empty file is damage: the ledger is created
  complete, with its header, by writing a temporary file and hard-linking
  it into place, so it never exists empty. Any doubt fails closed with
  `ledger-corrupt`, never as an empty count.
- **Atomic spend**: open the ledger (no links, mode must be 0600), take an
  exclusive lock, re-read and re-validate the pass, check the expected
  digest, the window (with revocation) and the remaining total, append the
  entry and `fdatasync` it, release the lock. A refusal writes nothing. The
  write is confirmed to the caller only after the sync.
- **Locking** uses `std::fs::File::lock` / `lock_shared` (stable since Rust
  1.89; `flock(2)` on Linux). No crate is needed. `status` and `ledger`
  take a shared lock so they never read half a spend.
- **Notes are operator text** and end up on terminals. A note is one line
  without control characters; since 0.2 a new note may also not contain
  the Unicode line and paragraph separators or bidirectional controls
  (which can make text display as something else, as in "Trojan Source").
  Reading keeps the 0.1 rule, so a ledger written by 0.1 stays readable.
  Text output escapes every such character as `\u{...}` (and `\` as `\\`,
  so an escape cannot be faked); JSON keeps the exact text, as JSON
  escaping already makes it one line.
- **Edits**: the spent amount of a counter is the sum over all entries with
  that name, whatever their digest. Raising a total takes effect; no edit
  resets the count. Changing the pass `id` makes the ledger foreign and is
  refused, so the id cannot be used to start over.
- **Tested** with 16 threads in-process and 3 rounds of 12 concurrent
  processes; both tests fail when the lock is removed (checked by hand by
  commenting out the lock call).

## The witness

The hash chain catches damage inside the ledger, but not the loss of the
whole file, an older copy put back, or an edit to the last line (nothing
follows it to check its hash). These are the accidents that happen: a
ledger left behind when the pass is copied or moved, a `git clean`, a
restore from yesterday's backup, an editor that rewrote the file. The
witness catches them.

- **What**: one small JSON file per pass id,
  `$XDG_STATE_HOME/hallpass/<id>.witness` (default
  `~/.local/state/hallpass/`), with the ledger's last sequence number, the
  SHA-256 of its last line, the totals, the ledger's resolved path and the
  time. It lives outside the engagement directory on purpose: whatever
  removes or replaces that directory leaves the witness.
- **The rule** is that the ledger must extend what the witness saw: line
  `seq` must hash to the witnessed hash. Lines after it are accepted (with
  a warning) because a ledger only grows: extra lines can only raise the
  count. Anything else (fewer lines, a different line at that position) is
  `ledger-changed`. A missing ledger with a witness of any line is
  `ledger-missing`, and nothing is created, so the count does not restart
  at 0.
- **Identity is the chain, not the path.** The path in the witness is
  recorded for messages only. A pass moved with its ledger matches, and the
  witness follows it (warning). If the ledger was copied, the first copy
  spent from wins and the other becomes `ledger-changed`, so two copies can
  never both be spent from. Two pass files with the same id and separate
  ledgers are noticed the same way, and a second pass reusing an id without
  a ledger is `ledger-missing`; the message names where the other ledger
  is and says to give one pass its own id.
- **Order of writes**: ledger first (appended and synced), witness second
  (written aside, synced, renamed, directory synced). A crash between the
  two leaves the witness one line behind, which the rule above accepts: no
  lock-out, and the spend counts. Writing the witness first would make a
  crash look like a lost line and lock the operator out. If the witness
  cannot be written after the ledger was, the caller gets
  `witness-not-updated` (do not proceed; the spend counts). To make that
  rare, the state directory is checked for writability (a probe file)
  before anything is appended.
- **Locks**: writers (`spend`, `adopt`) take an exclusive lock on
  `<id>.lock` in the state directory, then on the ledger. Every writer uses
  that order, so they cannot deadlock. The witness lock serializes writers
  of the same id across different ledgers (copies), which the ledger lock
  alone cannot. Readers take only a shared ledger lock and read the
  witness, which is replaced atomically by rename.
- **A ledger without a witness** (a pass brought from another machine or
  user, or a ledger from 0.1) is accepted with a warning, and `spend`
  records a witness for it, even when the spend is then refused. Refusing
  would make a legitimate move impossible; the warning says that until a
  witness exists, a loss would go unnoticed. `hallpass adopt` records the
  same acknowledgment explicitly in the ledger.
- **Adoption** (`hallpass adopt FILE --reason TEXT`) is the one way past
  `ledger-missing` and `ledger-changed`. It writes an `adopt` line into the
  chain with the reason, the pass digest and the witness's previous record,
  so the event is in the record itself. It **carries** the witnessed
  totals that the ledger no longer holds: per counter, `max(0, witnessed -
  in ledger)`, counted as spent. This is the improvement on a plain
  "acknowledge the reset": the operator can recover from a lost ledger
  without being able to reset the count by losing it. There is no option to
  reset to zero, because no accident calls for one: a ceiling is the
  owner's, and more budget is a raised ceiling in the pass or a new pass.
  Adopting twice carries nothing the second time (the totals already
  include the first carry), so a retry after a failed witness write does
  not double-count.
- **State directory failures**: `spend` and `adopt` fail closed
  (`witness-unavailable`) when there is no state directory (neither
  `XDG_STATE_HOME` nor `HOME` is an absolute path), it cannot be created,
  it is not a private (0700-like, no group or other bits) directory, it is
  not writable, or the witness is damaged or not private. The read-only
  commands (`status`, `permits`, `ledger`) answer with a warning and
  `"witness": "not-checked"`: they record nothing, so they cannot make the
  count wrong, and an operator with a broken home directory can still see
  the state of the pass. They still fail closed on everything they can
  check: a damaged ledger, and a lost or changed one when the witness is
  readable.
- **Considered and not chosen**: storing the tail hash in the pass (the
  operator edits the pass, and the digest would change on every spend);
  extended attributes on the ledger (lost by many copy tools, not on every
  file system); refusing a ledger whose window opened long ago without a
  flag (the bone's first idea; it does not catch a lost ledger after the
  first spend, and the witness does); a ledger outside the pass directory
  altogether (the pass and its count would no longer travel together).

## Files and links

- The pass and the ledger are opened only after `lstat` says they are
  regular files and not symbolic links, and the opened file's device and
  inode must match what `lstat` saw. A link swapped in between is refused
  too. This is done with the standard library only (no `O_NOFOLLOW`
  constant without `libc`). Only the last path component is checked.
- A pass writable by group or others is refused: someone else could widen
  the approval. A ledger readable or writable by group or others is refused.
- `init` creates with `O_EXCL` and mode 0600 and never overwrites, not even
  through a dangling link.

## The test clock

`HALLPASS_UNSAFE_TEST_CLOCK=<RFC 3339>` sets "now" for `status`, `permits`
and `spend`. It is honoured only by debug builds (`cargo build`, `cargo
test`) and by builds with the `test-clock` feature; a release build prints
that it ignores the variable and uses the real clock. When it is honoured,
every command prints a warning on standard error and the JSON output says
`"test_clock": true`. The name says what it is, so nobody sets it by
accident. To run the integration tests against a release build use
`cargo test --release --features test-clock` (all pass). A plain
`cargo test --release` builds a binary that ignores the variable: the
tests that never set the clock pass, the ones that rely on it fail because
the real clock decides, and `release_build_ignores_the_test_clock`, which
is compiled only into that configuration, checks that a release binary
ignores the variable, says so, and decides on the real clock
(`cargo test --release --test cli -- release_build`).

## Dependencies

| Crate | Why |
|---|---|
| `clap` (derive) | the command line |
| `serde`, `serde_json` | JSON output and ledger lines |
| `toml` | the pass format |
| `rustix` | safe Unix effective-UID and write-access queries |
| `time` | RFC 3339 parsing, offsets, durations |
| `thiserror` | error types |
| `sha2` | SHA-256 for the digest and the ledger chain (RustCrypto, small, maintained) |
| `proptest`, `tempfile` | tests only |

No locking crate: the standard library has file locks.

## Residual risks

- **Advisory only.** hallpass answers tools that ask. It does not stop a
  tool that does not ask, and it does not filter packets.
- **A determined operator can still cheat.** They own the pass, the
  ledger and the witness. Deleting or rewriting the ledger and the witness
  together, consistently, is not detected; neither is editing the witness
  to match an edited ledger. hallpass cannot prevent this and does not try:
  the witness catches accidents and casual edits (a lost or replaced
  ledger, a moved pass, a rewritten last line), not a deliberate cheat.
  Keep the engagement directory private (0700) and back up the ledger with
  the evidence.
- **One witness per user and machine.** A pass used from two machines or
  two user accounts has two witnesses that do not see each other; the
  ledger's lock and chain still hold, but a loss is noticed only by the
  machine that last wrote it. Run one engagement from one place.
- **The first spend on a new machine is trusted.** A ledger without a
  witness is accepted (with a warning). A ledger that was already lost
  before any witness existed (for example under 0.1) is not noticed.
- **A line added right after a crash** (before the witness was updated)
  could be edited undetected until the next spend updates the witness.
- **Locks are advisory and local.** `flock` does not work reliably on some
  network file systems. Keep the pass on a local disk.
- **The window uses the caller's clock.** Changing the system clock moves
  the window. CLI spends sample time after preparatory witness writes under the writer locks;
  status, permits and previews sample after verifying their evidence. A
  decision instant strictly earlier than the most recent ledger event
  produces a warning, including a difference of one nanosecond. Equal times
  are valid. A historical advanced clock cannot indefinitely block legitimate
  spending. Correct the system clock and review the timestamp and totals;
  the ledger stays intact. Explicit-time Rust callers control their instant.
- **Parent directories are not checked for links**; only the pass and
  ledger file names themselves, and the state directory itself.
- **Broadcast addresses of the owner's real network**: hallpass refuses
  the edges of each listed network, but when the listed network is smaller
  than the owner's real one (a /25 listed inside a /24), the real broadcast
  address can be a listed host. hallpass cannot know the real size.
- **Provider-chosen IPv6 transition prefixes** (6rd, MAP, NAT64
  network-specific prefixes) cannot be recognized from the address and are
  not refused; see "Addresses".
- **Revocation reaches a tool only when it asks.** A long step that is
  already running is not interrupted. Tools should ask before each step.

## Ownership of the pass

The effective user and UID 0 may own the pass. This supports both a private
operator copy and a centrally provisioned, root-owned approval. An arbitrary
peer's 0644 file remains mutable by that peer, so loading it returns
`untrusted-owner` with both UIDs. Group/other write bits are rejected for
either trusted owner. UID and mode are checked on the opened file.
Read-only permission checks report unavailable witness evidence as a warning
because they answer a scope question. A counted operation and its preview
require usable witness evidence.

### Streaming verification

Ledger decisions scan the complete chain line by line, hashing the original
bytes. Summary reads retain totals, the tail, and the requested witnessed
prefix instead of retaining every event or line hash. Retained memory therefore
depends on counter names and the largest line, while each decision still takes
linear time in the number of ledger lines. Full-history reads retain events for
listing. A separately retained checkpoint commits to an exact prefix but does
not establish who approved it or authenticate a checkpoint rewritten alongside
the ledger.

### Current accounting and proposed release policy

Hallpass currently uses monotone spend-only accounting. The caller spends once,
immediately before the first send of a unit with known costs. A read-only
preflight can help prepare work, but its result is advisory and concurrent
callers can spend the observed budget before the first send. First-send
spending still checks all costs together under the writer locks.

For a pass with one request and 100 bytes available, a proposed
one-request, 101-byte unit is refused and both recorded counters remain
zero. A caller can preflight a one-request, 100-byte unit as often as needed.
When two callers reach the first send with that cost, exactly one obtains
a committed sequence and both counters reach their ceilings. If that
caller crashes after the debit and before the send, both charges stand.
When the witness recorded the debit and an older ledger is restored,
adoption carries both missing amounts forward.

A reservation and release model would require authority to attest that the
unit never left. Only the caller's send boundary could furnish evidence, and
a recovered caller can be uncertain after a crash around that boundary.
Concurrent attempts would require an identity for each reservation and one
durable decision per release, with rules for missing history and carry
forward during adoption. The proposal is to keep spend-only accounting
while that uncertainty remains. The approval owner’s disposition on
release is pending.

A crash or I/O error around append requires reconciliation by sequence and
digest (and a caller reference when available) before retry. An explicit
witness-update failure identifies a synced sequence. Verify it and account
for it as spent, even if a caller never obtained permission to send.

A capacity instrumentation run with one counter and synthetic fixed-shape
records used `cargo test summary_retains_no_per_event_storage_at_scale -- --nocapture`.
At 10,000 and 100,000 records the inputs were 2,428,933 and 24,388,934 bytes;
the largest lines were 243 and 244 bytes. The previous parser retained at least
2,748,965 and 27,588,966 bytes in its input buffer and 32-byte hashes alone,
excluding event objects and allocator overhead. The streaming summary retained
zero event/adoption vector capacity at both sizes, one counter, one tail and one
requested prefix. These are instrumented retained structures, not process RSS;
the test fixture itself constructs the input in memory and is excluded.

Archive checks the opened directory and entry metadata, and syncs the directory
after publishing. The private archive directory and its parent path are a trust
boundary: another process able to rename or replace those paths without taking
locks can race pathname operations. A present witness may corroborate only an
earlier prefix when the ledger extends it, not necessarily the exported tail.

Preparatory witness updates retain the most recent ledger event timestamp (or
the prior witness timestamp, or the Unix epoch for a new header). This timestamp
describes available evidence, not the later decision instant. A failed or invalid
clock after preparation can therefore leave the corroborating witness updated,
but no spend is appended.
