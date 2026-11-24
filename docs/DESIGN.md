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

A spend without a target that is allowed, or a preview that would allow
it, has a warning that no destination was checked and that the owner can
add `require_target_v1 = true`. Without the warning, a forgotten `--to`,
or a wrapper that drops it, records a debit that nobody checked against
scope, and nothing says so. A pass with the term refuses such a debit, so
the warning follows from the decision and needs no second reading of the
pass. The term stays opt-in. `init` writes it as a commented line, because
an approval term is the owner's to write, and the template must not add a
term the owner did not approve.

The spend reply is a view of the decision, not of the ledger line. Every
reply has the same keys, with null where a key does not apply, so a caller
decodes one shape whatever the flags. The ledger line keeps its compact
encoding, which omits absent values, because the chain hashes its exact
bytes and existing ledgers must still verify.

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
  (which can make text display as something else, as in "Trojan Source"),
  and after 0.2.0 no other Unicode format character either (zero-width and
  tag characters, the soft hyphen, the byte order mark: invisible, so two
  texts that differ look the same). New caller references and reasons
  follow the same rule. Reading keeps the earlier, looser rules (for
  notes the 0.1 rule), so an older ledger stays readable. Text output escapes every such
  character as `\u{...}` (and `\` as `\\`, so an escape cannot be
  faked), and a quoted value also escapes its quotes, once; JSON keeps the
  exact text, as JSON escaping already makes it one line.
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
  ledgers are noticed the same way. A second pass reusing an id without a
  ledger is `ledger-elsewhere` when the ledger where the witness last saw
  it is intact (opened under the usual rules, fully verified, ending with
  the witnessed line), else `ledger-missing`. The first is the common
  case of an amended approval saved as a new file: the message names the
  live ledger and its pass file, says to replace that file's content with
  the revision, and `adopt` refuses, since adopting would fork the
  history. A ledger that cannot be verified there falls back to
  `ledger-missing`, so the path in the witness never decides a count.
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
  same acknowledgment explicitly in the ledger. A guarded spend
  (`--require-new-ref`) on a nonempty ledger records no witness: it cannot
  show that a reference is new in a ledger that may be a partial copy, so
  it refuses and names `adopt`, after which it checks references again.
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
  not double-count. A carry keeps totals, not caller references: an
  adoption that records a previous witness of at least one line, or
  carries anything, accepted a ledger without lines hallpass had recorded,
  so the reference guard stays inconclusive on that ledger until the
  operator records, in a reference reconciliation line, which references
  may be in the lost lines (from the run records, with a reason): then
  listed references are duplicates and others are checked again. Only an
  explicit list in the ledger lets a reference that may be lost pass as
  new, and a later loss makes references inconclusive again. An adoption
  without a witness appends to the ledger as it stands and loses no
  reference. The existing `witness` and `carried` fields tell the two
  apart, so telling them apart needed no new field. The reconciliation
  is a new kind of line, which an older hallpass refuses as damage rather
  than skipping.
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
- One function reads a pass file, for every command and the library. The
  bytes it returns are the ones parsed and the ones digested. After reading
  it `fstat`s the open file. If the modification time is less than 0.25 s
  old, it waits until 0.25 s after that time, reads the open file again, and
  requires the same bytes, size and modification time, or the pass is
  `invalid-pass`. A save in place truncates the file and writes it in
  pieces, and a prefix that ends at a line boundary can be a valid pass
  that grants more than the whole (the evaluator's 4 KiB writes, one of
  them ending just before the last `names` line). Editors and tools
  normally pause microseconds between writes, and Linux throttles a writer
  for at most 200 ms at a time, so 0.25 s leaves a margin and keeps the
  delay short. Only a command that reads the pass within 0.25 s of a write
  waits. A modification time
  with no fraction of a second may be a whole-second file system's
  rounding, so 2 s is added to it. The second read uses the open file: a
  pass replaced by `mv` meanwhile is read as it was when it was opened.
  The status-change time is not used: `chmod` and `mv` change it without
  changing the bytes.
- The directory that holds the pass, the ledger and the lock is checked
  for write by group or others without the sticky bit, because the file
  modes do not stop a `rename` into such a directory. The attack that
  matters is not a stranger's file, which the owner check refuses: it is
  the operator's own older revision (`eng.pass.toml.old`, a backup, an
  archived copy) moved over the current pass by another user. It has the
  right owner, mode 0600 and the same id, and the ledger beside it matches,
  so an unpinned spend would run under an older, wider approval. The same
  user can unlink the pass and ledger or take the lock file. So a directory
  that any user can write, without the sticky bit, fails closed: `spend`,
  `adopt` and `reconcile-references` are refused (`shared-directory`, fix
  `chmod o-w DIR` or `chmod +t DIR`) and the read-only commands warn. This
  is a compatibility change. A directory only the group can write is a
  warning, not a refusal: team directories under umask 002 are common, and
  the group is usually the team. Group write is warned about whatever the
  group's members, as for the pass file, because a group of one cannot be
  told from a larger one cheaply. The state directory is held to a stricter
  rule: it is refused unless mode 0700 (see The witness). Parent
  directories are not checked.
- A pass whose last byte is not a newline is refused. A cut inside a line
  can still parse and change the approval (`ports = 443` read as
  `ports = 44`). TOML does not require the newline, so a pass saved by an
  editor set not to add one is refused until the newline is added.
- Rejected: a file lease, which tells whether any process has the file
  open for writing, but needs the file's owner and a signal handler, which
  needs `unsafe` code.

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
- **A pass saved in place.** A save that truncates the pass and writes it
  in pieces leaves a prefix on disk, and the prefix can be a valid pass
  that grants more. hallpass reads a pass modified in the last 0.25 s again
  0.25 s after the modification and refuses it if anything changed, and it
  refuses a last line without a newline. A save that pauses for more than
  0.25 s part-way, or a writer that sets the modification time back, can
  still be read part-way. Replace a pass by writing the new version in the
  same directory, `chmod 600`, then `mv` over the old file; a tool that
  spends while the owner may change the pass should pin the digest
  (`--digest`, `expect_digest`).
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
depends on counter names, the largest line and at most 16 recorded targets
already checked, while each decision still takes
linear time in the number of ledger lines. Full-history reads retain events for
listing. A separately retained checkpoint commits to an exact prefix but does
not establish who approved it or authenticate a checkpoint rewritten alongside
the ledger.

### Cost per call

Every `permits`, `status`, `spend` and spend preview verifies the whole ledger
once: it reads every byte, hashes every line, checks each `seq` and `prev`,
and decodes and validates every record. No call verifies twice. A line in the
spelling hallpass writes is read directly (`src/ledger/written.rs`): keys in
hallpass's order, no spaces, and strings whose only escapes are `\"` and
`\\`. Every spend and debit line that hallpass writes has this spelling,
whatever its note, caller reference or names say, because that text has no
control characters. Any other spelling (an adoption, or a line that another
program wrote) goes to `serde_json`. Both accept the same lines with the same
values, and property tests compare them.

`cargo test --release --test ledger_scale -- --ignored --nocapture` measures
this with two mixes of lines:

- **Plain** (about 300 bytes a line): half legacy spends, a quarter debits
  and a quarter debits with a caller reference and a recorded target, with
  whole-second times.
- **Receipts** (about 490 bytes a line): every line is a debit of two
  counters with a note, a caller reference and a recorded target with a
  request name, as `spend --caller-ref REF --record-target --note NOTE`
  writes it with the real clock, so times have fractions of a second. One
  note in four has non-ASCII text and one in eight has quotation marks. The
  test checks that its lines are, byte for byte, the lines that real spends
  write.

The numbers below are medians of three runs, alternating before and after
bn-iyn, on a loaded 32-core AMD Threadripper 9970X with SHA extensions. The
ledger is on tmpfs, so the sync after each append costs nothing here. These
are not the figures for a real disk: see "On a real disk" below, where a
spend costs about 15 ms more.

In milliseconds per call, all on tmpfs. `permits` and `spend` call the library; CLI `spend`
starts the binary for each call. For the receipts mix, both spends record a
receipt with `--require-new-ref`. The last column is spends a second from 16
threads together.

| Mix | Ledger lines | Size | Read and hash | `permits` | `spend` | CLI `spend` | 16 spenders |
|---|---:|---:|---:|---:|---:|---:|---:|
| plain | 1,000 | 0.3 MB | 0.17 | 0.44 → 0.36 | 0.48 → 0.40 | 1.4 → 1.3 | 1,360 → 1,580 |
| plain | 10,000 | 3.0 MB | 1.7 | 4.2 → 3.3 | 4.2 → 3.2 | 6.5 → 4.7 | 194 → 247 |
| plain | 100,000 | 30 MB | 18.7 | 43 → 36 | 42 → 34 | 46 → 37 | 23 → 28 |
| receipts | 1,000 | 0.5 MB | 0.25 | 0.99 → 0.57 | 1.06 → 0.63 | 2.2 → 1.5 | 707 → 1,090 |
| receipts | 10,000 | 4.9 MB | 2.7 | 10.2 → 5.8 | 9.9 → 5.9 | 12.1 → 7.4 | 92 → 159 |
| receipts | 100,000 | 49 MB | 30.0 | 100 → 60 | 102 → 63 | 102 → 63 | 10 → 16 |

`permits`, `status` and `receipt` cost the same. Before bn-2n0, a plain call
at 100,000 lines took about 150 ms (tmpfs).

**On a real disk.** A spend appends one line and then syncs it (fsync), and
the sync dominates. The figures below were measured on 2026-11-23 with a
release build of the CLI, on the ext4 home disk (an NVMe drive, `/dev/nvme1n1p1`,
not tmpfs), with `XDG_STATE_HOME` on the same disk. The machine was loaded
by other builds (load average 26 to 41 on 64 CPUs), and the disk was shared.
Ledgers of 10,000 and 100,000 lines were synthesized (one line of about 430
bytes each, 4.3 MB and 43 MB, the receipts style) and adopted. Each row is
three runs, shown as the lowest and highest of the three medians. Each run
times 30 `permits` calls, 40 plain `spend` calls and 40 guarded spends
(`--caller-ref REF --require-new-ref`), then 100 more guarded spends in a
row from one process, then 8 processes with 25 guarded spends each. All are
CLI calls. Times are in milliseconds, throughputs in spends a second.

| Ledger lines | `permits` | `spend` | guarded `spend` | 1 process | 8 processes | 8 processes, p50 | 8 processes, p99 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 (small) | 0.7 to 0.8 | 14.2 to 15.4 | 15.2 to 15.8 | 62 to 66 | 62 to 71 | 110 to 116 | 127 to 489 |
| 10,000 | 6.0 to 18.5 | 20.7 to 22.2 | 21.7 to 21.8 | 44 to 49 | 40 to 51 | 148 to 171 | 239 to 602 |
| 100,000 | 47 to 48 | 64 to 72 | 71 to 81 | 11 to 15 | 12 to 13 | 573 to 621 | 906 to 1,560 |

Read-only calls match the tmpfs figures (one run of `permits` at 10,000 lines
read 18.5 ms because of the load; the other two read 6 ms). A spend costs
about 15 ms more than a read: the sync. The sync time varies with what else
the disk is doing. The best spend took 13 to 15 ms in every run, and a
second set of runs on the same ledger, made while the disk was busy, gave 24
to 30 ms. So plan for about 15 ms a spend, and 30 ms on a busy disk: one
process does about 60 spends a second at best, and 35 to 40 on a busy disk.
In one run of 3,000 guarded spends in a row on a small ledger (the
evaluator's `perf.py real 3000`, same disk, loaded), the total was 74.8 s,
which is 40 spends a second (25 ms a spend). Spends on one pass run one at a
time, so 8 processes get the same total as one (40 to 70 a second on a small
ledger), and each waits for the other seven: the p50 is about 8 times the
cost of one spend.

"Read and hash" is the floor for a call that checks every byte: it reads the
ledger and hashes each line, and decodes nothing. It costs about 0.6 ms a
MB. Before bn-iyn, a line with a string that had a non-ASCII character, a
quotation mark or a backslash (in a note, for example) went to `serde_json`,
and such a line cost about 1.6 times as much. At 29,533 receipt lines (15
MB), a CLI call took about 40 ms when every note had a non-ASCII character
and about 25 ms when every note was ASCII. Both now take about 19 to 21 ms.
In a profile of the ASCII case before bn-iyn, SHA-256 took about 25% of a
call, finding the end of each string and checking its UTF-8 one string at a
time about 22%, the other validation (the set of charged counters, the note
and reference checks, parsing the digest and the time) about 18%, and memory
allocation about 8%. Now reading and hashing (with one UTF-8 check a line)
are about 45% of a call, reading the fields about 16%, validation about 15%
and allocation about 10%.

**Practical size.** The cost follows the size of the ledger more than its
number of lines: a call costs about 1.2 ms per MB, that is about 0.35 µs per
plain line and about 0.6 µs per receipt line. A CLI call adds about 0.7 ms
to start the process and load the pass. Up to 10,000 lines, a read-only call takes a
few milliseconds, and a spend about 20 ms on the ext4 disk. At 100,000 receipt lines (49 MB), a call takes about 60
ms. Spends hold both locks while they verify, so the spends on one pass run
one at a time: on tmpfs, all callers together sustain about 16 spends a
second at that size, and on the ext4 disk about 12 (see "On a real disk"). Cost grows linearly: 1,000,000 receipt lines would take about 0.6 s
per call. Keep the ledger of one pass below about 100,000 lines and 50 MB.

**Waiting for the lock.** With no `--lock-timeout-ms`, a spend that finds
the writer lock busy takes the blocking `flock`, so the kernel queues the
waiters and wakes them, and no waiter is starved. The notice after about 2
seconds comes from a helper thread with a timer; it never touches the lock.
With `--lock-timeout-ms`, a spend polls with short sleeps (50 µs to 5 ms)
until the limit, because a blocked `flock` cannot be cancelled: a helper that
gave up at the limit could still take the lock afterwards. Pollers are not
queued, so under heavy contention a bounded wait is not fair, and one waiter
can lose many races in a row. Before bn-mti the CLI always polled, even with
no limit, because it always set the notice callback.

Latency of one CLI `spend`, with 8 writer processes each making 50 spends
against one pass (an earlier run on the same ext4 home disk, not repeated
here; a release build, receipts-style lines; the script is the evaluator's
`race.py`). For the current blocking-lock numbers, see the table above: at
100,000 lines the p50 is about 0.6 s and the total about 12 spends a second.

| Ledger lines | Waiting | p50 | p99 | max | Spends a second |
|---:|---|---:|---:|---:|---:|
| 10,000 | polling every 20 ms (before) | 14 ms | 1,117 ms | 1,679 ms | 72 |
| 10,000 | blocking lock (now) | 106 ms | 125 ms | 131 ms | 74 |
| 100,000 | polling every 20 ms (before) | 61 ms | 3,742 ms | 5,767 ms | 17 |
| 100,000 | blocking lock (now) | 497 ms | 593 ms | 602 ms | 16 |

Throughput is the same: one spend at a time. What changed is who waits. With
polling, a lucky process spent many times in a row and the others waited
seconds. Now the waits are even, and each is about (writers x cost of one
call): at 100,000 lines, 8 x 63 ms is about 500 ms.

**Choosing `--lock-timeout-ms`.** Set it above the expected wait, which is
(writers on this pass x cost of one call) with a margin of several times
that. For 8 writers at 100,000 lines that wait is about 0.6 s (measured p50
0.57 to 0.62 s, p99 0.9 to 1.6 s on the ext4 disk), so 5,000 ms is safe. Because a bounded wait polls, its worst case is longer than the
figure above, so a limit close to the typical wait can give a spurious
`lock-timeout`; nothing is recorded when it does, and the caller can run the
command again. If every writer can wait, leave the limit off: that is the
fair path.

**Batch with `--n`.** The cost depends on the number of lines, not on the
amounts. A caller that counts every request at a high rate should spend once
per group: `hallpass spend PASS requests --n 50` (or `--charge requests=50
--charge bytes=N`) immediately before the first send of the group records one
line for the group. A recorded spend is final, so a group that stops early
still counts its unsent part. Batching can count more than was sent, never
less. Choose the group size so that the ledger stays below about 100,000
lines for the whole engagement. For example, 10,000,000 requests in groups of
100 make 100,000 lines.

**Incremental verification was considered and not adopted.** To skip the
prefix that an earlier call verified, a call must know that the prefix has
not changed since. There are two ways, and neither is worth its cost:

- Trust file metadata (size, inode, change time). The cost per call would be
  flat. But a changed middle line would be found only when the metadata
  shows a change, or by a full verification. A write that does not change the
  metadata (storage damage, or a raw device write) would go unnoticed on
  every call. That moves detection from every call to fewer calls.
- Keep a digest of the verified prefix and its totals, for example beside the
  witness. Detection stays on every call, because the call still hashes every
  byte, so this saves only the decoding. The "read and hash" column shows the
  most it can save: about half of a call. In exchange, ceiling decisions would
  depend on a cached copy of the totals in the state directory instead of the
  ledger. A later release that tightens a validation rule would also not
  check the cached prefix again.

Batching reduces the number of lines, and so every cost, by the group size.
If larger ledgers become necessary, revisit the prefix digest: it is the
design that keeps detection on every call.

### Recorded spends are final

The approval owner chose to keep recorded spends final. The caller spends once,
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
forward during adoption. Returning credit after an ambiguous send could let a
second caller exceed the approved ceiling. Revisit reservations if a caller
needs guaranteed capacity before it can begin preparation.

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
