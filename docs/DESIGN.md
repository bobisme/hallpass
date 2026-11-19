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
  functions and adds no rule of its own.
- **Pure decisions, injected clock.** `Pass::window_at`,
  `Pass::check_window` and `Pass::permits` take `now` from the caller and
  read nothing. Only `load`, `tally`, `spend` and `write_template` touch the
  file system.
- **Small public API**: `load`, `Pass` (with `permits`, `window_at`,
  `check_window`, `destination_for`), `spend`, `tally`, `ledger_path`,
  `write_template`, the address parsers, and their value types. Structs
  that the library builds are `#[non_exhaustive]` so a caller cannot build
  an unvalidated `Pass`.

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
  miss that. The caller must ask with the IPv4 address. 6to4 (`2002::/16`)
  and Teredo also embed IPv4 but route through relays, not to the embedded
  host; they are not refused (see "Residual risks").
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
`cargo test --release --features test-clock`.

## Dependencies

| Crate | Why |
|---|---|
| `clap` (derive) | the command line |
| `serde`, `serde_json` | JSON output and ledger lines |
| `toml` | the pass format |
| `time` | RFC 3339 parsing, offsets, durations |
| `thiserror` | error types |
| `sha2` | SHA-256 for the digest and the ledger chain (RustCrypto, small, maintained) |
| `proptest`, `tempfile` | tests only |

No locking crate: the standard library has file locks.

## Residual risks

- **Advisory only.** hallpass answers tools that ask. It does not stop a
  tool that does not ask, and it does not filter packets.
- **Deleting the ledger resets the count.** A missing ledger means nothing
  was spent. So does moving the pass to a new path. Anyone who can write the
  directory can do either. Keep the engagement directory private (0700) and
  back up the ledger with the evidence.
- **The last entry can be altered** without detection (nothing follows it
  to check its hash), and a whole ledger can be rewritten consistently by
  anyone with write access. The chain catches accidents, not a determined
  insider.
- **Locks are advisory and local.** `flock` does not work reliably on some
  network file systems. Keep the pass on a local disk.
- **The window uses the caller's clock.** Changing the system clock moves
  the window. Keep NTP on.
- **Parent directories are not checked for links**; only the pass and
  ledger file names themselves.
- **Subnet broadcast**: in a listed network such as `192.0.2.0/24`,
  hallpass cannot know whether `192.0.2.255` is a directed broadcast
  address on the owner's network. It is permitted like any other address in
  the network.
- **Relay-embedding IPv6** (6to4, Teredo) is not refused.
- **Revocation reaches a tool only when it asks.** A long step that is
  already running is not interrupted. Tools should ask before each step.
