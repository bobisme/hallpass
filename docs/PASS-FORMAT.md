# Pass format (format 1)

A pass is one TOML file, written by hand from the owner's written approval.
`hallpass init FILE` writes a commented template. `hallpass check FILE`
reports every problem at once, each with its field path and what to do.

## Example

```toml
# Pass for the voice-edge test. Copied from the owner's email of 2026-11-18.
format = 1
id = "example-2026-11"
name = "Example voice edge"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18, subject 'test window'"
operator = "Sam Tester"
valid_from = 2026-11-20T08:00:00Z
valid_until = "2026-11-20T18:00:00+01:00"   # quoted or unquoted, offset required
revoked = false

[[destination]]
label = "sip-edge"
address = "192.0.2.10"
protocol = "udp"
ports = [5060, "10000-10100"]
hostname = "sip.example.net"   # a DNS name the owner uses for it; grants nothing

[[destination]]
label = "web"
network = "2001:db8::/120"
protocol = "tcp"
ports = 443

[ceilings]
calls = 6
requests = 500
```

## General rules

- **Unknown keys are an error**, in every table. A misspelt key (`prots`,
  `revokd`) would otherwise drop a restriction without anyone noticing.
- **Text fields** (`name`, `owner`, `reference`, `operator`, `label`,
  `revoked_reason`, `hostname`) must be quoted strings on one line: no
  control characters (newline, tab), no Unicode line or paragraph
  separator (U+2028, U+2029) and no Unicode format character, no leading
  or trailing spaces, not empty. The format characters are general
  category Cf of Unicode 16.0 and the whole Tags block: the bidirectional
  controls (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069),
  the zero-width space and joiners (U+200B to U+200D), the word joiner and
  invisible operators (U+2060 to U+2064), the soft hyphen (U+00AD), the
  byte order mark (U+FEFF), the interlinear annotation controls (U+FFF9 to
  U+FFFB), the tag characters (U+E0000 to U+E007F) and a few others. A
  bidirectional control reorders the text around it, and most of the
  others are invisible, so an owner or reference could read as something
  other than the bytes the owner approved, and two passes that differ
  could look the same. Two more groups are refused for the same reason:
  - the other invisible characters: every default-ignorable code point
    of Unicode 16.0 (`Default_Ignorable_Code_Point`). Beyond the format
    characters, these are the combining grapheme joiner (U+034F), the
    Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), two Khmer inherent
    vowels (U+17B4, U+17B5), the variation selectors (U+180B to U+180F,
    U+FE00 to U+FE0F, U+E0100 to U+E01EF) and the code points reserved as
    ignorable (U+2065, U+FFF0 to U+FFF8 and the rest of U+E0000 to
    U+E0FFF);
  - every space other than the ASCII space U+0020 (general category Zs):
    the no-break space (U+00A0), U+1680, the en, em and other fixed-width
    spaces (U+2000 to U+200A), U+202F, U+205F and the ideographic space
    (U+3000). Each looks like a plain space.

  `--note` refuses them too. A pass that holds one fails to load, with
  the field and the character named, for example:
  - `approval.owner: contains a Unicode format character (U+200B)`;
  - `name: contains an invisible character (U+3164)`;
  - `approval.reference: contains a look-alike space (U+00A0)`.

  Right-to-left text itself (Arabic, Hebrew) is accepted: only the
  controls are refused. These refusals are new
  after 0.2.0; a pass written earlier that holds such a character must be
  re-approved without it. `hallpass approval-id` applies the same rules to
  `--owner` and `--reference`, so it never prints an id that no pass can
  carry. Text output escapes these characters as `\u{...}` wherever it
  shows caller- or pass-supplied text; JSON carries the exact text.
- **The whole file** refuses the same characters, comments, keys and
  whitespace included, and every control character other than a tab and
  a line end (LF or CRLF). The owner approves, and a reviewer reads, every
  byte of the file: a bidirectional control in a comment can reorder how
  the rest of its line shows in an editor or a code review tool, and a
  zero-width character can hide text. The problem gives the line and the
  column (from 1, in characters) and names the character:
  - `(file): line 18, column 40 holds a bidirectional text control (U+202E)`;
  - `(file): the file starts with a byte order mark (U+FEFF)`.

  A character inside a string value is reported once, by its field's own
  rule. The first 16 characters are reported one by one, and one more
  problem counts the rest. This is new after 0.2.0: a pass that holds such
  a character outside its text fields, such as in a comment or as a byte
  order mark, no longer loads. Delete the character, then have the owner
  approve the edited file.
- **Numbers** (`format`, ports, ceilings) are plain decimal digits. TOML's
  other spellings are refused: `0x10`, `0o17`, `0b110`, `1_000`, `+6`. A
  reviewer who reads `0x10` as 10 would approve less than the 16 a tool
  would use.
- **Strings and quoted keys are written with the characters they hold.**
  A backslash escape such as `\u0030` or `\x41`, or a line-continuation
  backslash, is refused (`"192.0.2.1\u0030"` is `192.0.2.10` to TOML). Only
  `\"` and `\\` are accepted; a single-quoted string has no escapes.
- **The file** must be UTF-8, at most 1 MiB, a regular file (not a symbolic
  link), owned by the effective user or root, and not writable by group or others (mode 0600 or 0644; `init`
  writes 0600). The directory that holds it should not be writable by group or others unless it has the sticky bit. If others can write it, `spend`, `adopt` and `reconcile-references` are refused (`chmod o-w DIR`); if only the group can, commands warn. Its last line must end with a newline: a last line without
  one may be a save cut short. `init` writes the newline. A file modified in
  the last quarter second is read twice; see [Changing a
  pass](#changing-a-pass).
- **Field paths** in problems are dotted: `approval.valid_until`,
  `ceilings.calls`, `destination[2].ports`. Destinations count from 1, in
  file order.

## Top level

| Key | Required | Rule |
|---|---|---|
| `format` | yes | the integer `1` |
| `id` | yes | 1-64 characters from letters, digits, `.`, `_`, `-`, starting with a letter or digit. The ledger belongs to this id (see "Ledger") |
| `name` | yes | text, at most 80 characters |
| `required_counters_v1` | no | list of 1 to 64 distinct counter names from `[ceilings]` that every debit must charge |
| `require_target_v1` | no | literal `true` to require a destination check on every debit |
| `[approval]` | yes | see below |
| `[[destination]]` | yes, at least one | see below; at most 1024 |
| `[ceilings]` | no | see below; a pass without it has no counters |

Place `required_counters_v1 = ["requests", "bytes"]` before any table header
to require a positive cost for both counters on every spend, including
targetless spends. The caller supplies the measured cost. Omitting the key
lets a caller charge any subset of declared counters. Older format-1 readers
reject the new key through their unknown-key check. Each debit uses the rule
in its current pass revision. Historical ledger records retain their original
charges. `permits` checks window and destination only.

The rule applies to **every debit under the pass**, whatever kind of work it
records. It does not apply only to the debits you have in mind. If the pass
also meters other work, such as scans, each of those debits must charge every
required counter too, and each charge must be a positive amount. With
`required_counters_v1 = ["requests", "bytes"]`, a scan is refused unless it
charges both:

```sh
hallpass spend pass.toml --charge requests=1 --charge bytes=24 --to 192.0.2.10:443/tcp
```

Charges must be strictly positive, so a unit that has no bytes to report
cannot satisfy `bytes`. If the owner does not mean the rule for that work,
put it in a separate pass with its own `required_counters_v1`, or with none.

Place `require_target_v1 = true` before any table header to require a literal
destination on every debit. For example, the top level of a metered pass
can start with

```toml
format = 1
id = "example-2026-11"
name = "Metered endpoint checks"
required_counters_v1 = ["requests", "bytes"]
require_target_v1 = true
```

Omit the key to allow targetless accounting. Strict older readers reject this
new key. Checking a destination does not store it in the ledger. The caller
opts into retention with `spend --record-target` or `record_targets` in Rust.
A targetless debit returns `target-required` after digest and window checks.

## `[approval]`

| Key | Required | Rule |
|---|---|---|
| `owner` | yes | who approved: the owner of the destinations (text, at most 200) |
| `reference` | yes | where the written approval is, for example "email of 2026-11-18" (text, at most 200) |
| `operator` | yes | who runs the test (text, at most 200) |
| `valid_from` | yes | the first instant the pass is valid (inclusive) |
| `valid_until` | yes | the first instant it is no longer valid (exclusive); must be later than `valid_from`. `check`, `status` and `lint` warn (exit codes unchanged) about a window longer than 90 days, one that has ended, or one that opens more than 30 days ahead |
| `revoked` | yes | `true` or `false`. Write `false` explicitly |
| `revoked_reason` | no | text, at most 500; only with `revoked = true` |

Timestamps are RFC 3339 with an explicit offset: `2026-11-20T08:00:00Z` or
`2026-11-20T09:00:00+01:00`. Both TOML's unquoted date-time and a quoted
string are accepted. A local time without an offset (`2026-11-20T08:00:00`)
and a bare date are refused: their instant depends on the reader's time
zone. Fractions of a second are kept. The instant must fall in the years
0001 to 9999 in UTC (`9999-12-31T23:59:59-01:00` is refused: it is year
10000 in UTC).

A revoked pass permits nothing, whatever its window. `spend` reads the file
again under the ledger lock, so setting `revoked = true` stops the next
spend of every running tool that asks.

## `[[destination]]`

| Key | Required | Rule |
|---|---|---|
| `label` | yes | unique within the pass, ignoring ASCII letter case (`web` and `WEB` are refused together: people read, type and match labels); same characters as `id`. Every decision names it |
| `address` | one of the two | one literal IP address |
| `network` | one of the two | one CIDR network (`192.0.2.0/28`, `2001:db8::/120`) |
| `protocol` | yes | `"tcp"` or `"udp"` |
| `ports` | yes | `443`, `[80, 443]`, `"8000-8100"`, or a list mixing ports and range strings: `[5060, "10000-10100"]` |
| `hostname` | no | what the owner calls this destination. It must be a DNS host name: at most 253 characters of ASCII letters, digits, `.`, `-` and `_`, whose last dot-separated part is not a number (`10`, `0x7f`). It is not an IP address (put that in `address`). Free text such as `"ExampleCo CDN edge"` is refused. **Informational only: it grants nothing**, and hallpass never resolves it |
| `names` | no | the only host names this destination is approved for, as a list: `names = ["app.example.com", "admin.example.com"]`. **It narrows and never grants**: see below |
| `overlap_acknowledged` | no | on a destination with `names`: the labels of the nameless destinations whose overlap with this `names` list the owner accepts, as a list: `overlap_acknowledged = ["wide"]`. Each label must name another destination that has no `names`; an empty list, a repeated label, the destination itself or an unknown label is refused. It changes no decision: see "Reviewing an overlap". **A hallpass older than this key refuses the pass as having an unknown key** |
| `whole_network_approved` | no | `true` only when the written approval names this whole network; needed for a network broader than the cap. Not allowed with `address` |

### Names

One address often answers for many sites: a CDN, shared hosting, a reverse
proxy. Which site a request reaches is decided by the host name it carries
(the TLS server name and the HTTP `Host` header), so approving the address
alone would also approve every other party on it. `names` closes that gap.

- A destination with `names` allows only a query that carries one of the
  listed names: `hallpass permits FILE --to ADDR:PORT/PROTO --name NAME`.
  A query without a name is refused (`name-required`); a query with another
  name is refused (`name-not-listed`).
- A destination without `names` has no name restriction.
- A name never grants anything. The address, protocol and port must be
  listed, and hallpass never resolves a name. The tool resolves the name
  itself, asks about each address, connects to an address that was allowed,
  and sends exactly the name it asked about.
- Names are written in full, in lower case, without a trailing dot. There
  are no wildcards. An internationalized name is written in its `xn--`
  form. At most 64 names per destination; an empty list is refused.
- A name whose last part is a number (`10.1`, `010.0.0.1`, `2130706433`,
  `0x7f000001`, `example.123`) is refused, in a pass and in a query:
  `inet_aton` and URL parsers read it as an IPv4 address, in exactly the
  spellings the address rules refuse. The same holds for `hostname`.
- A query's name is compared without regard to case, and one trailing dot
  is ignored.
- hallpass is advisory, and this check more than most: nothing on the
  network can see the name inside an encrypted request, so only the tool
  that sends it can keep to it.

### Reviewing an overlap

Suppose `web` grants TCP port 443 on `192.0.2.10` for the name
`app.example.com`. If a second rule `subnet` grants the same port on
`192.0.2.0/28` with no names, an unnamed request to `192.0.2.10:443/tcp`
also qualifies through `subnet` during the approval window. Run
`hallpass lint PASS` to see both labels, the shared service and the example
decision. The stable finding code is `name-restriction-overlap`. `check` and
`status` print the same overlap as a warning, and `check` still exits 0.

To accept an overlap, add the other destination's label to
`overlap_acknowledged` on the named destination:

```toml
[[destination]]
label = "app"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
names = ["app.example.com"]
overlap_acknowledged = ["subnet"]
```

One entry names exactly one overlap (`app` with `subnet`); an acknowledgement
does not cover another pair. It never changes a decision: `subnet` still
allows the unnamed request. `status` then prints one `Note:` line instead of
a warning on every call. `check`, `lint` and `diff` still list the overlap in
full and mark it acknowledged, so a reviewer sees it. If the two destinations
do not overlap (a port or address was edited), `check`, `status` and `lint`
warn that the acknowledgement covers nothing, so it can be removed. Because
the key is part of the approved bytes, adding it is a pass change that
`diff` shows as `destination[app].overlap_acknowledged` with review
required.

### Address spelling

hallpass accepts exactly one spelling of each address, the canonical one
(what Rust's standard library prints, which for IPv6 is RFC 5952: lower
case, zeros compressed). A reviewer reads exactly the address that is used.
Refused, each with a message that says what to write instead:

| Refused | Why |
|---|---|
| a host name (`sip.example.net`, `localhost`) | names are never authorization |
| an IPv4 part with a leading zero (`010.0.0.1`) | some tools read it as octal (8) |
| a shortened IPv4 form (`10.1`, `10.1.2`, `2130706433`) | tools expand it differently |
| a non-canonical IPv6 spelling (`2001:DB8::1`, `2001:0db8::1`) | the message gives the canonical form |
| an interface suffix (`fe80::1%eth0`) | a pass cannot name an interface |
| an IPv6 form that carries an IPv4 address: IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96` (other than `::1`), NAT64 `64:ff9b::/96` and `64:ff9b:1::/48` | traffic to these reaches the IPv4 address, past an IPv4-only reading of the list; name the IPv4 address itself |
| an IPv6 transition address that tunnels or translates to IPv4: 6to4 `2002::/16`, Teredo `2001::/32`, SIIT-translated `::ffff:0:0:0/96`, and an ISATAP interface identifier (`…:0:5efe:a.b.c.d`, `…:200:5efe:a.b.c.d`) under any prefix (as an address, or a network of /96 or longer) | packets to these are carried over IPv4 to the address inside; the message names it. Name the native address instead |
| the unspecified address `0.0.0.0/8`, `::` | "any" is not a destination |
| multicast `224.0.0.0/4`, `ff00::/8` | not one host |
| broadcast `255.255.255.255`, and the reserved block `240.0.0.0/4` | not one host |
| link-local `169.254.0.0/16`, `fe80::/10` | see below |

A network is refused if it contains or overlaps any of these ranges, so
`0.0.0.0/0` and `::/0` are refused too. (A network such as `2001:db8::/64`
contains ISATAP-form addresses among ordinary ones; it is accepted, and
each ISATAP-form address in it is refused when a tool asks about it.)

A listed IPv4 network of /30 or broader is accepted, but `permits` refuses
its first (network) and last (all-ones, directed broadcast) address with
`network-or-broadcast`: they are not hosts, and a packet to the broadcast
address may reach every host on the network. If the owner's network is
larger than the one listed and such an address is really one host, list it
as its own `address`; then it is permitted. /31 and /32 are unaffected.

A CIDR must have no host bits set: `192.0.2.1/24` is refused (write
`192.0.2.0/24` for the network, or `address = "192.0.2.1"` for the host).
The prefix length is decimal without leading zeros. `network =
"192.0.2.7/32"` is accepted and is the same as `address = "192.0.2.7"`.
`address` never takes a `/`.

**Loopback** (`127.0.0.0/8`, `::1`) is treated like any other unicast
address: allowed only when listed, never implied. Services on loopback (a
local database, an agent's control port) can be harmed too, and a pass for
a local practice target should say so explicitly. `127.0.0.0/8` is broader
than the cap and needs `whole_network_approved`.

**Link-local** is refused. An IPv6 link-local address means nothing without
an interface, which a pass cannot name, and IPv4 link-local holds cloud
metadata endpoints (169.254.169.254), a classic target of unintended
requests. If a test ever needs link-local, that needs a new format version
with an interface field.

### Breadth cap

A network broader than **/24 (IPv4)** or **/64 (IPv6)** is refused unless the
destination says `whole_network_approved = true`. Write that only when the
written approval names that whole network; otherwise list the narrower
networks the owner approved.

No network broader than **/8 (IPv4)** or **/32 (IPv6)** is accepted, even
with `whole_network_approved`. That is the size of a whole provider
allocation, not one owner's service.

Across the whole pass, `check` and `status` count the union of declared
addresses in each family, including IPv4 network edges. For example, a /28
and two hosts inside it contribute 16 IPv4 addresses even if the service
rules use different ports. A total above 16,777,216 IPv4 addresses (one /8)
or 18,446,744,073,709,551,616 IPv6 addresses (one /64) produces an advisory
warning. Pass validation continues to use the per-network limits above.
JSON reports each total as a decimal string to preserve its exact value.

### Ports and protocols

Ports are 1-65535, written as numbers: `443`, not `"443"`. A quoted string
is a range only: `"start-end"` (inclusive, start not above end, no spaces,
no leading zeros). A quoted single port is refused. An empty list is
refused, and so is a port listed twice in one destination: `[443, 443]`, or
`[80, "1-1024"]`, whose range holds 80 again. The problem names the port.
Ranges that only touch, such as `["1-80", "81-100"]`, are accepted.

`hallpass lint` gives a `wide-port-grant` finding for a destination that
grants more than 1,024 ports, or every port (`"1-65535"`), with the count.
A test normally reaches a few services, so such a grant is more often a
shortcut than what the owner approved. It is advice only: the pass loads.

Only `tcp` and `udp` are accepted: every consumer's transport maps onto one
of them (TLS, HTTP/1 and HTTP/2 are tcp; QUIC, DTLS and RTP are udp), and
both have ports. ICMP has no ports and SCTP has no consumer yet; adding one
is a format change. For a service on both protocols, write two destinations.

## `[ceilings]`

Named counters with the total the owner approved, for example `calls = 6`,
`requests = 500`. Each tool defines its own units.

- Names: 1-32 characters, lower-case letters, digits, `_` and `-`, starting
  with a letter.
- Values: whole numbers from 0 to 1,000,000,000,000. `0` means "none
  approved yet". Negative numbers, fractions and quoted numbers are refused.
- At most 64 counters.

Only a counter listed here can be spent. A pass without `[ceilings]` is
valid; every spend under it is refused as `unknown-counter`.

## Digest

`hallpass digest FILE` prints `sha256:` and the SHA-256 of the file's exact
bytes. Any edit changes it, a comment included. A tool records it at the
start of a run, and passes it to `spend --digest` to be refused
(`pass-changed`) if the pass was edited during the run. The digest is only
printed for a pass that validates.

## Changing a pass

Replace a pass in one step, so that no command reads it half-written.
Write the new version to a file in the same directory, make it private,
check it, then `mv` it over the old file:

```sh
cp engagement.pass.toml engagement.pass.toml.new
$EDITOR engagement.pass.toml.new
chmod 600 engagement.pass.toml.new
hallpass check engagement.pass.toml.new
mv engagement.pass.toml.new engagement.pass.toml
```

`mv` within one directory renames the file in one step: a command that has
already opened the pass reads the old version, and every later one reads
the new version. The path stays the same, so the ledger beside it carries
on. A revision kept under a second name with the same id has no ledger
beside it and is refused as `ledger-elsewhere`.

Most editors, and `cat > FILE`, save by writing the file at its path in
pieces, starting from an empty file. For a moment the path holds only the
first part, and that part can be a valid pass that grants more than the
whole: the pass without its last `names` line, for example. So hallpass
reads a pass whose modification time is less than a quarter second old
again once that quarter second has passed (2.25 seconds when the time has
no fraction of a second, as on file systems that keep whole seconds). If
the bytes, the size or the modification time changed, the pass is refused
as `invalid-pass` (the file changed while hallpass was reading it); run the
command again once the save has finished. A pass modified longer ago is
read once, with no wait.

A save that pauses for more than a quarter second part-way can still be read
part-way. Replace the pass with `mv`, and pin the digest (`--digest`, or
`expect_digest` in Rust) in any tool that spends while the owner may change
the pass. A pinned spend refuses every pass that differs from the pinned
bytes, a part-written one included: `pass-changed`, or `invalid-pass` when
the save is caught in progress.

## Ledger

`spend` records into `<pass file>.ledger` beside the pass (for
`engagement.pass.toml`, `engagement.pass.toml.ledger`), mode 0600. Do not
edit it. It is JSON Lines:

```text
{"hallpass_ledger":1,"pass_id":"example-2026-11"}
{"seq":1,"time":"2026-11-20T09:00:00Z","counter":"calls","n":1,"digest":"sha256:…","note":"first call","prev":"sha256:…"}
```

- The first line names the pass id. A ledger whose id differs from the
  pass's is refused (`ledger-foreign`): changing `id` does not start a new
  count. A new approval is a new pass file.
- Each entry has a sequence number from 1 and `prev`, the SHA-256 of the
  line before it. A missing, reordered or edited line, a cut last line, an
  empty file, or any unreadable line fails closed (`ledger-corrupt`): nothing
  more can be spent until a person repairs it. The one safe repair is
  removing a final line that is cut short: that spend never completed, so
  the tool never got the go-ahead.
- An **adoption** is a line of its own in the chain, written by
  `hallpass adopt FILE --reason TEXT`:

  ```text
  {"seq":3,"time":"…","event":"adopt","reason":"ledger lost in a copy","digest":"sha256:…","carried":{"calls":4},"witness":{"ledger":"/…/engagement.pass.toml.ledger","seq":2,"tail":"sha256:…","totals":{"calls":4},"updated":"2026-11-20T09:00:00Z"},"prev":"sha256:…"}
  ```

  `carried` amounts count as spent; `witness` is what the witness recorded
  before (or null). hallpass 0.1 does not know this line and fails closed
  on a ledger that has one.
- A **reference reconciliation** is a line of its own too, written by
  `hallpass reconcile-references FILE --adoption SEQ --references LIST
  --reason TEXT` after an adoption that may have lost lines:

  ```text
  {"seq":5,"time":"…","event":"reconcile-references","adoption":3,"reason":"every reference in the shift 17 journals","digest":"sha256:…","references":["unit-1","unit-2"],"prev":"sha256:…"}
  ```

  `adoption` is the latest adoption before it that may have lost lines;
  `references` are the caller references the operator listed as possibly
  in those lines. It counts nothing. A hallpass from before it does not
  know this line and fails closed (`ledger-corrupt`) on a ledger that has
  one. See "`reconcile-references`" in [the specification](spec.md).
- A line written under the test clock (`HALLPASS_UNSAFE_TEST_CLOCK`, which
  only debug builds honour) carries `"test_clock":true` just before `prev`,
  in the hash chain. A line without it was written at the real time. A
  ledger holds one kind of line: hallpass refuses to add a test-clock line
  to a ledger with real-clock lines, and the reverse (`ledger-clock-mix`).
  Audits report each test-clock line as `test-clock-entry`, so they never
  call such a ledger `complete`. A hallpass from before the marker fails
  closed (`ledger-corrupt`) on a marked line. See "Test-clock lines" in
  [the specification](spec.md#test-clock-lines).
- **The witness.** Each spend also writes
  `$XDG_STATE_HOME/hallpass/<pass id>.witness` (default
  `~/.local/state/hallpass/`), one JSON object with the last sequence
  number, the hash of the last line, the totals and the ledger's path. A
  ledger that is gone while the witness records lines (`ledger-missing`),
  or that does not hold the witnessed line (`ledger-changed`), permits
  nothing until it is restored or adopted. Do not edit the witness either;
  move it with the ledger if the engagement moves machines (or adopt the
  ledger on the new machine, which is recorded). A move must stop the old
  copy: a copy left on the old machine has its own witness and stays live,
  so both would spend. Move the old ledger away there, and it is refused as
  `ledger-missing`. Back up the witness with the ledger only to restore it.
- `hallpass ledger FILE` lists the entries and verifies the chain; read
  the file with it rather than by hand.
- **When the pass is edited**, spends recorded under the old digest still
  count. The spent amount of a counter is the sum of every entry with that
  counter name, whatever digest it carries. So a ceiling the owner raises
  takes effect at once, a ceiling lowered below what was spent leaves 0
  remaining, and no edit resets the count. A counter removed from the pass
  can no longer be spent; `status` still shows what was spent on it.

## Limits

| Limit | Value |
|---|---|
| pass file size | 1 MiB |
| destinations | 1024 |
| counters | 64 |
| ceiling total | 10^12 |
| note on a spend | 500 characters, one line: no control characters, line separators, Unicode format characters (such as bidirectional controls and zero-width characters), other invisible characters or spaces other than the ASCII space |

### Versioned debit records

A debit represents one unit of work and has a single sequence number. It
shares the version 1 ledger header, predecessor chain and witness with legacy
spends and adoptions. Each named counter is charged once. The charges array
holds 1 to 64 distinct counter names and amounts within the pass ceiling
range. A reader rejects an unfamiliar debit version, unknown fields, an
invalid charge, or a sum outside that range.

The following example shows the writer's field order. The example digest and
predecessor stand in for the SHA-256 digest of the actual pass bytes and the
previous ledger line, respectively.

~~~json
{"seq":2,"time":"2026-11-20T09:00:00Z","event":"debit","version":1,"charges":[{"counter":"requests","n":1},{"counter":"bytes","n":100}],"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","note":"first send","receipt":{"caller_ref":"run-81/unit-02","targets":[{"target":"192.0.2.10:5060/udp","name":"sip.example.net","label":"sip-edge"}]},"prev":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}
~~~

The note and receipt are optional. The receipt is present only if the caller
opts in. A new caller reference is nonblank, at most 128 characters, has
no leading or trailing spaces, and holds only ASCII characters and no
control character, so a reference cannot differ from another only by a
character that does not show, a look-alike space, a combining mark or a
look-alike letter. A reader still
accepts a reference recorded under the earlier rule, which
refused only control characters, line separators and bidirectional
controls. The target list is optional and records the approved literals and
matched labels in request order. Each name is the canonical request name, if
supplied. Targets, names and labels reflect the pass checked at the recorded
digest, so later edits do not rewrite prior receipts. Store only approved
references and targets. The private ledger and any exported JSON containing
receipts carry those details.

Ordinary scalar spends keep their existing record format. A scalar spend
with a receipt uses a debit with one charge. An old reader rejects the debit
line and cannot verify or extend that ledger. Upgrade all readers and
writers sharing a ledger before recording a debit. A target or reference is
never needed to interpret the accounting.

Ledger JSON places the debit once in the sequence-sorted entries array. It
exposes seq, time, event, version, charges, digest, note and receipt. The
last two are null when absent. With a counter filter, a matching debit still
includes its full charge array and receipt. Legacy JSON entries keep their
scalar counter and n fields.


### Witness size

Version 1 witness files are limited to 1 MiB, including the newline.
The larger read limit also accepts valid witnesses written by older
versions that exceeded their 64 KiB read limit. The witness retains
historical counter names across pass edits. Before a spend or adoption
appends an event, the writer checks that the resulting witness fits.
If it would exceed the limit, preserve the existing ledger and witness.
The approval owner can issue a new pass ID with ceilings that account
for the amounts already spent. Deleting old evidence can lose those counts.
