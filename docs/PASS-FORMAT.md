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
hostname = "sip.example.net"   # what the owner calls it; grants nothing

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
  control characters (newline, tab), no leading or trailing spaces, not
  empty.
- **The file** must be UTF-8, at most 1 MiB, a regular file (not a symbolic
  link), and not writable by group or others (mode 0600 or 0644; `init`
  writes 0600).
- **Field paths** in problems are dotted: `approval.valid_until`,
  `ceilings.calls`, `destination[2].ports`. Destinations count from 1, in
  file order.

## Top level

| Key | Required | Rule |
|---|---|---|
| `format` | yes | the integer `1` |
| `id` | yes | 1-64 characters from letters, digits, `.`, `_`, `-`, starting with a letter or digit. The ledger belongs to this id (see "Ledger") |
| `name` | yes | text, at most 80 characters |
| `[approval]` | yes | see below |
| `[[destination]]` | yes, at least one | see below; at most 1024 |
| `[ceilings]` | no | see below; a pass without it has no counters |

## `[approval]`

| Key | Required | Rule |
|---|---|---|
| `owner` | yes | who approved: the owner of the destinations (text, at most 200) |
| `reference` | yes | where the written approval is, for example "email of 2026-11-18" (text, at most 200) |
| `operator` | yes | who runs the test (text, at most 200) |
| `valid_from` | yes | the first instant the pass is valid (inclusive) |
| `valid_until` | yes | the first instant it is no longer valid (exclusive); must be later than `valid_from` |
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
| `label` | yes | unique within the pass; same characters as `id`. Every decision names it |
| `address` | one of the two | one literal IP address |
| `network` | one of the two | one CIDR network (`192.0.2.0/28`, `2001:db8::/120`) |
| `protocol` | yes | `"tcp"` or `"udp"` |
| `ports` | yes | `443`, `[80, 443]`, `"8000-8100"`, or a list mixing ports and range strings: `[5060, "10000-10100"]` |
| `hostname` | no | what the owner calls this destination. **Informational only: it grants nothing**, and hallpass never resolves it. A value that is an IP address is refused (put it in `address`) |
| `names` | no | the only host names this destination is approved for, as a list: `names = ["app.example.com", "admin.example.com"]`. **It narrows and never grants**: see below |
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
- A query's name is compared without regard to case, and one trailing dot
  is ignored.
- hallpass is advisory, and this check more than most: nothing on the
  network can see the name inside an encrypted request, so only the tool
  that sends it can keep to it.

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

### Ports and protocols

Ports are 1-65535. A range is `"start-end"` (inclusive, start not above end,
no spaces, no leading zeros). An empty list is refused.

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
- **The witness.** Each spend also writes
  `$XDG_STATE_HOME/hallpass/<pass id>.witness` (default
  `~/.local/state/hallpass/`), one JSON object with the last sequence
  number, the hash of the last line, the totals and the ledger's path. A
  ledger that is gone while the witness records lines (`ledger-missing`),
  or that does not hold the witnessed line (`ledger-changed`), permits
  nothing until it is restored or adopted. Do not edit the witness either;
  back it up with the ledger if the engagement moves machines (or adopt the
  ledger on the new machine, which is recorded).
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
| note on a spend | 500 characters, one line: no control characters, line separators or bidirectional controls |
