# C3-DNS design

C3-DNS is a DNS blocker and forwarding resolver for the ESP32-C3 (RISC-V, 400 KB SRAM, 4 MB
flash, no PSRAM). Clients on the LAN use it as their DNS server. It answers names on a
blocklist with `0.0.0.0` / `::`, forwards everything else to upstream resolvers, caches the
answers, and has a small password-protected web UI for rules, statistics and settings.

This document describes how it works and why. The code is the reference: where this text and
the code disagree, the code wins (please open an issue).

Out of scope on purpose: OTA updates, on-device blocklist upload or auto-update, HTTPS on the
device, DNS-over-HTTPS/TLS, DNSSEC validation, DHCP, regex rules, schedules, and keeping the
per-query log across reboots.

## 1. Architecture

The repository has two crates:

| Crate | What it holds | Where it runs |
|---|---|---|
| `dnscore/` | All the logic: DNS wire parsing and building, the decision engine, blocklist lookup, rules, cache, rate limiting, statistics, the storage format and ring, persistence policy, web API request parsing, JSON, auth helpers, the setup form, the Host allowlist | Host (`cargo test`) and device |
| `firmware/` | ESP-IDF glue: Wi-Fi, sockets, tasks, the HTTP server, NVS, flash partitions, SNTP, mDNS, the BOOT button | Device only |

Why the split: the logic can be tested on a laptop in seconds, including power cuts at every
flash operation, malformed packets and auth edge cases, while flashing a board takes minutes.
`dnscore` is `#![forbid(unsafe_code)]` and has no dependencies at all (two dev-dependencies
provide a reference PBKDF2 for tests). The DNS parser handles untrusted input; it bounds every
read, never sizes an allocation from a count field, follows at most 16 compression pointers,
and has randomised mutation tests (`dnscore/tests/fuzz.rs`).

`firmware` is a thin std application on `esp-idf-svc` (ESP-IDF v5.5.3). Its `unsafe` blocks are
limited to ESP-IDF calls (partition mmap, heap statistics, socket options) and carry `SAFETY`
comments.

### Tasks and priorities

DNS must keep working whatever the web UI is doing, so every DNS task runs above the HTTP
server:

```
 priority  task                       role
 --------  -------------------------  ----------------------------------------------------
   23      Wi-Fi driver (ESP-IDF)
   19      dns-udp                    receive UDP/53, LAN + rate + heap checks, enqueue
   18      lwIP tcpip (ESP-IDF)
   11      dns-up                     receive upstream replies, finish pending queries
   10      dns-work x3                parse, decide, answer or forward
   10      dns-tcp (+ per-connection) DNS over TCP/53, at most 4 connections
    5      httpd (ESP-IDF)            web UI and JSON API, one task, 2 connections
    1      main                       BOOT button, network poll, SNTP, saves, status line
```

The UDP receiver sits just above lwIP: it only copies each packet into a small buffer and
queues it. At priority 10 the socket's receive mailbox overflowed during bursts because lwIP
kept preempting it (measured: only ~60 of a 200-query burst reached the application).

Shared state (engine, cache, limiter, statistics, settings) sits behind one mutex that is
held only for in-memory work, never across a socket call, a sleep or a flash erase.

## 2. The query path

```
 UDP/53 packet
     |
     v
 [dns-udp]  non-LAN source? ---------------------------------> drop (counted)
            per-client token bucket, then global bucket ------> drop (counted)
            free heap < 52 KB? --------------------------------> drop (counted)
            copy into a 128-entry queue (full: drop newest)
     |
     v
 [dns-work] older than 900 ms? / heap low again? --------------> drop
            parse query (malformed: drop)
            Engine::decide  (order below)
              Drop  -> no answer (banned client)
              Block -> 0.0.0.0 / :: / empty NOERROR, TTL 60
              Local -> own name or local record, TTL 60
              Resolve:
                cache fresh?  -> answer from cache
                else forward (pending table, 32 entries)
     |
     v
 [dns-up]   reply matched by (id, socket, upstream, exact question)
            CNAME uncloaking -> block whole answer if a chain member is blocked
            cache, then answer the client
            timeout / SERVFAIL / REFUSED -> next upstream
            all failed -> stale cache entry (TTL 30) or SERVFAIL
```

### Admission

1. **LAN only.** A query is answered only if it comes from the device's own IPv4 subnet, an
   IPv6 link-local (`fe80::/10`) or unique-local (`fc00::/7`) address, or one of the global
   /64 prefixes the device learned through SLAAC. Loopback, multicast, unspecified and
   everything else is dropped silently, so the device is never an open resolver.
   (Covered by host tests; the drop of a real non-LAN source has not been exercised on
   hardware because none was available.)
2. **Rate limits** (section 8): a per-client token bucket, then one global bucket for all
   clients together.
3. **Low-heap guard:** below 52 KB of free heap new queries are dropped (section 7).

Clients are keyed by their full address (IPv4-mapped IPv6 counts as IPv4), not by IPv6 /64:
every on-link client shares the router's /64, so a /64 key would merge them all into one
bucket and one ban.

### Decision order

`Engine::decide` stops at the first match:

| # | Check | Result |
|---|---|---|
| 1 | Client is banned | No answer at all |
| 2 | Name is the device's own name (`adblock.home` by default) | Its own addresses |
| 3 | Blocking is paused | Forward (cache skipped) |
| 4 | A custom **allow** rule matches | Forward |
| 5 | A local DNS record matches | Its addresses |
| 6 | A custom **block** rule matches | Blocked |
| 7 | The name or a parent is in the common blocklist | Blocked |
| 8 | Otherwise | Forward |

Allow always wins over block, and over the common list. The own name answers before pause
and allow rules because an allow rule would forward it upstream, where it does not exist;
for the same reason the own name must end in `.home`, `.lan`, `.internal` or `.home.arpa`
(with at most two labels in front), so it can never hijack a public name.

The same order applies to every query type. Blocked answers: `A` gets `0.0.0.0`, `AAAA` gets
`::` (TTL 60), any other type an empty NOERROR answer. Local answers carry the record's
addresses for `A` and `AAAA` (TTL 60) and are empty for other types.

### Cache

- At most 80 entries and 12 KB (response + name + 64 bytes of bookkeeping each), oldest
  evicted first.
- Only NOERROR and NXDOMAIN answers of at most 512 bytes with a TTL above zero are stored;
  truncated answers never. TTLs are capped at 24 hours and aged on the way out.
- A cached answer is given back with the asking client's own letter case and query ID.
- **Serve-stale:** when every upstream fails, an expired entry up to 6 hours past its TTL
  (`stale_secs`) is answered with TTL 30, so clients retry soon once the upstream is back.
- Nothing is cached, and the cache is not read, while blocking is paused: a pause must not
  leave unblocked answers behind or serve cached blocks.

### Upstream forwarding

- Default upstreams, tried in order: Quad9 `9.9.9.9`, Cloudflare `1.1.1.1`,
  `2620:fe::fe`, `2606:4700:4700::1111`. 1 to 8 can be set in the UI, at least one IPv4.
  IPv6 upstreams are used only while the device has a global IPv6 address.
- 800 ms per attempt; on timeout, SERVFAIL or REFUSED the next upstream is tried. At most 32
  queries are in flight; when the table is full a stale answer is used if there is one,
  else the query is dropped.
- One dual-stack UDP socket talks to every upstream. Spoof resistance with a single source
  port: random query IDs, 0x20 case randomisation of the name (turned off for an upstream
  that echoes a different case 3 times in a row, re-tried after 10 minutes), replies
  matched on ID, socket, upstream address and the exact question, and the socket replaced
  (new ephemeral port) every 60 s or 2,000 sends.
- The EDNS UDP size is clamped to 1232 to avoid fragmented answers. A truncated answer is
  retried over TCP (up to 8 KB).
- An upstream equal to one of the device's own addresses is refused (it would loop).

### CNAME uncloaking

Some trackers hide behind a first-party name that is a CNAME for a tracking domain. After
an upstream answer, every name in its CNAME chain is checked against the custom rules and
the common list. If any member is blocked and none is allowed, the whole answer is replaced
by a blocked answer, which is cached for 60 s (so a newly added allow rule takes effect for
that name within a minute). This was observed working on hardware for real cloaked names
whose own names are not on the list.

### DNS over TCP

TCP/53 is served too (dual-stack listener): at most 4 connections, 16 queries per
connection, 3 s idle timeout, 2 s per framed query and 10 s per connection however slowly a
client trickles. A TCP client waits at most 6 s for an upstream answer.

### IPv6 and pause

DNS is served on IPv4 and IPv6 from dual-stack sockets (`[::]:53`). The device takes a
link-local address and a global address through SLAAC (this needed non-default netif flags
in ESP-IDF); advertise its IPv6 address through your router's RDNSS or DHCPv6 settings if you
want IPv6 DNS transport. `AAAA` queries are blocked, cached and forwarded like `A`.

Blocking can be paused for 30 s, 5 min or 30 min (`POST /api/pause`) and resumed early.
While paused every name is forwarded; bans and the own name still apply. The pause is held
in memory only.

## 3. The common blocklist

The common blocklist uses the idea of
[esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) (MIT): keep **hashes**
in flash, not domain strings in RAM.

- **Format:** each domain is hashed with 64-bit FNV-1a over its lower-case bytes and
  truncated to the low 40 bits. The hashes are sorted, de-duplicated and stored as 5 bytes
  each, little-endian, with no header. The format is byte-for-byte compatible with the
  `blocklist.bin` that esp32-c3-adblock's `tools/build_blocklist.py` produces.
- **Storage:** the `blocklist` partition (0x210000, 1,984 KB) is memory-mapped read-only at
  boot. The image is padded with `0xFF`; the end of the list is found by binary search for
  the first all-`0xFF` record, so no length header is needed.
- **Capacity:** 2,031,616 bytes / 5 = **406,323 domains**. A 121,044-domain list uses about
  0.6 MB.
- **Lookup:** binary search over the mapped flash, about 17 reads for 121k entries. Measured
  on hardware: **40 us per search** (1,000 searches, half hits; measured with the flash at
  40 MHz, before the 80 MHz setting). RAM cost: none beyond the mapping.
- **Parent matching:** for `a.b.ads.example.com` the device checks `a.b.ads.example.com`,
  `b.ads.example.com`, `ads.example.com`, `example.com` and `com` in turn and stops at the
  first hit. A leading `www.` is ignored at each step (the builder strips it too).
- **Collisions:** a 40-bit hash can collide. The chance that a given unlisted name matches
  one of 121k entries is about 1 in 9 million per hash checked (1 in 2.7 million with a full
  partition). The fix for any false block is an allow rule.

Release images ship a list built from StevenBlack's unified hosts list (MIT). The list
changes only by rebuilding the image on a computer and writing the partition over USB. Build
your own (any list whose licence suits you, GPL-licensed ones included, since you build it
yourself) from hosts files, plain domain lists or basic AdGuard rules (`||domain^`;
`@@||domain^` removes a domain):

```sh
cd dnscore
cargo run --release --example build_blocklist -- out.bin hosts.txt other-list.txt
../tools/flash-blocklist.sh out.bin
```

`flash-blocklist.sh` refuses images larger than the partition and pads smaller ones with
`0xFF` to the full partition, so no stale records survive past the new end.

## 4. Custom rules, local records and bans

Rules are added in the UI and kept as text in RAM and in storage.

| Pattern | Matches |
|---|---|
| `example.com` | that name only |
| `\|\|example.com^` | that name and every subdomain |
| `*.ads.*` | glob, `*` spans any characters including dots (at most 128 characters, 8 stars) |

Exact names and subtrees are hash-set lookups; globs run only when those miss. Local records
map a name to 1 to 8 IPv4/IPv6 addresses. Bans (at most 64) drop every query from one client
address.

**Memory budget, not a count:** your custom rules, local records and bans together may use 10 KB of
estimated heap (`OWNER_RAM_BUDGET` in `firmware/src/http.rs`; the per-item model in
`dnscore/src/budget.rs` was fitted to measured heap deltas). That is about 90 typical rules
plus a few records and bans. Beyond it the UI refuses additions with "No room: ... X KB of
Y KB". Hard caps of 500 rules and 100 records also exist, but the budget is reached first.

## 5. Flash map

4 MB flash, one app slot, no OTA, nothing left empty (`firmware/partitions.csv`):

| Name | Offset | Size | Contents |
|---|---|---|---|
| bootloader + partition table | 0x0 | 36 KB | |
| `nvs` | 0x9000 | 24 KB | Wi-Fi setting and admin password hash (namespace `c3dns`), PHY data |
| `phy_init` | 0xF000 | 4 KB | RF calibration |
| `factory` | 0x10000 | 1.5 MB (0x180000) | the application |
| `storage` | 0x190000 | 512 KB (0x80000) | settings, rules, records, bans, daily summaries |
| `blocklist` | 0x210000 | 1,984 KB (0x1F0000) | sorted 40-bit hashes |

`storage` and `blocklist` use data subtype `undefined` (0x06) and are found by label, because
espflash cannot parse custom numeric subtypes. Flash runs at 80 MHz DIO (`espflash.toml`);
code executes from flash through a cache, and at 40 MHz the per-query cost doubled (idle
device time per query went from 3.4 ms to 1.9 ms with 80 MHz).

The default application image is 89.3% of its partition (1,403,920 of 1,572,864 bytes),
about 165 KB left. Any new feature needs a size check first.

## 6. Storage and what persists

| Kept across reboots | Not kept |
|---|---|
| Rules, local records, bans | The query log |
| Settings: upstreams, per-client rate, own name, stale limit | The cache, client table, counters |
| Daily summaries for 7 days (allowed and blocked totals, top 10 queried and top 10 blocked names, names clipped to 64 bytes) | Pause state |

Credentials are not in this storage; they live in NVS (section 10).

**Format:** a hand-written binary blob (`C3DS` magic, version, length, payload, CRC32).

**The ring** (`dnscore/src/ring.rs`): the 512 KB `storage` partition is a ring of 128 sectors
of 4 KB. Each save writes one record into the sectors after the newest good record, erasing
only those, payload first and header last, then reads it back. On boot the record with the
highest sequence number whose header and payload CRCs both check out wins. A record never
takes more than half the ring, so a save never erases the newest good copy: a power cut
mid-save leaves the previous save loadable. This is host-tested with a cut at every flash
operation, and the corrupt/torn cases were also checked on hardware with prepared images.

**Save policy:**

- Checked once a minute; at most one save per 10 minutes and 144 per day, only when
  something changed. Never a write per query.
- Nothing is saved, and no day rolls over, until SNTP has synced this boot and the clock
  reads between 2026 and 2100. A bogus clock would otherwise pin the save budget.
- One save encodes into a single buffer of at most 24 KB (`BLOB_BUDGET`); to fit, the oldest
  summaries are dropped first, then top lists trimmed. Rules and settings are never trimmed
  (over budget the save is refused). A save is skipped unless 40 KB of heap stays free
  after the buffer. A typical blob is 0.1 to 4 KB, one 4 KB sector erase.
- Wear estimate (not measured): even at the daily maximum of 144 saves of one sector, each
  of the 128 sectors is erased about once a day.

**Failure handling:** bad storage never stops DNS. A missing partition, an empty, corrupt or
interrupted store all start with defaults (or the previous save) and show a warning in the
UI. A blob written by a newer firmware also starts with defaults, and storage becomes
read-only for that boot so the newer data is not overwritten.

Days are UTC. A day already summarised (the device rebooted that day) is merged, not
duplicated. (The midnight roll is host-tested; a real midnight roll writing a summary has not
been observed on hardware in a recorded test.)

## 7. Memory

The C3 has no PSRAM, so heap is the scarce resource. The network stack alone costs about
76 KB (measured: 259 KB free before Wi-Fi/HTTP/mDNS start, 183 KB after, with only a stub
DNS socket).

**Fixed sizes** (`firmware/src/dns.rs`, `firmware/sdkconfig.defaults`):

| Item | Size |
|---|---|
| Query log | 64 entries (RAM only) |
| Top queried / top blocked | 50 names each (Space-Saving counters) |
| Client table | 64 clients |
| Response cache | 80 entries, 12 KB |
| Custom rules, records, bans | 10 KB estimated heap |
| DNS work queue | 128 packets, 512-byte buffers |
| Pending upstream queries | 32 |
| Wi-Fi dynamic RX / TX buffers | 8 / 16 |
| lwIP UDP receive mailbox | 32 |
| lwIP TCP send buffer | 2,880 bytes (2 x MSS) per connection |
| HTTP connections | 2 (least recently used closed for a new one) |
| HTTP task stack | 7,168 bytes |

**Low-heap guard:** below 52 KB free (`MIN_FREE_HEAP`), new DNS queries are dropped (counted
as `lowmem`) so a burst cannot drive the allocator into an out-of-memory abort. Work already
in flight dips 15 to 20 KB below the guard. The design floor is 30 KB.

**Measured on hardware** (default caps as above):

| Condition | Free heap |
|---|---|
| Idle after boot, default build | about 107 KB |
| 30 q/s of never-cached names, rule budget full, steady | about 73 KB |
| Same, with one browser polling the UI | lowest 55.7 KB |
| Same, with two UI clients streaming `/api/log` at once | lowest 49.2 to 51.4 KB (0 to 1 queries dropped by the guard per minute) |
| Flood of 400 q/s upstream misses (measured before the web UI existed) | lowest 37.7 KB (guard holding) |

Two concurrent UI clients under load therefore touch the guard; one stays above it. With
three connections the heap fell to 47.2 KB and 18 queries were dropped, which is why the HTTP
server allows two. The Wi-Fi RX buffers were capped at 8 because every queued frame pins one
(~1.6 KB) until the application reads it: with the default 32, a query flood took free heap
to 6 KB.

## 8. Rate limits and bounds

| What | Limit |
|---|---|
| Per client (default, editable 1 to 1000) | burst 50, 20 queries/s sustained |
| Client table | 64; a client new to a full table starts with a burst of 10 (stops address rotation from getting a fresh full burst each time) |
| All clients together | burst 300, 150 queries/s (not persisted; not in the UI) |
| Queued queries | 128, dropped unanswered after 900 ms |
| Web password checks | 12 per minute for all clients together, one at a time |
| Failed logins | 5 per client, then 60 s lockout (16 clients tracked) |
| Setup portal form | 10 attempts per minute, 4 KB body |
| API request body | 2 KB, at most 8 keys |

Over-limit queries are dropped and counted, not refused, so a flooding client gets nothing to
amplify. On hardware, 30 q/s of never-cached names for 60 s with the rule budget full and no
UI client open was answered 1,800 of 1,800 times.

## 9. Web UI and JSON API

`GET /` serves one static page (`firmware/ui/index.html`), gzipped into the firmware at build
time (9.4 KB). It holds no data, so it needs no login. Its Content-Security-Policy allows
only the page's own script and style, by SHA-256 hash (`build.rs` computes them), plus
`frame-ancestors 'none'`, `nosniff` and `no-referrer`. All data is rendered as DOM text nodes
(names in the log come from clients and are untrusted). While visible, the page polls every
5 s, one request at a time.

Tabs: **Overview** (status, pause buttons, totals, rule-budget meter, top allowed and top
blocked), **Log** (filterable, blocked-only toggle), **Clients** (per-client counts, ban and
unban), **Rules** (lookup box that explains why a name is blocked, custom block/allow rules,
local names), **Settings** (upstreams, per-client rate, own name, admin password change,
device info).

### API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/overview` | status, counters, pause, warnings, budget |
| GET | `/api/top?kind=queried\|blocked&n=` | top lists (default 20, max 50) |
| GET | `/api/log?n=` | recent queries (streamed) |
| GET | `/api/clients` | per-client counts and bans |
| GET | `/api/rules` | rules, local records, own name |
| GET | `/api/lookup?d=` | decision and reason for one name |
| POST | `/api/rules` | `{"op":"add"\|"remove","kind":"block"\|"allow","pattern":"..."}` |
| POST | `/api/records` | `{"op":"add","name":"nas.home","ips":[...]}` or `{"op":"remove","name":...}` |
| POST | `/api/ban` | `{"op":"ban"\|"unban","client":"..."}` |
| POST | `/api/pause` | `{"secs":30\|300\|1800}`, or `0` to resume |
| POST | `/api/settings` | any of `upstreams`, `rate_burst`, `rate_per_sec`, `local_name` |
| POST | `/api/password` | `{"old":"...","new":"..."}` |

Replies are JSON, streamed in chunks of at most 512 bytes, with `Cache-Control: no-store`.
`GET /ok` is a plain unauthenticated health check.

### Request checks, in order

1. **Host allowlist (DNS-rebinding defence):** the `Host` header must name the device:
   `adblock.local`, the configured own name, or one of the device's addresses (IPv6 in
   brackets), with an optional port. Anything else, or no `Host`, gets 421 before
   authentication. This applies to the page too.
2. **LAN source only** (same policy as DNS), else 403. This and the following checks apply
   to `/api/*`; the static page needs only step 1.
3. **CSRF header on POST:** `X-Requested-With: c3-dns`. A cross-site page cannot send a
   custom header without a CORS preflight, and the server never answers preflights or sends
   CORS headers. Missing header: 403.
4. **Admin password set:** if not, every API call is 403 with a pointer to the setup portal.
   There is no way to set the first password over the LAN.
5. **Lockout and HTTP Basic auth** (user `admin`). A password check is PBKDF2-HMAC-SHA256 with
   10,000 iterations, about 0.5 s on the C3, so a verified `Authorization` header is
   remembered by its SHA-256 for 10 idle minutes (4 slots, all wiped on a password change).

No cookies are used. The UI keeps the Basic header in the tab's `sessionStorage`; "Sign out"
forgets it in the tab but does not revoke the device's cached session (see `SECURITY.md`).

Refusals sent before the body is read (401, 403, 411, 413, 421, 429) close the connection
instead of draining an announced body. The server has one task; a watchdog notices when it
has been stuck on one client for 3 s and cuts every session's socket timeouts to 300 ms, so a
client trickling its request holds the UI for about 6 s per connection.

## 10. Credentials, setup portal and BOOT button

**Credentials** live in the default NVS partition, namespace `c3dns`, never in the storage
ring: `wifi` (SSID and Wi-Fi password in one blob, written in one operation) and `admin` (a
53-byte record: version, iteration count, 16-byte salt from the hardware RNG, PBKDF2 hash;
the password itself is never stored). The admin password must be 12 to 128 characters. The
Wi-Fi driver runs without NVS, so it keeps no second copy of the Wi-Fi password. Neither
secret is ever logged. Plaintext password buffers in our code are zeroed after use, best
effort (`dnscore/src/secret.rs`); copies in ESP-IDF's HTTP and lwIP buffers are not.

The default build carries no credentials. (The `dev-wifi` development feature seeds Wi-Fi
from a gitignored `firmware/cfg.toml` when NVS holds none; never use it for a release.)

**Provisioning state at boot:**

| NVS `wifi` entry | Behaviour |
|---|---|
| Absent (first boot, or after a BOOT hold) | Start the setup portal |
| Present | Join Wi-Fi; if the network is down, keep retrying with backoff (1 s to 60 s), never the portal |
| Unreadable (read error, damaged blob, NVS that will not open) | Do not open the portal (its next save would replace the admin password); retry with backoff 2 s to 60 s; a BOOT hold is the way out |

NVS is opened without ESP-IDF's automatic erase on "no free pages / new version", for the same
reason: an automatic erase would silently open the portal.

**Setup portal:** an open access point `C3-DNS-XXXX` (last two MAC bytes, at most 2 stations)
at `http://192.168.4.1/`. Its DHCP server hands out 192.168.4.1 as DNS and a catch-all DNS on
the AP address answers every name with it, so phones should open the page by themselves. The
form asks for the network (scanned list), the Wi-Fi password and a new admin password twice.
POST only, with a per-boot random token, bodies of at most 4 KB, 10 attempts per minute,
every reflected value HTML-escaped and passwords never echoed. After a valid save the portal
stops accepting requests at once and the device restarts about 1.5 s later.

The AP is open because a WPA2 key would have to be a default password or printed somewhere.
The exposure is bounded: after 15 minutes without a completed setup, the AP and server shut
down and the radio stays off until a BOOT hold or a power cycle. A plain reboot would bring
the open AP straight back, which is why the device waits instead.

Verified on hardware: the AP comes up, the form handlers work (exercised over the LAN in a
debug build), a save stores the credentials and restarts, and the 15-minute shutdown fires.
Not yet verified on hardware: a phone joining the AP, the captive pop-up on iOS/Android, and
the AP-only catch-all DNS answering a real client.

**BOOT button (GPIO9):** polled every 100 ms by the main task. A debounced hold of 5 s clears
the Wi-Fi setting and the admin password (not rules, records or settings) and restarts into
the portal. If NVS cannot even be opened, the hold erases the NVS partition instead (not yet
verified on hardware). The timing logic is host-tested and the clear-and-restart path was verified on hardware through
a debug hook; a physical button press is not yet verified on hardware. Do not hold BOOT while
plugging in or resetting: that enters the chip's download mode.

## 11. Names: `adblock.home` and `adblock.local`

- **Own name** (`local_name`, default `adblock.home`, changeable in Settings): a built-in
  record answering the device's IPv4 address and its global/ULA IPv6 addresses (never
  link-local, at most 8), TTL 60, refreshed every 2 s so DHCP renewals and SLAAC changes are
  picked up. It works for any client that uses the device as its DNS server. It is not
  stored with your local records and does not count against the rule budget.
- **mDNS:** the device announces `adblock.local` (ESP-IDF `espressif/mdns` component), so the
  UI can be reached before any client uses the device for DNS.

Give the device a fixed DHCP reservation on your router: clients are configured with its
address.

## 12. Known limitations

- **Wi-Fi TX power** is capped at 15 dBm (`firmware/src/net.rs`): on the development board,
  at about -72 dBm RSSI, the chip's 20 dBm default never associated. The value is board- and
  placement-specific.
- **Slow HTTP clients and DNS.** An unread TCP segment pins one of the 8 Wi-Fi RX buffers. Two
  or more LAN clients sending request bytes slowly but often can starve DNS of receive
  buffers (measured with three such clients: 49 of 60 probe queries answered at one byte per
  3 s, 17 of 45 at one byte per second; one such client caused no loss). Fixing it needs a
  network-stack configuration change and a new flood measurement.
- **Upstream health is not tracked:** when the first upstream stops answering, every query
  pays its 800 ms timeout before the next one is tried.
- **Burst replies:** 200 queries sent at once were answered 154 to 169 times for locally
  answered names during development; this was measured before the RX buffers were capped at
  8 and has not been re-measured since.
