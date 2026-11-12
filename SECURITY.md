# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's private vulnerability reporting
on this repository: open the **Security** tab and choose **Report a vulnerability**. Do not
open a public issue for a security problem. There is no security email address.

Useful details: the firmware version or commit, how the device was set up, the steps to
reproduce, and what an attacker gains. Reports are handled on a best-effort basis by
volunteers; you will get an answer in the advisory thread.

## Supported versions

Only the latest release gets security fixes. Please check that a problem still exists in the
latest release (or on `main`) before reporting it.

## Threat model and known limitations

C3-DNS is a home-network appliance. It assumes a LAN where the people with network access
are mostly trusted, and it is built so that a web page from the internet, or a device on the
LAN without the admin password, cannot change its settings. It is not hardened against an
attacker who controls the LAN, can sniff it, or can touch the board. Details below; design
background is in [docs/design.md](docs/design.md).

### Not an open resolver

DNS (UDP and TCP port 53) and the JSON API answer only LAN sources: the device's own IPv4
subnet, IPv6 link-local and unique-local addresses, and the global IPv6 /64 prefixes the
device learned from router advertisements. Other DNS queries are dropped and other API calls
get 403. (The static UI page itself holds no data and is served to any source with an allowed
`Host` header.) Do not forward port 53 or 80 to the device from the internet. (The non-LAN
drop is covered by host tests; it has not been exercised on hardware with a real non-LAN
source.)

### Plain HTTP and Basic auth, no TLS

The web UI and API use plain HTTP with HTTP Basic authentication (user `admin`). Anyone who
can observe traffic between your browser and the device (an untrusted Wi-Fi segment, a
compromised host on the path) can read the admin password. There is no HTTPS on the device.
Use the UI from a network you trust.

The admin password is stored only as a salted PBKDF2-HMAC-SHA256 hash (10,000 iterations,
16-byte random salt). It must be 12 to 128 characters.

### Sessions and "Sign out"

A password check takes about 0.5 s on the C3, so after a successful check the device
remembers the SHA-256 of the exact `Authorization` header for up to 10 idle minutes (4
slots). The web page keeps that header (base64 of `admin:password`) in the browser tab's
`sessionStorage` until the tab is closed.

"Sign out" only forgets the header in that tab and shows the login form. It does **not**
revoke the device's cached session: the same header stays valid on the device for up to 10
idle minutes, and anyone who holds it can use it until then. Changing the admin password
clears every cached session.

### Online password guessing

- At most 12 password checks per minute for all clients together, one at a time (17,280 a
  day). That is fine for a random password of 12 or more characters and weak for a common
  or breached password. Use a random one.
- After 5 failures a client is locked out for 60 s. The lockout is keyed by the full client
  address, so a client rotating IPv6 privacy addresses can dodge it; the global cap above
  still bounds the total number of guesses.
- Three or more client addresses guessing continuously can keep fresh logins at 429 ("try
  again") indefinitely. Sessions that are already cached keep working.

### Cross-site requests (CSRF)

Every state-changing request (POST) must carry the header `X-Requested-With: c3-dns`. A web
page on another origin cannot add a custom header without a CORS preflight, and the device
never answers preflights or sends CORS headers. The API uses no cookies, so a cross-site page
also has no ambient session to ride on.

### DNS rebinding

Every UI and API request must carry a `Host` header naming the device: `adblock.local`, the
configured own name (default `adblock.home`), or one of the device's own IP addresses (IPv6
in brackets), with an optional port. Any other `Host`, or none, is refused with 421 before
authentication. This stops a malicious site that rebinds its own domain name to the device's
address from talking to the API through your browser.

### The setup access point

When the device has no stored Wi-Fi setting (first boot, or after a 5-second BOOT hold) it
opens an **open** (unencrypted) access point, `C3-DNS-XXXX`, with a setup page at
`http://192.168.4.1/`. During that window:

- anyone in radio range can join it and provision the device, choosing both its Wi-Fi
  network and its admin password;
- the Wi-Fi password you type crosses an unencrypted radio link once.

The window is bounded: after 15 minutes without a completed setup the access point and its
server shut down and the radio stays off until the next BOOT hold or power cycle. The portal
stops accepting requests as soon as one setup has been saved. Provision the device promptly
after the first boot, in a place you control.

The portal opens only when the Wi-Fi setting is definitively absent. If it is present but
cannot be read (damaged data, NVS errors), the device does not open the portal (that would
let the next visitor replace the admin password); it retries, and a BOOT hold starts over.

### Slow clients

The HTTP server handles one request at a time. A LAN client that sends its request very
slowly holds the UI until a watchdog cuts the session's timeouts (about 6 s per connection).
More importantly, unread TCP data pins the device's Wi-Fi receive buffers (8 of them): two or
more LAN clients trickling data often can make DNS lose queries (measured: 17 of 45 probe
queries answered with three clients sending one byte per second). This is a denial-of-service
risk from inside the LAN; it does not give access to anything.

Flood protection for DNS: per-client and global rate limits, a bounded work queue and a
low-heap guard that drops new queries before memory runs out.

### Secrets at rest and physical access

The Wi-Fi SSID and password and the admin password hash are stored in the ESP32-C3's NVS
partition. The Wi-Fi password is stored in plaintext there. **This project does not enable
flash encryption or NVS encryption** (neither is set in `firmware/sdkconfig.defaults`), so
anyone with the board and a USB cable can read the whole flash, including the Wi-Fi
password and the admin password hash, and can reflash the device with any firmware. You can
enable ESP-IDF flash encryption and secure boot yourself; that configuration is not tested
by this project.

Physical access also means full control in other ways: a 5-second BOOT hold clears the stored
Wi-Fi setting and admin password and reopens the setup access point.

Plaintext passwords in buffers owned by C3-DNS are zeroed after use. This is best effort:
copies inside ESP-IDF's HTTP server and the lwIP network stack are not wiped.

### Debug builds

The `debug-hooks` cargo feature adds unauthenticated, LAN-restricted `/debug/*` endpoints that
can change settings and credentials. It exists for development only. Never run a
`debug-hooks` build on a device other people rely on. The default build contains none of them
(every `/debug/` path is a 404).

### Out of scope

- Attackers who can sniff or control your LAN, or who have physical access to the board.
- DNS answers from the upstream resolvers you configure: C3-DNS forwards and caches them and
  does not validate DNSSEC. Spoofed replies are made harder (random IDs, 0x20 case
  randomisation, source-port rotation, exact question matching) but not impossible.
- Blocklist accuracy and false blocks (use an allow rule).
