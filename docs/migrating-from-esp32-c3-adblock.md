# Migrating from esp32-c3-adblock

This guide is for people who run [esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)
on an ESP32-C3 and want to move to C3-DNS, on the same board or on a new one. It keeps a
way back at every step: a full flash backup of the old board, and a router setting you can
undo in seconds.

What carries over and what does not:

| | |
|---|---|
| Blocklist | **Same format.** C3-DNS reads the `blocklist.bin` that esp32-c3-adblock's `tools/build_blocklist.py` produces (sorted 40-bit FNV-1a hashes, 5 bytes each, little-endian, no header). |
| Wi-Fi and admin password | Not imported. You set them again in C3-DNS's setup portal. |
| Custom blocked domains, bans, counters | Not imported. Add custom rules again in the web UI (Rules tab). C3-DNS bans by client IP address, not MAC. |
| Hostname | The UI moves from `c3adblock.local` to `adblock.local` (and `adblock.home` for clients that use the device as DNS). |
| OTA, on-device list upload, remote list updates | Not available in C3-DNS. The list is updated by flashing its partition over USB. |
| Classic ESP32 boards | Not supported. C3-DNS targets the ESP32-C3 with 4 MB flash only. |

## What you need

- The board on USB, and a computer with macOS or Linux (the helper scripts support both).
- [espflash](https://github.com/esp-rs/espflash) 4.x on your `PATH`.
- Either a C3-DNS release (the browser installer, or the release images), or the toolchain
  to build from source ([building.md](building.md)).
- A blocklist image: the one in the release (StevenBlack's unified hosts list), one you
  build (step 5), or the `blocklist.bin` you already use with esp32-c3-adblock. On the old
  device the list lives inside a LittleFS filesystem, so use the `.bin` **file** (from that
  project's `data/` folder or its release), not a piece of the flash backup.
- A second DNS server your router can hand out while you switch (your ISP's or a public
  resolver), so the household keeps DNS if something goes wrong.

Serial ports below are written as `/dev/cu.usbmodemXXXX` (macOS) or `/dev/ttyACM0` (Linux);
use whatever your system shows. `<board-ip>` is the device's LAN address.

## 1. Back up the old board (full 4 MB)

Do this before anything else. With **only** the old board plugged in:

```sh
espflash board-info --port /dev/ttyACM0          # confirm it is the board you expect
espflash read-flash --port /dev/ttyACM0 0 0x400000 old-c3-backup.bin
espflash read-flash --port /dev/ttyACM0 0 0x400000 old-c3-backup-2.bin
shasum -a 256 old-c3-backup.bin old-c3-backup-2.bin   # Linux: sha256sum
```

The two hashes must match; if they differ, read again. Keep the backup somewhere safe and
outside any git repository: it contains your old Wi-Fi password and the old firmware's
settings. If you have a second C3, rehearse the restore (step 8) on it once; a restore that
was never tried is a hope, not a plan.

## 2. Prepare the router

- Give the board a **DHCP reservation**. If you reuse the same board, its MAC (and so an
  existing reservation) stays the same, and it will come back on its old address.
- While you switch, configure the router's DHCP to hand out a second DNS server next to the
  board, or point it at that other server entirely for the duration.

## 3. Tell the helper scripts which board to flash

The scripts in `tools/` refuse to write unless exactly one USB device is attached and its USB
serial is the one you configured. On ESP32-C3 boards that use the chip's built-in USB port,
the serial is the chip's MAC address.

```sh
tools/guard.sh --list                                  # prints the attached serial
echo 'C3DNS_BOARD=AA:BB:CC:DD:EE:FF' > tools/board.env  # that serial (board.env is gitignored)
tools/guard.sh                                         # must say the board is OK
```

If you have other ESP boards that must never be flashed, list their serials in
`C3DNS_PROTECT` in the same file. Boards with a separate USB-to-UART chip may not report a
usable serial; then the scripts cannot identify them and you have to run `espflash` by hand
with great care.

## 4. Erase the old layout

esp32-c3-adblock uses two OTA app slots and a LittleFS filesystem. Those areas overlap
C3-DNS's `storage` (0x190000) and `blocklist` (0x210000) partitions, and its NVS layout
differs. The whole chip must be blank (or fully overwritten) so no old data is misread.
Any of these does it:

- the browser installer: choose **Erase device** when it asks (it asks on a first install);
- the release's `c3-dns-full-4mb.bin`, which covers the whole flash (step 5, option A);
- or explicitly:

  ```sh
  espflash erase-flash --port "$(tools/guard.sh --port)"
  ```

This is the point of no return for the old firmware on this board (until you restore the
backup).

## 5. Flash C3-DNS

**Option A, a release.** Use the browser installer linked from the README (choose
**Erase device**), or write the full image, which contains the bootloader, partition table,
firmware and the default blocklist, and blanks NVS and storage:

```sh
espflash write-bin --port "$(tools/guard.sh --port)" 0x0 c3-dns-full-4mb.bin
```

Then continue with "Your own blocklist" below if you want a different list, or go to step 6.

**Option B, from source.** Flash the blocklist first, then the firmware (below).

### Your own blocklist

The blocklist goes to the `blocklist` partition at 0x210000. The script refuses images larger
than the partition (2,031,616 bytes, 406,323 domains) and pads smaller ones with `0xFF`:

```sh
tools/flash-blocklist.sh blocklist.bin
```

Lists of up to about 406,000 domains fit, so esp32-c3-adblock's default list fits; its very
large "ultimate" list (over 500,000 domains) does not.

To build your own image from hosts files or domain lists (for example a list whose licence
you prefer not to redistribute, such as a GPL-licensed one):

```sh
cd dnscore
cargo run --release --example build_blocklist -- ../blocklist.bin list1.txt list2.txt
```

### Firmware from source

Build and flash the firmware (this writes the bootloader, the partition table and the app,
then opens a serial monitor; quit it with Ctrl+C):

```sh
cd firmware && cargo build --release && cd ..
tools/flash.sh firmware/target/riscv32imc-esp-espidf/release/firmware
```

The flash scripts run `espflash` from the repository root so it picks up `espflash.toml`
(the partition table, 4 MB, flash at 80 MHz DIO). Do not flash the app with plain
`espflash flash` from elsewhere: espflash would write its default partition table instead.

On boot the serial log should show `blocklist: N records mapped` with your list's size, and,
since nothing is stored yet, the setup portal starting.

## 6. Provision through the setup portal

1. On a phone or laptop, join the open Wi-Fi network `C3-DNS-XXXX`.
2. The setup page should open by itself; if it does not, open `http://192.168.4.1/`.
3. Pick your network, enter its password, and choose an admin password (12 to 128
   characters; use a random one) twice.
4. The device saves, restarts and joins your Wi-Fi. Reconnect your phone or laptop to your
   normal network.

The access point is open and anyone in range can use it while it is up, so do this right
away. It shuts down after 15 minutes without a completed setup; hold BOOT for 5 seconds (or
power-cycle) to start it again. See [SECURITY.md](../SECURITY.md). Note: the portal has been
tested on hardware, but a phone joining the access point and the automatic captive pop-up
are not yet verified on hardware; opening `http://192.168.4.1/` by hand is the fallback.

Find the device's address in your router's DHCP client list, in the serial log
(`net: ipv4 ...`), or by name with `ping adblock.local`.

## 7. Check it, then switch the network over

From a computer on the LAN:

```sh
dig @<board-ip> example.com          # a real answer
dig @<board-ip> doubleclick.net      # 0.0.0.0 if it is on your list
dig @<board-ip> adblock.home         # the board's own address
```

Open `http://adblock.local/` (or `http://<board-ip>/`), sign in as `admin`, and look at the
Overview and Log tabs. Then:

- If the board kept its old address (same board, same reservation), the router already sends
  clients to it. Otherwise set the router's DHCP DNS server to `<board-ip>`.
- For IPv6 clients, advertise the board's IPv6 address via RDNSS or DHCPv6 if you want DNS
  over IPv6 too.
- Clients pick up the change when they renew their DHCP lease; reconnecting Wi-Fi speeds it up.
- Keep the second DNS server configured for the first week or so, then remove it if you want
  every query to pass through the blocker. (With two servers listed, some clients will
  sometimes bypass blocking.)

## 8. Roll back

**Fast (seconds):** point the router's DNS back at the other resolver. Clients follow at
their next lease renewal or reconnect.

**Full:** restore the old firmware from the backup, with only that board attached:

```sh
espflash write-bin --port "$(tools/guard.sh --port)" 0x0 old-c3-backup.bin
```

Then reset or power-cycle the board. It comes back exactly as it was at step 1, with the old
firmware, settings and blocklist. Writing the backup to a different board also copies the
old board's stored Wi-Fi credentials onto it.
