# Building from source

You only need this to change the firmware. To just use C3-DNS, flash a release from the
[web installer](https://shivashishrs.github.io/c3-dns/) or the
[Releases](https://github.com/shivashishrs/c3-dns/releases) page.

## Layout

| Path | What |
|---|---|
| `dnscore/` | All the logic: DNS wire format, rules, blocklist, cache, rate limits, storage format, web API, auth, setup. Plain Rust, no ESP dependencies, tested on your computer. |
| `firmware/` | The thin ESP-IDF crate: Wi-Fi, sockets, flash, NVS, HTTP server, setup portal, BOOT button. |
| `firmware/ui/index.html` | The web UI (one static page, gzipped into the firmware by `build.rs`). |
| `tools/` | Flash, erase and release scripts, plus the board guard. |
| `web/` | The browser installer page (GitHub Pages). |
| `docs/` | Design, migration guide, this file. |

## Host tests (any OS, stable Rust)

```sh
cd dnscore
cargo test
```

`tools/test-guard.sh` tests the flash scripts with stubbed USB tools (it never touches a board).

## Firmware toolchain

Developed on macOS (Apple silicon); the CI workflow builds on Ubuntu:

1. Rust via [rustup](https://rustup.rs).
2. [espup](https://github.com/esp-rs/espup) 0.17.1, then the `esp` toolchain that
   `firmware/rust-toolchain.toml` selects:
   ```sh
   espup install --targets esp32,esp32c3 --std --toolchain-version 1.97.0.0
   . ~/export-esp.sh        # every new shell
   ```
   (`esp32` is listed so that espup installs the `esp` channel; the C3 itself is RISC-V.)
   Plain `nightly` does not currently build `std` for `riscv32imc-esp-espidf`.
3. `cargo install ldproxy espflash` (CI pins ldproxy 0.3.5 and espflash 4.6.0).
4. Linux only: `libudev-dev`, `cmake`, `ninja-build`, Python 3 with `venv`.

The first build downloads ESP-IDF v5.5.3 into `firmware/.embuild/` (several GB, gitignored).

```sh
cd firmware
cargo build --release
# -> target/riscv32imc-esp-espidf/release/firmware
```

After editing `firmware/partitions.csv`, run `touch firmware/sdkconfig.defaults` (the build
does not watch the CSV).

**Flash budget:** the app partition is 1.5 MB and the release build already uses about 90%
of it. CI prints the size; check it before adding features.

## Flashing your build

The scripts in `tools/` flash only the board you name, so a board that serves your home's DNS
can stay plugged in by mistake without being overwritten:

```sh
tools/guard.sh --list                      # with only your dev board plugged in
echo 'C3DNS_BOARD=AA:BB:CC:DD:EE:FF' > tools/board.env
echo 'C3DNS_PROTECT="11:22:33:44:55:66"' >> tools/board.env   # optional: never flash these
tools/flash.sh firmware/target/riscv32imc-esp-espidf/release/firmware
```

On boards that use the C3's built-in USB port the serial is the chip's MAC address.
The guard reads `ioreg` on macOS and `/dev/serial/by-id` on Linux; elsewhere use `espflash`
directly. `tools/board.env` is gitignored.

| Script | Does |
|---|---|
| `tools/flash.sh <elf>` | Flash the app (bootloader and partition table from `espflash.toml`) and open the serial monitor. |
| `tools/flash-blocklist.sh <bin>` | Write a blocklist image to the `blocklist` partition (0x210000), padded with 0xFF. |
| `tools/erase-nvs.sh` | Erase only NVS: forgets Wi-Fi and the admin password (back to the setup portal). |
| `tools/erase-storage.sh` | Erase only the storage ring: forgets rules, settings and statistics. |
| `tools/write-storage.sh <bin>` | Write a test image to the storage ring (see `dnscore/examples/storage_image.rs`). |
| `tools/make-release.sh <version>` | Build the release images into `dist/` (no board needed). |
| `tools/soak.sh` | Long-running read-only check of a device (latency, heap) into a CSV. |

`espflash.toml` sets 4 MB flash at **80 MHz DIO**. Without it espflash's bundled bootloader
runs the flash at 40 MHz, which roughly doubles the per-query cost.

The espflash monitor needs a terminal. To flash from a script, run it under `script -q <log>`.

## Blocklists

The release image ships [StevenBlack's unified hosts](https://github.com/StevenBlack/hosts)
(MIT, about 56k domains, 14% of the partition). The partition holds about 400k domains. Build your own from any
hosts files, domain lists or basic AdGuard rules:

```sh
curl -fsSLO https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
curl -fsSLO https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt
cd dnscore
cargo run --release --example build_blocklist -- ../my-blocklist.bin ../hosts ../light-onlydomains.txt
cd .. && tools/flash-blocklist.sh my-blocklist.bin
```

Check each list's licence before you share an image built from it (Hagezi's lists are
GPL-3.0). The format is the same as esp32-c3-adblock's `blocklist.bin`, so an existing image
from that project works as is.

## Development builds

| Feature | Adds |
|---|---|
| `dev-wifi` | When NVS holds no Wi-Fi setting, seed it from `firmware/cfg.toml` (copy `cfg.toml.example`; gitignored). Skips the portal on every reflash. The admin password is never seeded. |
| `debug-hooks` | Unauthenticated, LAN-only `/debug/*` endpoints for testing (listed in `firmware/src/debug.rs`). Changes they make are persisted. **Never run this build on a network you do not control.** |

```sh
cargo build --release --features dev-wifi,debug-hooks
```

Release builds never include either feature and carry no credentials.
