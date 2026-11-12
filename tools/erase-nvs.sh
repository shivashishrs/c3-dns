#!/bin/bash
# Erase the development board's default `nvs` partition (0x9000, 0x6000 bytes) and nothing else.
# Usage: tools/erase-nvs.sh   (no arguments)
# It holds the Wi-Fi setting and the admin password (namespace `c3dns`; Task 8) plus PHY
# calibration (redone at the next boot). Used to bring the board back to "not provisioned"
# when it cannot be reached on the LAN (e.g. after a wrong stored Wi-Fi password). Never erases
# the whole flash, the app, the storage ring, the partition table or the blocklist. The port
# comes from `guard.sh --port`; C3DNS_PORT is only a cross-check (a different port is refused).
set -eu
unset GUARD_FAKE_MAC   # never honour the test override when touching hardware
NVS_OFF=0x9000
NVS_SIZE=0x6000
here="$(cd "$(dirname "$0")" && pwd)"
[ $# -eq 0 ] || { echo "usage: $0   (no arguments; erases only the nvs partition)" >&2; exit 2; }
port=$("$here/guard.sh" --port) || { echo "erase-nvs: guard refused, not erasing" >&2; exit 1; }
[ -n "$port" ] || { echo "erase-nvs: no port from guard, not erasing" >&2; exit 1; }
if [ -n "${C3DNS_PORT:-}" ] && [ "$C3DNS_PORT" != "$port" ]; then
  echo "erase-nvs: C3DNS_PORT=$C3DNS_PORT but the board is on $port; not erasing" >&2; exit 1
fi
cd "$here/.."
[ -f espflash.toml ] || { echo "erase-nvs: $(pwd)/espflash.toml missing, not erasing" >&2; exit 1; }
exec espflash erase-region --port "$port" "$NVS_OFF" "$NVS_SIZE"
