#!/bin/bash
# Flash an app ELF to the development board only. Usage: tools/flash.sh <elf>
# The port is the configured board's own serial device as found by `guard.sh --port`.
# C3DNS_PORT, if set, is only a cross-check: a different port is refused.
set -eu
unset GUARD_FAKE_MAC   # never honour the test override when touching hardware
here="$(cd "$(dirname "$0")" && pwd)"
[ $# -eq 1 ] && [ -f "$1" ] || { echo "usage: $0 <elf>" >&2; exit 2; }
port=$("$here/guard.sh" --port) || { echo "flash: guard refused, not flashing" >&2; exit 1; }
[ -n "$port" ] || { echo "flash: no port from guard, not flashing" >&2; exit 1; }
if [ -n "${C3DNS_PORT:-}" ] && [ "$C3DNS_PORT" != "$port" ]; then
  echo "flash: C3DNS_PORT=$C3DNS_PORT but the board is on $port; not flashing" >&2; exit 1
fi
# Run espflash from the repo root so it picks up espflash.toml (v3 partition table, 4 MB).
img="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
cd "$here/.."
[ -f espflash.toml ] || { echo "flash: $(pwd)/espflash.toml missing, not flashing" >&2; exit 1; }
exec espflash flash --port "$port" --monitor "$img"
