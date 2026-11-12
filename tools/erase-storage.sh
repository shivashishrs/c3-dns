#!/bin/bash
# Erase the development board's `storage` partition (0x190000, 0x80000 bytes) and nothing else.
# Usage: tools/erase-storage.sh   (no arguments)
# Used to test the empty-storage boot path. Never erases the whole flash, the app, the
# partition table or the blocklist. The port comes from `guard.sh --port`; C3DNS_PORT is only
# a cross-check (a different port is refused).
set -eu
unset GUARD_FAKE_MAC   # never honour the test override when touching hardware
STORE_OFF=0x190000
STORE_SIZE=0x80000
here="$(cd "$(dirname "$0")" && pwd)"
[ $# -eq 0 ] || { echo "usage: $0   (no arguments; erases only the storage partition)" >&2; exit 2; }
port=$("$here/guard.sh" --port) || { echo "erase-storage: guard refused, not erasing" >&2; exit 1; }
[ -n "$port" ] || { echo "erase-storage: no port from guard, not erasing" >&2; exit 1; }
if [ -n "${C3DNS_PORT:-}" ] && [ "$C3DNS_PORT" != "$port" ]; then
  echo "erase-storage: C3DNS_PORT=$C3DNS_PORT but the board is on $port; not erasing" >&2; exit 1
fi
cd "$here/.."
[ -f espflash.toml ] || { echo "erase-storage: $(pwd)/espflash.toml missing, not erasing" >&2; exit 1; }
exec espflash erase-region --port "$port" "$STORE_OFF" "$STORE_SIZE"
