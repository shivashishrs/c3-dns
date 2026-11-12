#!/bin/bash
# Write an image to the development board's `storage` partition (0x190000, 0x80000 bytes).
# Usage: tools/write-storage.sh <bin>
# Used to test the corrupt / unknown-version / torn-save boot paths with images built on the
# host. The image is padded with 0xFF (erased flash) to the full partition, so nothing from
# before survives; images larger than the partition are refused. The port comes from
# `guard.sh --port`; C3DNS_PORT is only a cross-check (a different port is refused).
set -eu
unset GUARD_FAKE_MAC   # never honour the test override when touching hardware
STORE_OFF=0x190000
STORE_SIZE=$((0x80000))
here="$(cd "$(dirname "$0")" && pwd)"
[ $# -eq 1 ] && [ -f "$1" ] || { echo "usage: $0 <bin>" >&2; exit 2; }
size=$(wc -c < "$1" | tr -d ' ')
if [ "$size" -gt "$STORE_SIZE" ]; then
  echo "write-storage: $1 is $size bytes, larger than the partition ($STORE_SIZE); not writing" >&2; exit 1
fi
port=$("$here/guard.sh" --port) || { echo "write-storage: guard refused, not writing" >&2; exit 1; }
[ -n "$port" ] || { echo "write-storage: no port from guard, not writing" >&2; exit 1; }
if [ -n "${C3DNS_PORT:-}" ] && [ "$C3DNS_PORT" != "$port" ]; then
  echo "write-storage: C3DNS_PORT=$C3DNS_PORT but the board is on $port; not writing" >&2; exit 1
fi
padded=$(mktemp "${TMPDIR:-/tmp}/storage-padded.XXXXXX")
trap 'rm -f "$padded"' EXIT
cp "$1" "$padded"
head -c $((STORE_SIZE - size)) /dev/zero | LC_ALL=C tr '\000' '\377' >> "$padded"
[ "$(wc -c < "$padded" | tr -d ' ')" = "$STORE_SIZE" ] || { echo "write-storage: padding failed" >&2; exit 1; }
cd "$here/.."
[ -f espflash.toml ] || { echo "write-storage: $(pwd)/espflash.toml missing, not writing" >&2; exit 1; }
espflash write-bin --port "$port" "$STORE_OFF" "$padded"
