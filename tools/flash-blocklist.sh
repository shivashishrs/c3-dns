#!/bin/bash
# Write a blocklist image to the development board's blocklist partition (0x210000, 0x1F0000 bytes).
# Usage: tools/flash-blocklist.sh <bin>
# The image is padded with 0xFF to the full partition size so no stale records survive past
# its end (the firmware counts records up to the first all-0xFF one). Bins larger than the
# partition are refused. The port comes from `guard.sh --port`; C3DNS_PORT is only a cross-check.
set -eu
unset GUARD_FAKE_MAC   # never honour the test override when touching hardware
PART_SIZE=$((0x1F0000))
here="$(cd "$(dirname "$0")" && pwd)"
[ $# -eq 1 ] && [ -f "$1" ] || { echo "usage: $0 <bin>" >&2; exit 2; }
size=$(wc -c < "$1" | tr -d ' ')
if [ "$size" -gt "$PART_SIZE" ]; then
  echo "flash-blocklist: $1 is $size bytes, larger than the partition ($PART_SIZE); not writing" >&2; exit 1
fi
port=$("$here/guard.sh" --port) || { echo "flash-blocklist: guard refused, not writing" >&2; exit 1; }
[ -n "$port" ] || { echo "flash-blocklist: no port from guard, not writing" >&2; exit 1; }
if [ -n "${C3DNS_PORT:-}" ] && [ "$C3DNS_PORT" != "$port" ]; then
  echo "flash-blocklist: C3DNS_PORT=$C3DNS_PORT but the board is on $port; not writing" >&2; exit 1
fi
padded=$(mktemp "${TMPDIR:-/tmp}/blocklist-padded.XXXXXX")
trap 'rm -f "$padded"' EXIT
cp "$1" "$padded"
head -c $((PART_SIZE - size)) /dev/zero | LC_ALL=C tr '\000' '\377' >> "$padded"
[ "$(wc -c < "$padded" | tr -d ' ')" = "$PART_SIZE" ] || { echo "flash-blocklist: padding failed" >&2; exit 1; }
cd "$here/.."
[ -f espflash.toml ] || { echo "flash-blocklist: $(pwd)/espflash.toml missing, not writing" >&2; exit 1; }
espflash write-bin --port "$port" 0x210000 "$padded"
