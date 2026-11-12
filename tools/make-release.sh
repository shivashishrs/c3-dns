#!/bin/bash
# Package release images from an already built firmware ELF. Never touches a board.
#
#   tools/make-release.sh <version> [elf]      (elf defaults to the release build)
#
# Writes to dist/:
#   bootloader.bin           at 0x0       \
#   partition-table.bin      at 0x8000     | the parts the web installer writes; together they
#   c3-dns.bin               at 0x10000    | never touch nvs (0x9000) or storage (0x190000),
#   blocklist.bin            at 0x210000  /  so an update keeps Wi-Fi, password and rules
#   c3-dns-full-4mb.bin      at 0x0: everything in one file for a FIRST install with any
#                            flasher (it blanks nvs and storage: settings are lost)
#   manifest.json            ESP Web Tools manifest (web/ installer)
#   SHA256SUMS, THIRD-PARTY-NOTICES.txt
#
# The blocklist is StevenBlack's unified hosts list (MIT), fetched now; set BLOCKLIST_SOURCES
# (space-separated URLs or files) to build from other lists instead.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/.."
[ $# -ge 1 ] || { echo "usage: $0 <version> [elf]" >&2; exit 2; }
version=$1
elf=${2:-$root/firmware/target/riscv32imc-esp-espidf/release/firmware}
[ -f "$elf" ] || { echo "make-release: no ELF at $elf (build the firmware first)" >&2; exit 1; }
sources=${BLOCKLIST_SOURCES:-https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts}

PART_SIZE=$((0x1F0000))
FLASH_SIZE=$((0x400000))
dist="$root/dist"
rm -rf "$dist"; mkdir -p "$dist"
work=$(mktemp -d "${TMPDIR:-/tmp}/c3dns-release.XXXXXX"); trap 'rm -rf "$work"' EXIT

pad_ff() { # pad_ff <file> <size>: append 0xFF up to <size> bytes
  local size; size=$(wc -c < "$1" | tr -d ' ')
  [ "$size" -le "$2" ] || { echo "make-release: $1 is $size bytes, over $2" >&2; exit 1; }
  [ "$size" -eq "$2" ] || head -c $(($2 - size)) /dev/zero | LC_ALL=C tr '\000' '\377' >> "$1"
}

# 1. Blocklist.
lists=()
i=0
for s in $sources; do
  i=$((i + 1))
  if [ -f "$s" ]; then lists+=("$s"); else curl -fsSL --retry 3 -o "$work/list$i" "$s"; lists+=("$work/list$i"); fi
done
(cd "$root/dnscore" && cargo run --quiet --release --example build_blocklist -- "$work/blocklist.raw" "${lists[@]}") \
  | tee "$work/blocklist.txt"
cp "$work/blocklist.raw" "$dist/blocklist.bin"
pad_ff "$dist/blocklist.bin" "$PART_SIZE"   # no stale records survive past the list's end

# 2. App, bootloader, partition table: one merged image from espflash (padded to 4 MB), cut
# into parts.
(cd "$root" && espflash save-image --chip esp32c3 --merge \
  --partition-table firmware/partitions.csv \
  --flash-size 4mb --flash-mode dio --flash-freq 80mhz \
  "$elf" "$work/merged.bin" >/dev/null)
merged_size=$(wc -c < "$work/merged.bin" | tr -d ' ')
[ "$merged_size" -le "$FLASH_SIZE" ] || { echo "make-release: merged image too big ($merged_size)" >&2; exit 1; }
pad_ff "$work/merged.bin" "$FLASH_SIZE"
cut_out() { # cut_out <out> <offset> <size>   (both multiples of 4 KB)
  dd if="$work/merged.bin" of="$1" bs=4096 skip=$(($2 / 4096)) count=$(($3 / 4096)) 2>/dev/null
}
cut_out "$dist/bootloader.bin" 0 $((0x8000))
cut_out "$dist/partition-table.bin" $((0x8000)) $((0x1000))
cut_out "$dist/c3-dns.bin" $((0x10000)) $((0x180000))
# Trailing 0xFF from the merge padding is harmless but makes the download bigger: drop it.
python3 - "$dist/c3-dns.bin" <<'PY'
import sys
p = sys.argv[1]; b = open(p, 'rb').read().rstrip(b'\xff')
b += b'\xff' * (-len(b) % 16)
open(p, 'wb').write(b)
PY
[ "$(head -c 2 "$dist/partition-table.bin" | od -An -tx1 | tr -d " \n")" = aa50 ] \
  || { echo "make-release: no partition table at 0x8000" >&2; exit 1; }
[ "$(head -c 1 "$dist/c3-dns.bin" | od -An -tx1 | tr -d " \n")" = e9 ] \
  || { echo "make-release: no app image at 0x10000" >&2; exit 1; }
[ "$(head -c 1 "$dist/bootloader.bin" | od -An -tx1 | tr -d " \n")" = e9 ] \
  || { echo "make-release: no bootloader at 0x0" >&2; exit 1; }

# 3. Full 4 MB image for first installs: everything below 0x210000, then the blocklist.
dd if="$work/merged.bin" of="$dist/c3-dns-full-4mb.bin" bs=4096 count=$((0x210000 / 4096)) 2>/dev/null
cat "$dist/blocklist.bin" >> "$dist/c3-dns-full-4mb.bin"
[ "$(wc -c < "$dist/c3-dns-full-4mb.bin" | tr -d ' ')" = "$FLASH_SIZE" ] \
  || { echo "make-release: full image is not 4 MB" >&2; exit 1; }

# 4. Web installer manifest (ESP Web Tools), notices, checksums.
cat > "$dist/manifest.json" <<JSON
{
  "name": "C3-DNS",
  "version": "$version",
  "new_install_prompt_erase": true,
  "builds": [
    {
      "chipFamily": "ESP32-C3",
      "parts": [
        { "path": "bootloader.bin", "offset": 0 },
        { "path": "partition-table.bin", "offset": 32768 },
        { "path": "c3-dns.bin", "offset": 65536 },
        { "path": "blocklist.bin", "offset": 2162688 }
      ]
    }
  ]
}
JSON
{
  echo "C3-DNS $version: third-party data in blocklist.bin and c3-dns-full-4mb.bin"
  echo
  echo "blocklist.bin holds 40-bit hashes of the domains in:"
  for s in $sources; do echo "  $s"; done
  echo "built $(date -u +%Y-%m-%dT%H:%MZ):"
  sed -e 's/^/  /' -e 's/ -> .*//' "$work/blocklist.txt"
  echo
  echo "StevenBlack/hosts is MIT licensed: https://github.com/StevenBlack/hosts/blob/master/license.txt"
  echo "If you build an image from other lists, their licences apply to that image."
} > "$dist/THIRD-PARTY-NOTICES.txt"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$dist" && sha256 bootloader.bin partition-table.bin c3-dns.bin blocklist.bin c3-dns-full-4mb.bin > SHA256SUMS)
ls -l "$dist"
