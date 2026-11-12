#!/bin/bash
# Board guard: exit 0 only if exactly one USB device with a serial is attached and it is the
# board you chose for development. Read-only: never opens a serial port.
#
#   tools/guard.sh          human-readable check
#   tools/guard.sh --port   same check; on success stdout is ONLY that board's serial device
#   tools/guard.sh --list   print the USB serials attached now (to fill in tools/board.env)
#
# Configuration (environment variables win over tools/board.env, which is gitignored):
#   C3DNS_BOARD    USB serial of the development board. On ESP32-C3 boards that use the
#                  chip's built-in USB port this is the chip's MAC, e.g. AA:BB:CC:DD:EE:FF.
#   C3DNS_PROTECT  optional, space-separated serials that must never be flashed (for example
#                  the board that serves DNS to your home). Refused even if it is C3DNS_BOARD.
#
# macOS reads `ioreg`; Linux reads /dev/serial/by-id. GUARD_FAKE_MAC (space-separated serials,
# may be empty) replaces the USB read for tests; the flash scripts unset it and --port refuses
# it. GUARD_OS and GUARD_BYID_DIR exist for tests only.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
board_env_set=${C3DNS_BOARD+set}
protect_env_set=${C3DNS_PROTECT+set}
env_board=${C3DNS_BOARD:-}
env_protect=${C3DNS_PROTECT:-}
if [ -f "$here/board.env" ]; then
  # shellcheck source=/dev/null
  . "$here/board.env"
fi
[ -n "$board_env_set" ] && C3DNS_BOARD=$env_board
[ -n "$protect_env_set" ] && C3DNS_PROTECT=$env_protect
BOARD=$(printf '%s' "${C3DNS_BOARD:-}" | tr 'a-f' 'A-F')
PROTECT=$(printf '%s\n' "${C3DNS_PROTECT:-}" | tr ' ' '\n' | sed '/^$/d' | tr 'a-f' 'A-F')

mode=check
case "${1:-}" in
  --port) mode=port ;;
  --list) mode=list ;;
  "") ;;
  *) echo "usage: $0 [--port|--list]" >&2; exit 2 ;;
esac
# Human-readable lines go to stderr in --port mode so stdout carries only the port.
say() { if [ "$mode" = port ]; then echo "$@" >&2; else echo "$@"; fi; }

os=${GUARD_OS:-$(uname -s)}
byid=${GUARD_BYID_DIR:-/dev/serial/by-id}
# Linux by-id names look like usb-Espressif_USB_JTAG_serial_debug_unit_AA:BB:CC:DD:EE:FF-if00:
# the serial is the last "_" field before "-ifNN".
linux_serial() { basename "$1" | sed -nE 's/^usb-.*_([^_]+)-if[0-9]+(-port[0-9]+)?$/\1/p' | tr 'a-f' 'A-F'; }
fake=0
tree=""
if [ -n "${GUARD_FAKE_MAC+set}" ]; then
  fake=1
  echo "!!! FAKE MAC IN USE (test only): GUARD_FAKE_MAC='$GUARD_FAKE_MAC' replaces the USB read !!!" >&2
  serials=$(printf '%s\n' "$GUARD_FAKE_MAC" | tr ' ' '\n' | sed '/^$/d' | tr 'a-f' 'A-F' | sort -u)
elif [ "$os" = Darwin ]; then
  tree=$(ioreg -r -c IOUSBHostDevice -l)
  serials=$(printf '%s\n' "$tree" | grep '"USB Serial Number"' \
    | sed -E 's/.*"USB Serial Number" = "([^"]*)".*/\1/' | sed '/^$/d' | tr 'a-f' 'A-F' | sort -u)
elif [ "$os" = Linux ]; then
  serials=$(for l in "$byid"/usb-*; do [ -e "$l" ] || [ -L "$l" ] || continue; linux_serial "$l"; done \
    | sed '/^$/d' | sort -u)
else
  echo "refusing: unsupported OS '$os' (macOS and Linux only); use espflash directly" >&2; exit 1
fi

if [ "$mode" = list ]; then
  printf '%s\n' "${serials:-}" | sed '/^$/d'
  exit 0
fi

say "usb serial(s): $(printf '%s' "${serials:-<none>}" | tr '\n' ' ')"

if [ -z "$BOARD" ]; then
  echo "refusing: no development board configured." >&2
  echo "  Plug in only the board you want to flash, run 'tools/guard.sh --list', then:" >&2
  echo "  echo 'C3DNS_BOARD=<that serial>' > tools/board.env" >&2
  exit 1
fi
for p in $PROTECT; do
  if printf '%s\n' "$serials" | grep -qxF "$p"; then
    echo "refusing: protected board ($p) is on USB" >&2; exit 1
  fi
done
count=$(printf '%s\n' "$serials" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$count" = 0 ]; then
  echo "refusing: no USB board found" >&2; exit 1
fi
if [ "$count" != 1 ]; then
  echo "refusing: more than one USB device with a serial ($count); unplug all but the board" >&2; exit 1
fi
if [ "$serials" != "$BOARD" ]; then
  echo "refusing: unknown device $serials (configured board is $BOARD)" >&2; exit 1
fi

if [ "$mode" = check ]; then
  say "ok: board $BOARD"
  exit 0
fi

if [ "$fake" = 1 ]; then
  echo "refusing: --port cannot derive a port from a fake MAC" >&2; exit 1
fi
if [ "$os" = Darwin ]; then
  # Find the port inside the board's own ioreg node. Each "+-o " marker starts a node; its
  # column is the node's depth. The board's node is the (outermost) node whose own properties
  # carry its serial. A callout counts only if it belongs to that node or a node nested deeper;
  # the next node at the same depth or shallower ends the subtree. So a serial-less sibling on
  # the same hub (e.g. another USB-UART) can never supply the port.
  ports=$(printf '%s\n' "$tree" | awk -v board="$BOARD" '
    /^[ |]*\+-o / { d = index($0, "+-o "); if (anchor && d <= anchor) anchor = 0; cur = d; next }
    /"USB Serial Number"/ { s = $0; sub(/.*"USB Serial Number" = "/, "", s); sub(/".*/, "", s)
                            if (toupper(s) == board && !anchor && cur) anchor = cur }
    /"IOCalloutDevice"/   { if (anchor) { p = $0; sub(/.*"IOCalloutDevice" = "/, "", p); sub(/".*/, "", p); print p } }
    ' | sed '/^$/d' | sort -u)
else
  ports=$(for l in "$byid"/usb-*; do
      [ "$(linux_serial "$l")" = "$BOARD" ] || continue
      if [ -n "${GUARD_BYID_DIR:-}" ]; then readlink "$l"; else readlink -f "$l"; fi
    done | sed '/^$/d' | sort -u)
fi
# Inherent window: the board could be swapped between this check and espflash opening the
# port. The flash scripts call espflash immediately after; swapping boards while a flash
# script runs defeats any check of this kind.
pcount=$(printf '%s\n' "$ports" | sed '/^$/d' | wc -l | tr -d ' ')
if [ "$pcount" != 1 ]; then
  echo "refusing: the board's serial port was not found or is ambiguous (${pcount} devices)" >&2; exit 1
fi
say "ok: board $BOARD on $ports"
echo "$ports"
exit 0
