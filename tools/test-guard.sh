#!/bin/bash
# Tests for tools/guard.sh, tools/flash.sh, tools/flash-blocklist.sh,
# tools/erase-storage.sh, tools/write-storage.sh and tools/erase-nvs.sh.
# Never touches a board: `ioreg` and `espflash` are replaced by stubs first on PATH.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
PROT=02:00:00:00:00:01   # protected board (made up)
BOARD=02:00:00:00:00:02  # development board (made up)
OTHER=AA:BB:CC:DD:EE:FF
PART_SIZE=$((0x1F0000))
fails=0
# The guard is configured through the environment here, so a local tools/board.env never
# matters; GUARD_OS=Darwin makes the stubbed-ioreg tests run the same on Linux CI.
export C3DNS_BOARD=$BOARD C3DNS_PROTECT=$PROT GUARD_OS=Darwin
unset GUARD_BYID_DIR
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
# Stub ioreg: prints $tmp/ioreg.txt, whatever the arguments.
cat > "$tmp/bin/ioreg" <<STUB
#!/bin/sh
cat "$tmp/ioreg.txt"
STUB
# Stub espflash: records its arguments and keeps a copy of the image (last argument).
cat > "$tmp/bin/espflash" <<STUB
#!/bin/bash
echo "\$@" >> "$tmp/called"
if [ -f "\${@: -1}" ]; then cp "\${@: -1}" "$tmp/received"; fi
STUB
chmod +x "$tmp/bin/ioreg" "$tmp/bin/espflash"
P="$tmp/bin:$PATH"

# fake_ioreg <serial> <callout>... : one USB device per "serial=callout" pair (callout may be empty).
fake_ioreg() {
  : > "$tmp/ioreg.txt"
  for pair in "$@"; do
    local s=${pair%%=*} c=${pair#*=}
    {
      echo "+-o USB JTAG/serial debug unit@00100000  <class IOUSBHostDevice>"
      echo "  |   \"USB Serial Number\" = \"$s\""
      echo "  +-o IOUSBHostInterface@1  <class IOUSBHostInterface>"
      echo "  | |   \"USB Serial Number\" = \"$s\""
      if [ -n "$c" ]; then
        echo "  |   +-o IOSerialBSDClient  <class IOSerialBSDClient>"
        echo "  |         \"IOCalloutDevice\" = \"$c\""
      fi
    } >> "$tmp/ioreg.txt"
  done
}

# --- guard.sh with the GUARD_FAKE_MAC override (the brief's standalone checks) ---
# expect_guard <name> <fake-mac> <want-exit> [want-message]
expect_guard() {
  local name=$1 mac=$2 want=$3 msg=${4:-}
  out=$(PATH="$P" GUARD_FAKE_MAC="$mac" "$here/guard.sh" 2>&1); code=$?
  if [ "$code" != "$want" ]; then fail "$name: exit $code, want $want ($out)"; return; fi
  if [ -n "$msg" ] && ! printf '%s' "$out" | grep -q -- "$msg"; then fail "$name: missing '$msg' in: $out"; return; fi
  if ! printf '%s' "$out" | grep -q "FAKE MAC IN USE (test only)"; then fail "$name: no FAKE MAC warning"; return; fi
  pass "$name (exit $code)"
}
fake_ioreg "$BOARD=/dev/cu.usbmodem101"   # must be ignored while the override is set
expect_guard "fake: protected MAC refused"    "$PROT"           1 "refusing: protected board"
expect_guard "fake: board MAC accepted"  "$BOARD"          0 "ok: board"
expect_guard "fake: unknown MAC refused" "$OTHER"          1 "refusing"
expect_guard "fake: empty MAC refused"   ""                1 "refusing"
expect_guard "fake: protected+board refused"  "$BOARD $PROT"    1 "refusing: protected board"
expect_guard "fake: board+other refused" "$BOARD $OTHER"   1 "refusing"
expect_guard "fake: glob not expanded"   "*"               1 "refusing"

# --- guard.sh reading (stubbed) ioreg ---
# expect_ioguard <name> <want-exit> <want-stdout|-> <guard args...>   (ioreg.txt already set)
expect_ioguard() {
  local name=$1 want=$2 wantout=$3; shift 3
  out=$(env -u GUARD_FAKE_MAC PATH="$P" "$here/guard.sh" "$@" 2>/dev/null); code=$?
  if [ "$code" != "$want" ]; then fail "$name: exit $code, want $want ($out)"; return; fi
  if [ "$wantout" != - ] && [ "$out" != "$wantout" ]; then fail "$name: stdout '$out', want '$wantout'"; return; fi
  pass "$name (exit $code)"
}
fake_ioreg "$BOARD=/dev/cu.usbmodem101"
expect_ioguard "ioreg: board accepted"            0 -
expect_ioguard "ioreg: --port prints callout"     0 /dev/cu.usbmodem101 --port
fake_ioreg "$PROT=/dev/cu.usbmodem101"
expect_ioguard "ioreg: protected refused"              1 -
fake_ioreg "$BOARD=/dev/cu.usbmodem101" "$PROT=/dev/cu.usbmodem201"
expect_ioguard "ioreg: board+protected refused"        1 -
fake_ioreg
expect_ioguard "ioreg: nothing attached refused"  1 -
fake_ioreg "$BOARD="
expect_ioguard "ioreg: --port without callout refused" 1 "" --port
fake_ioreg "$BOARD=/dev/cu.usbmodem101" "$BOARD=/dev/cu.usbmodem301"
expect_ioguard "ioreg: --port two callouts refused" 1 "" --port

# --- flash scripts (stubbed ioreg + espflash) ---
echo fake > "$tmp/app.elf"
# expect_flash <name> <script> <image> <want-called yes|no> [want-args]   (ioreg.txt already set)
# Extra environment for the script is passed via the FLASH_ENV array.
expect_flash() {
  local name=$1 script=$2 img=$3 want=$4 args=${5:-}
  rm -f "$tmp/called" "$tmp/received"
  out=$(env "${FLASH_ENV[@]}" PATH="$P" "$here/$script" "$img" 2>&1); code=$?
  if [ "$want" = no ]; then
    if [ -e "$tmp/called" ]; then fail "$name: espflash was called: $(cat "$tmp/called")"; return; fi
    if [ "$code" = 0 ]; then fail "$name: exit 0 although it should refuse"; return; fi
    pass "$name (exit $code, espflash not called)"
  else
    if [ ! -e "$tmp/called" ]; then fail "$name: espflash not called ($out)"; return; fi
    got=$(cat "$tmp/called")
    if [ -n "$args" ] && [ "$got" != "$args" ]; then fail "$name: espflash args '$got', want '$args'"; return; fi
    pass "$name (espflash $got)"
  fi
}
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)

fake_ioreg "$PROT=/dev/cu.usbmodem101"
expect_flash "flash: protected refused"            flash.sh     "$tmp/app.elf" no
expect_flash "flash-blocklist: protected refused"        flash-blocklist.sh "$tmp/app.elf" no
fake_ioreg
expect_flash "flash: nothing attached refused" flash.sh    "$tmp/app.elf" no
fake_ioreg "$OTHER=/dev/cu.usbmodem101"
expect_flash "flash-blocklist: unknown refused"     flash-blocklist.sh "$tmp/app.elf" no

# A stray exported fake MAC must not bypass the hardware check.
fake_ioreg "$PROT=/dev/cu.usbmodem101"
FLASH_ENV=(-u C3DNS_PORT GUARD_FAKE_MAC=$BOARD)
expect_flash "flash: exported fake board MAC, protected on USB -> refused"     flash.sh     "$tmp/app.elf" no
expect_flash "flash-blocklist: exported fake board MAC, protected on USB -> refused" flash-blocklist.sh "$tmp/app.elf" no

# Port comes from the checked device; C3DNS_PORT is only a cross-check.
fake_ioreg "$BOARD=/dev/cu.usbmodem777"
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_flash "flash: board, port from ioreg"  flash.sh     "$tmp/app.elf" yes "flash --port /dev/cu.usbmodem777 --monitor $tmp/app.elf"
FLASH_ENV=(-u GUARD_FAKE_MAC C3DNS_PORT=/dev/cu.usbmodem777)
expect_flash "flash: C3DNS_PORT matches"      flash.sh     "$tmp/app.elf" yes "flash --port /dev/cu.usbmodem777 --monitor $tmp/app.elf"
FLASH_ENV=(-u GUARD_FAKE_MAC C3DNS_PORT=/dev/cu.usbmodem101)
expect_flash "flash: C3DNS_PORT mismatch refused"     flash.sh     "$tmp/app.elf" no
expect_flash "flash-blocklist: C3DNS_PORT mismatch refused" flash-blocklist.sh "$tmp/app.elf" no
fake_ioreg "$BOARD="
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_flash "flash: no callout refused"      flash.sh     "$tmp/app.elf" no
expect_flash "flash-blocklist: no callout refused"  flash-blocklist.sh "$tmp/app.elf" no

# Relative image path still reaches espflash as an absolute path.
fake_ioreg "$BOARD=/dev/cu.usbmodem101"
rm -f "$tmp/called"
(cd "$tmp" && env -u GUARD_FAKE_MAC -u C3DNS_PORT PATH="$P" "$here/flash.sh" app.elf >/dev/null 2>&1)
if [ "$(cat "$tmp/called" 2>/dev/null)" = "flash --port /dev/cu.usbmodem101 --monitor $tmp/app.elf" ]; then
  pass "flash: relative image path made absolute"
else fail "flash: relative image path ($(cat "$tmp/called" 2>/dev/null))"; fi

# Missing argument must not reach espflash even on the board.
rm -f "$tmp/called"
if ! env -u GUARD_FAKE_MAC PATH="$P" "$here/flash.sh" >/dev/null 2>&1 && [ ! -e "$tmp/called" ]; then
  pass "flash: no argument refused"
else fail "flash: no argument refused"; fi

# Blocklist padding: small bin -> exactly 0x1F0000 bytes, original head, 0xFF tail.
printf '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a' > "$tmp/small.bin"
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_flash "flash-blocklist: board writes at 0x210000" flash-blocklist.sh "$tmp/small.bin" yes
if grep -q "^write-bin --port /dev/cu.usbmodem101 0x210000 " "$tmp/called" 2>/dev/null; then
  pass "flash-blocklist: write-bin args"
else fail "flash-blocklist: write-bin args ($(cat "$tmp/called" 2>/dev/null))"; fi
if [ -e "$tmp/received" ]; then
  size=$(wc -c < "$tmp/received" | tr -d ' ')
  head_ok=$(head -c 10 "$tmp/received" | cmp -s - "$tmp/small.bin" && echo y)
  tail_bytes=$(tail -c +11 "$tmp/received" | LC_ALL=C tr -d '\377' | wc -c | tr -d ' ')
  if [ "$size" = "$PART_SIZE" ] && [ "$head_ok" = y ] && [ "$tail_bytes" = 0 ]; then
    pass "flash-blocklist: padded to $size bytes, head intact, tail all 0xFF"
  else fail "flash-blocklist: padding (size $size want $PART_SIZE, head_ok '$head_ok', non-FF tail bytes $tail_bytes)"; fi
else fail "flash-blocklist: no image received"; fi
if [ -n "$(cat "$tmp/called" 2>/dev/null)" ] && [ "$(awk '{print $NF}' "$tmp/called")" != "$tmp/small.bin" ] \
   && [ ! -e "$(awk '{print $NF}' "$tmp/called")" ]; then
  pass "flash-blocklist: padded temp file removed afterwards"
else fail "flash-blocklist: padded temp file not removed (or original passed)"; fi

# Exactly partition-sized bin is accepted; oversize is refused before espflash.
head -c "$PART_SIZE" /dev/zero > "$tmp/exact.bin"
expect_flash "flash-blocklist: exactly 0x1F0000 accepted" flash-blocklist.sh "$tmp/exact.bin" yes
head -c $((PART_SIZE + 1)) /dev/zero > "$tmp/big.bin"
expect_flash "flash-blocklist: oversize refused"         flash-blocklist.sh "$tmp/big.bin" no


# --- storage scripts: erase-storage.sh (no args) and write-storage.sh <file> ---
STORE_SIZE=$((0x80000))
# expect_store <name> <want-called yes|no> <want-args|-> <script> [args...]   (ioreg.txt already set)
expect_store() {
  local name=$1 want=$2 args=$3; shift 3
  rm -f "$tmp/called" "$tmp/received"
  out=$(env "${FLASH_ENV[@]}" PATH="$P" "$here/$@" 2>&1); code=$?
  if [ "$want" = no ]; then
    if [ -e "$tmp/called" ]; then fail "$name: espflash was called: $(cat "$tmp/called")"; return; fi
    if [ "$code" = 0 ]; then fail "$name: exit 0 although it should refuse"; return; fi
    pass "$name (exit $code, espflash not called)"
  else
    if [ ! -e "$tmp/called" ]; then fail "$name: espflash not called ($out)"; return; fi
    if [ "$(wc -l < "$tmp/called" | tr -d ' ')" != 1 ]; then fail "$name: espflash called more than once: $(cat "$tmp/called")"; return; fi
    got=$(cat "$tmp/called")
    if [ "$args" != - ] && [ "$got" != "$args" ]; then fail "$name: espflash args '$got', want '$args'"; return; fi
    pass "$name (espflash $got)"
  fi
}
printf 'C3SR\x01\x02' > "$tmp/st.bin"
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
fake_ioreg "$PROT=/dev/cu.usbmodem101"
expect_store "erase-storage: protected refused"           no - erase-storage.sh
expect_store "write-storage: protected refused"           no - write-storage.sh "$tmp/st.bin"
fake_ioreg "$BOARD=/dev/cu.usbmodem101" "$PROT=/dev/cu.usbmodem201"
expect_store "erase-storage: board+protected refused"     no - erase-storage.sh
expect_store "write-storage: board+protected refused"     no - write-storage.sh "$tmp/st.bin"
fake_ioreg
expect_store "erase-storage: nothing attached refused" no - erase-storage.sh
fake_ioreg "$OTHER=/dev/cu.usbmodem101"
expect_store "write-storage: unknown refused"        no - write-storage.sh "$tmp/st.bin"
fake_ioreg "$BOARD="
expect_store "erase-storage: no callout refused"     no - erase-storage.sh
expect_store "write-storage: no callout refused"     no - write-storage.sh "$tmp/st.bin"
# A stray exported fake board MAC must not bypass the hardware check.
fake_ioreg "$PROT=/dev/cu.usbmodem101"
FLASH_ENV=(-u C3DNS_PORT GUARD_FAKE_MAC=$BOARD)
expect_store "erase-storage: exported fake board MAC, protected on USB -> refused" no - erase-storage.sh
expect_store "write-storage: exported fake board MAC, protected on USB -> refused" no - write-storage.sh "$tmp/st.bin"
# C3DNS_PORT is only a cross-check.
fake_ioreg "$BOARD=/dev/cu.usbmodem777"
FLASH_ENV=(-u GUARD_FAKE_MAC C3DNS_PORT=/dev/cu.usbmodem101)
expect_store "erase-storage: C3DNS_PORT mismatch refused" no - erase-storage.sh
expect_store "write-storage: C3DNS_PORT mismatch refused" no - write-storage.sh "$tmp/st.bin"
# Spare: exactly one espflash call, exactly the storage region, nothing else.
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_store "erase-storage: board -> one erase-region of exactly 0x190000+0x80000" yes \
  "erase-region --port /dev/cu.usbmodem777 0x190000 0x80000" erase-storage.sh
FLASH_ENV=(-u GUARD_FAKE_MAC C3DNS_PORT=/dev/cu.usbmodem777)
expect_store "erase-storage: C3DNS_PORT matches" yes "erase-region --port /dev/cu.usbmodem777 0x190000 0x80000" erase-storage.sh
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_store "erase-storage: extra argument refused" no - erase-storage.sh 0x0
expect_store "write-storage: board -> one write-bin at 0x190000" yes - write-storage.sh "$tmp/st.bin"
if grep -qx "write-bin --port /dev/cu.usbmodem777 0x190000 [^ ]*" "$tmp/called" 2>/dev/null; then
  pass "write-storage: write-bin args"
else fail "write-storage: write-bin args ($(cat "$tmp/called" 2>/dev/null))"; fi
if [ -e "$tmp/received" ]; then
  size=$(wc -c < "$tmp/received" | tr -d ' ')
  head_ok=$(head -c 6 "$tmp/received" | cmp -s - "$tmp/st.bin" && echo y)
  tail_bytes=$(tail -c +7 "$tmp/received" | LC_ALL=C tr -d '\377' | wc -c | tr -d ' ')
  if [ "$size" = "$STORE_SIZE" ] && [ "$head_ok" = y ] && [ "$tail_bytes" = 0 ]; then
    pass "write-storage: padded to $size bytes, head intact, tail all 0xFF"
  else fail "write-storage: padding (size $size want $STORE_SIZE, head_ok '$head_ok', non-FF tail bytes $tail_bytes)"; fi
else fail "write-storage: no image received"; fi
if [ ! -e "$(awk '{print $NF}' "$tmp/called")" ]; then
  pass "write-storage: padded temp file removed afterwards"
else fail "write-storage: padded temp file not removed"; fi
head -c "$STORE_SIZE" /dev/zero > "$tmp/st-exact.bin"
expect_store "write-storage: exactly 0x80000 accepted" yes - write-storage.sh "$tmp/st-exact.bin"
head -c $((STORE_SIZE + 1)) /dev/zero > "$tmp/st-big.bin"
expect_store "write-storage: oversize refused"        no - write-storage.sh "$tmp/st-big.bin"
expect_store "write-storage: no argument refused"     no - write-storage.sh
expect_store "write-storage: missing file refused"    no - write-storage.sh "$tmp/does-not-exist.bin"
expect_store "write-storage: two arguments refused"   no - write-storage.sh "$tmp/st.bin" "$tmp/st.bin"
# Neither script may ever use another espflash subcommand (erase-flash, erase-parts, flash, ...).
if grep -nE "espflash" "$here/erase-storage.sh" "$here/write-storage.sh" | grep -v "^[^:]*:[0-9]*:#" \
   | grep -vE "espflash (erase-region|write-bin) --port|espflash.toml" >/dev/null; then
  fail "storage scripts: an espflash call other than erase-region/write-bin"
else pass "storage scripts: only erase-region / write-bin espflash calls"; fi

# --- erase-nvs.sh (no args): only the nvs partition 0x9000+0x6000 ---
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
fake_ioreg "$PROT=/dev/cu.usbmodem101"
expect_store "erase-nvs: protected refused"                 no - erase-nvs.sh
fake_ioreg "$BOARD=/dev/cu.usbmodem101" "$PROT=/dev/cu.usbmodem201"
expect_store "erase-nvs: board+protected refused"           no - erase-nvs.sh
fake_ioreg
expect_store "erase-nvs: nothing attached refused"     no - erase-nvs.sh
fake_ioreg "$OTHER=/dev/cu.usbmodem101"
expect_store "erase-nvs: unknown refused"              no - erase-nvs.sh
fake_ioreg "$BOARD="
expect_store "erase-nvs: no callout refused"           no - erase-nvs.sh
fake_ioreg "$PROT=/dev/cu.usbmodem101"
FLASH_ENV=(-u C3DNS_PORT GUARD_FAKE_MAC=$BOARD)
expect_store "erase-nvs: exported fake board MAC, protected on USB -> refused" no - erase-nvs.sh
fake_ioreg "$BOARD=/dev/cu.usbmodem777"
FLASH_ENV=(-u GUARD_FAKE_MAC C3DNS_PORT=/dev/cu.usbmodem101)
expect_store "erase-nvs: C3DNS_PORT mismatch refused"  no - erase-nvs.sh
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_store "erase-nvs: board -> one erase-region of exactly 0x9000+0x6000" yes \
  "erase-region --port /dev/cu.usbmodem777 0x9000 0x6000" erase-nvs.sh
FLASH_ENV=(-u GUARD_FAKE_MAC C3DNS_PORT=/dev/cu.usbmodem777)
expect_store "erase-nvs: C3DNS_PORT matches" yes "erase-region --port /dev/cu.usbmodem777 0x9000 0x6000" erase-nvs.sh
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
expect_store "erase-nvs: extra argument refused"       no - erase-nvs.sh 0x0
if grep -nE "espflash" "$here/erase-nvs.sh" | grep -v "^[0-9]*:#" \
   | grep -vE "espflash erase-region --port|espflash.toml" >/dev/null; then
  fail "erase-nvs: an espflash call other than erase-region"
else pass "erase-nvs: only an erase-region espflash call"; fi
if [ "$(grep -c "^exec espflash\|^ *espflash" "$here/erase-nvs.sh")" = 1 ]; then
  pass "erase-nvs: exactly one espflash invocation in the script"
else fail "erase-nvs: espflash invocation count"; fi

# Missing espflash.toml after the cd to the repo root -> refused.
mkdir -p "$tmp/repo/tools"
cp "$here/guard.sh" "$here/flash.sh" "$here/flash-blocklist.sh" \
   "$here/erase-storage.sh" "$here/write-storage.sh" "$here/erase-nvs.sh" "$tmp/repo/tools/"
fake_ioreg "$BOARD=/dev/cu.usbmodem101"
for s in flash.sh flash-blocklist.sh erase-storage.sh write-storage.sh erase-nvs.sh; do
  arg="$tmp/app.elf"; { [ "$s" = erase-storage.sh ] || [ "$s" = erase-nvs.sh ]; } && arg=""
  rm -f "$tmp/called"
  if ! env -u GUARD_FAKE_MAC -u C3DNS_PORT PATH="$P" "$tmp/repo/tools/$s" $arg >/dev/null 2>&1 && [ ! -e "$tmp/called" ]; then
    pass "$s: missing espflash.toml refused"
  else fail "$s: missing espflash.toml refused"; fi
done

# --- port must come from the board's own node (or its descendants), never a sibling ---
# hub_ioreg <board-callout|""> : hub printed at column 0 with the board and a serial-less
# USB-UART sibling nested under it (structure as `ioreg -r -c IOUSBHostDevice -l` prints it).
hub_ioreg() {
  local board_callout=$1
  {
    echo '+-o USB3.1 Hub@01100000  <class IOUSBHostDevice, id 0x100010001, registered, matched, active>'
    echo '  | {'
    echo '  |   "USB Product Name" = "USB3.1 Hub"'
    echo '  | }'
    echo '  | '
    echo '  +-o USB JTAG/serial debug unit@01110000  <class IOUSBHostDevice, id 0x100010002, registered, matched, active>'
    echo '  | | {'
    echo "  | |   \"USB Serial Number\" = \"$BOARD\""
    echo '  | | }'
    echo '  | | '
    echo '  | +-o IOUSBHostInterface@1  <class IOUSBHostInterface, id 0x100010003, registered, matched, active>'
    echo '  |   | {'
    echo "  |   |   \"USB Serial Number\" = \"$BOARD\""
    echo '  |   | }'
    if [ -n "$board_callout" ]; then
      echo '  |   +-o IOSerialBSDClient  <class IOSerialBSDClient, id 0x100010004, registered, matched, active>'
      echo '  |       {'
      echo "  |         \"IOCalloutDevice\" = \"$board_callout\""
      echo '  |       }'
    fi
    echo '  +-o USB Serial@01120000  <class IOUSBHostDevice, id 0x100010005, registered, matched, active>'
    echo '    | {'
    echo '    |   "USB Product Name" = "USB Serial"'
    echo '    | }'
    echo '    +-o IOSerialBSDClient  <class IOSerialBSDClient, id 0x100010006, registered, matched, active>'
    echo '        {'
    echo '          "IOCalloutDevice" = "/dev/cu.usbserial-1120"'
    echo '        }'
  } > "$tmp/ioreg.txt"
}
FLASH_ENV=(-u GUARD_FAKE_MAC -u C3DNS_PORT)
hub_ioreg ""
expect_ioguard "hub: board without callout, sibling has one -> --port refused" 1 "" --port
expect_flash   "hub: board without callout, sibling has one -> flash refused"     flash.sh     "$tmp/app.elf" no
expect_flash   "hub: board without callout, sibling has one -> flash-blocklist refused" flash-blocklist.sh "$tmp/app.elf" no
hub_ioreg /dev/cu.usbmodem1111
expect_ioguard "hub: --port picks the board's callout, not the sibling's" 0 /dev/cu.usbmodem1111 --port
expect_flash   "hub: flash uses the board's callout" flash.sh "$tmp/app.elf" yes "flash --port /dev/cu.usbmodem1111 --monitor $tmp/app.elf"
# Real ioreg output (one ESP32-C3 attached; serial replaced): tools/testdata/ioreg-c3-sample.txt
cp "$here/testdata/ioreg-c3-sample.txt" "$tmp/ioreg.txt"
expect_ioguard "real fixture: --port prints /dev/cu.usbmodem101" 0 /dev/cu.usbmodem101 --port
expect_flash   "real fixture: flash uses /dev/cu.usbmodem101" flash.sh "$tmp/app.elf" yes "flash --port /dev/cu.usbmodem101 --monitor $tmp/app.elf"

# --- configuration: no board configured, tools/board.env, protected board even if configured ---
fake_ioreg "$BOARD=/dev/cu.usbmodem101"
out=$(env -u GUARD_FAKE_MAC C3DNS_BOARD= PATH="$P" "$here/guard.sh" 2>&1); code=$?
if [ "$code" = 1 ] && printf '%s' "$out" | grep -q "no development board configured"; then
  pass "config: no board configured refused"; else fail "config: no board configured ($code: $out)"; fi
out=$(env -u GUARD_FAKE_MAC C3DNS_BOARD=$BOARD C3DNS_PROTECT=$BOARD PATH="$P" "$here/guard.sh" 2>&1); code=$?
if [ "$code" = 1 ] && printf '%s' "$out" | grep -q "refusing: protected board"; then
  pass "config: protected wins over configured board"; else fail "config: protected wins ($code: $out)"; fi
mkdir -p "$tmp/cfg/tools"; cp "$here/guard.sh" "$tmp/cfg/tools/"
printf 'C3DNS_BOARD=%s\nC3DNS_PROTECT="%s"\n' "$(printf %s "$BOARD" | tr 'A-F' 'a-f')" "$PROT" > "$tmp/cfg/tools/board.env"
out=$(env -u GUARD_FAKE_MAC -u C3DNS_BOARD -u C3DNS_PROTECT PATH="$P" "$tmp/cfg/tools/guard.sh" --port 2>/dev/null); code=$?
if [ "$code" = 0 ] && [ "$out" = /dev/cu.usbmodem101 ]; then
  pass "config: board.env read (lower-case serial accepted)"; else fail "config: board.env ($code: $out)"; fi
out=$(env -u GUARD_FAKE_MAC -u C3DNS_PROTECT C3DNS_BOARD=$OTHER PATH="$P" "$tmp/cfg/tools/guard.sh" 2>/dev/null); code=$?
if [ "$code" = 1 ]; then pass "config: environment wins over board.env"; else fail "config: environment wins ($code: $out)"; fi
out=$(env -u GUARD_FAKE_MAC PATH="$P" "$here/guard.sh" --list 2>/dev/null); code=$?
if [ "$code" = 0 ] && [ "$out" = "$BOARD" ]; then pass "config: --list prints attached serials"; else fail "config: --list ($code: $out)"; fi

# --- Linux: /dev/serial/by-id ---
byid="$tmp/by-id"
# fake_byid <serial=target>... : one by-id symlink per pair, named like the C3's USB-Serial-JTAG.
fake_byid() {
  rm -rf "$byid"; mkdir -p "$byid"
  for pair in "$@"; do
    ln -s "${pair#*=}" "$byid/usb-Espressif_USB_JTAG_serial_debug_unit_${pair%%=*}-if00"
  done
}
# expect_linux <name> <want-exit> <want-stdout|-> <guard args...>
expect_linux() {
  local name=$1 want=$2 wantout=$3; shift 3
  out=$(env -u GUARD_FAKE_MAC GUARD_OS=Linux GUARD_BYID_DIR="$byid" PATH="$P" "$here/guard.sh" "$@" 2>/dev/null); code=$?
  if [ "$code" != "$want" ]; then fail "$name: exit $code, want $want ($out)"; return; fi
  if [ "$wantout" != - ] && [ "$out" != "$wantout" ]; then fail "$name: stdout '$out', want '$wantout'"; return; fi
  pass "$name (exit $code)"
}
fake_byid "$BOARD=../../ttyACM0"
expect_linux "linux: board accepted"            0 -
expect_linux "linux: --port prints the device"  0 ../../ttyACM0 --port
fake_byid "$PROT=../../ttyACM0"
expect_linux "linux: protected refused"         1 -
fake_byid "$BOARD=../../ttyACM0" "$OTHER=../../ttyACM1"
expect_linux "linux: two boards refused"        1 "" --port
fake_byid
expect_linux "linux: nothing attached refused"  1 -
out=$(env -u GUARD_FAKE_MAC GUARD_OS=Plan9 PATH="$P" "$here/guard.sh" 2>/dev/null); code=$?
if [ "$code" = 1 ]; then pass "other OS refused"; else fail "other OS ($code)"; fi

if [ "$fails" = 0 ]; then echo "ALL PASS"; exit 0; else echo "$fails FAILED"; exit 1; fi
