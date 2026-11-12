#!/bin/bash
# Soak test of a running device (read-only HTTP + dig; never touches serial or flash).
#   C3DNS_HOST=<ip or adblock.local>  ADMIN_PW=<password>  tools/soak.sh [hours]
# Appends: iso_time,uptime,heap_free,heap_min,allowed,blocked,p50_ms,p95_ms to soak-<date>.csv (gitignored)
# Point C3DNS_HOST at a test device, not one your household depends on.
set -u
: "${C3DNS_HOST:?set C3DNS_HOST to the device address}"
: "${ADMIN_PW:?set ADMIN_PW (never put it in the repo)}"
hours=${1:-24}
cd "$(dirname "$0")/.."
out="soak-$(date +%F).csv"
names=(example.com wikipedia.org apple.com github.com rust-lang.org)
[ -f "$out" ] || echo "time,uptime,heap_free,heap_min,allowed,blocked,p50_ms,p95_ms" >"$out"

probe() { # prints "p50 p95" in ms over cached repeats (each name queried 5x)
  local t=() n q
  for n in "${names[@]}"; do
    dig +tries=1 +time=2 @"$C3DNS_HOST" "$n" A >/dev/null 2>&1   # warm the cache
    for _ in 1 2 3 4 5; do
      q=$(dig +tries=1 +time=2 @"$C3DNS_HOST" "$n" A 2>/dev/null | awk '/Query time/ {print $4}')
      t+=("$q")
    done
  done
  printf '%s\n' "${t[@]}" | sed '/^$/d' | sort -n |
    awk '{a[NR]=$1} END{i=int(NR*0.95+0.5); if(i>NR)i=NR; if(!NR)print "NA NA"; else printf "%d %d\n", a[int((NR+1)/2)], a[i]}'
}

field() { sed -n 's/.*"'"$1"'":\([0-9][0-9]*\).*/\1/p'; }

end=$(( $(date +%s) + hours*3600 ))
while [ "$(date +%s)" -lt "$end" ]; do
  j=$(curl -s -m 10 -u "admin:$ADMIN_PW" "http://$C3DNS_HOST/api/overview")
  pr=$(probe)
  now=$(date -u +%FT%TZ)
  row="$now"
  for k in uptime heap_free heap_min allowed blocked; do
    v=$(printf '%s' "$j" | field "$k")
    row="$row,$v"
  done
  echo "$row,${pr% *},${pr#* }" >>"$out"
  sleep 60
done
