#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$WORKDIR/out"
NMAP_DIR="$OUT_DIR/nmap"
HARV_DIR="$OUT_DIR/harvester"
MASSCAN_JSON="$OUT_DIR/masscan.json"
INVENTORY_JSON="$OUT_DIR/inventory.json"
TARGETS_FILE="$WORKDIR/targets.txt"

MASSCAN_RATE=${MASSCAN_RATE:-1000}
SKIP_MASSCAN=${SKIP_MASSCAN:-1}   # default skip masscan
NMAP_OPTS=( -sC -sV -O -p- -T4 )  # array avoids CRLF/token issues

mkdir -p "$OUT_DIR" "$NMAP_DIR" "$HARV_DIR"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "targets.txt not found." >&2; exit 1
fi

mapfile -t TARGETS < <(grep -vE '^\s*$|^#' "$TARGETS_FILE" || true)
if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "No targets in targets.txt" >&2; exit 1
fi

if [ "$SKIP_MASSCAN" -ne 1 ] && command -v masscan >/dev/null 2>&1; then
  echo "Running masscan (rate=$MASSCAN_RATE)"
  sudo masscan --rate "$MASSCAN_RATE" -p1-65535 --open \
    --output-format json -oJ "$MASSCAN_JSON" "${TARGETS[@]}" || true
else
  echo "Skipping masscan"
fi

HOSTS_TO_SCAN=()
if [ -s "$MASSCAN_JSON" ] && command -v jq >/dev/null 2>&1; then
  jq -r '.[] | select(.ip) | .ip' "$MASSCAN_JSON" | sort -u > "$OUT_DIR/_hosts_from_masscan.txt" || true
  mapfile -t HOSTS_TO_SCAN < "$OUT_DIR/_hosts_from_masscan.txt" || true
fi
if [ ${#HOSTS_TO_SCAN[@]} -eq 0 ]; then
  mapfile -t HOSTS_TO_SCAN < <(printf "%s\n" "${TARGETS[@]}")
fi

for ip in "${HOSTS_TO_SCAN[@]}"; do
  outbase="$NMAP_DIR/$ip"
  echo "Running nmap on $ip"
  sudo nmap "${NMAP_OPTS[@]}" -oA "$outbase" "$ip" || true
done

for t in "${TARGETS[@]}"; do
  if [[ "$t" == *.* ]]; then
    echo "Running theHarvester for $t"
    if command -v theHarvester >/dev/null 2>&1; then
      theHarvester -d "$t" -b all -l 500 -f "$HARV_DIR/$t" || true
    else
      echo "theHarvester not installed. Doing basic DNS for $t"
      host "$t" > "$HARV_DIR/$t.dns.txt" 2>&1 || true
      dig +short any "$t" > "$HARV_DIR/$t.dig.txt" 2>&1 || true
    fi
  fi
done

python3 "$WORKDIR/tools/aggregate.py" \
  --nmap-dir "$NMAP_DIR" \
  --masscan-json "$MASSCAN_JSON" \
  --harv-dir "$HARV_DIR" \
  --out-json "$INVENTORY_JSON" \
  --out-csv "$OUT_DIR/inventory.csv"

echo "Done. See $INVENTORY_JSON and $OUT_DIR/inventory.csv"
