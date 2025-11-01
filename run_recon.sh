#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: run_recon.sh [options]

Options:
  --scanner <smrib|nmap|masscan>  Scanner to use for port discovery (default: smrib).
  --top-ports <n>                 Scan the top N ports (default: 200).
  --port-range <range>            Scan an explicit port range (e.g. 1-1024 or 80,443).
  --smrib-path <path>             Path to smrib.py (default: ~/Desktop/RT/smrib.py).
  -h, --help                      Show this message and exit.

Environment variables:
  MASSCAN_RATE                    Rate for masscan executions (default: 1000).
  SKIP_MASSCAN                    When set to 1 skips the pre-discovery masscan stage (default: 1).
  SMRIB_EXTRA_ARGS                Additional arguments for smrib (split on whitespace).
EOF
}

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$WORKDIR/out"
NMAP_DIR="$OUT_DIR/nmap"
HARV_DIR="$OUT_DIR/harvester"
MASSCAN_JSON="$OUT_DIR/masscan.json"
INVENTORY_JSON="$OUT_DIR/inventory.json"
TARGETS_FILE="$WORKDIR/targets.txt"

MASSCAN_RATE=${MASSCAN_RATE:-1000}
SKIP_MASSCAN=${SKIP_MASSCAN:-1}   # default skip masscan
SCANNER="smrib"
TOP_PORTS=200
PORT_RANGE=""
SMRIB_PATH=${SMRIB_PATH:-"$HOME/Desktop/RT/smrib.py"}
SMRIB_OUTPUT_FLAG=${SMRIB_OUTPUT_FLAG:---output-dir}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scanner)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --scanner" >&2
        usage
        exit 1
      fi
      SCANNER="$2"
      shift 2
      ;;
    --top-ports)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --top-ports" >&2
        usage
        exit 1
      fi
      TOP_PORTS="$2"
      PORT_RANGE=""
      shift 2
      ;;
    --port-range)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --port-range" >&2
        usage
        exit 1
      fi
      PORT_RANGE="$2"
      TOP_PORTS=""
      shift 2
      ;;
    --smrib-path)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --smrib-path" >&2
        usage
        exit 1
      fi
      SMRIB_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

SCANNER=$(printf '%s' "$SCANNER" | tr '[:upper:]' '[:lower:]')
case "$SCANNER" in
  smrib|nmap|masscan)
    ;;
  *)
    echo "Invalid scanner '$SCANNER'. Choose smrib, nmap, or masscan." >&2
    exit 1
    ;;
esac

if [[ -n "$TOP_PORTS" ]] && ! [[ "$TOP_PORTS" =~ ^[0-9]+$ ]]; then
  echo "--top-ports expects a numeric value" >&2
  exit 1
fi

if [[ -n "$PORT_RANGE" ]] && [[ ! "$PORT_RANGE" =~ ^[0-9,-]+$ ]]; then
  echo "--port-range expects a comma-separated list or range (e.g. 1-1024,80,443)" >&2
  exit 1
fi

if [[ "$SCANNER" == "masscan" ]]; then
  SKIP_MASSCAN=1
fi

PORT_DESC=""
declare -a NMAP_PORT_ARGS=()
declare -a MASSCAN_PORT_ARGS=()
declare -a SMRIB_PORT_ARGS=()

if [[ -n "$PORT_RANGE" ]]; then
  PORT_DESC="ports $PORT_RANGE"
  NMAP_PORT_ARGS=(-p "$PORT_RANGE")
  MASSCAN_PORT_ARGS=(-p "$PORT_RANGE")
  SMRIB_PORT_ARGS=(--ports "$PORT_RANGE")
else
  PORT_DESC="top ${TOP_PORTS:-200} ports"
  PORT_VALUE=${TOP_PORTS:-200}
  NMAP_PORT_ARGS=(--top-ports "$PORT_VALUE")
  MASSCAN_PORT_ARGS=(--top-ports "$PORT_VALUE")
  SMRIB_PORT_ARGS=(--top-ports "$PORT_VALUE")
fi

mkdir -p "$OUT_DIR" "$NMAP_DIR" "$HARV_DIR"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "targets.txt not found." >&2; exit 1
fi

mapfile -t TARGETS < <(grep -vE '^\s*$|^#' "$TARGETS_FILE" || true)
if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "No targets in targets.txt" >&2; exit 1
fi

if [ "$SKIP_MASSCAN" -ne 1 ] && command -v masscan >/dev/null 2>&1; then
  echo "Running discovery masscan (rate=$MASSCAN_RATE, $PORT_DESC)"
  sudo masscan --rate "$MASSCAN_RATE" "${MASSCAN_PORT_ARGS[@]}" --open \
    --output-format json -oJ "$MASSCAN_JSON" "${TARGETS[@]}" || true
else
  echo "Skipping discovery masscan"
fi

HOSTS_TO_SCAN=()
if [ -s "$MASSCAN_JSON" ] && command -v jq >/dev/null 2>&1; then
  jq -r '.[] | select(.ip) | .ip' "$MASSCAN_JSON" | sort -u > "$OUT_DIR/_hosts_from_masscan.txt" || true
  mapfile -t HOSTS_TO_SCAN < "$OUT_DIR/_hosts_from_masscan.txt" || true
fi
if [ ${#HOSTS_TO_SCAN[@]} -eq 0 ]; then
  mapfile -t HOSTS_TO_SCAN < <(printf "%s\n" "${TARGETS[@]}")
fi

case "$SCANNER" in
  nmap)
    NMAP_OPTS=( -sC -sV -O -T4 )
    NMAP_OPTS+=("${NMAP_PORT_ARGS[@]}")
    for ip in "${HOSTS_TO_SCAN[@]}"; do
      outbase="$NMAP_DIR/$ip"
      echo "Running nmap on $ip ($PORT_DESC)"
      sudo nmap "${NMAP_OPTS[@]}" -oA "$outbase" "$ip" || true
    done
    ;;
  smrib)
    if [ ! -f "$SMRIB_PATH" ]; then
      echo "smrib scanner not found at $SMRIB_PATH" >&2
      exit 1
    fi
    echo "Running smrib scanner ($PORT_DESC)"
    SMRIB_CMD=(python3 "$SMRIB_PATH")
    if [[ -n "$SMRIB_PATH" ]] && [[ ! -x "$SMRIB_PATH" ]]; then
      chmod +x "$SMRIB_PATH" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SMRIB_OUTPUT_FLAG" ]]; then
      SMRIB_CMD+=("$SMRIB_OUTPUT_FLAG" "$NMAP_DIR")
    fi
    SMRIB_CMD+=("${SMRIB_PORT_ARGS[@]}")
    if [[ -n "${SMRIB_EXTRA_ARGS:-}" ]]; then
      IFS_SAVE=$IFS
      IFS=$' \t\n'
      # shellcheck disable=SC2206
      EXTRA_ARGS=(${SMRIB_EXTRA_ARGS})
      IFS=$IFS_SAVE
      SMRIB_CMD+=("${EXTRA_ARGS[@]}")
    fi
    SMRIB_CMD+=("${HOSTS_TO_SCAN[@]}")
    "${SMRIB_CMD[@]}" || true
    ;;
  masscan)
    echo "Running masscan scan (rate=$MASSCAN_RATE, $PORT_DESC)"
    sudo masscan --rate "$MASSCAN_RATE" "${MASSCAN_PORT_ARGS[@]}" --open \
      --output-format json -oJ "$MASSCAN_JSON" "${TARGETS[@]}" || true
    ;;
esac

if [[ "$SCANNER" != "masscan" ]]; then
  xml_count=$(find "$NMAP_DIR" -maxdepth 1 -type f -name '*.xml' | wc -l | tr -d ' ')
  if [[ "$xml_count" == "0" ]]; then
    echo "Warning: no XML files generated in $NMAP_DIR. Aggregation may be incomplete." >&2
  fi
fi

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
