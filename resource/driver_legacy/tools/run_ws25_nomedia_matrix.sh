#!/usr/bin/env bash
set -euo pipefail

# Run WS25 runtime-capture scenarios without MD DATA media.
# Each scenario is executed in its own AUTOEXEC-patched floppy image.

BASE_IMG="${BASE_IMG:-freedos-1.4M-auto.img}"
HDA_DIR="${HDA_DIR:-/tmp/qemu_hda}"
REPEATS="${REPEATS:-2}"
TIMEOUT_SECS="${TIMEOUT_SECS:-20}"
ROOT_DIR="${ROOT_DIR:-results/runtime/ws25_nomedia}"
ANALYSIS_DIR="${ANALYSIS_DIR:-analysis/ws25_nomedia}"
TMPDIR_LOCAL="${TMPDIR_LOCAL:-$PWD/results/runtime/tmp}"

mkdir -p "$ROOT_DIR" "$ANALYSIS_DIR" "$TMPDIR_LOCAL"

if [[ ! -f "$BASE_IMG" ]]; then
  echo "missing base image: $BASE_IMG" >&2
  exit 2
fi
if [[ ! -d "$HDA_DIR" ]]; then
  echo "missing hda dir: $HDA_DIR" >&2
  exit 2
fi
if [[ ! -f "$HDA_DIR/md31out/mdcache.exe" ]]; then
  echo "missing installed binaries under $HDA_DIR/md31out" >&2
  exit 2
fi

run_scenario() {
  local name="$1"
  local cmd="$2"
  local img="/tmp/ws25-${name}.img"
  local bat="/tmp/ws25-${name}.bat"

  cat >"$bat" <<EOF
@ECHO OFF
CLS
$cmd
EOF
  python3 tools/patch_fat12_autoexec.py --image "$BASE_IMG" --out "$img" --script "$bat" >/dev/null

  for i in $(seq 1 "$REPEATS"); do
    local run_dir="$ROOT_DIR/$name/run$i"
    mkdir -p "$run_dir"
    echo "[run] scenario=$name pass=$i"
    TMPDIR="$TMPDIR_LOCAL" timeout "${TIMEOUT_SECS}s" \
      tools/run_qemu_trace.sh \
      --boot a \
      --fda "$img" \
      --hda-fat-dir "$HDA_DIR" \
      --log-dir "$run_dir" \
      --headless \
      --debug int,cpu \
      --no-kvm \
      --no-monitor >/dev/null 2>&1 || true

    python3 tools/extract_ws25_qemu_events.py \
      --log "$run_dir/qemu.log" \
      --out "$ANALYSIS_DIR/${name}_run${i}.csv" \
      --tool "$name" \
      --site int21_44xx \
      --limit 300 >/dev/null
  done

  if [[ "$REPEATS" -ge 2 ]]; then
    python3 tools/compare_ws25_runs.py \
      --run1 "$ANALYSIS_DIR/${name}_run1.csv" \
      --run2 "$ANALYSIS_DIR/${name}_run2.csv" \
      --out "$ANALYSIS_DIR/${name}_intersection.csv" >/dev/null
  fi
}

run_scenario "mdcache_is" "C:\\MD31OUT\\MDCACHE D: IS"
run_scenario "mdcache_on" "C:\\MD31OUT\\MDCACHE D: ON"
run_scenario "mdcache_off" "C:\\MD31OUT\\MDCACHE D: OFF"
run_scenario "mdcache_flush" "C:\\MD31OUT\\MDCACHE D: FLUSH"
run_scenario "mdfsck" "C:\\MD31OUT\\MDFSCK D:"
run_scenario "mdformat_qo" "C:\\MD31OUT\\MDFORMAT D: -Q -O"

python3 - <<'PY'
import csv
from pathlib import Path

base = Path("analysis/ws25_nomedia")
rows = []
for p in sorted(base.glob("*_run1.csv")):
    scenario = p.name.replace("_run1.csv", "")
    r1 = list(csv.DictReader(p.open(encoding="utf-8")))
    r2p = base / f"{scenario}_run2.csv"
    r2 = list(csv.DictReader(r2p.open(encoding="utf-8"))) if r2p.exists() else []
    ip = base / f"{scenario}_intersection.csv"
    inter = list(csv.DictReader(ip.open(encoding="utf-8"))) if ip.exists() else []
    ax_set = sorted(set(r["ax"] for r in r1 + r2))
    rows.append({
        "scenario": scenario,
        "run1_rows": len(r1),
        "run2_rows": len(r2),
        "intersection_rows": len(inter),
        "ax_set": " ".join(ax_set),
    })

out = base / "summary.csv"
with out.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(
        f, fieldnames=["scenario", "run1_rows", "run2_rows", "intersection_rows", "ax_set"]
    )
    w.writeheader()
    w.writerows(rows)
print(out)
PY

echo "[done] outputs under $ROOT_DIR and $ANALYSIS_DIR"
