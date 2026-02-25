#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/run_qemu_trace.sh [options]

Options:
  --hda <path>         Raw HDD image path (optional)
  --hda-fat-dir <dir>  Map host directory as FAT HDD (QEMU vvfat, optional)
  --fda <path>         Floppy image path (optional)
  --boot <a|c|d>       Boot device (default: a if only fda, else c)
  --memory <MB>        Guest memory in MB (default: 64)
  --log-dir <path>     Log output directory (default: results/runtime/<timestamp>)
  --debug <flags>      QEMU debug flags for -d (default: int,cpu)
  --no-debug           Disable -d debug logging
  --gdb <port>         Start GDB stub on tcp::<port> and pause at startup
  --no-monitor         Disable monitor unix socket output
  --headless           Run in terminal (-nographic)
  --no-kvm             Disable KVM and force TCG
  -h, --help           Show this help

Examples:
  tools/run_qemu_trace.sh --fda freedos-1.4M.img
  tools/run_qemu_trace.sh --hda win95.raw --boot c
  tools/run_qemu_trace.sh --hda win95.raw --fda tools.img --boot c --headless
  tools/run_qemu_trace.sh --fda freedos-1.4M.img --gdb 1234
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

HDA=""
HDA_FAT_DIR=""
FDA=""
BOOT=""
MEMORY_MB="64"
LOG_DIR=""
DEBUG_FLAGS="int,cpu"
ENABLE_DEBUG=1
GDB_PORT=""
ENABLE_MONITOR=1
HEADLESS=0
FORCE_TCG=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hda)
      HDA="${2:-}"
      shift 2
      ;;
    --hda-fat-dir)
      HDA_FAT_DIR="${2:-}"
      shift 2
      ;;
    --fda)
      FDA="${2:-}"
      shift 2
      ;;
    --boot)
      BOOT="${2:-}"
      shift 2
      ;;
    --memory)
      MEMORY_MB="${2:-}"
      shift 2
      ;;
    --log-dir)
      LOG_DIR="${2:-}"
      shift 2
      ;;
    --debug)
      DEBUG_FLAGS="${2:-}"
      shift 2
      ;;
    --no-debug)
      ENABLE_DEBUG=0
      shift
      ;;
    --gdb)
      GDB_PORT="${2:-}"
      shift 2
      ;;
    --no-monitor)
      ENABLE_MONITOR=0
      shift
      ;;
    --headless)
      HEADLESS=1
      shift
      ;;
    --no-kvm)
      FORCE_TCG=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

need_cmd qemu-system-i386
need_cmd date

if [[ -z "$HDA" && -z "$HDA_FAT_DIR" && -z "$FDA" ]]; then
  echo "at least one of --hda, --hda-fat-dir, or --fda is required" >&2
  exit 2
fi

if [[ -n "$HDA" && ! -f "$HDA" ]]; then
  echo "hda image not found: $HDA" >&2
  exit 2
fi

if [[ -n "$HDA" && -n "$HDA_FAT_DIR" ]]; then
  echo "use either --hda or --hda-fat-dir, not both" >&2
  exit 2
fi

if [[ -n "$HDA_FAT_DIR" && ! -d "$HDA_FAT_DIR" ]]; then
  echo "hda fat directory not found: $HDA_FAT_DIR" >&2
  exit 2
fi

if [[ -n "$FDA" && ! -f "$FDA" ]]; then
  echo "fda image not found: $FDA" >&2
  exit 2
fi

if [[ -z "$LOG_DIR" ]]; then
  ts="$(date +%Y%m%d_%H%M%S)"
  LOG_DIR="results/runtime/$ts"
fi
mkdir -p "$LOG_DIR"

if [[ -z "$BOOT" ]]; then
  if [[ -n "$FDA" && -z "$HDA" && -z "$HDA_FAT_DIR" ]]; then
    BOOT="a"
  else
    BOOT="c"
  fi
fi

if [[ "$BOOT" != "a" && "$BOOT" != "c" && "$BOOT" != "d" ]]; then
  echo "invalid --boot value: $BOOT (allowed: a/c/d)" >&2
  exit 2
fi

accel="kvm:tcg"
if [[ "$FORCE_TCG" -eq 1 || ! -e /dev/kvm ]]; then
  accel="tcg"
fi

args=(
  -machine "pc,accel=$accel"
  -cpu pentium
  -m "$MEMORY_MB"
  -rtc base=localtime
  -boot "$BOOT"
  -no-reboot
  -D "$LOG_DIR/qemu.log"
  -serial "file:$LOG_DIR/serial.log"
)

if [[ "$ENABLE_MONITOR" -eq 1 ]]; then
  args+=(-monitor "unix:$LOG_DIR/monitor.sock,server,nowait")
else
  args+=(-monitor none)
fi

if [[ "$ENABLE_DEBUG" -eq 1 ]]; then
  args+=(-d "$DEBUG_FLAGS")
fi

if [[ -n "$GDB_PORT" ]]; then
  args+=(-gdb "tcp::$GDB_PORT" -S)
fi

if [[ -n "$HDA" ]]; then
  args+=(-drive "file=$HDA,if=ide,format=raw")
fi
if [[ -n "$HDA_FAT_DIR" ]]; then
  args+=(-hda "fat:rw:$HDA_FAT_DIR")
fi
if [[ -n "$FDA" ]]; then
  args+=(-fda "$FDA")
fi
if [[ "$HEADLESS" -eq 1 ]]; then
  args+=(-nographic)
fi

printf '%s\n' "log_dir=$LOG_DIR"
printf '%s\n' "accel=$accel"
printf '%s\n' "boot=$BOOT"
if [[ "$ENABLE_DEBUG" -eq 1 ]]; then
  printf '%s\n' "debug_flags=$DEBUG_FLAGS"
else
  printf '%s\n' "debug_flags=disabled"
fi
if [[ -n "$GDB_PORT" ]]; then
  printf '%s\n' "gdb=tcp::$GDB_PORT (paused at startup)"
fi
if [[ "$ENABLE_MONITOR" -eq 1 ]]; then
  printf '%s\n' "monitor=$LOG_DIR/monitor.sock"
else
  printf '%s\n' "monitor=disabled"
fi
printf '%s\n' "running: qemu-system-i386 ${args[*]}"

exec qemu-system-i386 "${args[@]}"
