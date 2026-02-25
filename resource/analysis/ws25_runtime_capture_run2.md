# WS25 Runtime Capture Run 2 (Linux/QEMU)

Date: 2026-02-17
Status: partial capture complete

## Setup
- Boot image: `/tmp/freedos-ws25-short.img`
- HDD mapping: `fat:rw:/tmp/qemu_hda`
- Command:
  - `TMPDIR=$PWD/results/runtime/tmp timeout 30s tools/run_qemu_trace.sh --boot a --fda /tmp/freedos-ws25-short.img --hda-fat-dir /tmp/qemu_hda --log-dir results/runtime/ws25_capture_short_intcpu_run2 --headless --debug int,cpu --no-kvm --no-monitor`

## Observed Guest Output
- `MDcache` (`IS/ON/OFF/FLUSH`) executed.
- `MDfsck D:` executed.
- `MDformat D: -Q -O` executed.
- All commands reported non-MD media errors (expected in current environment).

## Artifacts
- `results/runtime/ws25_capture_short_intcpu_run2/serial.log`
- `results/runtime/ws25_capture_short_intcpu_run2/qemu.log`
- `analysis/ws25_capture_short_events_run2.csv`

## Cross-Run Stability
- Intersection against run1 (signature: `ax,bx,cx,dx,ds,buf_ptr,buf_len`):
  - `analysis/ws25_capture_intersection_run1_run2.csv`
  - stable signatures: `20`
