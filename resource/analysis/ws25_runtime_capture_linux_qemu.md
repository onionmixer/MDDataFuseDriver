# WS25 Runtime Capture (Linux/QEMU Procedure)

Date: 2026-02-17
Status: ready-to-run

## Goal
Produce runtime artifacts usable for `analysis/ws25_mdctl_runtime_capture.md` promotion flow:
- register snapshots around IOCTL/transport events
- stack/buffer pointer context
- per-scenario run logs

## Prerequisites
- Host: Linux
- Installed: `qemu-system-i386`, `qemu-img`
- Workspace script: `tools/run_qemu_trace.sh`
- For `vvfat` (`--hda-fat-dir`) in this environment, set:
  - `TMPDIR=$PWD/results/runtime/tmp`

## Scenario Runs
Use one run directory per scenario so evidence does not mix.

1. `mdcache <drive>: ON`
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_mdcache_on \
  --debug int,cpu \
  --no-monitor
```

2. `mdcache <drive>: OFF`
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_mdcache_off \
  --debug int,cpu
```

3. `mdcache <drive>: IS`
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_mdcache_is \
  --debug int,cpu
```

4. `mdcache <drive>: FLUSH`
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_mdcache_flush \
  --debug int,cpu
```

5. `mdformat <drive>: -q -o`
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_mdformat_qo \
  --debug int,cpu
```

6. `mdfsck <drive>:` / `mdfsck <drive>: -v`
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_mdfsck \
  --debug int,cpu
```

## Output Artifacts
Each run writes:
- `qemu.log`: interrupt/cpu-state trace (`-d int,cpu`)
- `serial.log`: guest serial output
- `monitor.sock`: QEMU monitor socket

## No-Media Batch Run
To execute all WS25 command scenarios without MD media and collect per-scenario
cross-run intersections:
```bash
REPEATS=2 TIMEOUT_SECS=20 tools/run_ws25_nomedia_matrix.sh
```
Outputs:
- `results/runtime/ws25_nomedia/*`
- `analysis/ws25_nomedia/summary.csv`
- `analysis/ws25_nomedia/*_intersection.csv`
- `analysis/ws25_nomedia/common_all_scenarios.csv`

## Optional Deep Debug
For instruction-by-instruction capture around known static anchors:
```bash
tools/run_qemu_trace.sh \
  --fda freedos-1.4M.img \
  --log-dir results/runtime/ws25_gdb \
  --gdb 1234 \
  --debug int,cpu
```
Then attach GDB and continue to breakpoints mapped from:
- `analysis/ws24_mdctl_callsite_lift.md`
- `analysis/ioctl_trace2.md`

## Promotion Hook
After each scenario run:
1. Normalize event rows to the WS25 output schema:
   `tool,site,phase,cs_ip,ax,bx,cx,dx,ds,es,ss_sp,buf_ptr,buf_len,buf_hex_prefix,notes`
2. Append candidate lanes in `analysis/ws26_mdctl_schema_matrix.csv`
3. Mark `confidence=confirmed` only when repeated in >=2 runs with >=1 contrasting scenario
