# WS25 No-Media Matrix Report

Date: 2026-02-17
Status: complete (no-MD-media scope)

## Scope
Executed WS25 scenario set without MD DATA media:
- `mdcache is`
- `mdcache on`
- `mdcache off`
- `mdcache flush`
- `mdfsck d:`
- `mdformat d: -q -o`

Each scenario was captured 2 times (`QEMU -d int,cpu`) and reduced to:
- run CSV (`*_run1.csv`, `*_run2.csv`)
- per-scenario intersection (`*_intersection.csv`)

## Outputs
- Summary: `analysis/ws25_nomedia/summary.csv`
- Per-scenario intersections: `analysis/ws25_nomedia/*_intersection.csv`
- Common across all 6 scenarios: `analysis/ws25_nomedia/common_all_scenarios.csv`

## Key Result
- Cross-run stable lane signatures per scenario: `11~14`
- Common stable signatures across all scenarios: `10`
- Common set is entirely in `AX=0x4400` domain in this no-media environment.

## Interpretation
- Runtime transport lanes (`AX/BX/CX/DX/DS:DX`) are repeatable without MD media.
- Command-specific/private payload semantics are still unresolved; MD media run is required for closure.
