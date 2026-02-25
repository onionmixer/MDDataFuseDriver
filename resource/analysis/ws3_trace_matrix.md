# WS3 Trace Matrix (Dynamic Validation Plan)

Date: 2026-02-16
Status: Partial (no MD DATA physical media trace yet)

## Objective
Confirm on-media byte layout and control behavior during format/check/mount using runtime traces.

## Matrix
| ID | Scenario | Required Environment | Capture Method | Current Status | Output |
|---|---|---|---|---|---|
| WS3-01 | `mdformat -q` quick format | DOS/Win95 + real MD DATA media/device | I/O trace (sector write map) | BLOCKED | pending |
| WS3-02 | `mdformat -s` safe format | DOS/Win95 + real MD DATA media/device | I/O trace + duration + defect map writes | BLOCKED | pending |
| WS3-03 | `mdfsck -v` on clean media | DOS/Win95 + formatted media | Read pattern trace + checker output correlation | BLOCKED | pending |
| WS3-04 | `mdcache ON/OFF/FLUSH` | DOS/Win95 + mounted media | control request trace to `MDCTL` path | BLOCKED | pending |
| WS3-05 | Mount/unmount cycle | Win95 stack (`MDHLP/MDMGR/MDFSD`) | VxD debug/log trace if available | BLOCKED | pending |
| WS3-06 | Static-only fallback | current extracted binaries | string/LE header/import surface correlation | COMPLETE | `analysis/ws1_*`, `analysis/ws2_*` |

## What Is Already Verified Without Live Media
- Installer payload integrity and post-install equivalence for Win3.1 package.
- InstallShield package extraction and locale mapping for Win95 package.
- DOS tool CLI/control surface (`mdfsex`, `mdmgr`, `mdformat`, `mdfsck`, `mdcache`).
- Win95 VxD stack composition + IFSMgr/IOR evidence.

## Blocking Constraints
- No captured raw I/O trace from real MD DATA media.
- No confirmed disk image containing real MDFS formatted volume from hardware.
- Without one of the above, VD/VSB/MTB/ERB/DRB byte offsets remain partly inferred.

## Minimum Data Needed to Unblock
1. One raw image (or sector dump) before and after `mdformat -q`.
2. One raw image (or sector dump) before and after `mdformat -s`.
3. Verbose `mdfsck -v` output for the same media snapshots.
4. Optional: low-level driver log/trace around `\MDCTL` requests.
