# MDFS Test Vectors (Current)

Date: 2026-02-16
Status: Preliminary (static evidence vectors + structural checks)

## 1. Integrity Vectors
- Input set: `w31/extract/*`, `w95/extract/us/*`
- Method A (primary subset): SHA-1 + file size match against `document/MDFS_SPEC_RFC.md` baseline
- Method B (full set): SHA-1 + file size match against `document/MDFS_BINARY_MANIFEST.csv`
- Expected:
  - RFC baseline binaries match exactly
  - manifest rows (full extracted set) match exactly

## 2. Win3.1 Extraction Vector
- Command: `python3 verify_w31_install.py --installer-dir w31 --installed-dir w31/extract`
- Expected:
  - `expected files: 13`
  - `installed files: 13`
  - `RESULT: PASS`

## 3. Win95 Driver Equivalence Vector
- Compare pairs:
  - `w95/extract/us/mdfsd.vxd` vs `w95/extract/jp/mdfsd.vxd`
  - `w95/extract/us/mdmgr.vxd` vs `w95/extract/jp/mdmgr.vxd`
  - `w95/extract/us/mdhlp.vxd` vs `w95/extract/jp/mdhlp.vxd`
- Expected: hash equality for all pairs

## 4. LE Entry/DDB Vector
- Source: `analysis/ws2_vxd_ddb_candidates.csv`
- Expected:
  - 3 rows total
  - all rows `name_match=1`
  - candidate offsets map to module names at `+0x0c`

## 5. LE Page Map Vector
- Source: `analysis/ws2_le_pagemap.csv`
- Expected rule:
  - `physical_page == (raw >> 16)` for all rows

## 6. LE Fixup Table Vector
- Source: `analysis/ws2_le_fixup_summary.csv`
- Expected row counts:
  - `mdmgr.vxd`: 33
  - `mdhlp.vxd`: 14
  - `mdfsd.vxd`: 147

## 7. Open Runtime Vectors (Blocked)
- Media-dependent vectors requiring authentic MD DATA media trace:
  - quick/safe format sector mutation maps
  - fsck verbose output vs raw structure offset correlation
  - MDCTL opcode/payload runtime capture

## 8. Installer Locale Indirection Vector
- Source: binary `w95/merged/SETUP.INS`
- Expected:
  - contains installer locale indirection strings for `US\\SETUP.INS` and `JP\\SETUP.INS`
  - extractor path resolution remains reproducible
