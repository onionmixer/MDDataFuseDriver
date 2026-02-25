# WS4 Unknown Reduction (x86/DOS/Win95 Focus)

Date: 2026-02-16

## Scope
- Continue disassembly under original target assumptions:
  - DOS tools as 16-bit x86 MZ
  - Win95 drivers as x86 LE VxD

## 1) mdfsck code/data separation cleanup
- Updated `analysis/mdfsck_field_xref.py` to disassemble only code window:
  - start: MZ entry offset
  - end: first stable runtime string anchor (`"MDfsck version"`)
- Result (`analysis/mdfsck_field_xref.md`):
  - immediate hits into VD label offset range: `0`
  - prior noisy hits were code+string linear-disassembly false positives.

## 2) DOS IOCTL wrapper hunt across Win3.1 tools
- Added `analysis/ioctl_wrapper_hunt.py`.
- Output (`analysis/ioctl_wrapper_hunt.md/.csv`) confirms:
  - `mdcache.exe` and `mdformat.exe` share near-identical wrappers.
  - `AH=0x44` wrappers include generic DOS-style signatures:
    - `AL` function code
    - `BX` handle
    - optional `DS:DX` buffer
    - optional `CX` length
  - Direct caller evidence in these wrappers shows `AL=0/1` paths in key callsites
    (consistent with DOS device-info GET/SET style usage).

## 3) Attribute-bit unknown removed
- Added `analysis/mdfsck_flag_tables.py`.
- Parsed relocation-backed far-pointer tables in `mdfsck.exe` and mapped:
  - Volume-style flags (8)
  - Record-style flags (12)
- Results exported:
  - `analysis/mdfsck_flag_tables.md`
  - `analysis/mdfsck_flag_tables.csv`

## 4) Remaining unknowns after WS4
- On-media byte-accurate VD/VSB/MTB/ERB/DRB member offsets.
- Full MDCTL opcode/payload schema (runtime capture likely required).
- LE `type=3` flags byte (`0x03`) semantic meaning.

