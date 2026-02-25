# WS2 VxD Dispatch Surface (Static)

Date: 2026-02-16
Scope: `w95/extract/us/mdfsd.vxd`, `w95/extract/us/mdmgr.vxd`, `w95/extract/us/mdhlp.vxd`

## Binary Identity
- All three files are LE VxD binaries (`file` command).
- `us` and `jp` variants are byte-identical (same SHA-1):
  - `mdfsd.vxd`: `ebd4c5f887f1081461d9720a95afb25074f9fdda`
  - `mdmgr.vxd`: `1ace191b10bb9c6ebed8e048b7e6d7fff5aea00d`
  - `mdhlp.vxd`: `5a8e0363c93110c4f9cb0bbb13236d7d243fd24b`
- LE header parse summary (`analysis/ws2_le_headers.md`):
  - common LE offset `0x80`, CPU type `2` (386+), OS type `4`
  - common module flags `0x00038000`
  - all modules expose 2 objects (code/data split pattern)
- LE page-map/fixup summaries:
  - `analysis/ws2_le_pagemap.md`, `analysis/ws2_le_pagemap.csv`
  - `analysis/ws2_le_fixup_summary.md`, `analysis/ws2_le_fixup_summary.csv`
  - page map entries use `raw=0x000N0000` pattern (`physical_page = raw >> 16`)
  - fixup page tables have expected `num_pages + 1` entries in all three modules
- Entry/ordinal parse (`analysis/ws2_le_exports.md`):
  - each module currently shows one entry bundle (`ord 1-1`, `type=3`, `count=1`)
  - named ordinals observed:
    - `MDMGR`: ord0 (`MDMGR`), ord1 (`_The_DDB`)
    - `MDHLP`: ord0 (`MDHLP`), ord1 (`MDHlp_DDB`)
    - `MDFSD`: ord0 (`MDFSD`), ord1 (`_The_DDB`)
- Entry raw decode hypotheses (`analysis/ws2_le_entry_hypotheses.md`):
  - common raw prefix pattern: `01 00 03 ... ...`
  - `00 03` word pair is consistent across all 3 modules
  - exact field semantics (object/offset endianness layout) remain unresolved
- x86-specific LE interpretation (`analysis/ws2_le_entry_x86.md`):
  - entry layout interpreted as `count,type,obj(2),entry(3),terminator`
  - all modules decode as `type=3 obj=1`
  - entry bytes decode to `flags=0x03` + `offset16`, where `offset16` matches DDB candidate location
- DDB candidate validation (`analysis/ws2_vxd_ddb_candidates.md`):
  - ord1 raw tail (`b3..4` LE) maps to plausible DDB offsets in all modules
  - probing `candidate_offset + 0x0c` yields module names:
    - `MDMGR   `
    - `MDHlp   `
    - `MDFSD   `
  - cross-module DDB field stability (`analysis/vxd_ddb_struct_scan.md`):
    - common `+0x00=0`, `+0x04=0x00000400`, `+0x0c=<module name8>`
    - role-dependent value at `+0x14`
  - this strongly supports `ord1` as DDB-related export pointer in the VxD stack
  - `type=3` entry `flags=0x03` meaning is still unresolved in semantics

## INF-Level Installation Chain (Confirmed)
- `w95/extract/us/mdh10.inf`, `w95/extract/us/mdm110.inf`, `w95/extract/us/mdm111.inf` all define:
  - `CopyFiles=@MDHLP.VXD,@MDMGR.VXD,@MDFSD.VXD`
  - SCSI hardware IDs:
    - `SCSI\\SONY____MDH-10__________1`
    - `SCSI\\SONY____MDM110__________1`
    - `SCSI\\SONY____MDM111__________1`
- This confirms a fixed 3-module driver stack is installed as one unit.

## mdfsd.vxd
- Product identity strings:
  - `0x01357e` `MD DATA File System Driver (Version 1.E0)`
  - `0x013632` `MDFSD.VXD`
  - `0x0134aa` PDB path `...\MDFSD.pdb`
- Control-path tokens:
  - `0x0062fc` `MDCTL`
  - `0x00630c` `MDFSD`
- Finding:
  - Core filesystem payload module, but explicit IOR opcode labels were not observed by strings-only analysis.

## mdmgr.vxd
- Product identity strings:
  - `0x00517f` `MD DATA MDMGR Driver (Version 1.E0)`
  - `0x00522b` `MDMGR.VXD`
  - `0x0050aa` PDB path `...\MDMGR.pdb`
- Mount/registration evidence:
  - `0x000bfb` `mountCFSD`
  - `0x000f18` `_INIT_IFSMgr_RegisterCFSD`
  - `0x000f6a` `_INIT_IFSMgr_RegisterMount`
  - `0x000f85` `_INIT_IFSMgr_RegisterNet`
- IFSMgr import surface indicates strong coupling to Win95 file-system registration path.

## mdhlp.vxd
- Product identity strings:
  - `0x002a84` `DOS386 MDHlp Device  (Version 4.0)`
  - `0x002c1a` `MDHLP.VXD`
  - `0x002c36` `Sony MDData Device Driver`
- I/O dispatch labels present as explicit strings:
  - `0x00136c` `IOR_READ`
  - `0x00137c` `IOR_WRITE`
  - `0x0013bc` `IOR_MEDIA_CHECK`
  - `0x001470` `IOR_GEN_IOCTL`
  - `0x001484` `IOR_FORMAT`
  - `0x001590` `IOR_FSD_EXIT`
  - plus multiple queue/media/sense operations.
- Finding:
  - `mdhlp.vxd` appears to implement or wrap low-level I/O request dispatch used by the MD DATA stack.

## Confirmed vs Inferred
- Confirmed:
  - `mdmgr.vxd` contains CFSD registration-related IFSMgr entry names.
  - `mdhlp.vxd` exposes many IOR operation labels, including format/media/check paths.
  - `mdfsd.vxd` is the named MDFS core FS module.
- Inferred:
  - Boot-time/init flow likely `mdmgr.vxd -> IFSMgr RegisterCFSD -> mdfsd.vxd`.
  - Data path likely traverses `mdhlp.vxd` for I/O request handling before/under FS logic.
- Unknown (needs disassembler-level RE):
  - Exact dispatch table offsets and handler addresses.
  - Precise opcode-to-function mapping and request payload structs.
  - Definitive LE type-3 entry `flags=0x03` semantic meaning.
