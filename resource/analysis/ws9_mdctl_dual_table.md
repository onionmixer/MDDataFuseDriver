# MDCTL Descriptor Dual Extract (WS9)

Date: 2026-02-17

## w31/extract/mdcache.exe
- candidate_blocks: 1
- selected_base: `0x0d0ac`
- callbacks: `0x000003a9`, `0x000003a9`, `0x000003a9`
- records:
  - rec0: off=`0x0d0ba` d0=`0x00000209` op=`0x0209` idx=`0` handler16=`0x0818`
  - rec1: off=`0x0d0ce` d0=`0x0001020a` op=`0x020a` idx=`1` handler16=`0x082c`
  - rec2: off=`0x0d0e2` d0=`0x00020202` op=`0x0202` idx=`2` handler16=`0x0840`
  - rec3: off=`0x0d0f6` d0=`0x00030243` op=`0x0243` idx=`3` handler16=`0x0854`
  - rec4: off=`0x0d10a` d0=`0x00040242` op=`0x0242` idx=`4` handler16=`0x0868`

## w31/extract/mdformat.exe
- candidate_blocks: 1
- selected_base: `0x1a01e`
- callbacks: `0x00000b9f`, `0x00000b9f`, `0x00000b9f`
- records:
  - rec0: off=`0x1a02c` d0=`0x00000209` op=`0x0209` idx=`0` handler16=`0x135a`
  - rec1: off=`0x1a040` d0=`0x0001020a` op=`0x020a` idx=`1` handler16=`0x136e`
  - rec2: off=`0x1a054` d0=`0x00020202` op=`0x0202` idx=`2` handler16=`0x1382`
  - rec3: off=`0x1a068` d0=`0x00030243` op=`0x0243` idx=`3` handler16=`0x1396`
  - rec4: off=`0x1a07c` d0=`0x00040242` op=`0x0242` idx=`4` handler16=`0x13aa`

## Interpretation
- The same 5-opcode structure appears in both DOS tools.
- `d0` packs `(opcode_low16, index_high16)` with index sequence `0..4`.
- `d1..d3` are zero across all 10 records (2 binaries x 5 records).
- `d4` low16 is a non-zero code pointer-like value per record.
