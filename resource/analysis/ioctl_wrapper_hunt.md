# DOS IOCTL Wrapper Hunt

Date: 2026-02-16

## w31/extract/mdcache.exe
- decoded_insn_count: 7824
- wrapper_candidates: 4
- wrapper_1: int21=0x01607, start=0x015fc, al=[bp+None] bx=[bp+6] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 2
    - call@0x01b60 pushes=ax
    - call@0x01b99 pushes=ax,ax,ax,ax
- wrapper_2: int21=0x025ca, start=0x025b6, al=[bp+8] bx=[bp+6] cx=[bp+14] ldsdx=[bp+10]
  - direct_callers: 2
    - call@0x03347 pushes=wordptr[bp+8],wordptr[bp+6],ax,wordptr[bp-8]
    - call@0x03371 pushes=dx,ax,ax,wordptr[bp-8]
- wrapper_3: int21=0x02acd, start=0x02a9f, al=[bp+None] bx=[bp+6] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 1
    - call@0x030c4 pushes=ax,ax
- wrapper_4: int21=0x02add, start=0x02a9f, al=[bp+None] bx=[bp+6] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 1
    - call@0x030c4 pushes=ax,ax

## w31/extract/mdfsex.exe
- decoded_insn_count: 160
- wrapper_candidates: 0

## w31/extract/mdfsck.exe
- decoded_insn_count: 22364
- wrapper_candidates: 4
- wrapper_1: int21=0x0493c, start=n/a, al=[bp+None] bx=[bp+None] cx=[bp+None] ldsdx=[bp+None]
- wrapper_2: int21=0x058bb, start=0x05856, al=[bp+None] bx=[bp+None] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 0
- wrapper_3: int21=0x05aab, start=n/a, al=[bp+None] bx=[bp+None] cx=[bp+None] ldsdx=[bp+None]
- wrapper_4: int21=0x05abb, start=n/a, al=[bp+None] bx=[bp+None] cx=[bp+None] ldsdx=[bp+None]

## w31/extract/mdformat.exe
- decoded_insn_count: 13714
- wrapper_candidates: 4
- wrapper_1: int21=0x02a7f, start=0x02a74, al=[bp+None] bx=[bp+6] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 2
    - call@0x03066 pushes=ax
    - call@0x0309f pushes=ax,ax,ax,ax
- wrapper_2: int21=0x0404d, start=0x04039, al=[bp+8] bx=[bp+6] cx=[bp+14] ldsdx=[bp+10]
  - direct_callers: 2
    - call@0x05792 pushes=wordptr[bp+8],wordptr[bp+6],ax,wordptr[bp-8]
    - call@0x057bc pushes=dx,ax,ax,wordptr[bp-8]
- wrapper_3: int21=0x04e0c, start=0x04dde, al=[bp+None] bx=[bp+6] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 1
    - call@0x05423 pushes=ax,ax
- wrapper_4: int21=0x04e1c, start=0x04dde, al=[bp+None] bx=[bp+6] cx=[bp+None] ldsdx=[bp+None]
  - direct_callers: 1
    - call@0x05423 pushes=ax,ax

## w31/extract/mdmgr.exe
- decoded_insn_count: 2552
- wrapper_candidates: 0

