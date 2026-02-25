# WS47 mdmgr 0x0c42 Pointer Semantics

Date: 2026-02-17

## Loader Evidence
- `0x0375`: `int 21h` with `AX=0x4402` (IOCTL Read from device), `DX=0xc42`, `CX=4` -> reads 4 bytes into `0x0c42` buffer

## Call Consumption
- `lcall [0x0c42]` sites: 4
- `0x0398` push prelude: 0x0393:push ss ; 0x0397:push ax
- `0x0501` push prelude: 0x04fd:push ds ; 0x04fe:push 0xc54
- `0x0573` push prelude: 0x056e:push ss ; 0x0572:push ax
- `0x0684` push prelude: 0x067f:push ss ; 0x0683:push ax

## Write Evidence
- direct in-image writes to `[0x0c42]`/`[0x0c44]`: 0

## String Anchor
- `MDFSEX01` occurrences in raw binary: 2 at ['0x2b9b', '0x2e7a']

## Conclusion
- `0x0c42` is consumed as a far pointer (`lcall m16:16`) and is loaded via 4-byte DOS read path.
- No static in-image direct writes to `0x0c42/0x0c44` were found in this pass.
- This strongly supports "external helper callback entry pointer" semantics for `0x0c42`.
