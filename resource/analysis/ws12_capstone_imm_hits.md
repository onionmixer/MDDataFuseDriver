# WS12 Capstone Immediate Hit Scan

Date: 2026-02-17

## w31/extract/mdcache.exe
- header_size: `0x1000`
- immediate hits: 0

## w31/extract/mdformat.exe
- header_size: `0x1c00`
- immediate hits: 2
  - `0x0f202`: `ljmp 0x20a:0xf526` (`0x020a`)
  - `0x11ade`: `ljmp 0x20a:0xf526` (`0x020a`)

## Note
- Linear disassembly over mixed code/data can miss hidden or alternate decode paths.
- However, low hit count here supports the descriptor-table interpretation for these values.
