# WS54 mdmgr Startup Dispatch-table Initialization

Date: 2026-02-17

Scope: startup init routine `0x2e58..0x312e`

## Key writes detected
- 0x2e6d `mov word ptr [bx + 0xd04], 0` (d02_table_write)
- 0x2e73 `mov word ptr [bx + 0xd02], 0` (d02_table_write)
- 0x2e7f `mov word ptr [bx + 0xe34], 0` (e32_table_write)
- 0x2e85 `mov word ptr [bx + 0xe32], 0` (e32_table_write)
- 0x2ecc `mov word ptr [0xd08], 0x11f` (d02_table_write)
- 0x2ed2 `mov word ptr [0xd06], 0x95c` (d02_table_write)
- 0x2ed8 `mov word ptr [0xe34], 0x73` (e32_table_write)
- 0x2ede `mov word ptr [0xe32], 0x601` (e32_table_write)
- 0x2efa `mov word ptr [0xe34], 0x73` (e32_table_write)
- 0x2f00 `mov word ptr [0xe32], 0x601` (e32_table_write)

## Derived runtime state model (post-init)
- `loop_zero_e32`: for i=0..7: [0xe32+4*i]=0, [0xe34+4*i]=0
- `loop_zero_d02`: for i=0..7: [0xd02+4*i]=0, [0xd04+4*i]=0
- `set_entry0_e32`: [0xe32]=0x0601, [0xe34]=0x0073 (written twice)
- `set_entry1_d02`: [0xd06]=0x095c, [0xd08]=0x011f

## Correction Note
- On-disk initial words at `0x0e32..0x0e3c` are overwritten by startup init before normal operation.
- Therefore runtime interpretation should prioritize startup-written values over raw image defaults.
