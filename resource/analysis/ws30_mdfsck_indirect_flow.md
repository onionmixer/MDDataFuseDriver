# WS30 mdfsck Indirect Flow

Date: 2026-02-17

## Segment Bases
- `CS=0x03f7` => `CS_base=0x3f70`
- `DS` init from `cs:[0x012e]=0x0dcd` => `DS_base=0xdcd0`

## Indirect call/jump resolution

| site | insn | slot_seg | slot_off | slot_lin | resolved | resolved_target_lin | hits_cluster | note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0x4091 | call word ptr [0x1962] | ds | 0x1962 | 0xf632 | near 0x00f2 | 0x4062 | no |  |
| 0x409a | call word ptr [0x145a] | ds | 0x145a | 0xf12a | near 0x0200 | 0x4170 | no |  |
| 0x40d1 | lcall [0x196c] | ds | 0x196c | 0xf63c | far 0000:0000 |  | no | null far ptr (likely runtime filled) |
| 0x40e4 | lcall [0x196c] | ds | 0x196c | 0xf63c | far 0000:0000 |  | no | null far ptr (likely runtime filled) |
| 0x41ad | call word ptr [0x1964] | ds | 0x1964 | 0xf634 | near 0x00f2 | 0x4062 | no |  |
| 0x41f9 | lcall [0x196c] | ds | 0x196c | 0xf63c | far 0000:0000 |  | no | null far ptr (likely runtime filled) |
| 0x4217 | lcall [di] | unknown | di | runtime | indirect-runtime | unknown | unknown | register-based far call; requires runtime trace |
| 0x422e | lcall [0x14d2] | ds | 0x14d2 | 0xf1a2 | far 0000:0000 |  | no | null far ptr (likely runtime filled) |
| 0x4264 | ljmp [0x14d6] | ds | 0x14d6 | 0xf1a6 | far ffff:ffff |  | no | sentinel far ptr (likely runtime filled) |
| 0x4430 | ljmp [0x14dc] | ds | 0x14dc | 0xf1ac | far 0000:0000 |  | no | null far ptr (likely runtime filled) |
| 0x4526 | call word ptr [0x1960] | ds | 0x1960 | 0xf630 | near 0x00f2 | 0x4062 | no |  |
| 0x4b03 | jmp word ptr cs:[bx + 0xb30] | cs | 0x0b30+bx | 0x4aa0 | jump-table | local parser states | no | table entries decode to offsets 0x0b98..0x0c7c (linear 0x4b08..0x4bec) |
| 0x4d2d | lcall [0x1766] | ds | 0x1766 | 0xf436 | far 03f7:02ce | 0x423e | no |  |
| 0x4d37 | lcall [0x1752] | ds | 0x1752 | 0xf422 | far 03f7:02ce | 0x423e | no |  |
| 0x4d50 | lcall [0x175e] | ds | 0x175e | 0xf42e | far 03f7:02ce | 0x423e | no |  |
| 0x4d65 | lcall [0x175a] | ds | 0x175a | 0xf42a | far 03f7:02ce | 0x423e | no |  |
| 0x5233 | call word ptr [0x1960] | ds | 0x1960 | 0xf630 | near 0x00f2 | 0x4062 | no |  |
| 0x5324 | call word ptr [0x1960] | ds | 0x1960 | 0xf630 | near 0x00f2 | 0x4062 | no |  |
| 0x5b51 | lcall [0x177a] | ds | 0x177a | 0xf44a | far 0000:0000 |  | no | null far ptr (likely runtime filled) |

## Conclusions
- Resolved indirect pointers in this pass do not target `0x3994..0x3f4a`.
- `lcall [0x1752/0x175a/0x175e/0x1766]` resolves to `0x3f7:0x02ce` (linear `0x423e`) at image-init state.
- `call word ptr [0x1960/0x1962/0x1964]` resolves to near offset `0x00f2` (linear `0x4062`) at image-init state.
- Remaining unresolved runtime vectors (`[0x196c]`, `[di]`, sentinel slots) require runtime tracing.
