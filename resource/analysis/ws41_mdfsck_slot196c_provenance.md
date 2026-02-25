# WS41 mdfsck Slot 0x196c Provenance

Date: 2026-02-17

## Setup
- `CS=0x03f7` (`CS_base=0x3f70`)
- `DS=0x0dcd` (`DS_base=0xdcd0`)
- slot linear: `DS_base + 0x196c = 0xf63c`
- image-init far value at slot: `0000:0000`

## References to slot/immediate 0x196c
| addr | insn | via | access |
| --- | --- | --- | --- |
| 0x40d1 | lcall [0x196c] | abs_mem | indirect_call |
| 0x40e4 | lcall [0x196c] | abs_mem | indirect_call |
| 0x41f9 | lcall [0x196c] | abs_mem | indirect_call |

## Conclusion
- indirect call sites using `[0x196c]`: 3
- static in-image direct writes to `[0x196c]`: 0
- In this static pass, slot `0x196c` behaves as runtime-populated callback/continuation vector.
