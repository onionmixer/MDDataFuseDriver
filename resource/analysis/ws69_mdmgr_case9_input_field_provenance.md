# WS69 mdmgr Case-9 Input Field Provenance

Date: 2026-02-17

Scope: `req[0x10..0x17]` consumed by case-9 path (`0x1047`).

## Findings
- case-9 reader sites reviewed: 10
- req-like local writes to `es:[bx+0x10..0x17]` with immediate base pattern `les bx,[bp+6]`: 0
- In current bounded static pass, case-9 input fields are observed as read-mostly contract bytes.
- Multiple helper mappers (`0x1205`, `0x1226`, `0x129b`) also read these offsets and emit transformed output buffers, reinforcing role as structured input lanes.
- Interpretation: `0x1047` consumes pre-assembled request-extension fields rather than constructing them locally.
