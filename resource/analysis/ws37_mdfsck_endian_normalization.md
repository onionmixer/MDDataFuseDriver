# WS37 mdfsck Endian Normalization Pass

Date: 2026-02-17

## Scope
- `w31/extract/mdfsck.exe`
- normalization block at `0x02e8..0x0562` (after bulk copy into `0x5b30..`)

## Key Evidence
1. Bulk external copy into checker workspace:
- `0x02e5: rep movsw` into `0x5b30` range.

2. Repeated 16-bit byte swap pattern:
- example:
  - `0x02e8: mov al, byte ptr [0x5b41]`
  - `0x02eb: mov ah, byte ptr [0x5b40]`
  - `0x02ef: mov word ptr [0x5b40], ax`
- same pattern repeats across many 16-bit lanes (`0x5b42`, `0x5b44`, ..., `0x5b82`, `0x5b88`).

3. 32-bit lane normalization pattern (word+byte reordering):
- representative pairs:
  - `0x5b48/0x5b4a`, `0x5b4c/0x5b4e`, `0x5b50/0x5b52`, ...
- sequence performs multi-step byte/word rearrangement and stores back to same lane pair.
- behavior is consistent with converting big-endian serialized dword to host little-endian form.

## Interpretation (Conservative)
- Numeric VD-related lanes in `0x5b40..0x5b88` are normalized after load.
- Checker arithmetic/compare/print code likely consumes host-little-endian values.
- Therefore source buffer byte order is likely big-endian for these fields.
- This still does **not** prove exact on-media offsets.

## Confidence Impact
- Endianness UNKNOWN for numeric VD lanes is reduced:
  - host-side interpretation: little-endian (post-normalization) `[INFERRED]`
  - source serialization: likely big-endian `[INFERRED]`
- Offset UNKNOWN remains open pending media-correlated trace.
