# WS3 Layout Verification State

Date: 2026-02-16

## Confirmed
- Logical structures exist in the design and checker output vocabulary:
  - `VD`, `VSB`, `MTB`, `ERB`, `DRB`
- `mdfsck` emits field labels for the volume descriptor and consistency checks.
- DOS/Win95 tools are consistent with a managed filesystem + driver control path.

## Not Yet Confirmed at Byte Level
- Exact on-media offsets and sizes for:
  - `VD` fields
  - `VSB` bitmap boundaries
  - `MTB/ERB/DRB` entry structures
- Complete opcode/request schema behind `\MDCTL` interactions.

## Confidence Summary
- Architecture-level spec feasibility: HIGH
- Byte-accurate on-media spec completeness: MEDIUM-LOW (needs live trace/image)

## Next Technical Step
Use one authentic MD DATA media trace set (quick/safe format + fsck verbose) to convert inferred fields to confirmed offsets.
