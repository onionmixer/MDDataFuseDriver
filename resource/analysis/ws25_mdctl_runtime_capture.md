# WS25 MDCTL Runtime Capture

Date: 2026-02-17
Status: capture protocol prepared (pending live run)

## Objective
Capture real request/response buffers at DOS IOCTL/transport boundaries to resolve MDCTL payload schema.

## Static Anchors
- DOS wrapper anchors:
  - `mdcache.exe`: wrapper `0x15b6`
  - `mdformat.exe`: wrapper `0x2439`
- `mdfsck.exe` transport anchors:
  - TX: `lcall 0x3f7:0x1396`
  - RX: `lcall 0x3f7:0x1298`
- Pre-call lane evidence source: `analysis/ws24_mdctl_callsite_lift.md`

## Capture Points
1. Wrapper entry and immediately before `int 0x21` (`AH=0x44`) in `mdcache`/`mdformat`.
2. `mdfsck` TX/RX callsites in frame builders (`0x3994..0x3f7d`).
3. Runtime vectors from `WS30` if they are initialized during run (`[0x196c]`, `[di]`).

## Minimum Register/Memory Snapshot
For each hit, capture:
- `CS:IP`, `DS`, `ES`, `SS:SP`
- `AX`, `BX`, `CX`, `DX`, `SI`, `DI`, `BP`
- Pointer lane dump:
  - if wrapper path: `DS:DX` length `CX`
  - if frame path: pushed frame pointer/segment + pushed length (from stack)
- 32-byte stack window at `SS:SP`

## Scenario Set
1. `mdcache <drive>: ON`
2. `mdcache <drive>: OFF`
3. `mdcache <drive>: IS`
4. `mdcache <drive>: FLUSH`
5. `mdformat <drive>: -q -o`
6. `mdfsck <drive>:` and `mdfsck <drive>: -v`

## Output Format
For each capture event, record CSV-like row:
- `tool,site,phase,cs_ip,ax,bx,cx,dx,ds,es,ss_sp,buf_ptr,buf_len,buf_hex_prefix,notes`

## Mapping Workflow
1. Group captures by `(tool,site,buf_len)`.
2. Align with `WS24` pre-call push lanes to infer field placement.
3. Compare request vs response for same site to separate input/output fields.
4. Promote stable lanes into `analysis/ws26_mdctl_schema_matrix.csv`.

## Promotion Criteria
- A field is promoted from inferred to confirmed only when repeated across >=2 runs and >=1 contrasting scenario.
- Command-level schema promotion requires at least one request and one response capture per command path.
