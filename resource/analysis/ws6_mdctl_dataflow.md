# WS6 MDCTL Dataflow (Static, Conservative)

Date: 2026-02-16

## Scope
- `w31/extract/mdcache.exe`
- Relocation-driven data xrefs + local code-window validation

## Findings

1. Parser token blob linked by relocation:
- Relocation `#115` points to blob around `0x0d052` containing:
  - `:\\mdctl`
  - command tokens: `ON`, `OFF`, `IS`, `FLUSH`, `?`
  - adjacent `ERROR:` labels
- Evidence: `analysis/mdcache_cmd_blob.md`, `analysis/reloc_string_xref.md`

2. Stub callback pointers near parser blob:
- Relocations `#127..#129` point to code offset `0x13a9`.
- `0x13a9` body is stub-like (`push/pop` + `retf`), likely placeholder/default callback slot.

3. Nearby descriptor-like numeric lanes exist:
- At `0x0d0ba..`, regular records (`0x14` stride) are now decodeable as 5 entries:
  - `(op_code, op_index)`: `(0209,0)`, `(020A,1)`, `(0202,2)`, `(0243,3)`, `(0242,4)`
  - handler offsets: `0x1818`, `0x182c`, `0x1840`, `0x1854`, `0x1868`
- See: `analysis/mdcache_descriptor_decode.md`
- This strongly suggests command descriptor metadata, though exact runtime field semantics are still unresolved.

## Confidence impact
- Increased confidence that `mdcache` command dispatch is table-driven and explicitly tied
  to `:\\mdctl` tokenized command paths.
- Still not sufficient to claim definitive MDCTL private opcode/payload layout.

## Remaining unknown
- Exact meaning of descriptor words/dwords and how they map to runtime payload bytes.
- Full MDCTL opcode/payload schema remains unresolved without deeper control-flow recovery
  or dynamic trace.
