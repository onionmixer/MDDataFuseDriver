# MDFS Reverse-Engineering Plan (UNKNOWN Closure)

Date: 2026-02-17  
Scope: close remaining UNKNOWN items in `document/MDFS_SPEC_FINAL.md` with evidence-bound steps.

## 1. Current UNKNOWN Set
1. On-disk byte-accurate offsets/layout for `VD/VSB/MTB/ERB/DRB`.
2. MDCTL opcode-to-payload schema (request/response field semantics).
3. LE `type=3` entry flags byte (`0x03`) semantics.
4. `mdfsck` helper cluster (`0x3994..0x3f4a`) top-level reachability/runtime path.

## 2. Strategy
- Rule 1: promote only when at least two independent evidences agree (static + static-cross, or static + dynamic).
- Rule 2: keep `CONFIRMED/INFERRED/UNKNOWN` tags synchronized across:
  - `document/MDFS_SPEC_RFC.md`
  - `document/MDFS_SPEC_FINAL.md`
  - `document/MDFS_EVIDENCE_GAP_AUDIT.md`
- Rule 3: every step must emit reproducible `WS` artifact files under `analysis/` and be revalidated by `analysis/revalidate_all.py`.

## 3. Workstreams

## WS-A: On-disk Layout Closure (`VD/VSB/MTB/ERB/DRB`)
Goal:
- derive byte offsets/sizes/endian for core records.

Steps:
1. Static offset candidate extraction:
- extend current `mdfsck` analyses (`ws19`) to identify all global readers/writers for `0x5b40..` lanes and backtrack field load origins.
2. Controlled image differential tracing:
- run format/check paths in DOS/QEMU with controlled input toggles.
- compare sector-level before/after deltas to map each printed field to media offsets.
3. Cross-check with checker output:
- force minimal single-field changes and validate `mdfsck` reported values align with mapped offsets.

Deliverables:
- `analysis/ws21_layout_candidate_map.md` (static candidate table)
- `analysis/ws22_media_diff_matrix.md` (operation vs sector delta matrix)
- `analysis/ws23_layout_confirmed_table.csv` (record/field/offset/size/confidence)

Acceptance:
- each core field has offset+size+endianness with at least one dynamic corroboration.

## WS-B: MDCTL Payload Schema Closure
Goal:
- map command IDs (currently strongly supported: `0209/020A/0202/0243/0242`) to request/response payload definitions.

Steps:
1. DOS-side transport lifting:
- reconstruct all callsites into IOCTL wrappers in `mdcache`, `mdformat`, `mdfsck`.
- normalize frame builders into canonical struct candidates.
2. Runtime capture:
- instrument/emulate DOS calls to capture `DS:DX` buffers at IOCTL boundary (`AH=44h`) for each command path (`ON/OFF/IS/FLUSH`, format/check actions).
3. Protocol matrix synthesis:
- cluster captures by opcode/subtype/length and map fixed fields vs variable fields.

Deliverables:
- `analysis/ws24_mdctl_callsite_lift.md`
- `analysis/ws25_mdctl_runtime_capture.md`
- `analysis/ws26_mdctl_schema_matrix.csv`

Acceptance:
- each known opcode has request/response layout with field names and byte ranges.

## WS-C: LE Type-3 Flags (`0x03`) Semantics
Goal:
- determine whether `0x03` is calling convention/entry-kind/privilege bitmask (or composite).

Steps:
1. Internal consistency check:
- scan all LE modules for type-3 entries and compare flags distribution with object attrs and DDB placement.
2. External reference correlation:
- compare against known LE/VxD type-3 conventions from tooling outputs/manual examples (kept as secondary evidence).
3. Negative test:
- patch-copy experiment in disposable sample (if feasible) changing flags byte and observe loader behavior in Win95 VM.

Deliverables:
- `analysis/ws27_le_type3_flags_survey.md`
- `analysis/ws28_le_type3_flags_hypothesis.md`
- `analysis/ws29_le_type3_flags_runtime_probe.md` (if VM probe succeeds)

Acceptance:
- either flags semantics promoted to `CONFIRMED/INFERRED` with explicit evidence, or `UNKNOWN` narrowed to bounded alternatives.

## WS-D: `mdfsck` Cluster Reachability Closure
Goal:
- prove real invocation path into `0x3994..0x3f4a` (or show dead/debug-only path).

Steps:
1. Static flow deepening:
- include indirect call/jump-table/function-pointer resolution beyond current direct xref (`ws20`).
2. Runtime trace:
- collect execution trace while running `mdfsck` options and representative media states.
3. Path classification:
- classify each helper as hot path / conditional path / unreachable in tested scenarios.

Deliverables:
- `analysis/ws30_mdfsck_indirect_flow.md`
- `analysis/ws31_mdfsck_runtime_trace.md`
- `analysis/ws32_mdfsck_path_classification.csv`

Acceptance:
- top-level-to-helper path is evidenced; semantics confidence updated accordingly.

## 4. Execution Order
1. WS-D first (reachability): removes ambiguity for WS-B interpretation.
2. WS-B second (payload schema): establishes control semantics.
3. WS-A third (on-disk offsets): ties protocol+checker semantics to media bytes.
4. WS-C in parallel where possible (mostly independent).

## 5. Tooling and Environment
- Static:
  - existing Python scripts in `analysis/`
  - capstone-based disassembly (`PYTHONPATH=/tmp/mdh10_py`)
- Runtime:
  - DOS/QEMU path already prepared in workspace
  - optional Win95 VM path for VxD loader behavior
- Integrity:
  - keep original extracted binaries immutable
  - write all derived artifacts under `analysis/` and `document/` only

## 6. Risk Register
1. No stable MD DATA media image:
- Mitigation: rely on deterministic format/check operation traces and diff clustering.
2. Indirect control paths in 16-bit binaries:
- Mitigation: combine static lifting and runtime breakpoint/capture.
3. LE flag semantics may require undocumented loader behavior:
- Mitigation: keep bounded hypotheses and runtime patch probe logs.

## 7. Completion Criteria
- `document/MDFS_SPEC_FINAL.md` has no blocking `UNKNOWN` for:
  - on-disk core fields
  - MDCTL payload schema
  - `mdfsck` cluster reachability
- LE type-3 flags is either resolved or reduced to explicit bounded hypotheses with probe evidence.
- `analysis/revalidate_all.py` remains PASS after each promotion step.
