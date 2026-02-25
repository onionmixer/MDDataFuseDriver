# x86 DOS/Win95 Disassembly Findings

Date: 2026-02-17
Scope:
- DOS MZ binaries (`w31/extract/*.exe`) as 16-bit x86
- Win95 VxD LE binaries (`w95/extract/us/*.vxd`) as 32-bit x86 LE modules

## 1) MDCTL / DOS IOCTL Path (Refined)

Primary evidence from `w31/extract/mdcache.exe`:
- IOCTL wrapper function around `0x025b6`:
  - sets `AH=0x44`
  - `AL` is caller-provided function code (`mov al, [bp+8]`)
  - `BX` handle, `DS:DX` buffer, `CX` length
  - executes `int 0x21`
- Recovered direct callsites in this segment use `AL=0/1` patterns compatible with
  DOS `4400h/4401h` device-info flow.
- Device open path uses `AH=0x3D` (`int 0x21`) with path pointer.
- Additional helper recovery:
  - `0x3ba2` behaves as `strlen` helper.
  - `0x3d29` is DOS write wrapper (`AH=0x40`).
  - `0x3bc3` is buffered write variant (LF->CRLF handling).
- Parser/dataflow cluster evidence:
  - token blob includes `:\\mdctl` + `ON/OFF/IS/FLUSH/?`
  - token blob, callback trio, and descriptor tuples are contiguous in one data cluster.
  - adjacent regular descriptor block (5 records, `0x14` stride) with:
    - candidate `(op_code, op_index)` pairs:
      - `(0x0209,0)`, `(0x020A,1)`, `(0x0202,2)`, `(0x0243,3)`, `(0x0242,4)`
    - handler offset words mapping into code region:
      - `0x1818`, `0x182c`, `0x1840`, `0x1854`, `0x1868`
- Cross-binary reinforcement from `w31/extract/mdformat.exe`:
  - a second block with the same 5-record shape and same `(opcode,index)` lane:
    - `(0x0209,0)`, `(0x020A,1)`, `(0x0202,2)`, `(0x0243,3)`, `(0x0242,4)`
  - corresponding handler words differ by binary, but record semantics are stable.
- IOCTL transport parity:
  - both `mdcache` and `mdformat` implement homologous DOS IOCTL wrappers:
    - `mov ah,0x44`, `mov al,[bp+8]`, `mov bx,[bp+6]`, `lds dx,[bp+0xa]`, `mov cx,[bp+0xe]`, `int 0x21`
  - direct callsites observed in both binaries show `AL=0` and `AL=1` usage patterns.

Interpretation:
- DOS utilities use INT 21h device handle + IOCTL control flow.
- MDCTL command opcode IDs above are strongly supported as table data across two binaries.
- additional low-confidence crosswalk candidate from order correlation:
  `ON/OFF/IS/FLUSH/?` <-> `0209/020A/0202/0243/0242` (same descriptor index order).
- Exact request payload schema/packing is unresolved; direct callsites still do not prove full
  private MDCTL opcode payload contract beyond generic DOS handle-control wrappers.
- Additional `mdfsck` framing evidence:
  - command helpers build fixed-size buffers (`0x20`, `0x208`, `0x4a`) with leading byte lanes
    (`type=2`, subtype values including `4/5/6`) then issue paired imported transport calls.
  - this constrains payload *shape* but does not map frame subtypes to MDCTL opcode IDs yet.
  - adjacent helper set shows additional frame families:
    - `type=1` with subtype-like byte `0x16/0x18` (mode-dependent path)
    - `type=2,sub=8,len=0x11` request/response pair
    - `type=1,sub=0x24,len=0x17` and `type=1,sub=7,len=0x10` probe-style requests
  - orchestrator at `0x3e32` sequences `0x3a4c` then `0x3adc` in one higher-level check flow.
  - core transport helper `0x3cca` has wrapper-selected direction (`0x3df2` pushes `0`, `0x3e12` pushes `1`);
    it performs tx/rx pair and conditionally copies payload caller->frame or frame->caller based on that flag.
  - argument-to-header mapping in `0x3cca` is now constrained:
    - `[bp+0x0c/0x0e] -> header +0x10/+0x12` (32-bit start-like field)
    - `[bp+0x10] -> header +0x14` and transfer-size driver (`<<11`)
    - payload byte count shape: `([bp+0x10] << 11) + 0x18`
  - direct near-call reachability from process entry did not include this helper cluster,
    so these semantics are treated as static-path inference pending dynamic confirmation.
  - indirect-call/jump resolution with segment-aware addressing:
    - `CS=0x03f7`, `DS_base=0xdcd0` (matches VD string-base inference)
    - resolved indirect sites (`call [0x1960/62/64]`, `lcall [0x1752/5a/5e/66]`,
      parser jump-table `cs:[bx+0xb30]`) do not target `0x3994..0x3f4a`
    - unresolved vectors are now narrowed to runtime callback/continuation slots
      (`0x196c`, `0x14d2/0x14d4`, `0x14d6`, `0x14dc/0x14de`, `0x177a/0x177c`),
      with no static indication of helper-cluster target linkage.
  - `lcall [di]` at `0x4217` is further constrained as callback-list walker dispatch:
    - walker (`0x4209`) iterates half-open range `[SI,DI)` in 4-byte far-pointer entries
    - observed static callsite with non-empty range uses `[0x1978,0x197c)` (single entry)
    - this path still shows no static linkage to `0x3994..0x3f4a`.

References:
- `analysis/ioctl_trace2.md`
- `analysis/unknown_reduction.md`
- `analysis/ws5_mdctl_refinement.md`
- `analysis/ws6_mdctl_dataflow.md`
- `analysis/mdcache_descriptor_decode.md`
- `analysis/ws8_imm16_usage.md`
- `analysis/ws9_mdctl_dual_table.md`
- `analysis/ws12_capstone_imm_hits.md`
- `analysis/ws13_ioctl_wrapper_audit.md`
- `analysis/ws14_mdfsck_frame_builders.md`
- `analysis/ws15_mdfsck_payload_shape_matrix.md`
- `analysis/ws16_mdfsck_3cca_semantics.md`
- `analysis/ws17_mdfsck_direct_reachability.md`
- `analysis/ws18_mdfsck_3cca_param_map.md`
- `analysis/ws24_mdctl_callsite_lift.md`
- `analysis/ws33_mdctl_opcode_crosswalk.md`
- `analysis/ws34_mdcache_blob_cluster.md`
- `analysis/ws35_mdcache_reloc_sanity.md`
- `analysis/ws19_mdfsck_vd_emit_map.md`
- `analysis/ws20_mdfsck_cluster_xrefs.md`
- `analysis/ws30_mdfsck_indirect_flow.md`
- `analysis/ws38_mdfsck_runtime_vector_slots.md`
- `analysis/ws39_mdfsck_vector_role_classification.md`
- `analysis/ws40_mdfsck_callback_walker.md`
- `analysis/ws41_mdfsck_slot196c_provenance.md`
- `analysis/ws42_mdfsck_runtime_slot_contract.md`
- `analysis/ws43_mdfsck_slot_write_proof.md`
- `analysis/ws44_cross_binary_callback_abi.md`
- `analysis/ws45_mdmgr_vector_slot_classes.md`
- `analysis/ws46_mdmgr_vector_population.md`
- `analysis/ws47_mdmgr_c42_pointer_semantics.md`
- `analysis/ws48_mdmgr_e32_dispatch_table.md`
- `analysis/ws49_mdmgr_e32_reloc_crosscheck.md`
- `analysis/ws50_mdmgr_e32_nonliteral_write_scan.md`
- `analysis/ws51_mdmgr_table_separation.md`
- `analysis/ws52_mdmgr_e32_farptr_classification.md`
- `analysis/ws53_mdmgr_farptr_loadseg_feasibility.md`
- `analysis/ws54_mdmgr_startup_dispatch_init.md`
- `analysis/ws55_mdmgr_e32_state_timeline.md`
- `analysis/ws56_mdmgr_1997_reachability.md`
- `analysis/ws57_mdmgr_indirect_1997_feasibility.md`
- `analysis/ws58_mdmgr_dynamic_vector_prioritization.md`
- `analysis/ws59_mdmgr_c42_load_chain_audit.md`
- `analysis/ws60_mdmgr_stride11_index_bounds.md`
- `analysis/ws61_mdmgr_0916_k_bound_trace.md`
- `analysis/ws62_mdmgr_8f4_precondition_closure.md`
- `analysis/ws63_mdmgr_second_dispatch_materialization.md`
- `analysis/ws64_mdmgr_req1_provenance_partition.md`
- `analysis/ws65_mdmgr_req1_writer_nondominance.md`
- `analysis/ws66_mdmgr_req1_domain_plausibility.md`
- `analysis/ws67_mdmgr_case9_1047_semantics.md`
- `analysis/ws68_mdmgr_case9_status_output_flow.md`
- `analysis/ws69_mdmgr_case9_input_field_provenance.md`
- `analysis/ws70_mdmgr_case9_subtype_profile.md`

## 2) LE type-3 Entry Interpretation (Win95 VxD)

Using x86-specific LE bundle interpretation:
- bundle header: `count(1), type(1), obj(2)`
- for `type=3`, entry bytes interpreted as `flags(1), offset16(2)`

Recovered results:
- `mdmgr.vxd`: `ord1 type=3 obj=1 raw=03 20 03 offset16=0x0320 file_off=0x1320`
- `mdhlp.vxd`: `ord1 type=3 obj=1 raw=03 bc 02 offset16=0x02bc file_off=0x12bc`
- `mdfsd.vxd`: `ord1 type=3 obj=1 raw=03 00 52 offset16=0x5200 file_off=0x6200`

These offsets match DDB candidate structures where `+0x0c` contains module names.
Validation across all 3 VxDs shows type-3 `middle16` is best interpreted as
object-relative DDB offset rather than code entry RVA.
Additional corpus survey across US/JP LE modules:
- all observed type-3 entries use `flags=0x03`
- type-3 ordinals correlate with DDB-style exports (`_The_DDB` / `MDHlp_DDB`)
- this narrows uncertainty to bit-level meaning of `0x03`, not presence/role coupling.

References:
- `analysis/ws2_le_entry_x86.md`
- `analysis/ws2_vxd_ddb_candidates.md`
- `analysis/ws10_le_type3_middleword.md`
- `analysis/ws27_le_type3_flags_survey.md`
- `analysis/ws28_le_type3_flags_hypothesis.md`

## 3) On-disk Field Offset Recovery Status

Current status:
- Logical field names are confirmed from checker strings.
- `mdfsck.exe` relocation-backed flag/name tables yielded concrete `A*` bit mappings.
- VD print routine mapping (`0x0670..0x085c`) now ties format labels to global lanes:
  - inferred DS string base `0xdcd0`
  - call sites map labels (`BlockSize`, `ClusterSize`, `AllocSize`, etc.) to
    globals in `0x5b40..0x5b88` before formatter call.
- a normalization block (`0x02e8..0x0562`) rewrites many `0x5b40..0x5b88` lanes
  via byte/word reordering after bulk copy into `0x5b30..` workspace:
  - 16-bit lanes follow explicit byte-swap pattern
  - 32-bit lane pairs follow dword reordering consistent with big-endian source
    to little-endian host normalization.
- direct `VD` format-string offset table pattern search in `mdfsck.exe` did not yield a simple contiguous pointer table.
- code-only immediate scan to the first runtime string anchor (`"MDfsck version"`) found no direct
  field-label offset immediates for the target label block.
- this improves semantic labeling of checker state variables but does not prove
  exact on-media member offsets; media-correlated trace is still required.

References:
- `analysis/unknown_reduction.md`
- `analysis/deep_static_re.md`
- `analysis/mdfsck_flag_tables.md`
- `analysis/mdfsck_field_xref.md`
- `analysis/ws19_mdfsck_vd_emit_map.md`
- `analysis/ws36_mdfsck_global_lane_xrefs.md`
- `analysis/ws37_mdfsck_endian_normalization.md`

## 4) Conservative Conclusion

Reduced uncertainty:
- LE entry parsing is now narrower and better aligned with x86 LE layout (`obj=1`, `flags=0x03`, `offset16` usable).
- LE type-3 middle16 meaning is materially reduced: DDB offset interpretation is validated on all 3 target VxDs.
- MDCTL opcode IDs for ON/OFF/IS/FLUSH/? are strongly supported via duplicated descriptor tables.

Remaining uncertainty:
- bit-level semantic meaning of `flags=0x03` in type-3 entry records
  (role coupling to DDB export is strongly suggested in current corpus).
- full MDCTL command payload schema.
- byte-accurate MDFS on-media structure offsets.
- helper-cluster (`0x3994..0x3f4a`) top-level entry is still not statically proven:
  direct and resolved-indirect static paths currently do not enter the cluster.
  The `lcall [di]` branch is now bounded by callback-walker semantics and resolves to
  static slot target `03f7:0796` (linear `0x4706`) in image-init state, outside the cluster.
  Remaining uncertainty is concentrated in mutable runtime vectors (notably `lcall [0x196c]`)
  that still require runtime capture; slot-contract lift shows this path uses an
  image-init-zero runtime callback/argument lane group (`0x196c..0x1976`) with
  no direct static writes, and write-proof scan found no immediate-base indirect-write
  candidates either. Cross-binary parity with `mdfsex` shows the same staged
  callback ABI (`AX:DX` + `BX=0/3/2` + gate/jcxz), reinforcing shared runtime contract.
  In `mdmgr`, slot-class mapping further separates parser callback (`0x0c42`) from
  guarded device-vector pairs and helper vectors, with explicit zero-init before guarded calls.
  Population provenance adds that `0x0c42` is file-loaded via DOS `int 21h/4402`,
  while guarded hook pairs remain zero-init-only in static image.
  Additional pointer-semantics evidence confirms `0x0c42` is consumed as
  `lcall m16:16` entry (4 callsites), consistent with external helper callback pointer.
  `0x0e32` is further constrained as indexed 3-entry far-pointer dispatch table
  with explicit code init for entry #1 and unresolved provider path for entry #0/#2.
  MZ relocation crosscheck does not mark `0x0e32..0x0e3c` words, so unresolved
  entry providers are unlikely to be explained by simple loader relocation alone.
  Additional bounded non-literal-write scan did not find register-based or
  block-copy write sources for #0/#2 entries.
  Device-table init writes (`0xe84/0xe86`) are isolated from dispatch window,
  supporting table separation rather than hidden provider linkage.
  Far-pointer/load-segment checks apply to raw on-disk defaults, but startup-init
  recovery (`0x2e58..0x312e`) shows runtime table is actively rewritten:
  loop-zero of 8 entries followed by entry #0 set to `0x0073:0x0601` (twice).
  Therefore runtime provider interpretation should be anchored on startup writes,
  with residual UNKNOWN focused on post-startup population path for non-default entries.
  Phase timeline is now explicit: raw defaults -> startup zero -> startup entry0 bind ->
  observed later entry1 rebind (ordering closure still pending).
  Reachability audit for the rebind write block (`0x1997..0x1a3f`) found zero
  direct xrefs to `0x1997`, zero external inbound refs into the block, and zero
  raw opcode-pattern hits targeting `0x1997`, so this path is statically isolated
  in current bounded evidence.
  Indirect-target feasibility sweep further shows no resolved indirect source
  encodes off-word `0x1997`; remaining possibility is confined to runtime-loaded
  vectors (notably `0x0c42`) and unresolved dynamic indexed sources.
  Dynamic-vector prioritization further ranks remaining closure work:
  highest is runtime-loaded external slot `0x0c42`, next is stride-`0x11`
  dynamic lanes (`0x0dcf/0x0dd3/0x0dd7/0x0ddb`), while resolved runtime tables
  (`0x0e32`, `0x0d02`) are currently excluded for `0x1997` target concern.
  Load-chain audit for `0x0c42` shows one bounded static producer sequence
  (`open -> read 4 bytes to 0x0c42 -> close`) and four consumers; no direct
  `mov` writes to `0x0c42/0x0c44` were found. Remaining uncertainty is runtime
  read payload content rather than producer multiplicity.
  Stride-`0x11` lane consolidation shows three consumers (`0x07fa`, `0x0879`,
  `0x08e1`) are explicitly bounded to `idx<3` and exclude `0x1997` in both raw
  and post-init models.
  k-bound trace for `0x0916` confirms `0x08f4` has a single direct caller
  (`0x0e70`) with pre-dispatch bound on `req[+1]` only (`<=0x0d`), while local
  in-function clamp for `req[+2]` is not observed before `0x0916` lane dispatch.
  Precondition-closure pass then closes prior `k>=8` concern for observed direct
  call path: same caller function gates `req[+2] < 8` before second dispatch
  that includes `0x0e70 -> 0x08f4`.
  Second-dispatch materialization audit (`0x0e58 -> cs:[bx+0x07df]`) shows no
  static writes and no relocation hits on table words; reachable domain from
  guards is `req[+1]=9..13`, where only 2/5 targets are in-image (`0x1047`,
  `0x00b4`). Residual uncertainty is now protocol-level reachable opcode subset
  within that bounded domain.
  req[+1] provenance partition confirms this handler (`0x0d31..0x0ef6`) is
  read-only for `req[+1]` (3 reads, 0 writes), so second-dispatch analysis
  treats `req[+1]` as externally supplied contract field at handler entry.
  Writer non-dominance check further shows all observed `req[+1]` write sites
  are outside handler window, with no direct `call/jmp` to `0x0d31` in image;
  writer helpers are not statically proven as immediate dominators of handler
  input, reinforcing external-contract scope.
  Domain plausibility refinement for `req[+1]=9..13` yields only one plausible
  in-image jump-entry target (`req[+1]=9 -> 0x1047`): `req[+1]=10` maps to
  `0x00b4` which is mid-instruction entry, and `11..13` are off-image.
  Case-9 semantic lift (`0x1047`) is coherent as structured formatter path:
  branch on `req[0x17]` selects output tag `0x45/0x48` and fills output fields
  from `req[0x10..0x15]` (including arithmetic combine in non-zero branch).
  Case-9 status/output flow shows handler pre-sets status byte to success
  (`req+3=0` at `0x0d5f`), while `0x1047` writes output payload fields only and
  does not overwrite status; successful case-9 therefore preserves outer
  success status unless earlier guard/error branch is taken.
  Case-9 input-field provenance (`req[0x10..0x17]`) remains read-mostly in
  bounded static evidence, with no req-like local writes found under immediate
  `les bx,[bp+6]` pattern. Mapper helpers (`0x1205/0x1226/0x129b`) also consume
  these bytes as structured input lanes, supporting pre-assembled contract field
  interpretation.
  Consolidated provisional subtype profile now treats `req[+1]=9` as stable
  case anchor in this corpus, while remaining UNKNOWN shifts to external field
  producer path and semantic naming taxonomy.
  Implementation mapping (WS73) now encodes this as unknown-path discipline in
  FUSE scaffold: non-case9 lanes are policy-mapped (`EIO` default,
  `ENOTSUP` optional), and short/truncated frames are hard-failed as `EIO`.
