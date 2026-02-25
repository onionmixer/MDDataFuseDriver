# MDFS Specification (RFC-Style, Reverse-Engineered)

## Status
- Document type: Informational / Reverse-engineering draft
- Version: 0.3
- Date: 2026-02-18

## 1. Scope
This document describes the Sony MD DATA File System (MDFS) behavior and layout
inferred from extracted binaries and installer payloads in this workspace.

Normative language:
- `MUST`: behavior confirmed by direct evidence
- `SHOULD`: strong inference, not yet byte-level proven end-to-end
- `MAY`: plausible but currently unverified

Confidence tags:
- `[CONFIRMED]`: explicit textual/binary evidence
- `[INFERRED]`: consistent indirect evidence
- `[UNKNOWN]`: not yet resolved

Promotion gate (mandatory):
- `[INFERRED] -> [CONFIRMED]` MUST NOT be promoted by plausibility-only static reasoning.
- Repeated no-media runtime captures MAY strengthen repeatability, but MUST remain `[INFERRED]`.
- Media-dependent fields/offsets/payload semantics MUST remain `[UNKNOWN]` until MD DATA media-backed evidence is captured.

## 2. Component Model

### 2.1 DOS/Win3.1 stack
- `mdfsex.exe` MUST be the MDFS installable file-system loader `[CONFIRMED]`
- `mdmgr.exe` MUST be the MD DATA device manager `[CONFIRMED]`
- `mdformat.exe` MUST format MD DATA media `[CONFIRMED]`
- `mdfsck.exe` MUST validate MDFS consistency `[CONFIRMED]`
- `mdcache.exe` MUST control write cache state `[CONFIRMED]`

### 2.2 Win95 stack
- `MDFSD.VXD` SHOULD implement core FS operations `[INFERRED]`
- `MDMGR.VXD` MUST register with IFSMgr CFSD-related path `[CONFIRMED]`
- `MDHLP.VXD` SHOULD mediate/patch I/O path for supported devices on OSR2 `[INFERRED]`
- The Win95 installer INF files MUST deploy the 3-module set
  (`MDHLP.VXD`, `MDMGR.VXD`, `MDFSD.VXD`) as one stack `[CONFIRMED]`

Evidence:
- `w95/extract/us/mdh10.inf`, `w95/extract/us/mdm110.inf`, `w95/extract/us/mdm111.inf`
- `w95/extract/us/mdmgr.vxd` symbol strings contain `mountCFSD`,
  `_INIT_IFSMgr_RegisterCFSD`
- `w95/extract/us/mdhlp.vxd` contains `IOR_*` dispatch labels
- LE parse artifacts:
  - `analysis/ws2_le_headers.md`
  - `analysis/ws2_le_exports.md`
  - `analysis/ws2_le_entry_x86.md`
  - `analysis/ws2_vxd_ddb_candidates.md`
  - `analysis/ws2_le_pagemap.md`
  - `analysis/ws2_le_fixup_summary.md`

## 3. CLI Contract (DOS Utilities)

### 3.1 `mdfsex`
- Syntax: `mdfsex [/L:drive][/?]` `[CONFIRMED]`
- `/L:<drive>` selects first assigned MDFS drive letter `[CONFIRMED]`

### 3.2 `mdformat`
- Syntax: `mdformat drive: [-q|-s] [-v:label -o -?]` `[CONFIRMED]`
- `-q` quick format (install FS, no certification) `[CONFIRMED]`
- `-s` certification/safety format `[CONFIRMED]`
- `-o` non-interactive `[CONFIRMED]`

### 3.3 `mdfsck`
- Syntax: `mdfsck drive: [-v -?]` `[CONFIRMED]`
- Returns conformance or error count `[CONFIRMED]`

### 3.4 `mdcache`
- Syntax: `mdcache [drive:] ON|OFF|IS|FLUSH` `[CONFIRMED]`

## 4. On-Disk Logical Model

MDFS MUST include at least these logical record groups:
- Volume Descriptor (`VD`) `[CONFIRMED]`
- Volume Space Bitmap (`VSB`) `[CONFIRMED]`
- Management Table Blocks (`MTB`) `[CONFIRMED]`
- Extent Record Blocks (`ERB`) `[CONFIRMED]`
- Directory Record Blocks (`DRB`) `[CONFIRMED]`

Primary VD fields observed in checker diagnostics:
- `Identifier`, `Version`, `BlockSize`, `ClusterSize`, `AllocSize`
- `NumAlloc`, `NumRecordable`, `NumAvailable`, `NumUsed`, `NumDefective`
- `VSBLoc/VSBNum`, `MTBLoc/MTBNum`, `ERBLoc/ERBNum`, `DRBLoc/DRBNum`
- `VolAttr`, `MaxIdNum`, `NumDir`, `NumFile`, timestamps

Field names are `[CONFIRMED]` as strings; exact offsets are `[UNKNOWN]`.
Additional static recovery from `mdfsck` VD emit path:
- formatter-call sequence (`0x0670..0x085c`) maps label printouts to globals
  in `0x5b40..0x5b88` using inferred string base `0xdcd0` `[INFERRED]`
- this narrows internal checker variable semantics but still does not prove
  byte-accurate on-media offsets `[UNKNOWN]`
- candidate field-size/lane map (`WS21`) and carry-forward table (`WS23`) now
  capture `%d/%ld/%x`-derived width hints and global-lane candidates `[INFERRED]`.
- additional normalization pass evidence (`0x02e8..0x0562`) shows numeric lanes
  are byte/word reordered after load, consistent with big-endian source to
  host-little-endian conversion `[INFERRED]`.

Attribute bit mappings from `mdfsck.exe` relocation-backed tables:
- Volume-style flag set `[CONFIRMED]`
  - `AMIRROR=0x0001`, `AINVISIBLE=0x0002`, `APROTECT=0x0040`, `ABACKUP=0x0080`
  - `AINHFORMAT=0x0100`, `AINHRENAME=0x0200`, `AINHCOPY=0x0400`, `AEXT32=0x8000`
- Record-style flag set `[CONFIRMED]`
  - `ADIR=0x0001`, `AINVISIBLE=0x0002`, `ASYSTEM=0x0004`, `ADELETED=0x0008`
  - `APROTECT=0x0040`, `ABACKUP=0x0080`, `AINHDELETE=0x0100`, `AINHRENAME=0x0200`
  - `AINHCOPY=0x0400`, `AEXTTYPE=0x2000`, `AFXTREC=0x4000`, `AAEXTREC=0x8000`

## 5. Control Interface Surface

### 5.1 Userland Control Transport (DOS)
The userland <-> driver control path SHOULD include symbolic endpoints:
- `\\MDCTL`, `MD001`, `MDFS000`, `IOMR000` `[INFERRED]`

- utilities SHOULD issue device-control requests rather than direct media parsing `[INFERRED]`
- DOS userland implementations (`mdcache`, `mdfsck`) use `INT 21h` with `AH=0x44`
  device IOCTL flow (`AL` function code, `BX` handle, `DS:DX` buffer, `CX` length)
  in observed wrapper code paths `[CONFIRMED]`
- `mdformat` also implements the same IOCTL wrapper shape (`AH=0x44`, caller-supplied `AL`,
  `BX/DS:DX/CX` argument lane), matching `mdcache` transport semantics `[CONFIRMED]`
- In currently recovered direct callsites, observed `AL=0/1` patterns are compatible with
  generic DOS device-info flow (`4400h/4401h`), so MDCTL-private opcode mapping remains `[UNKNOWN]`.

### 5.2 MDCTL Token/Descriptor Evidence
- `mdcache` contains parser token blob with `:\\mdctl` and
  `ON/OFF/IS/FLUSH/?` command tokens `[CONFIRMED]`.
- token blob, callback trio, and descriptor tuples are contiguous in one
  data cluster `[CONFIRMED]`.
- Near the same blob, `mdcache` has a regular 5-record descriptor block (`0x14` stride)
  with candidate `(op_code, op_index)` tuples
  (`0209/0`, `020A/1`, `0202/2`, `0243/3`, `0242/4`) and code-region handler offsets
  (`0x1818`, `0x182c`, `0x1840`, `0x1854`, `0x1868`) `[INFERRED]`.
- `mdformat` contains a second independent descriptor block with the same
  5-record `(op_code, op_index)` sequence and per-record handler words
  (`0x135a`, `0x136e`, `0x1382`, `0x1396`, `0x13aa`) `[CONFIRMED]`.
- Therefore command opcode IDs (`0209`,`020A`,`0202`,`0243`,`0242`) are
  strongly supported as shared MDCTL table keys; payload structure is still `[UNKNOWN]`.
- static callsite-lift table now records wrapper/transport callsites with
  pre-call push lanes and local header writes, improving payload-lane tracing
  for runtime capture design `[INFERRED]`.
- token-order correlation yields a bounded low-confidence candidate mapping:
  `ON/OFF/IS/FLUSH/?` -> `0209/020A/0202/0243/0242` `[INFERRED]`.
- relocation-derived linkage to this blob is method-sensitive across parsers,
  so relocation alone is treated as low-confidence supporting evidence `[INFERRED]`.
- this mapping is not promoted to confirmed until runtime command-path capture
  verifies dispatch linkage `[UNKNOWN]`.

### 5.3 Frame-Shape and Helper-Cluster Constraints
- In `mdfsck`, additional frame-builder routines create fixed-size request buffers
  (`0x20`, `0x208`, `0x4a`) with leading byte fields (`type=2`, subtype values including
  `4/5/6`) before paired imported transport calls `[INFERRED]`.
- Additional adjacent helper routines suggest more frame families:
  - `type=1` with subtype-like byte `0x16/0x18` (mode-dependent),
  - `type=2,sub=8,len=0x11` request/response pair,
  - `type=1,sub=0x24,len=0x17` and `type=1,sub=7,len=0x10` probe-style requests `[INFERRED]`.
- Core helper `0x3cca` is wrapped by entry points that inject direction flag (`0`/`1`);
  code path shows paired tx/rx transport and direction-dependent payload copy
  (caller->frame vs frame->caller) `[INFERRED]`.
- Parameter mapping inside `0x3cca` is constrained by direct writes:
  - `[bp+0x0c/0x0e]` -> header `+0x10/+0x12` (32-bit start-like field),
  - `[bp+0x10]` -> header `+0x14` and transfer-size driver (`<<11`) `[INFERRED]`.
- Transfer-length shape is consistent with `([bp+0x10] << 11) + 0x18` bytes `[INFERRED]`.
- Direct near-call reachability from process entry did not include the `0x3994..0x3f4a`
  helper cluster in this static pass, so these frame-semantics claims remain `[INFERRED]`
  pending dynamic trace confirmation.
- direct immediate call-xref sweep shows observed incoming calls are currently
  intra-cluster (`0x3e0d/0x3e2d/0x3e42/0x3e60` path), with no top-level caller
  proven yet in this pass `[INFERRED]`.
- segment-aware indirect-flow pass (`CS=0x03f7`, `DS_base=0xdcd0`) resolved
  current indirect sites (`call [0x1960/62/64]`, `lcall [0x1752/5a/5e/66]`,
  parser jump-table `cs:[bx+0xb30]`) and none target `0x3994..0x3f4a` `[INFERRED]`.
- unresolved runtime vectors are narrowed to callback/continuation slot family
  (`0x196c`, `0x14d2/0x14d4`, `0x14d6`, `0x14dc/0x14de`, `0x177a/0x177c`),
  still requiring runtime target capture for closure `[UNKNOWN]`.
- `lcall [di]` at `0x4217` is constrained by callback-walker routine (`0x4209`)
  that iterates a far-pointer list range `[SI,DI)`; observed non-empty static
  range is `[0x1978,0x197c)` (single entry) and resolves to `03f7:0796`
  (linear `0x4706`) in image-init state `[INFERRED]`.
- Static slot-contract survey (`0x1960..0x1976`) shows `0x196c/0x196e/0x1970..0x1976`
  are image-init zero and have no direct in-image writes; callsite usage matches
  runtime-populated callback vector + argument-lane contract `[INFERRED]`.
- Write-proof scan adds no contrary static evidence: zero direct writes and zero
  immediate-base indirect-write candidates into `0x196c..0x1976` in current
  linear pass `[INFERRED]`.
- Cross-binary parity scan (`WS44`) finds the same staged callback ABI in
  `mdfsex` (`AX:DX` payload lanes + `BX=0/3/2` selector + gate `mov cx,[slot+2]`
  / `jcxz` pattern), strengthening shared-runtime-contract interpretation `[INFERRED]`.

### 5.4 MDMGR Dynamic Dispatch and Runtime-Only Uncertainty
- `mdmgr` slot-class scan (`WS45`) shows parser callback lane `0x0c42` and
  guarded device-vector pairs (`0x0cfa/0x0cfc`, `0x0cfe/0x0d00`,
  `0x0e2a/0x0e2c`, `0x0e2e/0x0e30`) with explicit zero-init before optional
  `lcall`, plus high-frequency helper vector `0x0e32` `[INFERRED]`.
- Population provenance (`WS46`) identifies concrete provider for parser lane:
  `0x0c42` is loaded by DOS IOCTL-read path (`int 21h`, `AX=0x4402`,
  `DX=0x0c42`, `CX=4`), whereas guarded hook pairs are zero-init-only with no
  non-zero in-image writes in current static pass `[INFERRED]`.
- Pointer-semantics pass (`WS47`) shows `0x0c42` is consumed exclusively via
  `lcall [0x0c42]` (4 callsites) after 4-byte loader read, which strongly
  supports external helper callback far-pointer semantics `[INFERRED]`.
- Dispatch-table pass (`WS48`) shows `0x0e32` acts as an 8-entry indexed
  far-pointer dispatch table (`index<<2`, null-guard, `lcall [bx+0x0e32]`;
  startup-init zeroes all 8 entries per `WS54`, only entries 0..2 have
  dispatch/write evidence in bounded static pass); entry #1
  (`0x0e36/0x0e38`) is explicitly code-initialized, while entry #0/#2 remain
  without literal in-image write sources in this pass `[INFERRED]`.
- Relocation crosscheck (`WS49`) confirms `0x0e32..0x0e3c` entry words are not
  listed in MZ relocation targets, reducing likelihood of simple loader-reloc
  explanation for unresolved entry #0/#2 providers `[INFERRED]`.
- Non-literal write scan (`WS50`) found no additional register-based or block-copy
  writes into `0x0e32..0x0e3c` beyond entry #1 literal writes, keeping #0/#2
  provider path unresolved in bounded static analysis `[INFERRED]`.
- Table-separation scan (`WS51`) shows `0xe84/0xe86` device-table writes occur in
  init window and are absent from indexed dispatch window, reducing likelihood
  that device-table init is provider source for `0x0e32` entry #0/#2 `[INFERRED]`.
- Far-pointer classification (`WS52`) shows initial entry values for
  `0x0e32..0x0e3c` decode as far pointers, but this reflects raw on-disk values
  prior to startup overwrite `[INFERRED]`.
- Load-segment feasibility (`WS53`) shows feasible in-image segment windows for
  initial #0/#2 do not intersect with entry #1 rewritten in-image window,
  constraining raw-default interpretation space `[INFERRED]`.
- Startup-init recovery (`WS54`) establishes runtime baseline: `0x2e58..0x312e`
  zeroes 8 entries of `0x0e32/0x0e34` then sets entry #0 to `0x0073:0x0601`
  (twice). Runtime provider analysis MUST prioritize these startup writes over
  raw image defaults `[INFERRED]`.
- State-timeline synthesis (`WS55`) orders observed phases and keeps one key
  uncertainty explicit: entry #1 in-image rebind is observed, but exact ordering
  against startup path is not fully closed in bounded static evidence `[INFERRED]`.
- Reachability audit (`WS56`) further constrains that uncertainty: the write block
  containing `0x19d5/0x19db` (`0x1997..0x1a3f`) has zero direct static refs to
  `0x1997`, zero external inbound refs, and zero raw opcode-pattern hits to
  `0x1997` in current image-level evidence `[INFERRED]`.
- Indirect-source feasibility sweep (`WS57`) finds no resolved indirect transfer
  source that yields offset `0x1997`; remaining branch possibility is narrowed to
  runtime-loaded or otherwise unresolved dynamic vector sources `[INFERRED]`.
- Dynamic-vector prioritization (`WS58`) ranks residual work: highest is
  runtime-loaded `0x0c42` far pointer lane, then stride-`0x11` dynamic lanes
  (`0x0dcf/0x0dd3/0x0dd7/0x0ddb`); resolved runtime tables (`0x0e32`, `0x0d02`)
  are currently excluded for `0x1997` concern `[INFERRED]`.
- Load-chain audit (`WS59`) reduces producer-side ambiguity for `0x0c42`:
  one bounded static producer sequence (DOS open/read/close, 4-byte read into
  `0x0c42`) and four `lcall [0x0c42]` consumers are observed, with no direct
  static `mov` writes to `0x0c42/0x0c44` `[INFERRED]`.
- Stride-`0x11` lane consolidation (`WS60`) shows three consumers
  (`0x07fa/0x0879/0x08e1`) are explicitly bounded to `idx<3` and exclude
  `0x1997` in raw/post-init models `[INFERRED]`.
- k-bound trace (`WS61`) shows `0x08f4` has one direct caller (`0x0e70`) with
  pre-dispatch bound on `req[+1]` only, while no local clamp on `req[+2]` is
  observed before `0x0916` `[INFERRED]`.
- Precondition closure (`WS62`) then closes prior `k>=8` concern for the
  observed direct-call path by recovering caller-side `req[+2] < 8` gating
  before dispatch to `0x0e70 -> 0x08f4` `[INFERRED]`.
- Second-dispatch materialization (`WS63`) shows `0x0e58` jump-table words
  (`0x07df..0x07f9`) have no static write/reloc materialization, and guarded
  runtime domain is `req[+1]=9..13` with only two in-image targets (`0x1047`,
  `0x00b4`) in current sample `[INFERRED]`.

### 5.5 Case-9 Practical Subset and Semantics
- req[+1] provenance partition (`WS64`) confirms handler `0x0d31..0x0ef6` reads
  but does not write `req[+1]`, so second-dispatch modeling should treat this
  byte as externally supplied contract input at handler entry `[INFERRED]`.
- writer non-dominance check (`WS65`) adds that observed `req[+1]` writers are
  outside handler window and no direct `call/jmp` to `0x0d31` is found, so
  writer helpers are not statically proven to dominate handler input
  `[INFERRED]`.
- domain plausibility refinement (`WS66`) narrows practical second-dispatch
  subset: within `req[+1]=9..13`, only `9` maps to plausible in-image entry
  (`0x1047`); `10` is mid-instruction entry (`0x00b4`) and `11..13` are
  off-image `[INFERRED]`.
- case-9 semantic lift (`WS67`) shows `0x1047` implements coherent tagged
  formatter behavior (`0x45/0x48` branch by `req[0x17]`, field mapping from
  `req[0x10..0x15]`), reinforcing `req[+1]=9` as practical in-image subset
  candidate `[INFERRED]`.
- case-9 status/output flow (`WS68`) indicates status ownership remains in
  outer handler (`req+3=0` pre-set) while `0x1047` focuses on payload-field
  writes, reinforcing coherent success-path semantics `[INFERRED]`.
- case-9 input provenance (`WS69`) shows `req[0x10..0x17]` are read-mostly
  contract lanes in bounded static evidence (no immediate req-like local writes
  found), consistent with pre-assembled request-extension interpretation
  `[INFERRED]`.
- provisional subtype profile (`WS70`) consolidates `req[+1]=9` as practical
  stable anchor in current corpus, and reorders remaining case-scope unknowns
  to external producer path and semantic naming taxonomy `[INFERRED]`.
- FUSE policy mapping (`WS73`) defines implementation-side unknown handling:
  unknown `req1` lanes use fail-closed `EIO` by default (optional
  `ENOTSUP` feature mode), while frame-short/truncated-case9 conditions are
  always forced to `EIO` with stable key/value log records `[INFERRED]`.
- This narrows payload *shape* evidence but does not yet provide a definitive
  subtype-to-MDCTL-opcode map `[UNKNOWN]`.

### 5.6 Win95 VxD Entry Observations
- Each of `MDFSD.VXD`, `MDMGR.VXD`, `MDHLP.VXD` has a single `type=3` entry bundle
  at ordinal 1 `[CONFIRMED]`
- x86 LE interpretation indicates `type=3 obj=1` with entry bytes
  `flags=0x03, offset16=<value>` for ordinal 1 `[INFERRED]`
- Ordinal 1 `offset16` maps to DDB candidate offset where `+0x0c`
  matches module name (`MDFSD`, `MDMGR`, `MDHlp`) `[CONFIRMED]`
- DDB candidate structure also shows repeated stable offsets across modules:
  `+0x00=0`, `+0x04=0x00000400`, `+0x0c=<module name8>` `[CONFIRMED]`
- Type-3 `offset16` (middle 16-bit value) SHOULD be interpreted as
  object-relative DDB offset, not code entry RVA, for this driver set `[INFERRED]`
- In current corpus, type-3 flags byte is invariant (`0x03`) and correlates with
  DDB-style exports (`_The_DDB` / `MDHlp_DDB`) `[INFERRED]`
- Exact bit-level semantic meaning of `0x03` remains `[UNKNOWN]`

Promotion criteria linkage:
- `5.1` / `5.2` / `5.3` / `5.4` / `5.5` map to `WS77-A` (repeatability support) and `WS77-B` (payload semantic closure gate).
- `5.6` maps to `WS77-D` for definitive `type=3` flag semantics.

## 6. Installation Semantics

### 6.1 Win3.1 package
- Payload comes from proprietary `.RED` archives `[CONFIRMED]`
- Extracted payload was validated against archive metadata `[CONFIRMED]`

### 6.2 Win95 package
- InstallShield package
- `SETUP.PKG` MUST provide payload file table `[CONFIRMED]`
- `w95/merged/SETUP.INS` SHOULD contain locale script indirection entries
  (e.g., `US\\SETUP.INS`, `JP\\SETUP.INS`) used by installer flow `[CONFIRMED]`
- Win95 userland tools (`mdfmt.exe`, `mdfschk.exe`, `mdplayer.exe`) MUST rely on
  MD DATA drive abstraction and/or control endpoint usage `[CONFIRMED]`
  - e.g., `\\MDCTL` seen in `mdplayer.exe`
  - formatter/checker strings consistently reference MD DATA drive/media semantics

## 7. Gaps / Open Questions
- Full byte-level record layouts for VD/VSB/MTB/ERB/DRB `[UNKNOWN]`
- Complete IOCTL/control payload table `[UNKNOWN]`
- Exact mount handshake between `MDMGR.VXD` and `MDFSD.VXD` `[UNKNOWN]`
- Definitive semantic meaning of LE `type=3` entry flags (`0x03`) `[UNKNOWN]`

Normative restriction:
- The four gaps above MUST NOT be filled with estimated values in normative text.
- Candidate models MAY be documented only as `[INFERRED]` with explicit promotion criteria tied to later test-stage evidence.

No-media reinforcement note:
- WS25 no-media batch captures improve transport-lane repeatability only; they do not close media-dependent unknowns.
- Promotion workflow reference: `analysis/ws77_spec_promotion_checklist.md`
- Gap-to-checklist map:
  - VD/VSB/MTB/ERB/DRB byte-level layout -> `WS77-C`
  - IOCTL/control payload semantics -> `WS77-B`
  - LE type-3 flags `0x03` semantics -> `WS77-D`

Promotion summary table:

| Area | Current status | No-media reinforcement | Promotion gate |
|---|---|---|---|
| On-media layout (`VD/VSB/MTB/ERB/DRB`) | `[UNKNOWN]` | field-lane stability only | `WS77-C` |
| IOCTL/control payload semantics | `[UNKNOWN]` | transport-lane repeatability (`WS25` no-media matrix) | `WS77-B` |
| LE `type=3` flags `0x03` semantics | `[UNKNOWN]` | corpus invariance only | `WS77-D` |

Operational flow:
- Non-media phase (now): strengthen repeatability/audit evidence only; keep media-dependent claims unchanged.
- Media phase (later): run MD DATA-backed traces and apply `WS77-B/C/D` promotion gates.

## 8. Minimum Evidence Set
- `w31/extract/read.me`
- `w31/extract/mdfsex.exe`
- `w31/extract/mdfsck.exe`
- `w31/extract/mdformat.exe`
- `w31/extract/mdcache.exe`
- `w95/extract/us/mdh10.inf`
- `w95/extract/us/mdmgr.vxd`
- `w95/extract/us/mdfsd.vxd`
- `w95/extract/us/mdhlp.vxd`
- `analysis/ws2_vxd_ddb_candidates.md`
- `analysis/ws2_le_entry_x86.md`
- `analysis/vxd_ddb_struct_scan.md`
- `analysis/ws2_le_pagemap.md`
- `analysis/ws2_le_fixup_summary.md`
- `analysis/x86_dos_win95_disasm_findings.md`
- `analysis/ws5_mdctl_refinement.md`
- `analysis/ws6_mdctl_dataflow.md`
- `analysis/mdcache_descriptor_decode.md`
- `analysis/ws8_imm16_usage.md`
- `analysis/ws9_mdctl_dual_table.md`
- `analysis/ws10_le_type3_middleword.md`
- `analysis/ws12_capstone_imm_hits.md`
- `analysis/ws13_ioctl_wrapper_audit.md`
- `analysis/ws14_mdfsck_frame_builders.md`
- `analysis/ws15_mdfsck_payload_shape_matrix.md`
- `analysis/ws16_mdfsck_3cca_semantics.md`
- `analysis/ws17_mdfsck_direct_reachability.md`
- `analysis/ws18_mdfsck_3cca_param_map.md`
- `analysis/ws19_mdfsck_vd_emit_map.md`
- `analysis/ws20_mdfsck_cluster_xrefs.md`
- `analysis/ws30_mdfsck_indirect_flow.md`
- `analysis/ws27_le_type3_flags_survey.md`
- `analysis/ws28_le_type3_flags_hypothesis.md`
- `analysis/ws24_mdctl_callsite_lift.md`
- `analysis/ws25_mdctl_runtime_capture.md`
- `analysis/ws25_nomedia_matrix_report.md`
- `analysis/ws25_nomedia/summary.csv`
- `analysis/ws25_nomedia/common_all_scenarios.csv`
- `analysis/ws77_spec_promotion_checklist.md`
- `analysis/ws21_layout_candidate_map.md`
- `analysis/ws22_media_diff_matrix.md`
- `analysis/ws23_layout_confirmed_table.csv`
- `analysis/ws26_mdctl_schema_matrix.csv`
- `analysis/ws33_mdctl_opcode_crosswalk.md`
- `analysis/ws34_mdcache_blob_cluster.md`
- `analysis/ws35_mdcache_reloc_sanity.md`
- `analysis/ws36_mdfsck_global_lane_xrefs.md`
- `analysis/ws37_mdfsck_endian_normalization.md`
- `analysis/ws38_mdfsck_runtime_vector_slots.md`
- `analysis/ws39_mdfsck_vector_role_classification.md`
- `analysis/ws40_mdfsck_callback_walker.md`
- `analysis/ws42_mdfsck_runtime_slot_contract.md`
- `analysis/ws41_mdfsck_slot196c_provenance.md`
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
- `analysis/ws73_fuse_unknown_path_policy.md`
- `analysis/mdcache_cmd_blob.md`
- `analysis/reloc_string_xref.md`
- `analysis/mdfsck_flag_tables.md`
- `analysis/mdfsck_field_xref.md`
- `document/MDFS_EVIDENCE_GAP_AUDIT.md`

## 9. Binary Fingerprint Baseline
Selected baseline values for reproducible analysis:
- `w31/extract/mdfsex.exe`: size `47518`, SHA-1 `a3039ca82aae67ff0dc731d0c0df736870e14bd9`
- `w31/extract/mdfsck.exe`: size `65327`, SHA-1 `75db20f6700c4acf5e24349c592e4790c98bef59`
- `w31/extract/mdformat.exe`: size `109956`, SHA-1 `a630bfd9c87bf9721d5c29a182b21c809f67c060`
- `w31/extract/mdcache.exe`: size `55956`, SHA-1 `6f0f84524d86da3b1b7e8b4570f3fcdc5a126628`
- `w31/extract/mdmgr.exe`: size `13394`, SHA-1 `8bf42657727a819adaf38a6f94a4b428b942f8cd`
- `w95/extract/us/mdfsd.vxd`: size `79530`, SHA-1 `ebd4c5f887f1081461d9720a95afb25074f9fdda`
- `w95/extract/us/mdmgr.vxd`: size `21155`, SHA-1 `1ace191b10bb9c6ebed8e048b7e6d7fff5aea00d`
- `w95/extract/us/mdhlp.vxd`: size `11406`, SHA-1 `5a8e0363c93110c4f9cb0bbb13236d7d243fd24b`
- Full extracted set baseline: `document/MDFS_BINARY_MANIFEST.csv`
