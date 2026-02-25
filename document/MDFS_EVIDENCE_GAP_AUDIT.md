# MDFS Evidence Gap Audit

Date: 2026-02-24 (updated from 2026-02-18)
Scope: `document/*`, `analysis/*` vs extracted original binaries in `w31/extract/*`, `w95/extract/us/*`, live MD DATA media traces

## 1. Audit Outcome
- Overall: documentation is coherent and implementation-oriented.
- Strengthened areas in this pass:
  - reproducibility baseline (binary SHA-1/size) consolidated
  - Win95 VxD entry and DDB mapping evidence integrated
  - Win95 DDB candidate cross-module stable offset pattern added
  - `mdfsck.exe` relocation-backed `A*` attribute flag bit mapping recovered
  - DOS IOCTL/MDCTL interpretation tightened to avoid over-claiming private opcode proof
  - `mdcache` relocation-linked `:\\mdctl` command token blob and descriptor lanes documented
  - `mdcache` 5-record descriptor decode with candidate opcode/index tuples added
  - `mdformat` parallel 5-record descriptor block recovered with identical opcode/index lanes
  - LE type-3 middle16 value validated as DDB offset across all 3 Win95 VxDs
  - capstone immediate-value sweep shows target opcode values are predominantly table-data, not code immediates
  - DOS IOCTL wrapper parity confirmed between `mdcache` and `mdformat` (same `AH=44h` transport lane)
  - `mdfsck` fixed frame-builder patterns documented (`0x20`/`0x208`/`0x4a`, type/subtype byte lanes)
  - `mdfsck` adjacent frame families cataloged (`type1: 0x16/0x18,0x24,0x07`; `type2: 0x04/0x05/0x06/0x08`)
  - `mdfsck` core helper `0x3cca` direction semantics pinned (wrapper-injected mode 0/1, bidirectional payload copy)
  - direct near-call CFG check added; helper-cluster runtime reachability remains unconfirmed without dynamic trace
  - `mdfsck` `0x3cca` argument-to-header mapping documented (`+0x10/+0x12/+0x14` lanes, `<<11` size path)
  - `mdfsck` VD emit block now maps print labels to global lanes (`0x5b40..0x5b88`) via inferred string base `0xdcd0`
  - `mdfsck` helper-cluster direct call-xrefs (`0x3994..0x3f4a`) were enumerated; observed callers are intra-cluster only
  - segment-aware indirect-flow resolution added (`CS=0x03f7`, `DS_base=0xdcd0`); resolved indirect sites do not enter the helper cluster
  - LE type-3 flags survey across US/JP modules added: `flags=0x03` invariant and DDB-export correlated in current corpus
  - MDCTL static callsite-lift matrix added (wrapper/transport pre-call lanes and frame-write anchors)
  - VD field-size/lane candidate map (`WS21`) and carry-forward table (`WS23`) added; on-media offsets remain explicitly unresolved
  - MDCTL token/opcode bounded crosswalk candidate added (`WS33`) with explicit low-confidence tag
  - parser blob/descriptor contiguity documented (`WS34`); relocation-linkage sensitivity audited (`WS35`)
  - `mdfsck` global-lane xrefs and post-load endian-normalization pass documented (`WS36`,`WS37`)
  - `mdfsck` runtime indirect vectors narrowed to callback/continuation slot family (`WS38`,`WS39`)
  - `mdfsck` callback-walker (`0x4209`) non-empty range and initial far-target (`03f7:0796`) resolved (`WS40`)
  - `mdfsck` slot `0x196c` provenance isolated: 3 indirect-call sites, 0 static writes, image-init `0000:0000` (`WS41`)
  - `mdfsck` slot-contract map (`0x1960..0x1976`) confirms runtime callback+argument lane group with image-init zeros and no direct writes (`WS42`)
  - `mdfsck` write-proof sweep shows zero direct writes and zero immediate-base indirect-write candidates into `0x196c..0x1976` (`WS43`)
  - cross-binary parity (`mdfsex`) confirms same staged callback ABI shape (`AX:DX`, `BX=0/3/2`, gate+`jcxz`) (`WS44`)
  - `mdmgr` vector-slot classes recovered: parser callback lane, guarded device-vector pairs with zero-init, and helper vector lane (`WS45`)
  - `mdmgr` population provenance: parser lane `0x0c42` is IOCTL-read loaded (`int21/4402`), guarded hook pairs remain zero-init-only in static image (`WS46`)
  - `mdmgr` parser lane pointer semantics: `0x0c42` consumed by four `lcall [0x0c42]` sites after 4-byte load, consistent with external helper callback far pointer (`WS47`)
  - `mdmgr` `0x0e32` lane constrained as indexed 8-entry far-pointer dispatch table (startup-init zeroes all 8 per `WS54`; only entries 0..2 have dispatch/write evidence); entry #1 explicitly code-initialized, entry #0/#2 provider unresolved in static pass (`WS48`)
  - MZ relocation crosscheck confirms `0x0e32..0x0e3c` are not relocation targets, narrowing unresolved provider hypotheses for entry #0/#2 (`WS49`)
  - bounded non-literal write scan adds no register-based/block-copy source for `0x0e32..0x0e3c` entry #0/#2 in current static pass (`WS50`)
  - table-separation check isolates `0xe84/0xe86` init table from `0xe32` indexed dispatch path, reducing false linkage risk (`WS51`)
  - far-pointer and load-segment math for raw on-disk defaults captured as constraints (`WS52`,`WS53`)
  - startup-init recovery shows runtime overwrite of `0x0e32/0x0e34` table (8-entry zero + entry #0 default `0x0073:0x0601`), superseding raw-default runtime assumption (`WS54`)
  - state-timeline synthesis captures phase ordering and preserves entry #1 rebind ordering uncertainty (`WS55`)
  - reachability audit constrains rebind uncertainty: block `0x1997..0x1a3f` (contains `0x19d5/0x19db`) is statically isolated in current image-level evidence (`WS56`)
  - indirect-source feasibility sweep adds that no resolved indirect source encodes `0x1997`; residual path is dynamic-vector-only (`WS57`)
  - dynamic-vector prioritization ranks residual path closure as `0x0c42` first, stride-`0x11` lanes second (`WS58`)
  - `0x0c42` load-chain audit confirms single bounded static producer (DOS open/read/close, 4-byte read) and 4 consumers; residual uncertainty is runtime payload value (`WS59`)
  - stride-`0x11` lane bounds consolidated: three consumers are `idx<3` bounded and exclude `0x1997` (`WS60`)
  - `0x0916` k-bound trace confirms single direct caller with bound on `req[+1]` only; no local clamp on `req[+2]` before dispatch (`WS61`)
  - precondition closure confirms caller-side `req[+2] < 8` gating before `0x0e70 -> 0x08f4`, closing prior `k>=8` concern on observed path (`WS62`)
  - second-dispatch materialization shows `0x07df` table has no static write/reloc materialization; residual is protocol-level reachable `req[+1]` subset in domain `9..13` (`WS63`)
  - req[+1] provenance partition confirms `0x0d31..0x0ef6` is read-only for `req[+1]`; subset closure depends on external contract/runtime emission (`WS64`)
  - req[+1] writer non-dominance check finds no direct `call/jmp` to `0x0d31` and keeps writer helpers non-dominating in static evidence (`WS65`)
  - req[+1] domain plausibility narrows practical subset to `9` in current sample (`10` mid-instruction entry, `11..13` off-image) (`WS66`)
  - case-9 semantic lift confirms `0x1047` is a coherent tagged formatter path, strengthening practical subset focus on `req[+1]=9` (`WS67`)
  - case-9 status/output flow confirms outer-handler success status ownership with payload-only writes in `0x1047` (`WS68`)
  - case-9 input provenance confirms `req[0x10..0x17]` as read-mostly pre-assembled contract lanes in bounded static pass (`WS69`)
  - provisional subtype profile consolidates `req[+1]=9` as stable case anchor and reorders case-scope unknown priority (`WS70`)
  - no-media WS25 runtime matrix completed (6 scenarios x 2 runs), with per-scenario stable intersections and cross-scenario common lane signatures documented
  - plan/status alignment updated
  - **[WS78] Live MD DATA media trace via Adaptec USBXChange + MDH-10**:
    - VD at LBA 1056 with `\0MD001` signature confirmed, big-endian on-disk format confirmed
    - VD fields 0x00–0x27 (header + disk parameters + allocation counters) byte-accurately confirmed
    - VSB allocation bitmap at LBA 1057 confirmed (0xFF reserved + 0x55 data pattern, set bits = NumUsed)
    - MTB tag structure at LBA 1060 observed (0x80/0x90/0xA0 tag bytes)
    - DRB 42-byte record format at LBA 1061 confirmed (7+3 filename, Unix timestamps BE32, AU-based location)
    - Z920.EXE file: AU 392 → LBA 1568 MZ header confirmed
    - MODE SENSE Page 0x21 NumUsed value matches VD NumUsed (272)
    - MO disc characteristic: unwritten sectors return L-EC uncorrectable error (normal, not media damage)
  - **[WS79] VD 0x28–0x5A field boundary map — `WS77-C` gate closure for VD**:
    - Mapping formula established: `on-disk offset = mdfsck global address - 0x5b30`
    - Evidence chain: WS37 `rep movsw` copy destination + WS36 xref gap analysis + WS78 live hex validation
    - 18 fields + 3 reserved gaps in 0x28–0x59 region byte-accurately confirmed
    - NumDefective (0x28, BE32), NumDir (0x30, BE16), NumFile (0x32, BE16), MaxIdNum (0x34, BE32),
      VolAttr (0x38, BE16), VMALen (0x3C, BE32), VMALoc (0x40, BE32),
      VSBLoc/Num (0x44/0x46), MTBLoc/Num (0x48/0x4A), ERBLoc/Num (0x4C/0x4E),
      DRBLoc/Num (0x50/0x52), DirLen (0x54, BE32), NumChild (0x58, BE16)
    - Location resolution confirmed: `absolute LBA = VMALoc + xLoc` (VSBLoc→1057, MTBLoc→1060, DRBLoc→1061)
    - Type corrections from WS78 INFERRED: NumDefective u16→u32, MaxIdNum u16→u32, VMALoc offset 0x42→0x40
    - 9/9 cross-validations passed; VD layout promoted from UNKNOWN to CONFIRMED
    - P0 VD mount blocker resolved; remaining P0: VSB/MTB/ERB/DRB internal structure details
  - **[WS80] VSB 비트맵 인코딩 — `WS77-C` gate closure for VSB bitmap**:
    - Encoding: 2-bit per AU, MSB-first within byte (4 AU per byte)
    - State codes: 00=FREE, 01=USED, 10=DEFECTIVE, 11=RESERVED
    - VSBNum = ceil(NumAlloc / 8192), 1 sector = 2048 bytes = 8192 AU
    - NumAlloc 초과 슬롯은 0xFF (RESERVED) 패딩
    - VD 4개 카운터 동시 일치: FREE=17088, USED=272, DEFECTIVE=0, RESERVED=256 (5/5 match)
    - AU 할당 맵: AU 0-255 RESERVED (lead-in), AU 256-527 USED (VMA+Z920.EXE), AU 528+ FREE
    - WS78 "bit-per-AU" 추정을 "2-bit/AU MSB-first"로 보정
    - VSB 비트맵 인코딩 INFERRED→CONFIRMED 승격; remaining: MTB/DRB internal structures
  - **[WS81] MTB 구조 분석 — `WS77-C` gate closure for MTB**:
    - MTB = VSB 섹터별 FREE AU 카운트 테이블 (요약/캐시 구조)
    - TLV 포맷: 4-byte 레코드 [tag(1B) + value(BE24, 3B)]
    - 태그: 0x80=START, 0x90=DATA (per-VSB FREE count), 0xA0=END
    - VSB 3섹터 × FREE 카운트 교차 검증: 7664+8192+1232 = 17088 = NumAvailable (5/5 match)
    - WS78 "태그 구조, 의미 미확정"을 "VSB 섹터별 FREE AU 수"로 확정
    - TRAILER (tag=0x00, value=2): DRB 엔트리 수와 일치하나 단일 디스크로 확정 불가 (UNKNOWN)
    - MTB 구조 INFERRED→CONFIRMED 승격; remaining: DRB header fields, ERB
  - **[WS82] DRB 구조 분석 — 기본 레코드 레이아웃 확정**:
    - 가변 길이 레코드 확정: byte[1] = RecLen (root=42, Z920.EXE=58), 고정 42B 파싱 시 phantom entry 생성 확인
    - 속성 플래그 위치 확정: +0x02 BE16 (CONFIRMED), +0x04 해석 시 Z920에 ADIR 오설정 → 부정합
    - Root 속성: 0x0301 = ADIR|AINHDELETE|AINHRENAME, Z920: 0x0040 = APROTECT
    - 파일명: +0x06, 10B, 7+3 공백패딩 (CONFIRMED)
    - 타임스탬프: +0x10/+0x14/+0x18, Unix UTC BE32 (CONFIRMED)
    - EntryID: +0x1C BE32 (root=2, Z920=16=MaxIdNum) (INFERRED)
    - DataSize: +0x20 BE32, root=2048(=DirLen), Z920=1110476 (CONFIRMED)
    - +0x24/+0x26 이중 해석: dir→(DRBLoc=5, DRBNum=1), file→(0, StartAU=392) (INFERRED)
    - 확장 데이터: +0x2A = ExtentAUCnt BE16 = 136 = ceil(1110476/8192) (CONFIRMED)
    - EntryType +0x04: 0x02=dir, 0x01=file (INFERRED)
    - 8/8 교차 검증 통과; WS78 "42B 고정"→"가변 길이", "속성 +0x04"→"+0x02" 보정
    - UNKNOWN 잔여: +0x05, +0x28, 확장 슬롯 구조, AFXTREC/AAEXTREC 체인 메커니즘
  - **[WS83] ERB 구조 분석 — 테스트 미디어에 데이터 없음**:
    - ERBLoc=0, ERBNum=0, NumDefective=0 → ERB 미할당 확인
    - 역할 추정: 결함 AU 추적 테이블 (INFERRED, NumDefective + VSB DEFECTIVE 상태 + Loc/Num 패턴)
    - mdfsck 코드 참조: ERBLoc 4개 xref, ERBNum 3개 xref (정규화, 출력, 검증 루프)
    - 검증 루프 (0x0f28): ERBLoc이 MTBLoc과 함께 로딩, MTBNum>0 조건으로 진입
    - 내부 레코드 구조: UNKNOWN (결함 AU가 있는 디스크 필요)
    - FUSE 우회: VSB DEFECTIVE 상태(10) 감지 → EIO 반환 (ERB 파싱 불필요)

## 2. Consistency Checks Performed
- Verified core DOS tool strings and offsets (`mdfsex`, `mdmgr`, `mdformat`, `mdfsck`, `mdcache`) against `analysis/ws1_dos_symbols.md`.
- Verified Win95 VxD stack install chain (all three INF files copy the same VxD triplet).
- Verified LE-level artifacts:
  - headers/objects: `analysis/ws2_le_headers.*`
  - ordinals/entry bundles: `analysis/ws2_le_exports.*`
  - type-3 entry hypotheses: `analysis/ws2_le_entry_hypotheses.*`
  - DDB mapping candidates: `analysis/ws2_vxd_ddb_candidates.*`
  - page map/fixup summaries: `analysis/ws2_le_pagemap.*`, `analysis/ws2_le_fixup_summary.*`

## 3. Gaps Still Open

### 3.1 Closed Gaps
- ~~On-media byte-level layout for VD~~ → **CLOSED** (WS78/WS79, `WS77-C` gate passed)
  - 25 fields + 4 reserved gaps mapped at 0x00–0x59, 9/9 cross-validations passed
  - See `MDFS_SPEC_FINAL.md` §4.1 for complete field table
- ~~VSB bitmap encoding~~ → **CLOSED** (WS80, `WS77-C` gate passed)
  - 2-bit/AU MSB-first encoding confirmed with 5/5 VD counter cross-validation
  - See `MDFS_SPEC_FINAL.md` §4.2 for encoding specification
- ~~MTB structure~~ → **CLOSED** (WS81, `WS77-C` gate passed)
  - TLV per-VSB-sector FREE AU count table, 5/5 VSB/VD cross-validation
  - See `MDFS_SPEC_FINAL.md` §4.3 for structure specification
- DRB record layout → **CLOSED** (WS82+WS85, 12/12 cross-validations)
  - WS82: variable-length records, attribute flags +0x02, filename 7+3, timestamps, DataSize, 8/8 xval
  - WS85: CSC(+0x04) CONFIRMED, NLen(+0x05) INFERRED, dir/file extension separated,
    FLoc/FNum/ALen/ALoc/ANum (5×BE32) CONFIRMED, AFXTREC/AAEXTREC extent chain CONFIRMED, AEXT32 CONFIRMED
  - Remaining minor: dir +0x28 (2B), file +0x38 (2B), NLen≠1 format — non-blocking for FUSE
  - See `MDFS_SPEC_FINAL.md` §4.4 for complete record layout

### 3.2 Remaining Open Gaps
- On-media internal structure for ERB/DRB:
  - ~~VSB~~: **CLOSED** — see §3.1
  - ~~MTB~~: **CLOSED** — see §3.1
  - DRB record layout: **CLOSED** (WS82+WS85) — common header + dir/file extension fully mapped, 12/12 cross-validations
    - CSC(+0x04) CONFIRMED, NLen(+0x05) INFERRED, FLoc/FNum/ALen/ALoc/ANum CONFIRMED, DLoc/CNum CONFIRMED
    - Remaining minor unknowns: dir +0x28, file +0x38, NLen≠1 semantics (non-blocking for FUSE)
  - DRB extent chain: **CLOSED** (WS85) — AFXTREC/AAEXTREC mechanism code-confirmed, AEXT32 entry size toggle confirmed, ERB linked list structure hinted
  - ERB: **UNKNOWN** (WS83) — not present on test media (ERBLoc=0, ERBNum=0, NumDefective=0); role INFERRED as defective AU table; needs defective disc
  - Closure requirement: multi-disc comparison and/or format/write/delete diff traces
- LE type-3 entry flags byte (`0x03`) semantics remain unresolved.
- Complete MDCTL payload schema remains unresolved (opcode IDs are strongly supported; frame shape is partially constrained).
- Win95 mount handshake between `MDMGR.VXD` and `MDFSD.VXD` remains unresolved without runtime dynamic VxD trace.
- `mdmgr` entry #1 runtime rebind ordering vs startup is now narrowed to dynamic-only confirmation: static image evidence does not show direct reachability into `0x1997..0x1a3f`.
- For `0x1997` concern, unresolved dynamic sources are prioritized: `0x0c42` then stride-`0x11` lanes (`0x0dcf/0x0dd3/0x0dd7/0x0ddb`).
- `0x0c42` producer multiplicity is now largely closed statically; remaining gap is dynamic capture of the loaded 4-byte far pointer value.
- Prior `k>=8` concern for observed `0x08f4 -> 0x0916` path is closed by caller-side gating (`req[+2] < 8`).
- Remaining second-dispatch uncertainty is narrowed to which `req[+1]` values in `9..13` are actually emitted by runtime protocol flows.
- This `req[+1]` uncertainty is now explicitly external-input scope, not hidden local rewrite behavior in the handler body.
- External-input scope is further reinforced by lack of direct static transfer from observed req[+1] writer helpers into `0x0d31`.
- Current static sample further suggests practical second-dispatch value convergence toward `req[+1]=9` for plausible in-image entry.
- For current corpus, `req[+1]=9` now has both control-flow plausibility and local semantic coherence evidence.
- `req[+1]=9` also has consistent success-path status/payload ownership split (`handler status`, `0x1047 payload`).
- `req[+1]=9` path now additionally has input-lane provenance support (`req[0x10..0x17]` as externally assembled bytes).
- Highest remaining case-9 unknowns are now: external producer path for `req[0x10..0x17]`, then semantic naming/taxonomy label.
- No-media runtime repeatability evidence is now strong for transport lanes, but MUST NOT be used alone to close media-dependent payload/layout unknowns.

## 4. Reproducibility Baseline
- A complete size/SHA-1 list for `w31/extract/*` and `w95/extract/us/*` was regenerated and reflected in spec updates.
- High-value driver hashes:
  - `w95/extract/us/mdfsd.vxd`: `ebd4c5f887f1081461d9720a95afb25074f9fdda`
  - `w95/extract/us/mdmgr.vxd`: `1ace191b10bb9c6ebed8e048b7e6d7fff5aea00d`
  - `w95/extract/us/mdhlp.vxd`: `5a8e0363c93110c4f9cb0bbb13236d7d243fd24b`

## 5. Summary
- No critical contradiction was found between current docs and extracted binaries.
- **VD on-media layout is now fully resolved** (WS78/WS79): 25 fields byte-accurately confirmed with 9 independent cross-validations. `WS77-C` gate passed for VD.
- **VSB bitmap encoding is now fully resolved** (WS80): 2-bit/AU MSB-first, 4 states, 5/5 VD counter cross-validation. `WS77-C` gate passed for VSB.
- **MTB structure is now fully resolved** (WS81): TLV per-VSB-sector FREE AU count table, 5/5 cross-validation. `WS77-C` gate passed for MTB. Trailer field (4 bytes) remains `UNKNOWN`.
- **DRB record layout is now fully resolved** (WS82+WS85): common header (36B) with CSC/NLen, directory extension (DLoc/CNum, 6B), file extension (FLoc/FNum/ALen/ALoc/ANum, 22B). Byte-swap function two-path analysis confirms dir/file field divergence. AFXTREC/AAEXTREC extent chain mechanism code-confirmed. AEXT32 entry size toggle confirmed. 12/12 cross-validations passed. Remaining minor: dir +0x28, file +0x38, NLen≠1 (non-blocking).
- **ERB role is INFERRED** (WS83): defective AU tracking table, but no data on test media (NumDefective=0). Internal structure fully UNKNOWN. FUSE workaround available via VSB DEFECTIVE state detection.
- Remaining uncertainties are explicitly tagged `[UNKNOWN]` or `[INFERRED]` and trace back to:
  - DRB extension/chain details (needs fragmented files, subdirectories)
  - ERB internal structure (needs disc with defective AU sectors)
  - Control payload semantics (runtime capture needed)
  - LE type-3 flags (independent proof path needed)
  - Win95 mount handshake (runtime VxD trace needed)

Operational flow:
- ~~Non-media phase only~~ → **Media phase entered** (WS78/WS79): live MD DATA disc accessed via USBXChange adapter.
- VD + VSB + MTB + DRB closure achieved (WS82+WS85); ERB role INFERRED (WS83, no data). All P0 mount blockers resolved for defect-free single-extent discs. Next targets: ERB internal structure (defective disc), multi-disc validation, FUSE implementation.
- Control payload and LE type-3 gaps remain unchanged (need respective `WS77-B/D` gates).
