# MDFS Specification (Final Draft)

Date: 2026-02-24 (updated from 2026-02-18)
Status: Final Draft (Evidence-Bound; VD CONFIRMED WS78/79; VSB CONFIRMED WS80; MTB CONFIRMED WS81; DRB WS82; ERB WS83)

## 1. Scope and Confidence
This document defines the Sony MD DATA File System (MDFS) behavior that is currently recoverable from the extracted DOS/Win3.1 tools, Win95 VxD drivers, and installer metadata in this workspace.

Confidence policy:
- `CONFIRMED`: directly evidenced by binary strings, installer directives, parsed LE structures, or checksum-verified artifacts
- `INFERRED`: consistent cross-evidence interpretation without full byte-level proof
- `UNKNOWN`: unresolved without deeper disassembly and/or live-media trace

Promotion gate (mandatory):
- `INFERRED -> CONFIRMED` promotion MUST NOT be done by static plausibility alone.
- Repeated no-media runtime captures MAY strengthen repeatability claims, but MUST remain `INFERRED`.
- Any field/offset/payload semantic that depends on real MD DATA media behavior MUST stay `UNKNOWN` until media-backed trace evidence is recorded.

## 2. Component Architecture

### 2.1 DOS/Win3.1 userland stack (`w31/extract/*`)
- `mdfsex.exe` (filesystem loader) `CONFIRMED`
- `mdmgr.exe` (MD DATA manager) `CONFIRMED`
- `mdformat.exe` (format utility) `CONFIRMED`
- `mdfsck.exe` (consistency checker) `CONFIRMED`
- `mdcache.exe` (write-cache control) `CONFIRMED`

### 2.2 Win95 stack (`w95/extract/us/*`)
- `MDFSD.VXD` core FS driver role `INFERRED`
- `MDMGR.VXD` IFSMgr/CFSD registration role `CONFIRMED`
- `MDHLP.VXD` low-level I/O request mediation role `INFERRED`
- INF install chain copies all three VxDs together for supported Sony SCSI IDs `CONFIRMED`

## 3. DOS Utility Interface (Operational Contract)
- `mdfsex [/L:drive][/?]` `CONFIRMED`
- `mdformat drive: [-q|-s] [-v:label -o -?]` `CONFIRMED`
- `mdfsck drive: [-v -?]` `CONFIRMED`
- `mdcache [drive:] ON|OFF|IS|FLUSH` `CONFIRMED`

## 4. Logical Filesystem Model
MDFS logical entities observed in checker vocabulary:
- `VD`, `VSB`, `MTB`, `ERB`, `DRB` `CONFIRMED`

Observed VD field labels include:
- `Identifier`, `Version`, `BlockSize`, `ClusterSize`, `AllocSize`
- allocation/use counters
- area location/count tuples (`VSBLoc/VSBNum`, `MTBLoc/MTBNum`, `ERBLoc/ERBNum`, `DRBLoc/DRBNum`)
- metadata IDs/timestamps

Field names are confirmed. On-media byte offsets for VD are now `CONFIRMED` (WS78/WS79).

### 4.1 VD On-Media Layout — `CONFIRMED`

Mapping formula: `on-disk byte offset = mdfsck global address - 0x5b30`
(WS37: `rep movsw` at `0x02e5` copies VD sector into `0x5b30` range;
WS36: xref gaps identify reserved/padding positions;
WS78/WS79: live MD DATA media hex validates all offsets.)

All multi-byte numeric fields are big-endian (`CONFIRMED` by WS37 normalization + WS78 live data).

#### VD Header (0x00–0x0F)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x00 | 1 | u8 | RecordType | `CONFIRMED` |
| 0x01 | 5 | ASCII | Identifier (`"MD001"`) | `CONFIRMED` |
| 0x06 | 1 | u8 | Version | `CONFIRMED` |
| 0x07 | 9 | — | Reserved | `CONFIRMED` |

#### Disk Parameters (0x10–0x27)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x10 | 2 | BE16 | BlockSize (bytes) | `CONFIRMED` |
| 0x12 | 2 | BE16 | ClusterSize (sectors) | `CONFIRMED` |
| 0x14 | 2 | BE16 | AllocSize (sectors) | `CONFIRMED` |
| 0x16 | 2 | — | Reserved | `CONFIRMED` |
| 0x18 | 4 | BE32 | NumAlloc (AU) | `CONFIRMED` |
| 0x1C | 4 | BE32 | NumRecordable (AU) | `CONFIRMED` |
| 0x20 | 4 | BE32 | NumAvailable (AU) | `CONFIRMED` |
| 0x24 | 4 | BE32 | NumUsed (AU) | `CONFIRMED` |

#### Filesystem Counters (0x28–0x3B)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x28 | 4 | BE32 | NumDefective (AU) | `CONFIRMED` |
| 0x2C | 4 | — | Reserved | `CONFIRMED` |
| 0x30 | 2 | BE16 | NumDir | `CONFIRMED` |
| 0x32 | 2 | BE16 | NumFile | `CONFIRMED` |
| 0x34 | 4 | BE32 | MaxIdNum | `CONFIRMED` |
| 0x38 | 2 | BE16 | VolAttr | `CONFIRMED` |
| 0x3A | 2 | — | Reserved | `CONFIRMED` |

Note: NumDefective and MaxIdNum are BE32 on disk; `mdfsck` reads only the low u16 for display (`%d`).

#### VMA Location Table (0x3C–0x53)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x3C | 4 | BE32 | VMALen | `CONFIRMED` |
| 0x40 | 4 | BE32 | VMALoc (absolute sector) | `CONFIRMED` |
| 0x44 | 2 | BE16 | VSBLoc (relative to VMALoc) | `CONFIRMED` |
| 0x46 | 2 | BE16 | VSBNum (sector count) | `CONFIRMED` |
| 0x48 | 2 | BE16 | MTBLoc (relative to VMALoc) | `CONFIRMED` |
| 0x4A | 2 | BE16 | MTBNum (sector count) | `CONFIRMED` |
| 0x4C | 2 | BE16 | ERBLoc (relative to VMALoc) | `CONFIRMED` |
| 0x4E | 2 | BE16 | ERBNum (sector count) | `CONFIRMED` |
| 0x50 | 2 | BE16 | DRBLoc (relative to VMALoc) | `CONFIRMED` |
| 0x52 | 2 | BE16 | DRBNum (sector count) | `CONFIRMED` |

Location resolution: `absolute LBA = VMALoc + VSBLoc/MTBLoc/ERBLoc/DRBLoc`.

#### Directory Info (0x54–0x59)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x54 | 4 | BE32 | DirLen (bytes) | `CONFIRMED` |
| 0x58 | 2 | BE16 | NumChild | `CONFIRMED` |

VD managed field area ends at offset **0x59** (90 bytes, 25 fields + 4 reserved gaps).
Volume label, formatter ID, and timestamps occupy 0x80+ (see WS78 §3.3).

#### Live-media cross-validation (WS78/WS79)

| Check | Expected | Observed | Result |
|-------|----------|----------|--------|
| NumAlloc × AllocSize × BlockSize | — | 144,310,272 = READ CAPACITY | ✓ |
| NumUsed | 272 | VSB bitmap set bits: 272 | ✓ |
| NumUsed | 272 | MODE SENSE Page 0x21: 0x0110 | ✓ |
| VMALoc | — | 1056 = VD LBA (self-referential) | ✓ |
| VSBLoc=1 | — | LBA 1057: allocation bitmap | ✓ |
| MTBLoc=4 | — | LBA 1060: MTB tag structure | ✓ |
| DRBLoc=5 | — | LBA 1061: DRB variable-length records | ✓ |
| DirLen | 2048 | DRB occupies 1 sector | ✓ |
| NumChild=1 | — | 1 file entry in DRB | ✓ |

### 4.2 VSB Bitmap Encoding — `CONFIRMED`

VSB (Volume Space Bitmap) encodes AU allocation state using a 2-bit-per-AU scheme.

#### Encoding Format

```
2-bit per AU, MSB-first within byte

1 byte = 4 AU:  [AU₀ AU₁ AU₂ AU₃]
                 bit7-6  bit5-4  bit3-2  bit1-0

State codes:
  00 = FREE       (할당 가능)
  01 = USED       (파일/관리 데이터에 할당됨)
  10 = DEFECTIVE  (결함 AU)
  11 = RESERVED   (시스템 예약)
```

AU state extraction: `state = (vsb[au / 4] >> ((3 - au % 4) * 2)) & 0x03`

#### Layout

VSB occupies `VSBNum` consecutive sectors starting at `VMALoc + VSBLoc`.
Each sector (2048 bytes) covers 8192 AU (4 AU per byte × 2048 bytes).

```
VSBNum = ceil(NumAlloc / 8192)

VSB[0]: AU 0 – 8191
VSB[1]: AU 8192 – 16383
VSB[2]: AU 16384 – NumAlloc-1 (valid) + NumAlloc – 24575 (padding)
```

Slots beyond NumAlloc are padded with `0xFF` (= all RESERVED, `11` × 4).

#### Byte Pattern Reference

| Byte | 2-bit decomposition | Meaning |
|------|---------------------|---------|
| 0xFF | [11][11][11][11] | 4 AU all RESERVED |
| 0x55 | [01][01][01][01] | 4 AU all USED |
| 0x00 | [00][00][00][00] | 4 AU all FREE |
| 0xAA | [10][10][10][10] | 4 AU all DEFECTIVE |

#### Cross-validation (WS80)

Counting only valid AU (0 to NumAlloc-1):

| State | VSB count | VD field | VD value | Match |
|-------|-----------|----------|----------|-------|
| 00 (FREE) | 17,088 | NumAvailable | 17,088 | ✓ |
| 01 (USED) | 272 | NumUsed | 272 | ✓ |
| 10 (DEFECTIVE) | 0 | NumDefective | 0 | ✓ |
| 11 (RESERVED) | 256 | NumAlloc − NumUsed − NumAvailable | 256 | ✓ |
| **Total** | **17,616** | **NumAlloc** | **17,616** | ✓ |

5/5 match — `CONFIRMED`.

#### AU Allocation Map (test media)

| AU range | Count | State | LBA range | Content |
|----------|-------|-------|-----------|---------|
| 0–255 | 256 | RESERVED | 0–1023 | Lead-in area |
| 256–263 | 8 | USED | 1024–1055 | Pre-VMA (zeros) |
| 264–265 | 2 | USED | 1056–1063 | VD/VSB/MTB/DRB |
| 266–391 | 126 | USED | 1064–1567 | VMA reserved space |
| 392–527 | 136 | USED | 1568–2111 | Z920.EXE |
| 528–17615 | 17,088 | FREE | 2112–70463 | Unallocated |

### 4.3 MTB Structure — `CONFIRMED`

MTB (Management Table Block) is a per-VSB-sector FREE AU count summary table.

Location: `VMALoc + MTBLoc` (LBA 1060 on test media), occupying `MTBNum` sectors (1).

#### TLV Record Format

4-byte records: `[tag(1 byte)] [value(BE24, 3 bytes)]`

```
Tag codes:
  0x80 = START   (header marker, value=0)
  0x90 = DATA    (per-VSB-sector FREE AU count)
  0xA0 = END     (terminator, value=0)
```

Tag bit pattern: bit7 always set, bits 4–5 increment (0→1→2): `1000_0000`, `1001_0000`, `1010_0000`.

#### Layout

One DATA entry per VSB sector, in order. Entry count = `VSBNum`.

```
+0x00: [0x80] START  value=0
+0x04: [0x90] DATA   value=free_count_vsb0
+0x08: [0x90] DATA   value=free_count_vsb1
  ...
+0xNN: [0xA0] END    value=0
+0xNN+4: TRAILER (4 bytes, semantics UNKNOWN)
```

Invariant: `sum(DATA values) == NumAvailable`.

#### Cross-validation (WS81)

| VSB sector | AU range | Valid AU | FREE (VSB bitmap) | MTB DATA value | Match |
|------------|----------|---------|-------------------|----------------|-------|
| VSB[0] (LBA 1057) | 0–8191 | 8,192 | 7,664 | 7,664 | ✓ |
| VSB[1] (LBA 1058) | 8192–16383 | 8,192 | 8,192 | 8,192 | ✓ |
| VSB[2] (LBA 1059) | 16384–17615 | 1,232 | 1,232 | 1,232 | ✓ |
| **Sum** | | **17,616** | **17,088** | **17,088** | ✓ |

Sum = NumAvailable (17,088) ✓, entry count = VSBNum (3) ✓ — 5/5 match, `CONFIRMED`.

#### Trailer Field

After the END marker, 4 bytes `00 00 00 02` are present on test media.
Value (2) matches DRB entry count and NumDir+NumFile, but cannot be disambiguated
from a single disc. Marked `UNKNOWN` pending multi-disc comparison.

### 4.4 DRB Structure — WS82

DRB (Directory Record Block) stores file/directory metadata entries.

Location: `VMALoc + DRBLoc` (LBA 1061 on test media), occupying `DRBNum` sectors (1).

#### Variable-Length Records — `CONFIRMED`

Records use variable length: byte `+0x01` = record length in bytes.
Fixed 42-byte parsing creates phantom entries from extension data; variable-length
parsing is the only consistent interpretation.

Termination: 4+ consecutive null bytes signal end of record list.

#### Common Header (36 bytes)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x00 | 1 | u8 | RecType (always 0x00) | `CONFIRMED` |
| 0x01 | 1 | u8 | RecLen (variable) | `CONFIRMED` |
| 0x02 | 2 | BE16 | Attributes (flag bits) | `CONFIRMED` |
| 0x04 | 1 | u8 | CSC — Classification Code (0x01=file, 0x02=dir) | `CONFIRMED` (WS85) |
| 0x05 | 1 | u8 | NLen — Name type (1=standard 7+3) | `INFERRED` (WS85) |
| 0x06 | 10 | ASCII | FileName (7+3, space-padded) | `CONFIRMED` |
| 0x10 | 4 | BE32 | CreateTime (Unix UTC) | `CONFIRMED` |
| 0x14 | 4 | BE32 | ModifyTime (Unix UTC) | `CONFIRMED` |
| 0x18 | 4 | BE32 | AccessTime (Unix UTC) | `CONFIRMED` |
| 0x1C | 4 | BE32 | EntryID | `INFERRED` |
| 0x20 | 4 | BE32 | DataSize (bytes; dir=DLen, file=FLen) | `CONFIRMED` |

Note: CSC was previously labeled "EntryType" (WS82 INFERRED); mdfsck format string
`CSC=%-03d` confirms the name. NLen was previously "Unknown05"; mdfsck code branches on
`NLen==1` for standard 7+3 name format vs alternative (NLen≠1 uses +0x05 as name start).

#### Directory Extension (6 bytes, RecLen ≥ 42) — `CONFIRMED` (WS85)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x24 | 2 | BE16 | DLoc — child DRB sector location (VMA-relative) | `CONFIRMED` |
| 0x26 | 2 | BE16 | CNum — child DRB sector count | `CONFIRMED` |
| 0x28 | 2 | — | Unknown (not byte-swapped, byte fields) | `UNKNOWN` |

Root entry: DLoc=5 → LBA 1061 (= VMALoc + DRBLoc ✓), CNum=1 ✓.

#### File Extension (22 bytes, RecLen ≥ 58) — `CONFIRMED` (WS85)

| Offset | Size | Type | Field | Confidence |
|--------|------|------|-------|------------|
| 0x24 | 4 | BE32 | FLoc — F-extent location (StartAU or Extent Record Block ptr) | `CONFIRMED` |
| 0x28 | 4 | BE32 | FNum — F-extent AU count | `CONFIRMED` |
| 0x2C | 4 | BE32 | ALen — A-extent data size (bytes) | `CONFIRMED` |
| 0x30 | 4 | BE32 | ALoc — A-extent location (AU or ERB ptr) | `CONFIRMED` |
| 0x34 | 4 | BE32 | ANum — A-extent AU count | `CONFIRMED` |
| 0x38 | 2 | — | Unknown (not byte-swapped, byte fields) | `UNKNOWN` |

Key difference from directory: +0x24/+0x26 is a single BE32 (FLoc) for files vs two BE16
(DLoc/CNum) for directories. This dual interpretation is confirmed by byte-swap function
0x1672 which takes different paths based on ADIR flag.

Z920.EXE: FLoc=392 → LBA 1568 ✓, FNum=136 = ceil(1110476/8192) ✓, ALen=0, ALoc=0, ANum=0.

#### Extent Chain Mechanism (AFXTREC/AAEXTREC) — `CONFIRMED` (WS85)

When file data exceeds a single contiguous AU range:

- **AFXTREC** (attr bit 14, 0x4000): when set, FLoc points to an **Extent Record Block**
  (external sector containing extent entries) instead of a direct StartAU.
- **AAEXTREC** (attr bit 15, 0x8000): when set, ALoc points to an **Additional Extent
  Record Block** for the A-extent chain.
- **AEXT32** (VolAttr bit 15, 0x8000): controls extent record entry size —
  set: 32 bytes/entry, unset: 64 bytes/entry.

Extent chain depth: mdfsck supports up to 8 levels of recursive extent chains (function
0x2620). ERB linked list: `ERB Unused=%d Next=%d` format string suggests ERB sectors
have an unused counter and next pointer for chaining.

Without AEXT32: extent location encoded as `sector = loc >> 6, offset = loc & 0x3F`.
With AEXT32: direct sector/offset interpretation.

#### Attribute Flags (+0x02, BE16) — `CONFIRMED`

Position determination: +0x02 correctly identifies ADIR for directory entries and
clears ADIR for file entries; +0x04 fails this test (marks Z920.EXE with ADIR).

| Bit | Value | Name | Description |
|-----|-------|------|-------------|
| 0 | 0x0001 | ADIR | Directory |
| 1 | 0x0002 | AINVISIBLE | Hidden |
| 2 | 0x0004 | ASYSTEM | System |
| 3 | 0x0008 | ADELETED | Deleted (WS85 code-confirmed) |
| 6 | 0x0040 | APROTECT | Protected |
| 7 | 0x0080 | ABACKUP | Backup |
| 8 | 0x0100 | AINHDELETE | Delete inhibited |
| 9 | 0x0200 | AINHRENAME | Rename inhibited |
| 10 | 0x0400 | AINHCOPY | Copy inhibited |
| 13 | 0x2000 | AEXTTYPE | Extended type (WS85 code-confirmed) |
| 14 | 0x4000 | AFXTREC | FLoc → Extent Record Block (WS85 code-confirmed) |
| 15 | 0x8000 | AAEXTREC | ALoc → Additional Extent Record Block (WS85 code-confirmed) |

Test media entries:
- Root: 0x0301 = ADIR | AINHDELETE | AINHRENAME
- Z920.EXE: 0x0040 = APROTECT

#### Filename Format — `CONFIRMED`

10 bytes: 7 chars (base name) + 3 chars (extension), space-padded (0x20).
Parsing: `base[:7].rstrip() + "." + ext[7:10].rstrip()`, omit dot if extension empty.

#### Cross-validation (WS82 + WS85)

| Check | Expected | Observed | Result |
|-------|----------|----------|--------|
| Root Attributes ADIR | set | 0x0301 bit0=1 | ✓ |
| Z920 Attributes !ADIR | clear | 0x0040 bit0=0 | ✓ |
| Root DataSize (DLen) | DirLen (2048) | 2048 | ✓ |
| Root DLoc | DRBLoc (5) | 5 | ✓ |
| Root CNum | DRBNum (1) | 1 | ✓ |
| Z920 FLoc | AU 392 → MZ header | MZ confirmed at LBA 1568 | ✓ |
| Z920 FNum | ceil(1110476/8192)=136 | 136 | ✓ |
| Z920 ALen/ALoc/ANum | 0 (no A-extent) | 0/0/0 | ✓ |
| Root CSC | 0x02 (dir) | 0x02 | ✓ |
| Z920 CSC | 0x01 (file) | 0x01 | ✓ |
| max(EntryID) | MaxIdNum (16) | root=2, Z920=16, max=16 | ✓ |
| Byte-swap path divergence | ADIR→2×BE16, !ADIR→5×BE32 | code confirmed | ✓ |

12/12 cross-validations passed (WS82: 8, WS85: +4).

### 4.5 ERB Structure — WS83

ERB (Error Record Block) is inferred to be a defective AU tracking table.

Location: `VMALoc + ERBLoc` (not allocated on test media).

#### Test Media Status

```
ERBLoc = 0       (VD +0x4C, BE16)  → not allocated
ERBNum = 0       (VD +0x4E, BE16)  → 0 sectors
NumDefective = 0 (VD +0x28, BE32)  → no defective AU
```

No ERB data exists on the test media (MD DATA 140MB disc with zero defective AU).
Internal record structure cannot be determined. `UNKNOWN`.

#### Inferred Role — `INFERRED`

| Evidence | Implication |
|----------|------------|
| VD NumDefective field | Tracks defective AU count |
| VSB DEFECTIVE state (10) | Bitmap-level defect marking per AU |
| ERBLoc/ERBNum VD pair | Same Loc/Num pattern as VSB/MTB/DRB |
| mdfsck code at 0x0f28 | ERBLoc loaded alongside MTBLoc for validation |
| NumDefective=0 → ERBLoc=0 | ERB only allocated when defects exist |

ERB likely stores defective AU location/detail records, complementing the
VSB bitmap's 2-bit DEFECTIVE state with additional information (physical
defect location, replacement AU mapping, etc.).

#### mdfsck Code References

ERBLoc (global 0x5b7c): 4 xrefs — endian normalization (0x04fd/0x0501),
VD emit (0x07d8), and validation loop parameter (0x0f28).

ERBNum (global 0x5b7e): 3 xrefs — endian normalization (0x0507/0x050b)
and VD emit (0x07e8).

The validation loop at 0x0f28 loads ERBLoc into a local variable alongside MTBLoc,
gated by `MTBNum > 0`. Detailed ERB validation logic is not recoverable from
the available code context alone.

#### FUSE Implementation Note

ERB internal parsing is not required for read-only mount of defect-free discs.
For discs with defective AU, the VSB DEFECTIVE state (10) provides sufficient
detection: access to any AU with state=10 returns `EIO`.

#### Closure Requirement

ERB internal structure requires a disc with defective AU sectors.
Promotion gate: `WS77-C` (remaining).

### 4.6 Static Analysis Background

Static VD emit-path mapping provides the underlying evidence chain:
- `mdfsck` formatter-call block (`0x0670..0x085c`, code region) maps VD labels to globals
  in the `0x5b40..0x5b88` lane (data region) with inferred format-string base `0xdcd0`
  (note: code and data addresses coexist in the 16-bit MZ address space; code references
  like `0x0670` are IP-relative while data globals like `0x5b48` are DS-relative)
- `WS21/WS23` provide field-size/lane candidate tables (e.g., `%ld`-backed 32-bit counters)
- `WS37` shows a post-load numeric normalization pass (byte/word reordering), confirming
  checker-consumed numeric lanes are host-little-endian after conversion from big-endian source
- `WS79` closes the offset chain: live media hex at each predicted offset matches expected
  values, completing `WS77-C` gate for VD fields

Attribute bit mappings recovered from `mdfsck.exe` relocation-backed tables:
- Volume-style flags:
  - `AMIRROR=0x0001`, `AINVISIBLE=0x0002`, `APROTECT=0x0040`, `ABACKUP=0x0080`
  - `AINHFORMAT=0x0100`, `AINHRENAME=0x0200`, `AINHCOPY=0x0400`, `AEXT32=0x8000`
- Record-style flags:
  - `ADIR=0x0001`, `AINVISIBLE=0x0002`, `ASYSTEM=0x0004`, `ADELETED=0x0008`
  - `APROTECT=0x0040`, `ABACKUP=0x0080`, `AINHDELETE=0x0100`, `AINHRENAME=0x0200`
  - `AINHCOPY=0x0400`, `AEXTTYPE=0x2000`, `AFXTREC=0x4000`, `AAEXTREC=0x8000`
- Note: `AINVISIBLE=0x0002` appears in both flag tables with the same value;
  context (volume vs record) determines which table applies.

## 5. Driver and Control Surface

### 5.1 Control-path indicators
#### 5.1.1 Userland Control Transport (DOS)
- Tokens observed across DOS/Win95 binaries: `MDCTL`, `MD001`, `MDFS000`, `IOMR000`, `MDMR000`
- Userland utilities likely depend on manager/device-control interfaces rather than direct media parsing
- Observed DOS x86 code paths use `INT 21h` `AH=0x44` IOCTL wrapper style
  (`AL` function code, `BX` handle, `DS:DX` buffer, `CX` length)
- The same wrapper contract is present in both `mdcache` and `mdformat` with matching argument lanes.
- Recovered direct callsites include `AL=0/1` patterns compatible with generic DOS
  device-info flow (`4400h/4401h`), so MDCTL-private opcode mapping is still unresolved.
- The relationship between the `INT 21h AH=0x44` IOCTL wrapper path
  (observed in `mdcache`/`mdformat`/`mdfsck`) and the `lcall [0x0c42]` callback
  dispatch path (observed in `mdmgr`) remains `UNKNOWN`. These may represent
  different layers of the same transport stack or independent control paths.

#### 5.1.2 MDCTL Token/Descriptor Evidence
- `mdcache` includes parser token blob with `:\\mdctl` and
  command tokens `ON/OFF/IS/FLUSH/?`, indicating table-driven command dispatch.
- token blob, callback trio, and descriptor tuples are contiguous in one
  data cluster, reinforcing dispatch-table interpretation.
- `mdcache` descriptor block near this blob shows 5 regular records (`0x14` stride)
  with candidate `(op_code, op_index)` tuples and handler offsets in code region
  (`0x1818`, `0x182c`, `0x1840`, `0x1854`, `0x1868`).
- `mdformat` contains a second, independent 5-record descriptor block with the
  same `(op_code, op_index)` tuple sequence and handler words
  (`0x135a`, `0x136e`, `0x1382`, `0x1396`, `0x13aa`), reinforcing shared opcode IDs.
- Current status: opcode IDs are strongly supported; payload field schema remains unresolved.
- A static callsite-lift matrix is available for wrapper/transport calls
  (pre-call push lanes and local frame writes), providing concrete anchors for
  runtime payload capture.
- A bounded low-confidence token/opcode crosswalk candidate is now documented:
  `ON/OFF/IS/FLUSH/?` mapped by descriptor index order to
  `0209/020A/0202/0243/0242` (pending runtime proof).
- relocation-only linkage to this cluster is method-sensitive; it is not used
  as standalone proof for opcode semantics.

#### 5.1.3 Frame-Shape and Helper-Cluster Constraints
- `mdfsck` command helpers additionally show fixed request-frame shapes (`0x20`, `0x208`, `0x4a`)
  with leading type/subtype bytes (`type=2`, subtype values including `4/5/6`) before paired
  imported transport calls. This constrains payload structure but still does not finalize
  subtype-to-opcode semantics.
- Additional nearby helper families indicate further payload shapes:
  - `type=1` with mode-dependent subtype-like byte (`0x16/0x18`)
  - `type=2,sub=8,len=0x11` request/response pair
  - `type=1,sub=0x24,len=0x17` and `type=1,sub=7,len=0x10` probe/control style requests
  These are treated as structure evidence, not final semantic opcode mapping.
- Summary observation: two frame-class families are present—`type=1`
  (data-transfer-style, with mode/length variants) and `type=2`
  (control/query-style, with fixed small-frame shapes). This two-class
  distinction is structural evidence only; the semantic mapping between
  frame type byte and MDCTL opcode remains `UNKNOWN`.
- Core helper (`0x3cca`) is now constrained as a direction-sensitive transport primitive:
  wrappers inject `0/1` mode, tx/rx pair is executed, and payload copy direction flips
  by mode (caller->frame vs frame->caller).
- Internal parameter/write mapping is additionally constrained:
  - caller args `[+0x0c/+0x0e]` feed header words `+0x10/+0x12` (32-bit start-like lane),
  - caller arg `[+0x10]` feeds header `+0x14` and transfer-size path (`<<11`).
  - transfer-size shape matches `([arg+0x10] << 11) + 0x18`.
- Direct near-call CFG from process entry does not reach this helper cluster in current
  static traversal, so these semantics are retained as inferred static-path evidence
  (not yet runtime-confirmed behavior).
- Direct immediate call-xref sweep also currently shows only local/intra-cluster
  callers into `0x3994..0x3f4a`; no top-level entry is statically proven.
- Segment-aware indirect-flow analysis (`CS=0x03f7`, `DS_base=0xdcd0`) resolves
  currently visible indirect sites and also does not show a path into
  `0x3994..0x3f4a`; remaining uncertainty is now concentrated in runtime vectors
  (`lcall [0x196c]`, mutable/null/sentinel far-pointer slots).
- Additional slot-role tracing narrows these vectors to runtime
  callback/continuation slot family (`0x196c`, `0x14d2/0x14d4`, `0x14d6`,
  `0x14dc/0x14de`, `0x177a/0x177c`) rather than statically linked helper-cluster dispatch.
- `lcall [di]` at `0x4217` is constrained by callback-walker routine (`0x4209`)
  over `[SI,DI)`; the non-empty static range `[0x1978,0x197c)` resolves to
  `03f7:0796` (linear `0x4706`), outside helper cluster `0x3994..0x3f4a`.
- Slot-contract lift over `0x1960..0x1976` further constrains `0x196c` path:
  `0x196c/0x196e/0x1970..0x1976` are image-init zero, read/indirect-call only
  in current static image (no direct writes), consistent with runtime-populated
  callback vector + argument lane contract.
- Additional write-proof scan (`WS43`) found zero direct writes and zero
  immediate-base indirect-write candidates into `0x196c..0x1976`, reinforcing
  the runtime-populated contract interpretation.
- Cross-binary lift (`WS44`) shows `mdfsex` has the same callback ABI shape as
  `mdfsck` (`AX:DX` staged payload lanes, `BX=0/3/2` selector sequence, gate
  lane + `jcxz` before third call), supporting a shared runtime callback contract.

#### 5.1.4 MDMGR Dynamic Dispatch and Runtime-Only Uncertainty
- `mdmgr` slot-class scan (`WS45`) separates parser callback lane (`0x0c42`)
  from guarded device-vector pairs (`0x0cfa/0x0cfc`, `0x0cfe/0x0d00`,
  `0x0e2a/0x0e2c`, `0x0e2e/0x0e30`) and a high-frequency helper vector (`0x0e32`);
  paired vectors are explicitly zero-initialized before guarded `lcall`.
- Population provenance (`WS46`) further narrows provider paths:
  `0x0c42` is populated via DOS IOCTL read (`int 21h`, `AX=0x4402`, `DX=0x0c42`, `CX=4`),
  while guarded hook pairs remain zero-init-only in current static image
  (no non-zero in-image writes).
- Pointer semantics pass (`WS47`) confirms `0x0c42` is consumed via `lcall [0x0c42]`
  at four callsites and receives exactly 4 bytes from loader path, supporting
  interpretation as external helper callback far pointer entry.
- Dispatch-table pass (`WS48`) refines `0x0e32` lane semantics in `mdmgr`:
  it is an 8-entry indexed far-pointer dispatch table (`index<<2`, guard,
  `lcall [bx+0x0e32]`; startup-init zeroes all 8 entries per `WS54`,
  only entries 0..2 have dispatch/write evidence in bounded static pass);
  entry #1 (`0x0e36/0x0e38`) is code-initialized, while entry #0/#2 have no
  literal in-image writes in current static pass.
- Relocation crosscheck (`WS49`) shows `0x0e32..0x0e3c` entries are not MZ-relocation
  targets either, so unresolved entry #0/#2 provider is not explained by simple
  DOS loader relocation and remains runtime/non-literal-write territory.
- Non-literal write scan (`WS50`) adds no new provider path for entry #0/#2:
  only entry #1 direct writes (`0x0e36/0x0e38`) are observed, with no resolved
  register-based or block-copy writes into `0x0e32..0x0e3c`.
- Table-separation scan (`WS51`) shows `0xe84/0xe86` refs are confined to init
  path (`0x19fe..0x1a35`) and do not appear in indexed dispatch path
  (`0x1ccc..0x1d28`), reinforcing that device table is separate from
  `0x0e32` dispatch-provider source.
- Far-pointer classification (`WS52`) clarifies dispatch entry states:
  on-disk words decode as far pointers, but these defaults are overwritten by
  startup init before normal operation.
- Load-segment feasibility (`WS53`) adds quantitative support: feasible segment
  ranges for initial #0/#2 pointers have no overlap with entry #1 rewritten
  in-image range (for raw on-disk values).
- Startup-init recovery (`WS54`) supersedes raw-default interpretation for runtime:
  routine `0x2e58..0x312e` zeroes 8 entries of `0x0e32/0x0e34` table then sets
  entry #0 to `0x0073:0x0601` (twice). Thus runtime dispatch baseline is driven
  by startup writes; unresolved provider focus now narrows to how entry #1/#2 are
  populated after startup (entry #1 later receives explicit in-image handler writes).
- State-timeline synthesis (`WS55`) consolidates phases:
  raw-image defaults -> startup zero loop -> startup entry #0 bind ->
  observed later entry #1 rebind (`011f:095c`) with ordering still unresolved
  in bounded static evidence.
- Reachability audit (`WS56`) tightens this uncertainty boundary:
  the write block containing `0x19d5/0x19db` (`0x1997..0x1a3f`) has no direct
  static branch/call references to `0x1997`, no external inbound refs, and no
  raw opcode-pattern hits targeting `0x1997`. Treat this path as statically
  isolated unless runtime mutation/overlay evidence proves activation.
- Indirect-source feasibility sweep (`WS57`) adds one more bound:
  no resolved indirect transfer source provides offset `0x1997`; residual
  possibility is limited to runtime-loaded/unresolved dynamic vectors.
- Dynamic-vector prioritization (`WS58`) orders remaining closure:
  top priority is external-loaded far pointer slot `0x0c42`, followed by
  stride-`0x11` dynamic lanes (`0x0dcf/0x0dd3/0x0dd7/0x0ddb`); resolved runtime
  tables (`0x0e32`, `0x0d02`) are excluded for current `0x1997` concern.
- Load-chain audit (`WS59`) further narrows `0x0c42` uncertainty:
  bounded static producer is a single DOS open/read/close chain (`4` bytes
  into `0x0c42`), with four `lcall [0x0c42]` consumers and no direct `mov`
  writes to `0x0c42/0x0c44` observed.
- Stride-`0x11` consolidation (`WS60`) narrows dynamic lane uncertainty:
  `0x07fa/0x0879/0x08e1` have explicit `idx<3` bounds and exclude `0x1997` in
  raw/post-init models.
- k-bound trace (`WS61`) refines this boundary:
  `0x08f4` has one direct caller (`0x0e70`) with pre-dispatch bound on
  `req[+1]` only (`<=0x0d`), and no in-function clamp on `req[+2]` is observed
  before `0x0916` dispatch.
- Precondition closure (`WS62`) resolves prior `k>=8` concern on observed direct
  call path: caller-side gates enforce `req[+2] < 8` before second-stage
  dispatch that reaches `0x0e70 -> 0x08f4`.
- Second-dispatch materialization (`WS63`) adds remaining boundary:
  for `0x0e58 -> cs:[bx+0x07df]`, no static write/reloc materialization is
  observed; guard-derived domain is `req[+1] in {9..13}`, where only targets
  `0x1047` and `0x00b4` are in-image.

#### 5.1.5 Case-9 Practical Subset and Semantics
- req[+1] provenance partition (`WS64`) clarifies interpretation scope:
  in handler window `0x0d31..0x0ef6`, `req[+1]` is read-only (no local writes),
  so second-dispatch behavior should model `req[+1]` as external contract input.
- writer non-dominance check (`WS65`) strengthens this: observed `req[+1]`
  writers are outside handler window and no direct `call/jmp` to `0x0d31` is
  found, so local writer helpers are not proven to dominate handler input.
- domain plausibility refinement (`WS66`) narrows practical subset further:
  within guard domain `req[+1]=9..13`, only `req[+1]=9` maps to a plausible
  in-image jump-entry target (`0x1047`); `10` maps to mid-instruction entry and
  `11..13` are off-image in current sample.
- case-9 semantic lift (`WS67`) strengthens this practical narrowing:
  target `0x1047` shows coherent structured output construction (`0x45/0x48`
  tagged layouts driven by `req[0x17]`, fields sourced from `req[0x10..0x15]`).
- case-9 status/output flow (`WS68`) further anchors behavior:
  outer handler sets success status (`req+3=0`) before dispatch, and `0x1047`
  itself writes payload fields without status overwrite.
- case-9 input provenance (`WS69`) indicates `req[0x10..0x17]` are consumed as
  pre-assembled contract bytes (read-mostly in bounded static pass, with no
  req-like local writes under immediate `les bx,[bp+6]` pattern).
- provisional subtype profile (`WS70`) consolidates this slice:
  `req[+1]=9` is now the stable practical case anchor in current corpus, with
  remaining unknowns focused on external field producer path and semantic label.
- FUSE integration policy (`WS73`) adds fail-closed/error mapping discipline:
  `req1 != 9` is unknown-path (`EIO` default, optional `ENOTSUP` feature mode),
  while undersized header (`len < 2`) and truncated case-9 bodies are always
  hard-failed as `EIO` with structured one-line logs for audit.
Promotion criteria:
- `WS77-B` is required for control-payload semantic closure.
- `WS77-A` may strengthen transport-lane repeatability only (no semantic promotion by itself).

### 5.2 Win95 VxD LE-level findings
- All three VxDs are LE modules with common structural profile (2 objects, module flags `0x00038000`)
- Each exposes a single `type=3` entry bundle at `ord1`
- x86 LE interpretation indicates `type=3 obj=1`, with entry bytes `03 xx xx`
- `ord1` `offset16` maps to DDB candidate offsets where `+0x0c` matches module name (`MDFSD`, `MDMGR`, `MDHlp`)
- DDB candidate cross-file stable layout pattern observed:
  - `+0x00=0x00000000`, `+0x04=0x00000400`, `+0x0c=<8-byte module name>`
  - `+0x14` differs by module role (`0x80000000` vs `0xA0010100`)
- Type-3 middle 16-bit value (`offset16`) is validated as DDB offset for all 3 target VxDs.
- Type-3 flags byte is consistently `0x03` in all observed US/JP modules and is coupled
  to DDB-style ordinal-1 exports in this corpus.
- For reference: standard LE entry bundle flag byte defines bit 0 as `exported`
  and bit 1 as `uses shared data segment`. If applicable, `0x03` = both bits set.
  This decomposition is NOT confirmed for the observed MDFS VxD corpus and remains
  `UNKNOWN` pending `WS77-D`.
- Page-map and fixup-page tables parse consistently (`num_pages+1` fixup entries)
Promotion criteria:
- `WS77-D` is required before any definitive bit-level semantics are promoted for `type=3` flags `0x03`.

### 5.3 No-Media Runtime Reinforcement (WS25 Batch)
- A no-media runtime matrix (`mdcache is/on/off/flush`, `mdfsck d:`, `mdformat d: -q -o`) was executed under QEMU with two runs per scenario.
- Per-scenario run intersections are stable (`11~14` signature rows each).
- Common cross-scenario signature set contains `10` stable lane signatures (`AX/BX/CX/DX/DS:DX` form), all in `AX=0x4400` domain for this environment.
- This strengthens transport-lane repeatability only; it does NOT close payload semantics and does NOT upgrade media-dependent claims.
Promotion criteria:
- This subsection maps to `WS77-A` only and MUST remain non-normative for payload semantics.

## 6. Installation and Extraction Guarantees
- Win3.1 `.RED` payload extraction validated against installer metadata (`verify_w31_install.py` pass)
- Win95 extraction reconstructed from `SETUP.PKG` + installer locale indirection
  (`w95/merged/SETUP.INS` -> `US\\SETUP.INS` / `JP\\SETUP.INS`)
- US/JP VxD binaries are byte-identical for the three core drivers

## 7. Reproducibility Baseline (Primary Binaries)
- `w31/extract/mdfsex.exe` SHA-1 `a3039ca82aae67ff0dc731d0c0df736870e14bd9`
- `w31/extract/mdfsck.exe` SHA-1 `75db20f6700c4acf5e24349c592e4790c98bef59`
- `w31/extract/mdformat.exe` SHA-1 `a630bfd9c87bf9721d5c29a182b21c809f67c060`
- `w31/extract/mdcache.exe` SHA-1 `6f0f84524d86da3b1b7e8b4570f3fcdc5a126628`
- `w31/extract/mdmgr.exe` SHA-1 `8bf42657727a819adaf38a6f94a4b428b942f8cd`
- `w95/extract/us/mdfsd.vxd` SHA-1 `ebd4c5f887f1081461d9720a95afb25074f9fdda`
- `w95/extract/us/mdmgr.vxd` SHA-1 `1ace191b10bb9c6ebed8e048b7e6d7fff5aea00d`
- `w95/extract/us/mdhlp.vxd` SHA-1 `5a8e0363c93110c4f9cb0bbb13236d7d243fd24b`
- Full extracted-binary manifest: `document/MDFS_BINARY_MANIFEST.csv`

## 8. Known Gaps (Blocking Final Normative Layout)
- ~~Byte-accurate VD record layout~~
  - Current status: `CONFIRMED` (WS78/WS79, `WS77-C` gate passed for VD)
  - 25 fields + 4 reserved gaps mapped at 0x00–0x59 with 9/9 cross-validations
- ~~Byte-accurate VSB bitmap encoding~~
  - Current status: `CONFIRMED` (WS80, `WS77-C` gate passed for VSB bitmap)
  - 2-bit/AU MSB-first encoding, 4 states (FREE/USED/DEFECTIVE/RESERVED), 5/5 VD counter cross-validation
- ~~Byte-accurate MTB structure~~
  - Current status: `CONFIRMED` (WS81, `WS77-C` gate passed for MTB)
  - TLV format (tag 1B + BE24 3B), per-VSB-sector FREE AU count table, 5/5 cross-validation
  - Trailer field (4 bytes after END marker) remains `UNKNOWN`
- ~~Byte-accurate DRB record structure~~
  - Current status: largely `CONFIRMED` (WS82+WS85, 12/12 cross-validations)
  - Common header (36B): RecType, RecLen, Attributes, CSC(CONFIRMED), NLen(INFERRED), FileName, timestamps, EntryID, DataSize
  - Directory extension (6B): DLoc(BE16)+CNum(BE16) — CONFIRMED via byte-swap function two-path analysis
  - File extension (22B): FLoc/FNum/ALen/ALoc/ANum (5×BE32) — CONFIRMED via byte-swap + format strings + data verification
  - Extent chain: AFXTREC/AAEXTREC mechanism CONFIRMED via mdfsck code analysis; AEXT32 entry size toggle CONFIRMED
  - Remaining `UNKNOWN`: dir +0x28 (2 bytes), file +0x38 (2 bytes), NLen≠1 name format semantics
  - Remaining `INFERRED`: NLen field meaning (code-confirmed name but full semantics unclear)
  - These unknowns are non-blocking for FUSE read-only mount of defect-free single-extent discs
- Byte-accurate ERB internal structure
  - Current status: `UNKNOWN` (WS83: not present on test media, ERBLoc=0, ERBNum=0, NumDefective=0)
  - Role: defective AU tracking table (`INFERRED` from VD fields and VSB DEFECTIVE state)
  - FUSE workaround: VSB DEFECTIVE state (10) → EIO, no ERB parsing needed for defect-free discs
  - Closure requirement: disc with defective AU sectors
- Full control payload schema behind MD manager/control path
  - Current status: `UNKNOWN` (opcode IDs are strongly supported, payload semantics unresolved)
  - Closure requirement: MD DATA media-backed runtime request/response captures with contrasting scenarios
- Definitive semantics of LE entry `type=3` flags byte (`0x03`)
  - Current status: `UNKNOWN` (DDB-coupled/invariant only)
  - Closure requirement: independent semantic proof path (additional driver corpus and/or runtime behavior binding)
- Win95 mount handshake between `MDMGR.VXD` and `MDFSD.VXD`
  - Current status: `UNKNOWN` (CODEX P1; present in RFC Section 7 but previously missing here)
  - Closure requirement: runtime dynamic trace of VxD inter-module initialization/registration sequence

Normative restriction:
- Remaining open items MUST NOT be filled with estimated offsets/semantics in spec text.
- Estimated or model-derived candidates MUST remain explicitly tagged for later test-stage promotion.
- Promotion workflow reference: `analysis/ws77_spec_promotion_checklist.md`
- Gap-to-checklist map:
  - ~~VD layout offsets~~ -> `WS77-C` ✅ (closed by WS78/WS79)
  - ~~VSB bitmap encoding~~ -> `WS77-C` ✅ (closed by WS80)
  - ~~MTB structure~~ -> `WS77-C` ✅ (closed by WS81)
  - ~~DRB record structure~~ -> `WS77-C` ✅ (layout + extension + chain closed by WS82+WS85; minor unknowns non-blocking)
  - ERB internal layout -> `WS77-C` (remaining)
  - Control payload semantics -> `WS77-B`
  - LE type-3 flags semantics -> `WS77-D`
  - Mount handshake -> runtime VxD trace (no assigned WS77 sub-gate yet)

Promotion summary table:

| Area | Current status | Evidence | Promotion gate |
|---|---|---|---|
| On-media VD layout | `CONFIRMED` | WS78/WS79 live media + WS19/WS36/WS37 static analysis | `WS77-C` ✅ (VD) |
| On-media VSB bitmap encoding | `CONFIRMED` | WS80 live media 2-bit/AU + VD 5/5 counter cross-validation | `WS77-C` ✅ (VSB) |
| On-media MTB structure | `CONFIRMED` | WS81 TLV per-VSB FREE count + VSB/VD 5/5 cross-validation | `WS77-C` ✅ (MTB) |
| On-media DRB record layout | `CONFIRMED` | WS82+WS85: common header, dir/file extension, byte-swap paths, 12/12 cross-validations | `WS77-C` ✅ (layout confirmed; minor unknowns non-blocking) |
| On-media DRB extent chain | `CONFIRMED` | WS85: AFXTREC/AAEXTREC code paths, AEXT32 entry size, ERB linked list hint | `WS77-C` ✅ (mechanism confirmed; untested on fragmented disc) |
| On-media ERB layout | `UNKNOWN` | WS83: not present on test media; role INFERRED as defective AU table | `WS77-C` (remaining; needs defective disc) |
| Control payload semantics (MD manager path) | `UNKNOWN` | transport-lane repeatability (`WS25` no-media matrix) | `WS77-B` |
| LE `type=3` flags `0x03` semantics | `UNKNOWN` | corpus invariance only | `WS77-D` |
| Win95 mount handshake (`MDMGR↔MDFSD`) | `UNKNOWN` | none | runtime VxD trace |

Operational flow:
- Media phase active: VD/VSB/MTB/DRB all resolved via live media + static analysis (WS78-WS85).
- `WS77-C` gate passed for VD, VSB, MTB, DRB. ERB remaining (needs defective disc).
- Next: FUSE implementation (read-only mount of defect-free discs). Remaining `WS77-B/D` gates are non-blocking for basic mount.

## 9. Evidence Index
- Specs: `document/MDFS_SPEC.md`, `document/MDFS_SPEC_RFC.md`
- Audit: `document/MDFS_EVIDENCE_GAP_AUDIT.md`
- WS1: `analysis/ws1_dos_symbols.md`, `analysis/ws1_record_offsets.csv`
- WS1+: `analysis/mdfsck_flag_tables.md`, `analysis/mdfsck_field_xref.md`
- WS2: `analysis/ws2_vxd_dispatch.md`, `analysis/ws2_call_graph.md`
- x86 disasm summary: `analysis/x86_dos_win95_disasm_findings.md`
- LE artifacts:
  - `analysis/ws2_le_headers.*`
  - `analysis/ws2_le_exports.*`
  - `analysis/ws2_le_entry_x86.*`
  - `analysis/ws2_le_entry_hypotheses.*`
  - `analysis/ws2_vxd_ddb_candidates.*`
  - `analysis/vxd_ddb_struct_scan.*`
  - `analysis/ws2_le_pagemap.*`
  - `analysis/ws2_le_fixup_summary.*`
- WS3 state: `analysis/ws3_trace_matrix.md`, `analysis/ws3_layout_verified.md`
- WS4 state: `analysis/ws4_unknown_reduction.md`
- WS5 state: `analysis/ws5_mdctl_refinement.md`
- WS6 state: `analysis/ws6_mdctl_dataflow.md`, `analysis/mdcache_cmd_blob.md`
- WS7 state: `analysis/mdcache_descriptor_decode.md`
- WS8 state: `analysis/ws8_imm16_usage.md`
- WS9 state: `analysis/ws9_mdctl_dual_table.md`
- WS10 state: `analysis/ws10_le_type3_middleword.md`
- WS12 state: `analysis/ws12_capstone_imm_hits.md`
- WS13 state: `analysis/ws13_ioctl_wrapper_audit.md`
- WS14 state: `analysis/ws14_mdfsck_frame_builders.md`
- WS15 state: `analysis/ws15_mdfsck_payload_shape_matrix.md`
- WS16 state: `analysis/ws16_mdfsck_3cca_semantics.md`
- WS17 state: `analysis/ws17_mdfsck_direct_reachability.md`
- WS18 state: `analysis/ws18_mdfsck_3cca_param_map.md`
- WS19 state: `analysis/ws19_mdfsck_vd_emit_map.md`
- WS20 state: `analysis/ws20_mdfsck_cluster_xrefs.md`
- WS30 state: `analysis/ws30_mdfsck_indirect_flow.md`
- WS27 state: `analysis/ws27_le_type3_flags_survey.md`
- WS28 state: `analysis/ws28_le_type3_flags_hypothesis.md`
- WS24 state: `analysis/ws24_mdctl_callsite_lift.md`
- WS25 state: `analysis/ws25_mdctl_runtime_capture.md`
- WS25 no-media runs: `analysis/ws25_runtime_capture_run1.md`, `analysis/ws25_runtime_capture_run2.md`
- WS25 no-media matrix: `analysis/ws25_nomedia_matrix_report.md`, `analysis/ws25_nomedia/summary.csv`, `analysis/ws25_nomedia/common_all_scenarios.csv`
- WS21 state: `analysis/ws21_layout_candidate_map.md`
- WS22 state: `analysis/ws22_media_diff_matrix.md`
- WS23 state: `analysis/ws23_layout_confirmed_table.csv`
- WS26 state: `analysis/ws26_mdctl_schema_matrix.csv`
- WS33 state: `analysis/ws33_mdctl_opcode_crosswalk.md`
- WS34 state: `analysis/ws34_mdcache_blob_cluster.md`
- WS35 state: `analysis/ws35_mdcache_reloc_sanity.md`
- WS36 state: `analysis/ws36_mdfsck_global_lane_xrefs.md`
- WS37 state: `analysis/ws37_mdfsck_endian_normalization.md`
- WS38 state: `analysis/ws38_mdfsck_runtime_vector_slots.md`
- WS39 state: `analysis/ws39_mdfsck_vector_role_classification.md`
- WS40 state: `analysis/ws40_mdfsck_callback_walker.md`
- WS42 state: `analysis/ws42_mdfsck_runtime_slot_contract.md`
- WS41 state: `analysis/ws41_mdfsck_slot196c_provenance.md`
- WS43 state: `analysis/ws43_mdfsck_slot_write_proof.md`
- WS44 state: `analysis/ws44_cross_binary_callback_abi.md`
- WS45 state: `analysis/ws45_mdmgr_vector_slot_classes.md`
- WS46 state: `analysis/ws46_mdmgr_vector_population.md`
- WS47 state: `analysis/ws47_mdmgr_c42_pointer_semantics.md`
- WS48 state: `analysis/ws48_mdmgr_e32_dispatch_table.md`
- WS49 state: `analysis/ws49_mdmgr_e32_reloc_crosscheck.md`
- WS50 state: `analysis/ws50_mdmgr_e32_nonliteral_write_scan.md`
- WS51 state: `analysis/ws51_mdmgr_table_separation.md`
- WS52 state: `analysis/ws52_mdmgr_e32_farptr_classification.md`
- WS53 state: `analysis/ws53_mdmgr_farptr_loadseg_feasibility.md`
- WS54 state: `analysis/ws54_mdmgr_startup_dispatch_init.md`
- WS55 state: `analysis/ws55_mdmgr_e32_state_timeline.md`
- WS56 state: `analysis/ws56_mdmgr_1997_reachability.md`
- WS57 state: `analysis/ws57_mdmgr_indirect_1997_feasibility.md`
- WS58 state: `analysis/ws58_mdmgr_dynamic_vector_prioritization.md`
- WS59 state: `analysis/ws59_mdmgr_c42_load_chain_audit.md`
- WS60 state: `analysis/ws60_mdmgr_stride11_index_bounds.md`
- WS61 state: `analysis/ws61_mdmgr_0916_k_bound_trace.md`
- WS62 state: `analysis/ws62_mdmgr_8f4_precondition_closure.md`
- WS63 state: `analysis/ws63_mdmgr_second_dispatch_materialization.md`
- WS64 state: `analysis/ws64_mdmgr_req1_provenance_partition.md`
- WS65 state: `analysis/ws65_mdmgr_req1_writer_nondominance.md`
- WS66 state: `analysis/ws66_mdmgr_req1_domain_plausibility.md`
- WS67 state: `analysis/ws67_mdmgr_case9_1047_semantics.md`
- WS68 state: `analysis/ws68_mdmgr_case9_status_output_flow.md`
- WS69 state: `analysis/ws69_mdmgr_case9_input_field_provenance.md`
- WS70 state: `analysis/ws70_mdmgr_case9_subtype_profile.md`
- WS73 state: `analysis/ws73_fuse_unknown_path_policy.md`
- WS78 state: `analysis/ws78_live_media_vd_layout.md` (live MD DATA media VD/DRB on-disk layout)
- WS79 state: `analysis/ws79_vd_field_boundary_map.md` (VD 0x28–0x5A field boundary map, `WS77-C` gate closure for VD)
- WS80 state: `analysis/ws80_vsb_bitmap_encoding.md` (VSB 2-bit/AU bitmap encoding, `WS77-C` gate closure for VSB)
- WS81 state: `analysis/ws81_mtb_structure.md` (MTB TLV per-VSB-sector FREE AU count table, `WS77-C` gate closure for MTB)
- WS82 state: `analysis/ws82_drb_structure.md` (DRB variable-length record structure, attribute flags, extent data, 8/8 cross-validation)
- WS83 state: `analysis/ws83_erb_structure.md` (ERB: no data on test media, role INFERRED as defective AU table, FUSE workaround via VSB state)
- WS84 state: `analysis/ws84_vma_structure_summary.md` (VMA 영역 종합 구조: 5블록 배치, AU 레이아웃, 11/11 교차 검증 ALL PASS)
- WS85 state: `analysis/ws85_drb_static_analysis.md` (DRB 미확인 필드 mdfsck 정적 분석: CSC/NLen 확정, dir/file extension 분리, FLoc/FNum/ALen/ALoc/ANum, AFXTREC/AAEXTREC 메커니즘, 12/12 교차 검증)
