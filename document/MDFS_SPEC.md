# MDFS (MD DATA File System) - Working Specification

## 1. Document Status
- Type: reverse-engineered working spec
- Scope: Sony MD DATA software bundle for DOS/Windows 3.1/Windows 95
- Confidence: medium (high for user-visible behavior, medium/low for binary-internal details)

This document is based on extracted installer payloads and binary/string analysis from:
- `w31/extract/*`
- `w95/extract/us/*`, `w95/extract/jp/*`
- `document/dadc_minidisc_handbook.txt`
- `resource/linux-minidisc/*` (reference only; mostly Hi-MD/NetMD, not MDFS implementation)

## 2. Product / Component Overview

### 2.1 DOS/Win3.1 side (`w31/extract`)
- `mdfsex.exe`: installable file system component (MDFS)
- `mdmgr.exe`: MD DATA device manager (TSR behavior indicated in docs)
- `mdformat.exe`: media format utility
- `mdfsck.exe`: file system consistency checker
- `mdcache.exe`: write-cache control utility
- `mdplay.exe`: MiniDisc audio playback utility
- `dcam950.exe`, `aspi2cam.sys`: SCSI/CAM adapter drivers
- `wmdfmt.exe`, `wmdplay.exe`, `mdtool.dll`, `bwcc.dll`: Windows-side utilities/UI

Source evidence:
- `w31/extract/read.me` (tool descriptions, syntax, versions, install behavior)

### 2.2 Win95 side (`w95/extract/*`)
- `MDFSD.VXD`: file system driver
- `MDMGR.VXD`: manager/mount integration driver
- `MDHLP.VXD`: helper/patch driver for OSR2 stack
- `MDH10.INF`, `MDM110.INF`, `MDM111.INF`: PnP install definitions

Observed INF behavior:
- `[MDFSInstall] CopyFiles=@MDHLP.VXD,@MDMGR.VXD,@MDFSD.VXD`
- Device IDs:
  - `SCSI\\SONY____MDH-10__________1`
  - `SCSI\\SONY____MDM110__________1`
  - `SCSI\\SONY____MDM111__________1`

## 3. Functional CLI/API Spec (DOS tools)

Derived from `w31/extract/read.me` and binary strings:

### 3.1 `mdfsex`
- Purpose: install/register MD DATA file system
- Syntax: `mdfsex [/L:drive][/?]`
- Key option:
  - `/L:<drive>` first drive letter for MDFS assignment
- Reported version: `1.11`

### 3.2 `mdmgr`
- Purpose: MD DATA device manager
- Syntax: `mdmgr`
- Reported version: `1.2`

### 3.3 `mdformat`
- Purpose: format MD DATA media
- Syntax: `mdformat drive: [-q|-s] [-v:label -o -?]`
- Modes:
  - `-q`: quick format (install FS, no certification)
  - `-s`: safety/certification format
  - `-o`: non-interactive
  - `-v:label`: assign volume label
- Reported version: `1.95`

### 3.4 `mdfsck`
- Purpose: MDFS consistency check
- Syntax: `mdfsck drive: [-v -?]`
- Reported output includes:
  - `OK: MDFS in conformance`
  - `BAD: Total Errors: <n>`
  - volume and metadata diagnostics (see Section 4)
- Reported version: `1.4`

### 3.5 `mdcache`
- Purpose: write cache control
- Syntax: `mdcache [-?] [drive:] ON | OFF | IS | FLUSH`
- Behavior:
  - `ON/OFF`: toggle write cache
  - `IS`: query cache state
  - `FLUSH`: flush cache to media
- Reported version: `1.0`

### 3.6 `mdplay`
- Purpose: MiniDisc audio playback control
- Syntax: `mdplay [-?] [drive:] play [song-number] | pause | stop`
- Reported version: `1.1`

## 4. Inferred On-Disk MDFS Metadata Model

This section is inferred mainly from `mdfsck.exe` strings. It is not yet a fully validated byte-accurate on-disk structure definition.

### 4.1 Volume Descriptor (VD) fields observed
- Identifier
- Version
- BlockSize
- ClusterSize
- AllocSize
- NumAlloc
- NumRecordable
- NumAvailable / NumUsed / NumDefective
- NumDir / NumFile
- MaxIdNum
- VolAttr
- VMALen / VMALoc
- VSBLoc / VSBNum
- MTBLoc / MTBNum
- ERBLoc / ERBNum
- DRBLoc / DRBNum
- DirLen / NumChild
- BootID / VolID / PubID / PrepID / ApplID
- CrTime / MoTime / EfTime / ExTime

### 4.2 Core logical records referenced
- `VSB`: Volume Space Bitmap
- `MTB`: Management Table Block
- `ERB`: Extent Record Block
- `DRB`: Directory Record Block
- `VMA`: management area length/location

### 4.3 Attribute flags observed (names from checker binary)
- `mdfsck.exe` contains relocation-backed flag/name tables:
  - Volume-style:
    - `AMIRROR=0x0001`, `AINVISIBLE=0x0002`, `APROTECT=0x0040`, `ABACKUP=0x0080`
    - `AINHFORMAT=0x0100`, `AINHRENAME=0x0200`, `AINHCOPY=0x0400`, `AEXT32=0x8000`
  - Record-style:
    - `ADIR=0x0001`, `AINVISIBLE=0x0002`, `ASYSTEM=0x0004`, `ADELETED=0x0008`
    - `APROTECT=0x0040`, `ABACKUP=0x0080`, `AINHDELETE=0x0100`, `AINHRENAME=0x0200`
    - `AINHCOPY=0x0400`, `AEXTTYPE=0x2000`, `AFXTREC=0x4000`, `AAEXTREC=0x8000`

### 4.4 Consistency checks implied by checker
- VSB available/used/defective totals
- MTB linkage and entry type sanity
- ER chain integrity
- DR self-id/child counts/length consistency
- aggregate counters cross-validation (VD vs computed)

## 5. Driver-Level Behavior (Binary Inference)

### 5.1 Win95 VxD stack
- `MDFSD.VXD` strings indicate:
  - product/version metadata (`1.E0`)
  - service tokens `MDCTL`, `MD001`
  - product text: `MD DATA File System Driver`
- `MDMGR.VXD` strings indicate:
  - IFSMgr integration symbols including `mountCFSD`, `_INIT_IFSMgr_RegisterCFSD`
  - product text: `MD DATA MDMGR Driver`
- `MDHLP.VXD` strings indicate:
  - I/O dispatch labels (`IOR_READ`, `IOR_WRITE`, `IOR_FORMAT`, `IOR_SCSI_PASS_THROUGH`, etc.)
  - product text includes both:
    - `MDDATA Patch Driver for OSR2`
    - `Sony MDData Device Driver`

### 5.2 DOS device/control interface hints
- Binaries reference control paths/tokens such as:
  - `\\MDCTL`, `MD001`, `MDFS000`, `IOMR000`, `SCSIMGR$`
- Indicates a manager/control-device abstraction used by tools to invoke FS/device operations.

## 6. Installation Model

### 6.1 Win3.1 installer model
- Archive payloads in proprietary `.RED` containers.
- Installed result successfully reconstructed and validated against installer metadata.

### 6.2 Win95 installer model
- InstallShield-based package.
- `SETUP.PKG` contains payload table (filename + disk + size).
- `w95/merged/SETUP.INS` contains locale-specific source->destination mapping sections (US/JP).
- Resulting installed payload reconstructed into:
  - `w95/extract/us`
  - `w95/extract/jp`

## 7. What Is Specified vs Not Yet Specified

### 7.1 Specified with good confidence
- Component architecture and roles
- CLI utility syntax/behavior
- Driver stack composition and install bindings
- Main metadata entities (VD/VSB/MTB/ERB/DRB) and many field names

### 7.2 Not yet fully specified
- Exact byte layouts and offsets for all on-disk records
- Complete IOCTL/control protocol between userland tools and MD manager/driver
- Recovery/format algorithms at implementation level

## 8. Feasibility Assessment for a Full MDFS Spec

Full, implementation-grade MDFS spec is feasible, but requires additional reverse engineering work:
- Static disassembly/decompilation of:
  - `mdfsex.exe`, `mdfsck.exe`, `mdformat.exe`
  - `MDFSD.VXD`, `MDMGR.VXD`, `MDHLP.VXD`
- Dynamic validation with real media images (or hardware-backed traces)
- Correlating checker field names with actual binary record offsets

Estimated confidence if extended work is completed:
- High for read-only mount/inspection spec
- Medium-high for full write/format behavior

## 9. Reference Files
- `w31/extract/read.me`
- `w31/extract/mdfsex.exe`
- `w31/extract/mdfsck.exe`
- `w31/extract/mdformat.exe`
- `w31/extract/mdcache.exe`
- `w31/extract/mdmgr.exe`
- `w95/extract/us/mdh10.inf`
- `w95/extract/us/mdm110.inf`
- `w95/extract/us/mdm111.inf`
- `w95/extract/us/mdfsd.vxd`
- `w95/extract/us/mdmgr.vxd`
- `w95/extract/us/mdhlp.vxd`
- `analysis/ws2_le_headers.md`
- `analysis/ws2_le_exports.md`
- `analysis/ws2_vxd_ddb_candidates.md`
- `analysis/ws2_le_pagemap.md`
- `analysis/ws2_le_fixup_summary.md`
- `document/dadc_minidisc_handbook.txt`
- `resource/linux-minidisc/*` (Hi-MD/NetMD reference context)

## 10. Binary Baseline
Primary reproducibility fingerprints:
- `w31/extract/mdfsex.exe`: `a3039ca82aae67ff0dc731d0c0df736870e14bd9`
- `w31/extract/mdfsck.exe`: `75db20f6700c4acf5e24349c592e4790c98bef59`
- `w31/extract/mdformat.exe`: `a630bfd9c87bf9721d5c29a182b21c809f67c060`
- `w31/extract/mdcache.exe`: `6f0f84524d86da3b1b7e8b4570f3fcdc5a126628`
- `w31/extract/mdmgr.exe`: `8bf42657727a819adaf38a6f94a4b428b942f8cd`
- `w95/extract/us/mdfsd.vxd`: `ebd4c5f887f1081461d9720a95afb25074f9fdda`
- `w95/extract/us/mdmgr.vxd`: `1ace191b10bb9c6ebed8e048b7e6d7fff5aea00d`
- `w95/extract/us/mdhlp.vxd`: `5a8e0363c93110c4f9cb0bbb13236d7d243fd24b`

## 11. Driver Entry Note
LE entry-bundle reconstruction currently supports:
- `ord1` as DDB-related export candidate in all three VxD modules
- page-map/fixup table extraction for object/file mapping
- x86 LE interpretation: `type=3 obj=1` and entry bytes `03 xx xx` with usable `offset16`

Still unresolved:
- exact semantics of LE type-3 flags byte (`0x03`)
