# WS2 Call Graph (Evidence-Based Draft)

Date: 2026-02-16
Method: string-anchored static reconstruction from VxD binaries

## High-Level Graph
```text
User utilities / shell
  -> PnP install INF (SCSI SONY MDH-10/MDM110/MDM111 IDs)
     -> CopyFiles(MDHLP.VXD, MDMGR.VXD, MDFSD.VXD)
  -> IFSMgr registration path (Win95)
    -> MDMGR.VXD
       - mountCFSD
       - _INIT_IFSMgr_RegisterCFSD
       - _INIT_IFSMgr_RegisterMount
       - _INIT_IFSMgr_RegisterNet
    -> MDFSD.VXD
       - MD DATA File System Driver core module
    -> MDHLP.VXD
       - IOR_* request dispatch surface
         (READ/WRITE/MEDIA_CHECK/GEN_IOCTL/FORMAT/FSD_EXIT/...)
```

## Edge Evidence
1. `MDMGR.VXD -> IFSMgr`
- Symbols: `_INIT_IFSMgr_RegisterCFSD`, `_INIT_IFSMgr_RegisterMount`, `mountCFSD`.
- Confidence: High.

2. `IFSMgr/CFSD -> MDFSD.VXD`
- Evidence: module identity strings (`MDFSD.VXD`, `MD DATA File System Driver`).
- Confidence: Medium-High (registration symbol is in MDMGR; direct callsite unresolved).

3. `I/O Request path -> MDHLP.VXD`
- Evidence: rich `IOR_*` label set in `MDHLP.VXD` including format and media control operations.
- Confidence: High for participation, medium for exact insertion point.

4. `INF install -> 3-module stack`
- Evidence: all three INF files copy the exact same VxD triplet for Sony SCSI device IDs.
- Confidence: High.

5. `ord1 export -> DDB candidate`
- Evidence: LE entry bundle (`type=3`) raw tail maps to offsets where `+0x0c` contains module names (`MDMGR/MDHlp/MDFSD`).
- Confidence: Medium-High (strong structural match, remaining type-3 field semantics unresolved).

## Open Items for Next Pass
- Recover actual handler entry RVA table from each VxD LE segment.
- Map `IOR_*` labels to concrete routines and cross-calls into `MDFSD`/`MDMGR`.
- Recover exported services/ordinals and init order from LE object tables.

## Practical Conclusion
- A full implementation-grade driver SPEC is feasible from this corpus, but not complete with strings-only analysis.
- Minimum additional requirement: one decompiler/disassembler pass (Ghidra/IDA) over the three VxDs.
