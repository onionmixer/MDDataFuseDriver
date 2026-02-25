# MDFS Source Coverage Assessment

Date: 2026-02-16

## Scope Reviewed
- `w31/extract/*` (DOS/Win3.1 utilities)
- `w95/extract/us/*`, `w95/extract/jp/*` (Win95 drivers/tools)
- `document/*` (existing spec/notes/PDF text)
- `resource/linux-minidisc/*`

## Result
- A practical MDFS SPEC can be produced from this workspace.
- It is currently architecture-complete but not byte-complete.

## Evidence Density by Source
- `w31/extract/*`: HIGH for command semantics and logical metadata vocabulary.
- `w95/extract/*`: MEDIUM-HIGH for driver stack composition and dispatch surface.
- `document/*`: HIGH for consolidated interpretation and planning.
- `resource/linux-minidisc/*`: LOW for legacy MDFS specifics.

## Important Finding: `resource/linux-minidisc`
- This repository primarily targets Hi-MD (`HMDHIFI`, `.HMA`, `ATDATA`, `TRKIDX`, `MCLIST`) workflows.
- Direct `MDFS`/`VD`/`VSB`/`MTB`/`ERB`/`DRB` symbols were not found in reviewed sources.
- Therefore it is useful as broader MiniDisc context/tooling, but not a primary source for legacy MDFS on-media layout.

## Binary Driver Analysis Status
- DOS executables: string-surface + installer/archive correlation complete for WS1 level.
- Win95 VxD modules: stack composition and registration/IOR evidence extracted for WS2 level.
- Remaining gap: disassembler-level function recovery and live-media trace correlation.

## Bottom Line
- Yes, SPEC authoring is feasible now.
- A final normative byte layout requires at least one real-media trace/image set to resolve remaining unknown offsets and control payload schemas.
