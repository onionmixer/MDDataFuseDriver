# WS27 LE Type-3 Flags Survey

Date: 2026-02-17

## Scope
- Parsed LE modules under `w95/extract/*/*`.
- Entry-table decode mode: x86 LE type-3 bundle (`count,type,obj` + entry `[flags,u16]`).

## LE files discovered
- Total LE files: `6`
- Unique binaries by `(sha1,size)`: `3`

## Flags distribution (type-3 entries)
- `0x03`: `6` entries

## Name correlation
- `MDHlp_DDB`: `2` entries
- `_The_DDB`: `4` entries

## Observations
- All observed type-3 entries use `flags=0x03` in this corpus.
- Type-3 ordinal is consistently associated with DDB-style name (`_The_DDB` / `MDHlp_DDB`).
- US/JP duplicates do not add new flag variants (same binaries by hash).
