# WS73 FUSE Unknown-Path Error Policy

Date: 2026-02-17

## Summary
- `mdfs-fuse` now defines explicit unknown-path handling with two modes:
  fail-closed (`EIO`) and feature-gated unsupported (`ENOTSUP`).
- Safety guards are strict: undersized request frames and case-9 parse truncation
  are always rejected as `EIO` regardless of runtime mode.
- Logging format is stabilized as single-line key/value records:
  `level=WARN event=unknown_path req1=... req_len=... policy=... errno=... reason=...`.

## Policy Matrix
- `frame_len < 2` -> route `header guard`, errno `EIO`, policy `fail_closed_eio (forced)`, reason `frame_too_short_for_req1` (implemented)
- `req1 != 9` -> route `unknown-path classifier`, errno `EIO or ENOTSUP`, policy `configurable (FailClosedEio / FeatureEnotsup)`, reason `req1_not_in_supported_subset` (implemented)
- `req1 == 9 but frame truncated` -> route `case9 parser`, errno `EIO`, policy `fail_closed_eio (forced)`, reason `case9_too_short` (implemented)
- `req1 == 9 and parse ok` -> route `case9 parser`, errno `none`, policy `n/a`, reason `parsed_case9` (implemented)

## Implementation Anchor
- `mdfs-fuse-rs/crates/mdfs-fuse/src/lib.rs`
- Key symbols: `UnknownPathPolicy`, `FuseErrno`, `UnknownPathEvent`, `route_request()`.
