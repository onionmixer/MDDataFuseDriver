# Case-9 Profile (Scaffold)

Source alignment: WS62..WS70 in `analysis/`.

Rules:
- Accept `req[1] == 9` as supported practical path.
- Branch by `req[0x17]`:
  - `0`: tag `0x45`, mapped copy from `req[0x10..0x15]`
  - non-zero: tag `0x48`, reduced layout with `out7 = req[0x10] + req[0x14]`
- Treat status ownership as outer-handler responsibility.
- Treat `req[0x10..0x17]` as pre-assembled contract lanes.
- Unknown-path policy (WS73):
  - `req1 != 9`: configurable `EIO`(fail-closed) / `ENOTSUP`(feature mode)
  - `len < 2` or truncated case-9 body: always `EIO`
  - log line format:
    `level=WARN event=unknown_path req1=... req_len=... policy=... errno=... reason=...`
