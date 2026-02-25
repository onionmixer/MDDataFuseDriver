# WS65 mdmgr req[+1] Writer Non-dominance Check

Date: 2026-02-17

## Findings
- req[+1] writer sites: 6
- direct `call/jmp 0x0d31` sites in image: 0
- No direct `call/jmp` to `0x0d31` is observed (handler entry likely via table/indirect flow).
- req[+1] writes are in helper/builder functions outside handler window and are not proven as immediate dominators of `0x0d31` input.
- This strengthens external-contract interpretation for `req[+1]` at handler entry.
