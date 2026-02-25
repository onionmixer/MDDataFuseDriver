#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
BASE = 0x0E32
ENTRIES = 3  # observed usage: index byte << 2 then [bx+0xe32]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    h = u16(raw, 0x08) * 16
    img = raw[h:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    for s, e in [(0x19a0, 0x1d40), (0x1200, 0x1410), (0x0bc0, 0x0d40)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    rows = []
    for idx in range(ENTRIES):
        low = BASE + idx * 4
        high = low + 2

        writes = []
        reads = []
        for i, x in enumerate(ins):
            t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')

            # literal reads/writes
            if f'0x{low:x}' in t or f'0x{high:x}' in t:
                if x.mnemonic == 'mov' and x.op_str.lower().replace(' ', '').startswith(f'wordptr[0x{low:x}],'):
                    writes.append((x.address, x.mnemonic, x.op_str, 'write_low'))
                elif x.mnemonic == 'mov' and x.op_str.lower().replace(' ', '').startswith(f'wordptr[0x{high:x}],'):
                    writes.append((x.address, x.mnemonic, x.op_str, 'write_high'))
                else:
                    reads.append((x.address, x.mnemonic, x.op_str, 'read_literal'))

        init_low = u16(img, low)
        init_high = u16(img, high)

        rows.append(
            {
                'entry': idx,
                'low': f'0x{low:04x}',
                'high': f'0x{high:04x}',
                'init_low': f'0x{init_low:04x}',
                'init_high': f'0x{init_high:04x}',
                'write_count': len(writes),
                'read_count': len(reads),
                'writes': ' || '.join(f"0x{a:04x}:{m} {o}" for a, m, o, _ in writes),
            }
        )

    # capture indexed dispatch site
    dispatch_ctx = []
    for i, x in enumerate(ins):
        t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        if x.address == 0x1CE2 or x.address == 0x1CE6 or x.address == 0x1CFF:
            dispatch_ctx.append(f"0x{x.address:04x}:{x.mnemonic} {x.op_str}")

    md_lines = [
        '# WS48 mdmgr 0x0e32 Dispatch Table Semantics',
        '',
        'Date: 2026-02-17',
        '',
        '## Entry Summary',
        '| entry | low | high | init_low | init_high | writes | reads |',
        '| --- | --- | --- | --- | --- | --- | --- |',
    ]

    for r in rows:
        md_lines.append(
            f"| {r['entry']} | {r['low']} | {r['high']} | {r['init_low']} | {r['init_high']} | {r['write_count']} | {r['read_count']} |"
        )

    md_lines.extend([
        '',
        '## Indexed Dispatch Evidence',
        '- `0x1cdd: shl ax, 2` (index stride 4 bytes per entry)',
        '- `0x1ce2: mov ax, word ptr [bx + 0xe32]`',
        '- `0x1ce6: or ax, word ptr [bx + 0xe34]` (null guard)',
        '- `0x1cff: lcall [bx + 0xe32]`',
    ])

    if dispatch_ctx:
        md_lines.extend(['', '## Dispatch Context Hits'])
        for d in dispatch_ctx:
            md_lines.append(f'- `{d}`')

    md_lines.extend([
        '',
        '## Notable Write',
        '- Entry #1 (`0x0e36/0x0e38`) is explicitly initialized in code: `0x19db`/`0x19d5`.',
        '- Entry #0 (`0x0e32/0x0e34`) and entry #2 (`0x0e3a/0x0e3c`) have no literal in-image writes in this pass.',
        '',
        '## Conclusion',
        '- `0x0e32` is a base of 3-entry far-pointer dispatch table, not a single callback slot.',
        '- Provider confidence improves for entry #1 (code-initialized), while entry #0/#2 still require runtime/relocation-aware closure.',
    ])

    Path('analysis/ws48_mdmgr_e32_dispatch_table.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws48_mdmgr_e32_dispatch_table.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['entry', 'low', 'high', 'init_low', 'init_high', 'write_count', 'read_count', 'writes'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws48_mdmgr_e32_dispatch_table.md and .csv')


if __name__ == '__main__':
    main()
