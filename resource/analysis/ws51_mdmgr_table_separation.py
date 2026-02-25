#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')

# Two candidate table regions
TBL_DISP = (0x0E32, 0x0E3F)   # dispatch far pointers
TBL_DEV = (0x0E7E, 0x0E8F)    # device entry/state+ptr table

DISPATCH_FUNC = (0x1CCC, 0x1D28)
INIT_FUNC = (0x19FE, 0x1A35)


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def in_range(addr: int, lo: int, hi: int) -> bool:
    return lo <= addr <= hi


def touches_window(op_str: str, lo: int, hi: int) -> bool:
    t = op_str.lower().replace(' ', '')
    for x in range(lo, hi + 1):
        if f'0x{x:x}' in t:
            return True
    return False


def main() -> None:
    b = TARGET.read_bytes()
    h = u16(b, 0x08) * 16
    img = b[h:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    for s, e in [(0x19a0, 0x1d40), (0x1200, 0x1500), (0x0b00, 0x1100)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    rows = []
    for x in ins:
        a = x.address
        op = x.op_str
        hit_disp = touches_window(op, *TBL_DISP)
        hit_dev = touches_window(op, *TBL_DEV)
        if not (hit_disp or hit_dev):
            continue
        region = []
        if in_range(a, *DISPATCH_FUNC):
            region.append('dispatch_func')
        if in_range(a, *INIT_FUNC):
            region.append('init_func')
        if not region:
            region.append('other')
        rows.append(
            {
                'addr': f'0x{a:04x}',
                'mnemonic': x.mnemonic,
                'op_str': x.op_str,
                'hit_disp_table': 'yes' if hit_disp else 'no',
                'hit_dev_table': 'yes' if hit_dev else 'no',
                'region': ','.join(region),
            }
        )

    # aggregate
    disp_in_dispatch = sum(1 for r in rows if r['hit_disp_table'] == 'yes' and 'dispatch_func' in r['region'])
    dev_in_dispatch = sum(1 for r in rows if r['hit_dev_table'] == 'yes' and 'dispatch_func' in r['region'])
    dev_in_init = sum(1 for r in rows if r['hit_dev_table'] == 'yes' and 'init_func' in r['region'])
    disp_in_init = sum(1 for r in rows if r['hit_disp_table'] == 'yes' and 'init_func' in r['region'])

    md_lines = [
        '# WS51 mdmgr Table Separation (`0x0e32` vs `0x0e84` family)',
        '',
        'Date: 2026-02-17',
        '',
        f'- dispatch table window: `0x{TBL_DISP[0]:04x}..0x{TBL_DISP[1]:04x}`',
        f'- device table window: `0x{TBL_DEV[0]:04x}..0x{TBL_DEV[1]:04x}`',
        f'- dispatch function window: `0x{DISPATCH_FUNC[0]:04x}..0x{DISPATCH_FUNC[1]:04x}`',
        f'- init function window: `0x{INIT_FUNC[0]:04x}..0x{INIT_FUNC[1]:04x}`',
        '',
        '## Aggregates',
        f'- dispatch-table refs inside dispatch function: `{disp_in_dispatch}`',
        f'- device-table refs inside dispatch function: `{dev_in_dispatch}`',
        f'- device-table refs inside init function: `{dev_in_init}`',
        f'- dispatch-table refs inside init function: `{disp_in_init}`',
        '',
        '## Key observations',
        '- Dispatch function (`0x1ccc..`) uses `[bx+0xe32]/[bx+0xe34]` indexed far-call path.',
        '- Init function (`0x19fe..`) sets device table entries (`0xe7e`, `0xe84`, `0xe86`) and does not write `0x0e32` base entry words.',
        '- This supports that `0xe84/0xe86` table is separate per-device metadata, not provider source for `0xe32` entry #0/#2.',
    ]

    Path('analysis/ws51_mdmgr_table_separation.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    with open('analysis/ws51_mdmgr_table_separation.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['addr', 'mnemonic', 'op_str', 'hit_disp_table', 'hit_dev_table', 'region'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws51_mdmgr_table_separation.md and .csv')


if __name__ == '__main__':
    main()
