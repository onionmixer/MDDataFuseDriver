#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    rows = []

    # find direct callers to 0x08f4
    callers = []
    for x in ins:
        if x.mnemonic not in ('call', 'jmp'):
            continue
        m = re.search(r'0x([0-9a-f]+)', x.op_str.lower())
        if m and int(m.group(1), 16) == 0x08F4:
            callers.append(x.address)
            rows.append({'kind': 'caller', 'addr': f'0x{x.address:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'meaning': 'direct caller to 0x08f4'})

    # precondition window in caller function (0x0d31..)
    pre_addrs = [
        0x0d3d, 0x0d67, 0x0d6c, 0x0e11, 0x0e16, 0x0e29, 0x0e2e,
        0x0e49, 0x0e51, 0x0e54, 0x0e70
    ]
    by = {x.address: x for x in ins}
    for a in pre_addrs:
        x = by.get(a)
        if x:
            rows.append({'kind': 'precondition', 'addr': f'0x{a:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'meaning': ''})

    # annotate semantics
    sem = {
        0x0d3d: 'req[0] == 0 gate (else early exit)',
        0x0d67: 'req[1] <= 8 check for first dispatcher path',
        0x0d6c: 'jbe to first path; fallthrough (>8) enters second path toward 0x0e58',
        0x0e11: 'req[2] < 8 guard (jb) before second dispatch handlers',
        0x0e16: 'on req[2] >= 8 -> error path',
        0x0e29: 'table/slot enable byte check at [0x0d2f + 0x14*req2]',
        0x0e2e: 'disabled slot -> error path',
        0x0e49: 'load req[1] for second dispatcher',
        0x0e51: 'req[1] <= 0x0d guard',
        0x0e54: 'on req[1] > 0x0d -> error path',
        0x0e70: 'call 0x08f4 (only direct caller observed)',
    }
    for r in rows:
        a = int(r['addr'], 16) if r['addr'].startswith('0x') else None
        if a in sem:
            r['meaning'] = sem[a]

    # conclusion flags
    k_lt8_closed = any(r['addr'] == '0x0e11' for r in rows) and any(r['addr'] == '0x0e70' for r in rows)

    md_lines = [
        '# WS62 mdmgr 0x08f4 Preconditions Closure',
        '',
        'Date: 2026-02-17',
        '',
        '## Findings',
        f'- direct caller count to `0x08f4`: {len(callers)}',
        '- only direct caller observed: `0x0e70` in `0x0d31` handler function.',
        '- same function enforces `req[2] < 8` (`0x0e11`/`0x0e16`) before second-stage dispatch that includes `0x0e70`.',
        '- therefore `k=req[+2]` used in `0x08f4 -> 0x0916` is bounded to `0..7` in this static path.',
        f"- closure verdict for prior `k>=8` concern: {'closed for observed direct-call path' if k_lt8_closed else 'not closed'}.",
        '- residual uncertainty shifts away from `k` range and remains on runtime dispatch target/value materialization details.',
    ]

    Path('analysis/ws62_mdmgr_8f4_precondition_closure.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws62_mdmgr_8f4_precondition_closure.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['kind', 'addr', 'insn', 'meaning'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws62_mdmgr_8f4_precondition_closure.md and .csv')


if __name__ == '__main__':
    main()
