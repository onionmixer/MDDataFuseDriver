#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import re
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

SLOTS = [0x14D2, 0x14D6, 0x14DC, 0x177A, 0x196C]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    p = Path('w31/extract/mdfsck.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(code, 0))

    rows = []
    for i, x in enumerate(ins):
        s = f"{x.mnemonic} {x.op_str}".lower()
        ms = re.findall(r"\[0x([0-9a-f]{4})\]", s)
        if not ms:
            continue
        for m in ms:
            a = int(m, 16)
            if a not in SLOTS:
                continue
            access = 'read'
            if x.mnemonic.startswith('mov') and x.op_str.strip().lower().startswith('word ptr ['):
                access = 'write'
            if x.mnemonic in ('pop',):
                access = 'write'
            if x.mnemonic in ('call', 'lcall', 'jmp', 'ljmp'):
                access = 'indirect'
            if x.mnemonic in ('cmp', 'test'):
                access = 'test'

            ctx = ins[max(0, i - 3):min(len(ins), i + 4)]
            ctext = ' || '.join(f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in ctx)
            rows.append(
                {
                    'slot': f'0x{a:04x}',
                    'ins_addr': f'0x{x.address:04x}',
                    'mnemonic': x.mnemonic,
                    'access': access,
                    'op_str': x.op_str,
                    'context': ctext,
                }
            )

    byslot = {f'0x{s:04x}': [] for s in SLOTS}
    for r in rows:
        byslot[r['slot']].append(r)

    md_lines = [
        '# WS38 mdfsck Runtime Vector Slot Trace (Static)',
        '',
        'Date: 2026-02-17',
        '',
        '| slot | total_refs | writes | indirect_calls/jmps | tests |',
        '| --- | --- | --- | --- | --- |',
    ]

    for s in sorted(byslot.keys()):
        xs = byslot[s]
        w = sum(1 for r in xs if r['access'] == 'write')
        ind = sum(1 for r in xs if r['access'] == 'indirect')
        tst = sum(1 for r in xs if r['access'] == 'test')
        md_lines.append(f'| {s} | {len(xs)} | {w} | {ind} | {tst} |')

    md_lines.extend(['', '## Per-slot details'])
    for s in sorted(byslot.keys()):
        md_lines.append('')
        md_lines.append(f'### {s}')
        xs = sorted(byslot[s], key=lambda r: int(r['ins_addr'], 16))
        if not xs:
            md_lines.append('- no direct absolute refs found')
            continue
        for r in xs:
            md_lines.append(f"- {r['ins_addr']} `{r['mnemonic']} {r['op_str']}` ({r['access']})")

    md_lines.extend([
        '',
        '## Notes',
        '- Slots with only indirect use and no in-image concrete writes are likely runtime-populated vectors.',
        '- This pass is static only; runtime value capture is still needed for final reachability closure.',
    ])

    Path('analysis/ws38_mdfsck_runtime_vector_slots.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws38_mdfsck_runtime_vector_slots.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['slot', 'ins_addr', 'mnemonic', 'access', 'op_str', 'context'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws38_mdfsck_runtime_vector_slots.md and .csv')


if __name__ == '__main__':
    main()
