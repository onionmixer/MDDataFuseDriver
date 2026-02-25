#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

START = 0x1960
END = 0x1978


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    p = Path('w31/extract/mdfsck.exe')
    b = p.read_bytes()
    hdr = u16(b, 0x08) * 16
    img = b[hdr:]

    cs = u16(b, 0x16)
    cs_base = cs << 4
    ds_seg = u16(img, cs_base + 0x12E)
    ds_base = ds_seg << 4

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    detail_rows = []
    summary_rows = []

    for off in range(START, END, 2):
        pat = f'[0x{off:04x}]'
        refs = []
        writes = 0
        indirect = 0
        reads = 0

        for i, x in enumerate(ins):
            txt = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
            if pat not in txt:
                continue
            access = 'read'
            if x.mnemonic in ('call', 'lcall', 'jmp', 'ljmp'):
                access = 'indirect'
                indirect += 1
            elif x.mnemonic.startswith('mov') and x.op_str.lower().startswith('word ptr [0x'):
                access = 'write'
                writes += 1
            elif x.mnemonic in ('pop',):
                access = 'write'
                writes += 1
            else:
                reads += 1

            ctx = ins[max(0, i - 3):min(len(ins), i + 4)]
            ctx_s = ' || '.join(f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in ctx)
            refs.append((x.address, x.mnemonic, x.op_str, access, ctx_s))
            detail_rows.append(
                {
                    'slot': f'0x{off:04x}',
                    'addr': f'0x{x.address:04x}',
                    'mnemonic': x.mnemonic,
                    'op_str': x.op_str,
                    'access': access,
                    'context': ctx_s,
                }
            )

        init = u16(img, ds_base + off)
        summary_rows.append(
            {
                'slot': f'0x{off:04x}',
                'init_u16': f'0x{init:04x}',
                'ref_count': len(refs),
                'read_count': reads,
                'write_count': writes,
                'indirect_count': indirect,
            }
        )

    md_lines = [
        '# WS42 mdfsck Runtime Slot Contract (0x1960..0x1976)',
        '',
        'Date: 2026-02-17',
        '',
        '## Segment Bases',
        f'- `CS=0x{cs:04x}` => `CS_base=0x{cs_base:04x}`',
        f'- `DS=0x{ds_seg:04x}` => `DS_base=0x{ds_base:04x}`',
        '',
        '## Slot Summary',
        '| slot | init_u16 | refs | reads | writes | indirect |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for r in summary_rows:
        md_lines.append(
            f"| {r['slot']} | {r['init_u16']} | {r['ref_count']} | {r['read_count']} | {r['write_count']} | {r['indirect_count']} |"
        )

    md_lines.extend([
        '',
        '## Key Findings',
        '- `0x1960/0x1962/0x1964` are near-call vector words with image-init value `0x00f2` and no static writes.',
        '- `0x196c` is a far-call vector low word used at three `lcall [0x196c]` sites; image-init value is `0x0000` and static writes are not present.',
        '- `0x196e` gates the `0x196c` call path (`jcxz` checks) and is also image-init `0x0000` with no static writes.',
        '- `0x1970..0x1976` feed AX:DX arguments into `lcall [0x196c]`; all are image-init zero with read-only static usage.',
        '- Combined evidence supports a runtime-populated callback/continuation contract for the `0x196c..0x1976` slot family.',
    ])

    Path('analysis/ws42_mdfsck_runtime_slot_contract.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    with open('analysis/ws42_mdfsck_runtime_slot_contract.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['slot', 'init_u16', 'ref_count', 'read_count', 'write_count', 'indirect_count'],
        )
        w.writeheader()
        w.writerows(summary_rows)

    with open('analysis/ws42_mdfsck_runtime_slot_contract_refs.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['slot', 'addr', 'mnemonic', 'op_str', 'access', 'context'],
        )
        w.writeheader()
        w.writerows(detail_rows)

    print('wrote analysis/ws42_mdfsck_runtime_slot_contract.md/.csv/_refs.csv')


if __name__ == '__main__':
    main()
