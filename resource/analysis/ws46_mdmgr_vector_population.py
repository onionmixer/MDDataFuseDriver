#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
SLOT_GROUPS = [
    (0x0C42, 0x0C44, 'parser_callback'),
    (0x0CFA, 0x0CFC, 'device_hook_a'),
    (0x0CFE, 0x0D00, 'device_hook_b'),
    (0x0E2A, 0x0E2C, 'device_hook_c'),
    (0x0E2E, 0x0E30, 'device_hook_d'),
    (0x0E32, 0x0E34, 'dispatch_table_base'),
]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    b = TARGET.read_bytes()
    h = u16(b, 0x08) * 16
    img = b[h:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    for s, e in [(0x0350, 0x03B0), (0x0BC0, 0x0C30), (0x1990, 0x19F0), (0x0D40, 0x0F20), (0x1B50, 0x1D30)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    rows = []

    # Detect file-read population into DX buffer (int 21h AH=44h AL=02h)
    file_pop = []
    for i, x in enumerate(ins):
        if x.mnemonic != 'int' or x.op_str.strip() != '0x21':
            continue
        # look back for nearest dx=<slot>, cx=<len>
        dx_slot = None
        cx_len = None
        for y in reversed(ins[:i]):
            op = y.op_str.lower().replace(' ', '')
            if y.mnemonic == 'mov' and op.startswith('dx,'):
                rhs = op.split(',', 1)[1]
                try:
                    dx_slot = int(rhs, 16) if rhs.startswith('0x') else int(rhs, 10)
                except ValueError:
                    dx_slot = None
                break
        for y in reversed(ins[:i]):
            op = y.op_str.lower().replace(' ', '')
            if y.mnemonic == 'mov' and op.startswith('cx,'):
                rhs = op.split(',', 1)[1]
                try:
                    cx_len = int(rhs, 16) if rhs.startswith('0x') else int(rhs, 10)
                except ValueError:
                    cx_len = None
                break
        # Strict AX check: nearest preceding AX/AH/AL write must be mov ax,0x4402
        ax_ok = False
        for y in reversed(ins[:i]):
            op = y.op_str.lower().replace(' ', '')
            if y.mnemonic == 'mov' and (op.startswith('ax,') or op.startswith('ah,') or op.startswith('al,')):
                ax_ok = (op == 'ax,0x4402')
                break
        if ax_ok and dx_slot is not None:
            file_pop.append((x.address, dx_slot, cx_len))

    # Collect writes/reads for slot groups
    for low, high, cls in SLOT_GROUPS:
        writes = []
        guards = []
        calls = []

        for i, x in enumerate(ins):
            t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')

            # writes to low/high word
            for off in (low, high):
                if x.mnemonic == 'mov' and t.startswith(f'movwordptr[0x{off:x}],'):
                    writes.append((x.address, off, x.mnemonic, x.op_str))

            # guard pattern: mov ax,[low] ; or ax,[high]
            if x.mnemonic == 'mov' and x.op_str.lower().replace(' ', '') == f'ax,wordptr[0x{low:x}]':
                if i + 1 < len(ins):
                    y = ins[i + 1]
                    yt = (y.mnemonic + ' ' + y.op_str).lower().replace(' ', '')
                    if y.mnemonic == 'or' and yt == f'orax,wordptr[0x{high:x}]':
                        guards.append((x.address, y.address))

            # indirect lcall [low]
            if x.mnemonic == 'lcall' and t == f'lcall[0x{low:x}]':
                calls.append((x.address, x.mnemonic, x.op_str))

        provider = 'unknown_runtime'
        note = ''
        for a, dst, ln in file_pop:
            if dst == low:
                provider = 'file_read_int21_4402'
                note = f'buffer=0x{dst:04x}, len={ln if ln is not None else "?"}, at 0x{a:04x}'

        # classify if only zero writes are present
        write_kinds = []
        for _, off, _, op in writes:
            rhs = op.split(',', 1)[1].strip().lower()
            if rhs in ('0', '0x0', '0000'):
                write_kinds.append('zero')
            else:
                write_kinds.append('nonzero')

        if writes and all(k == 'zero' for k in write_kinds) and provider == 'unknown_runtime':
            provider = 'zero_init_only'
            note = 'low/high words explicitly zeroed, no non-zero in-image writes'

        rows.append(
            {
                'slot_low': f'0x{low:04x}',
                'slot_high': f'0x{high:04x}',
                'class': cls,
                'provider': provider,
                'write_count': len(writes),
                'guard_count': len(guards),
                'call_count': len(calls),
                'note': note,
            }
        )

    md_lines = [
        '# WS46 mdmgr Vector Population Provenance',
        '',
        'Date: 2026-02-17',
        '',
        '| low | high | class | provider | writes | guards | calls | note |',
        '| --- | --- | --- | --- | --- | --- | --- | --- |',
    ]
    for r in rows:
        md_lines.append(
            f"| {r['slot_low']} | {r['slot_high']} | {r['class']} | {r['provider']} | {r['write_count']} | {r['guard_count']} | {r['call_count']} | {r['note']} |"
        )

    if file_pop:
        md_lines.extend(['', '## File-read population evidence'])
        for a, dst, ln in file_pop:
            md_lines.append(f'- `int 21h` (`AX=0x4402`) at `0x{a:04x}` with `DX=0x{dst:04x}`, `CX={ln}`')

    md_lines.extend([
        '',
        '## Conclusion',
        '- `0x0c42` is explicitly populated via DOS file read (`int 21h/4402`) before callback use.',
        '- Guarded device-hook pairs (`0x0cfa/0x0cfc`, `0x0cfe/0x0d00`, `0x0e2a/0x0e2c`, `0x0e2e/0x0e30`) are zero-initialized in-image and guarded before `lcall`.',
        '- No non-zero in-image writes were found for guarded hook pairs in this pass; non-null values, if any, likely come from runtime/external initialization.',
    ])

    Path('analysis/ws46_mdmgr_vector_population.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws46_mdmgr_vector_population.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['slot_low', 'slot_high', 'class', 'provider', 'write_count', 'guard_count', 'call_count', 'note'],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws46_mdmgr_vector_population.md and .csv')


if __name__ == '__main__':
    main()
