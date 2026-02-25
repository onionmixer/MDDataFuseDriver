#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = 'w31/extract/mdmgr.exe'
SLOTS = [0x0C42, 0x0CFA, 0x0CFE, 0x0E2A, 0x0E2E, 0x0E32]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    b = Path(TARGET).read_bytes()
    h = u16(b, 0x08) * 16
    img = b[h:]
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    # Add focused windows for regions that can be missed in linear decode.
    for s, e in [(0x0BC0, 0x0C20), (0x1990, 0x19F0)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    rows = []
    zeros = []

    for i, x in enumerate(ins):
        t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        # capture explicit zeroing writes (mov word ptr [slot], 0)
        m0 = re.match(r'movwordptr\[0x([0-9a-f]{3,4})\],(.+)$', t)
        if m0:
            off = int(m0.group(1), 16)
            rhs = m0.group(2)
            if rhs in ('0', '0x0', '0000'):
                if off in SLOTS or off in [s + 2 for s in SLOTS]:
                    zeros.append((x.address, off, x.mnemonic, x.op_str))

    for slot in SLOTS:
        pat = f'[0x{slot:x}]'
        call_sites = []
        guard_sites = []

        for i, x in enumerate(ins):
            t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
            if x.mnemonic == 'lcall' and pat in t:
                # collect compact prelude
                pre = []
                for y in ins[max(0, i - 6):i]:
                    if y.mnemonic in ('push', 'mov', 'xor', 'cmp', 'test', 'jcxz', 'je', 'or'):
                        pre.append(f"0x{y.address:04x}:{y.mnemonic} {y.op_str}")
                call_sites.append((x.address, x.mnemonic, x.op_str, ' || '.join(pre)))

            # guard form: mov ax,[slot] ; or ax,[slot+2]
            if x.mnemonic == 'mov' and x.op_str.lower().replace(' ', '') == f'ax,wordptr[0x{slot:x}]':
                win = ins[i:i + 3]
                if len(win) >= 2:
                    y = win[1]
                    yt = (y.mnemonic + ' ' + y.op_str).lower().replace(' ', '')
                    if y.mnemonic == 'or' and yt == f'orax,wordptr[0x{slot+2:x}]':
                        guard_sites.append((x.address, y.address))

        cls = 'device_vector'
        if slot == 0x0C42:
            cls = 'parser_callback'

        rows.append(
            {
                'slot': f'0x{slot:04x}',
                'class': cls,
                'call_count': len(call_sites),
                'guard_count': len(guard_sites),
                'sample_call_site': f'0x{call_sites[0][0]:04x}' if call_sites else '',
                'sample_prelude': call_sites[0][3] if call_sites else '',
            }
        )

    md_lines = [
        '# WS45 mdmgr Vector Slot Classes',
        '',
        'Date: 2026-02-17',
        '',
        'Target: `w31/extract/mdmgr.exe`',
        '',
        '| slot | class | lcall sites | guard sites (`mov ax,[slot]; or ax,[slot+2]`) |',
        '| --- | --- | --- | --- |',
    ]
    for r in rows:
        md_lines.append(f"| {r['slot']} | {r['class']} | {r['call_count']} | {r['guard_count']} |")

    md_lines.extend([
        '',
        '## Zero-init evidence',
    ])
    if zeros:
        for a, off, m, op in zeros:
            md_lines.append(f'- `0x{a:04x}: {m} {op}` (slot `0x{off:04x}`)')
    else:
        md_lines.append('- no explicit zero-inits detected for tracked slots')

    md_lines.extend([
        '',
        '## Notes',
        '- `0x0c42` is used as parser-style callback with stack pointer argument blocks in multiple command handlers.',
        '- `0x0cfa/0x0cfe` and `0x0e2a/0x0e2e` show paired low/high-word guard checks before optional `lcall`.',
        '- `0x0e32` is a high-frequency helper vector used by multiple request builders.',
    ])

    Path('analysis/ws45_mdmgr_vector_slot_classes.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    with open('analysis/ws45_mdmgr_vector_slot_classes.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['slot', 'class', 'call_count', 'guard_count', 'sample_call_site', 'sample_prelude'],
        )
        w.writeheader()
        w.writerows(rows)

    with open('analysis/ws45_mdmgr_vector_slot_zeroinit.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['addr', 'slot', 'mnemonic', 'op_str'])
        for a, off, m, op in zeros:
            w.writerow([f'0x{a:04x}', f'0x{off:04x}', m, op])

    print('wrote analysis/ws45_mdmgr_vector_slot_classes.md/.csv and zeroinit.csv')


if __name__ == '__main__':
    main()
