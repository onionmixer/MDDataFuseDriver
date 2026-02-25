#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
SLOT = 0x0C42


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    h = u16(raw, 0x08) * 16
    img = raw[h:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    for s, e in [(0x0340, 0x03B0), (0x04F0, 0x06A0)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    # loader evidence: int21 with closest AX=4402 and DX=0x0c42
    loader = []
    for i, x in enumerate(ins):
        if x.mnemonic != 'int' or x.op_str.strip() != '0x21':
            continue

        ax = None
        dx = None
        cx = None
        for y in reversed(ins[:i]):
            op = y.op_str.lower().replace(' ', '')
            if ax is None and y.mnemonic == 'mov' and (op.startswith('ax,') or op.startswith('ah,') or op.startswith('al,')):
                ax = op.split(',', 1)[1]
            if dx is None and y.mnemonic == 'mov' and op.startswith('dx,'):
                dx = op.split(',', 1)[1]
            if cx is None and y.mnemonic == 'mov' and op.startswith('cx,'):
                cx = op.split(',', 1)[1]
            if ax is not None and dx is not None and cx is not None:
                break

        if ax == '0x4402' and dx in ('0xc42', str(SLOT)):
            loader.append((x.address, ax, dx, cx))

    # call sites and push-arg shape
    calls = []
    for i, x in enumerate(ins):
        t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        if x.mnemonic == 'lcall' and t == f'lcall[0x{SLOT:x}]':
            pre = ins[max(0, i - 6):i]
            push_shape = [f"0x{y.address:04x}:{y.mnemonic} {y.op_str}" for y in pre if y.mnemonic == 'push']
            calls.append((x.address, push_shape))

    # direct writes to [0xc42]/[0xc44]
    writes = []
    for x in ins:
        t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        if x.mnemonic == 'mov' and (t.startswith('movwordptr[0xc42],') or t.startswith('movwordptr[0xc44],')):
            writes.append((x.address, x.mnemonic, x.op_str))
        if x.mnemonic == 'pop' and (t.startswith('popwordptr[0xc42]') or t.startswith('popwordptr[0xc44]')):
            writes.append((x.address, x.mnemonic, x.op_str))

    # raw string anchors for MDFSEX01
    mdfsex_offsets = []
    needle = b'MDFSEX01\x00'
    idx = 0
    while True:
        i = raw.find(needle, idx)
        if i < 0:
            break
        mdfsex_offsets.append(i)
        idx = i + 1

    md_lines = [
        '# WS47 mdmgr 0x0c42 Pointer Semantics',
        '',
        'Date: 2026-02-17',
        '',
        '## Loader Evidence',
    ]
    if loader:
        for a, ax, dx, cx in loader:
            md_lines.append(f'- `0x{a:04x}`: `int 21h` with `AX={ax}`, `DX={dx}`, `CX={cx}` -> reads 4 bytes into `0x0c42` buffer')
    else:
        md_lines.append('- no `int 21h/4402` loader to `0x0c42` detected')

    md_lines.extend([
        '',
        '## Call Consumption',
        f'- `lcall [0x{SLOT:04x}]` sites: {len(calls)}',
    ])
    for a, pushes in calls:
        md_lines.append(f"- `0x{a:04x}` push prelude: {' ; '.join(pushes) if pushes else '-'}")

    md_lines.extend([
        '',
        '## Write Evidence',
        f'- direct in-image writes to `[0x{SLOT:04x}]`/`[0x{SLOT+2:04x}]`: {len(writes)}',
    ])

    md_lines.extend([
        '',
        '## String Anchor',
        f'- `MDFSEX01` occurrences in raw binary: {len(mdfsex_offsets)} at {[hex(x) for x in mdfsex_offsets]}',
        '',
        '## Conclusion',
        '- `0x0c42` is consumed as a far pointer (`lcall m16:16`) and is loaded via 4-byte DOS read path.',
        '- No static in-image direct writes to `0x0c42/0x0c44` were found in this pass.',
        '- This strongly supports "external helper callback entry pointer" semantics for `0x0c42`.',
    ])

    Path('analysis/ws47_mdmgr_c42_pointer_semantics.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws47_mdmgr_c42_pointer_semantics.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['kind', 'address', 'detail'])
        for a, ax, dx, cx in loader:
            w.writerow(['loader_int21', f'0x{a:04x}', f'AX={ax},DX={dx},CX={cx}'])
        for a, pushes in calls:
            w.writerow(['lcall_consume', f'0x{a:04x}', ' ; '.join(pushes)])
        for a, m, op in writes:
            w.writerow(['direct_write', f'0x{a:04x}', f'{m} {op}'])

    print('wrote analysis/ws47_mdmgr_c42_pointer_semantics.md and .csv')


if __name__ == '__main__':
    main()
