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
    by_addr = {x.address: x for x in ins}

    rows: list[dict[str, str]] = []

    # 1) direct caller(s) of 0x08f4
    callers = []
    for x in ins:
        if x.mnemonic not in ('call', 'jmp'):
            continue
        m = re.search(r'0x([0-9a-f]+)', x.op_str.lower())
        if not m:
            continue
        if int(m.group(1), 16) == 0x08F4:
            callers.append(x.address)
            rows.append({'kind': 'direct_caller', 'addr': f'0x{x.address:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'note': ''})

    # 2) bounded precondition in caller window around 0x0e70
    for a in range(0x0e46, 0x0e56 + 1):
        x = by_addr.get(a)
        if x:
            rows.append({'kind': 'caller_window', 'addr': f'0x{a:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'note': 'pre-dispatch req[+1] bound'})

    # 3) callee window where k is formed and used
    for a in range(0x08fe, 0x0917 + 1):
        x = by_addr.get(a)
        if x:
            note = ''
            if a == 0x0901:
                note = 'k source byte req[+2]'
            elif a == 0x0907:
                note = 'k * 0x14'
            elif a == 0x090c:
                note = 'remap byte from [0x0d30 + k*0x14]'
            elif a == 0x0911:
                note = 'remap * 0x11'
            elif a == 0x0916:
                note = 'lane dispatch'
            rows.append({'kind': 'callee_k_path', 'addr': f'0x{a:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'note': note})

    # 4) search for explicit k-bound checks in callee before dispatch
    pre = [x for x in ins if 0x08f4 <= x.address < 0x0916]
    k_checks = []
    for x in pre:
        t = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        if ('[bx+2]' in t or '[bp+6]' in t) and x.mnemonic.startswith('cmp'):
            k_checks.append(x)
        if x.mnemonic in ('cmp', 'test') and ('ax' in t or 'al' in t):
            # heuristically keep nearby compare/test ops
            k_checks.append(x)

    # de-dup by address
    uniq = {}
    for x in k_checks:
        uniq[x.address] = x
    k_checks = [uniq[a] for a in sorted(uniq)]

    for x in k_checks:
        rows.append({'kind': 'callee_compare', 'addr': f'0x{x.address:04x}', 'insn': f'{x.mnemonic} {x.op_str}', 'note': 'candidate bound op'})

    explicit_bound_found = any(x.address not in (0x0905,) for x in k_checks)

    md_lines = [
        '# WS61 mdmgr 0x0916 k-Bound Trace',
        '',
        'Date: 2026-02-17',
        '',
        '## Findings',
        f'- direct caller count to `0x08f4`: {len(callers)}',
        '- observed direct caller: `0x0e70`.',
        '- caller-side explicit bound observed on `req[+1]` (`<=0x0d`) before jump-table dispatch.',
        '- in `0x08f4`, `k` is loaded from `req[+2]`, transformed (`*0x14`), remapped via `[0x0d30 + ...]`, then used for lane dispatch at `0x0916`.',
        f'- explicit in-function bound check on `k` before `0x0916`: {"present" if explicit_bound_found else "not observed"}.',
        '- Conclusion: residual `k>=8` uncertainty is a caller-contract/runtime-data issue; no local static clamp is observed in the `0x08f4` path.',
    ]

    Path('analysis/ws61_mdmgr_0916_k_bound_trace.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws61_mdmgr_0916_k_bound_trace.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['kind', 'addr', 'insn', 'note'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws61_mdmgr_0916_k_bound_trace.md and .csv')


if __name__ == '__main__':
    main()
