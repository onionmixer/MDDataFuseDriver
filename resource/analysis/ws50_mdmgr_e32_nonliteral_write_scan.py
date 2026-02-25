#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
RANGE_LO = 0x0E32
RANGE_HI = 0x0E3C


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def parse_disp(expr: str) -> tuple[str, int] | None:
    # expr like 'bx', 'bx + 0xe32', 'di - 0x4'
    e = expr.replace(' ', '').lower()
    m = re.match(r'^(bx|si|di|bp)([+-]0x[0-9a-f]+)?$', e)
    if not m:
        return None
    reg = m.group(1)
    disp = 0
    if m.group(2):
        s = m.group(2)
        sign = -1 if s.startswith('-') else 1
        disp = sign * int(s[1:], 16)
    return reg, disp


def resolve_reg_const(ins, i, reg: str, window: int = 8):
    # tiny backward constant resolver for mov/xor/add/sub/shl patterns
    val = None
    for y in reversed(ins[max(0, i - window):i]):
        m = y.mnemonic.lower()
        o = y.op_str.lower().replace(' ', '')
        if m == 'mov' and o.startswith(f'{reg},0x'):
            try:
                val = int(o.split('0x', 1)[1], 16)
                return val
            except ValueError:
                return None
        if m == 'xor' and o == f'{reg},{reg}':
            return 0
        if m == 'add' and o.startswith(f'{reg},0x') and val is not None:
            val += int(o.split('0x', 1)[1], 16)
            return val
        if m == 'sub' and o.startswith(f'{reg},0x') and val is not None:
            val -= int(o.split('0x', 1)[1], 16)
            return val
    return None


def main() -> None:
    b = TARGET.read_bytes()
    h = u16(b, 0x08) * 16
    img = b[h:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))
    for s, e in [(0x1800, 0x1d80), (0x0b00, 0x1100), (0x1200, 0x1600), (0x19a0, 0x1a80)]:
        ins.extend(list(md.disasm(img[s:e], s)))
    uniq = {}
    for i in ins:
        uniq[(i.address, i.mnemonic, i.op_str)] = i
    ins = [uniq[k] for k in sorted(uniq.keys())]

    direct = []
    reg_candidates = []
    block_candidates = []

    for i, x in enumerate(ins):
        m = x.mnemonic.lower()
        o = x.op_str
        ol = o.lower().replace(' ', '')

        # direct absolute writes
        if m == 'mov' and ol.startswith('wordptr['):
            mm = re.match(r'wordptr\[0x([0-9a-f]{3,4})\],', ol)
            if mm:
                off = int(mm.group(1), 16)
                if RANGE_LO <= off <= RANGE_HI:
                    direct.append((x.address, x.mnemonic, x.op_str, off))

        # register+disp write candidates
        if m == 'mov' and ol.startswith('wordptr['):
            mm = re.match(r'wordptr\[([^\]]+)\],', o.lower())
            if mm:
                parsed = parse_disp(mm.group(1))
                if parsed:
                    reg, disp = parsed
                    base = resolve_reg_const(ins, i, reg)
                    if base is not None:
                        target = (base + disp) & 0xFFFF
                        if RANGE_LO <= target <= RANGE_HI:
                            ctx = ins[max(0, i - 4):min(len(ins), i + 3)]
                            reg_candidates.append(
                                {
                                    'addr': f'0x{x.address:04x}',
                                    'insn': f'{x.mnemonic} {x.op_str}',
                                    'reg': reg,
                                    'base': f'0x{base:04x}',
                                    'disp': disp,
                                    'target': f'0x{target:04x}',
                                    'context': ' || '.join(f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in ctx),
                                }
                            )

        # block copy candidates via stos*/movs* with DI constant in range
        if m in ('stosw', 'stosb', 'movsw', 'movsb', 'rep', 'repne'):
            di = resolve_reg_const(ins, i, 'di')
            if di is not None and RANGE_LO <= di <= RANGE_HI:
                block_candidates.append((x.address, x.mnemonic, x.op_str, di))

    md_lines = [
        '# WS50 mdmgr 0x0e32 Non-literal Write Scan',
        '',
        'Date: 2026-02-17',
        '',
        f'- target range: `0x{RANGE_LO:04x}..0x{RANGE_HI:04x}`',
        f'- direct absolute writes in range: `{len(direct)}`',
        f'- reg+disp resolved write candidates in range: `{len(reg_candidates)}`',
        f'- block-copy candidates with `DI` in range: `{len(block_candidates)}`',
    ]

    if direct:
        md_lines.extend(['', '## Direct writes'])
        for a, mnem, ops, off in direct:
            md_lines.append(f'- `0x{a:04x}: {mnem} {ops}` -> `0x{off:04x}`')

    if reg_candidates:
        md_lines.extend(['', '## Reg+disp candidates'])
        for r in reg_candidates:
            md_lines.append(f"- {r['addr']} `{r['insn']}` -> {r['target']} (via {r['reg']}={r['base']}, disp={r['disp']})")

    if block_candidates:
        md_lines.extend(['', '## Block-copy candidates'])
        for a, mnem, ops, di in block_candidates:
            md_lines.append(f'- `0x{a:04x}: {mnem} {ops}` with `DI=0x{di:04x}`')

    md_lines.extend([
        '',
        '## Conclusion',
        '- No additional non-literal write path into `0x0e32..0x0e3c` was confirmed by this bounded static scan.',
        '- Remaining provider uncertainty for entry #0/#2 persists as runtime/non-obvious dataflow issue.',
    ])

    Path('analysis/ws50_mdmgr_e32_nonliteral_write_scan.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws50_mdmgr_e32_nonliteral_write_scan.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['addr', 'insn', 'reg', 'base', 'disp', 'target', 'context'])
        w.writeheader()
        w.writerows(reg_candidates)

    print('wrote analysis/ws50_mdmgr_e32_nonliteral_write_scan.md and .csv')


if __name__ == '__main__':
    main()
