#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def mz_entry(path: Path):
    b = path.read_bytes()
    if b[:2] != b'MZ':
        return None
    e_cparhdr = struct.unpack_from('<H', b, 0x08)[0]
    ip = struct.unpack_from('<H', b, 0x14)[0]
    cs = struct.unpack_from('<H', b, 0x16)[0]
    return e_cparhdr * 16 + cs * 16 + ip


def disasm16(path: Path):
    b = path.read_bytes()
    base = mz_entry(path)
    if base is None or base >= len(b):
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    ins = list(md.disasm(b[base:], base))
    return ins


def find_ioctl_patterns(ins):
    # Detect DOS INT 21h nearby AX=44xx and open/read/write style handles
    out = []
    for i, x in enumerate(ins):
        if x.mnemonic == 'int' and x.op_str == '0x21':
            ctx = ins[max(0, i-6):i+1]
            text = []
            has44 = False
            for c in ctx:
                s = f"0x{c.address:05x}: {c.mnemonic} {c.op_str}".rstrip()
                text.append(s)
                if c.mnemonic in ('mov', 'cmp') and '0x44' in c.op_str:
                    has44 = True
                if c.mnemonic == 'mov' and 'ax, 0x44' in c.op_str:
                    has44 = True
            if has44:
                out.append('\n'.join(text))
    return out


def find_open_path_refs(ins):
    # Look for AX=3D00/3D02 and int21 nearby (open file/device)
    out = []
    for i, x in enumerate(ins):
        if x.mnemonic == 'int' and x.op_str == '0x21':
            ctx = ins[max(0, i-5):i+1]
            sctx = '\n'.join(f"0x{c.address:05x}: {c.mnemonic} {c.op_str}".rstrip() for c in ctx)
            if 'ax, 0x3d00' in sctx or 'ax, 0x3d02' in sctx or 'ah, 0x3d' in sctx:
                out.append(sctx)
    return out


def find_field_offset_candidates(ins):
    # Heuristic: collect [reg + imm] memory refs with small displacements,
    # likely struct-field accesses in checker paths.
    vals = {}
    for x in ins:
        for op in x.operands:
            if op.type == 3:  # MEM
                disp = op.mem.disp
                if 0 <= disp <= 0x200:
                    vals[disp] = vals.get(disp, 0) + 1
    top = sorted(vals.items(), key=lambda kv: (-kv[1], kv[0]))[:80]
    return top


def main():
    targets = [
        Path('w31/extract/mdfsex.exe'),
        Path('w31/extract/mdcache.exe'),
        Path('w31/extract/mdfsck.exe'),
    ]
    report = ['# Deep Static RE Notes', '', 'Date: 2026-02-16', '']

    for t in targets:
        report.append(f'## {t}')
        ins = disasm16(t)
        report.append(f'- decoded_insn_count: {len(ins)}')

        io = find_ioctl_patterns(ins)
        report.append(f'- ioctl_pattern_hits: {len(io)}')
        for blk in io[:6]:
            report.append('```asm')
            report.append(blk)
            report.append('```')

        op = find_open_path_refs(ins)
        report.append(f'- open_device_pattern_hits: {len(op)}')
        for blk in op[:6]:
            report.append('```asm')
            report.append(blk)
            report.append('```')

        if t.name == 'mdfsck.exe':
            top = find_field_offset_candidates(ins)
            report.append('- field_offset_candidates_top:')
            for disp, cnt in top[:40]:
                report.append(f'  - disp=0x{disp:02x} count={cnt}')

        report.append('')

    Path('analysis/deep_static_re.md').write_text('\n'.join(report) + '\n', encoding='utf-8')
    print('wrote analysis/deep_static_re.md')


if __name__ == '__main__':
    main()
