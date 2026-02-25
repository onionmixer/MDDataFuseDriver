#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def mz_entry(path: Path):
    b = path.read_bytes()
    e_cparhdr = struct.unpack_from('<H', b, 0x08)[0]
    ip = struct.unpack_from('<H', b, 0x14)[0]
    cs = struct.unpack_from('<H', b, 0x16)[0]
    return e_cparhdr * 16 + cs * 16 + ip


def main():
    p = Path('w31/extract/mdfsck.exe')
    b = p.read_bytes()
    base = mz_entry(p)
    # Stop linear disassembly before the first stable runtime string block.
    # This avoids treating .rdata-like regions as code.
    str_anchor = b.find(b'MDfsck version')
    if str_anchor < 0:
        str_anchor = len(b)

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    ins = list(md.disasm(b[base:str_anchor], base))

    target_lo = 0xE760
    target_hi = 0xEA40

    hits = []
    for i, x in enumerate(ins):
        # check immediate in op_str text to keep robust with capstone 5
        s = f"{x.mnemonic} {x.op_str}".lower()
        # parse all hex immediates like 0x1234 from text
        for tok in s.replace(',', ' ').split():
            if tok.startswith('0x'):
                try:
                    v = int(tok, 16)
                except ValueError:
                    continue
                if target_lo <= v <= target_hi:
                    hits.append((i, x.address, x.mnemonic, x.op_str, v))
                    break

    out = []
    out.append('# mdfsck Field Xref (Immediate Scan)')
    out.append('')
    out.append('Date: 2026-02-16')
    out.append(f'- decoded_insn_count: {len(ins)}')
    out.append(f'- code_window: [0x{base:05x},0x{str_anchor:05x})')
    out.append(f'- string_anchor: 0x{str_anchor:05x} ("MDfsck version")')
    out.append(f'- immediate_hits_in_[0x{target_lo:04x},0x{target_hi:04x}]: {len(hits)}')
    out.append('')

    for n, (idx, addr, mnem, opstr, imm) in enumerate(hits[:120], 1):
        out.append(f'## hit_{n} addr=0x{addr:05x} imm=0x{imm:04x}')
        ctx = ins[max(0, idx - 12): min(len(ins), idx + 16)]
        out.append('```asm')
        for c in ctx:
            out.append(f"0x{c.address:05x}: {c.mnemonic} {c.op_str}".rstrip())
        out.append('```')
        out.append('')

    # also scan raw 16-bit little-endian words matching target region
    raw_hits = []
    for off in range(0, len(b)-1):
        w = b[off] | (b[off+1] << 8)
        if target_lo <= w <= target_hi:
            raw_hits.append((off, w))
    out.append(f'- raw_word_hits_in_range: {len(raw_hits)}')
    out.append('- first_raw_hits:')
    for off, w in raw_hits[:40]:
        out.append(f'  - off=0x{off:05x} word=0x{w:04x}')

    Path('analysis/mdfsck_field_xref.md').write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('wrote analysis/mdfsck_field_xref.md')

if __name__ == '__main__':
    main()
