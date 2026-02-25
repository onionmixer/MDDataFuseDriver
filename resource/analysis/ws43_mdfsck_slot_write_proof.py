#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

SLOT_START = 0x196C
SLOT_END = 0x1976


WRITE_MNEMONIC_PREFIX = ('mov',)
WRITE_MNEMONICS = {'pop', 'stosb', 'stosw', 'xchg'}


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def parse_imm16_from_mov_reg(op_str: str):
    # e.g. "di, 0x196c"
    m = re.match(r"\s*(si|di|bx|bp)\s*,\s*0x([0-9a-fA-F]{1,4})\s*$", op_str)
    if not m:
        return None
    return m.group(1).lower(), int(m.group(2), 16)


def is_write_ins(mnemonic: str, op_str: str) -> bool:
    m = mnemonic.lower()
    o = op_str.lower().strip()
    if m in WRITE_MNEMONICS:
        return True
    if m.startswith(WRITE_MNEMONIC_PREFIX):
        # destination memory forms
        if o.startswith('word ptr [') or o.startswith('byte ptr ['):
            return True
    return False


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

    direct = []
    candidate = []

    # exact direct writes to slots
    for i, x in enumerate(ins):
        if not is_write_ins(x.mnemonic, x.op_str):
            continue
        text = (x.mnemonic + ' ' + x.op_str).lower().replace(' ', '')
        for off in range(SLOT_START, SLOT_END + 1, 2):
            if f'[0x{off:04x}]' in text:
                ctx = ins[max(0, i - 3):min(len(ins), i + 4)]
                direct.append(
                    {
                        'slot': f'0x{off:04x}',
                        'addr': f'0x{x.address:04x}',
                        'insn': f'{x.mnemonic} {x.op_str}',
                        'kind': 'direct',
                        'context': ' || '.join(f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in ctx),
                    }
                )

    # heuristic: register-based pointer write candidates
    # if write uses [di]/[si]/[bx]/[bp] and within last 6 insns reg loaded to slot-range immediate.
    for i, x in enumerate(ins):
        if not is_write_ins(x.mnemonic, x.op_str):
            continue
        op_l = x.op_str.lower().replace(' ', '')
        m = re.search(r'\[(si|di|bx|bp)(?:[+\-].*)?\]', op_l)
        if not m:
            continue
        base = m.group(1)

        imm = None
        src_addr = None
        for y in reversed(ins[max(0, i - 6):i]):
            parsed = parse_imm16_from_mov_reg(y.op_str) if y.mnemonic.lower() == 'mov' else None
            if parsed and parsed[0] == base:
                imm = parsed[1]
                src_addr = y.address
                break

        if imm is None:
            continue

        if SLOT_START <= imm <= SLOT_END:
            ctx = ins[max(0, i - 3):min(len(ins), i + 4)]
            candidate.append(
                {
                    'slot_like': f'0x{imm:04x}',
                    'addr': f'0x{x.address:04x}',
                    'insn': f'{x.mnemonic} {x.op_str}',
                    'kind': 'candidate_indirect',
                    'base_reg': base,
                    'base_src_addr': f'0x{src_addr:04x}',
                    'context': ' || '.join(f"0x{q.address:04x}:{q.mnemonic} {q.op_str}" for q in ctx),
                }
            )

    md_lines = [
        '# WS43 mdfsck Slot Write Proof (0x196c..0x1976)',
        '',
        'Date: 2026-02-17',
        '',
        '## Segment Bases',
        f'- `CS=0x{cs:04x}` (`CS_base=0x{cs_base:04x}`)',
        f'- `DS=0x{ds_seg:04x}` (`DS_base=0x{ds_base:04x}`)',
        '',
        '## Result Summary',
        f'- direct writes to `0x{SLOT_START:04x}..0x{SLOT_END:04x}`: {len(direct)}',
        f'- heuristic indirect-write candidates to same range: {len(candidate)}',
    ]

    if direct:
        md_lines.extend(['', '## Direct writes'])
        for r in direct:
            md_lines.append(f"- {r['addr']} `{r['insn']}` -> {r['slot']}")
    else:
        md_lines.extend(['', '## Direct writes', '- none found in linear-disassembly pass'])

    if candidate:
        md_lines.extend(['', '## Indirect candidates'])
        for r in candidate:
            md_lines.append(
                f"- {r['addr']} `{r['insn']}` (base `{r['base_reg']}` from {r['base_src_addr']} => {r['slot_like']})"
            )
    else:
        md_lines.extend(['', '## Indirect candidates', '- none found by immediate-base backtrace heuristic'])

    md_lines.extend([
        '',
        '## Conclusion',
        '- Static evidence continues to support that `0x196c..0x1976` are runtime-populated lanes.',
        '- Full closure still requires runtime capture of slot initialization source.',
    ])

    Path('analysis/ws43_mdfsck_slot_write_proof.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')

    with open('analysis/ws43_mdfsck_slot_write_proof_direct.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['slot', 'addr', 'insn', 'kind', 'context'])
        w.writeheader()
        w.writerows(direct)

    with open('analysis/ws43_mdfsck_slot_write_proof_candidates.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=['slot_like', 'addr', 'insn', 'kind', 'base_reg', 'base_src_addr', 'context'],
        )
        w.writeheader()
        w.writerows(candidate)

    print('wrote analysis/ws43_mdfsck_slot_write_proof.md and csv files')


if __name__ == '__main__':
    main()
