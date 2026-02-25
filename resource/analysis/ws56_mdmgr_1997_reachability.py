#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_16

TARGET = Path('w31/extract/mdmgr.exe')
ENTRY = 0x1997
BLOCK_LO = 0x1997
BLOCK_HI = 0x1A40
DISPATCH_WIN = (0x1C60, 0x1CB2)


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def s16(b: bytes, o: int) -> int:
    return struct.unpack_from('<h', b, o)[0]


def s8(b: bytes, o: int) -> int:
    return struct.unpack_from('<b', b, o)[0]


def main() -> None:
    raw = TARGET.read_bytes()
    hdr = u16(raw, 0x08) * 16
    ovno = u16(raw, 0x1A)
    img = raw[hdr:]

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    ins = list(md.disasm(img, 0))

    # Capstone-level direct references to entry and inbound refs to the block.
    branch_mn = {
        'call', 'lcall', 'jmp', 'ljmp',
        'je', 'jne', 'ja', 'jae', 'jb', 'jbe', 'jl', 'jle', 'jg', 'jge',
        'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jc', 'jnc',
        'jcxz', 'loop', 'loope', 'loopne',
    }

    direct_entry_refs = []
    inbound_block_refs = []
    for x in ins:
        if x.mnemonic not in branch_mn:
            continue
        nums = re.findall(r'0x([0-9a-f]+)', x.op_str.lower())
        if not nums:
            continue
        tgt = int(nums[1], 16) if x.mnemonic in ('lcall', 'ljmp') and len(nums) >= 2 else int(nums[0], 16)
        if tgt == ENTRY:
            direct_entry_refs.append((x.address, x.mnemonic, x.op_str, 'capstone_target'))
        if BLOCK_LO <= tgt < BLOCK_HI and not (BLOCK_LO <= x.address < BLOCK_HI):
            inbound_block_refs.append((x.address, x.mnemonic, x.op_str, f'0x{tgt:04x}'))

    # Raw opcode-level target scan for 0x1997 (reduces decoder blind spots).
    raw_hits = []
    for a in range(len(img) - 4):
        op = img[a]
        if op == 0xE8:  # call rel16
            rel = s16(img, a + 1)
            tgt = (a + 3 + rel) & 0xFFFF
            if tgt == ENTRY:
                raw_hits.append((a, 'E8_call_rel16', rel))
        elif op == 0xE9:  # jmp rel16
            rel = s16(img, a + 1)
            tgt = (a + 3 + rel) & 0xFFFF
            if tgt == ENTRY:
                raw_hits.append((a, 'E9_jmp_rel16', rel))
        elif op == 0xEB:  # jmp rel8
            rel = s8(img, a + 1)
            tgt = (a + 2 + rel) & 0xFFFF
            if tgt == ENTRY:
                raw_hits.append((a, 'EB_jmp_rel8', rel))
        elif 0x70 <= op <= 0x7F:  # jcc rel8
            rel = s8(img, a + 1)
            tgt = (a + 2 + rel) & 0xFFFF
            if tgt == ENTRY:
                raw_hits.append((a, f'{op:02X}_jcc_rel8', rel))
        elif op == 0x0F and 0x80 <= img[a + 1] <= 0x8F:  # jcc rel16
            rel = s16(img, a + 2)
            tgt = (a + 4 + rel) & 0xFFFF
            if tgt == ENTRY:
                raw_hits.append((a, f'0F{img[a + 1]:02X}_jcc_rel16', rel))
        elif op == 0x9A:  # lcall ptr16:16
            off = u16(img, a + 1)
            seg = u16(img, a + 3)
            if off == ENTRY:
                raw_hits.append((a, f'9A_lcall_far_seg_{seg:04x}', 0))

    # Dispatcher cases that are proven directly called.
    disp_rows = []
    for x in ins:
        if DISPATCH_WIN[0] <= x.address < DISPATCH_WIN[1] and x.mnemonic == 'call':
            disp_rows.append((x.address, x.mnemonic, x.op_str))

    rows = []
    for a, m, o, src in direct_entry_refs:
        rows.append({'kind': 'entry_direct_ref', 'addr': f'0x{a:04x}', 'insn': f'{m} {o}', 'extra': src})
    for a, m, o, tgt in inbound_block_refs:
        rows.append({'kind': 'block_inbound_ref', 'addr': f'0x{a:04x}', 'insn': f'{m} {o}', 'extra': tgt})
    for a, op, rel in raw_hits:
        rows.append({'kind': 'raw_opcode_hit', 'addr': f'0x{a:04x}', 'insn': op, 'extra': f'rel={rel}'})
    rows.extend(
        [
            {'kind': 'summary', 'addr': '-', 'insn': 'direct_entry_refs', 'extra': str(len(direct_entry_refs))},
            {'kind': 'summary', 'addr': '-', 'insn': 'inbound_block_refs', 'extra': str(len(inbound_block_refs))},
            {'kind': 'summary', 'addr': '-', 'insn': 'raw_opcode_hits', 'extra': str(len(raw_hits))},
            {'kind': 'summary', 'addr': '-', 'insn': 'mz_e_ovno', 'extra': str(ovno)},
        ]
    )

    md_lines = [
        '# WS56 mdmgr 0x1997 Reachability Audit',
        '',
        'Date: 2026-02-17',
        '',
        'Scope: `w31/extract/mdmgr.exe` block `0x1997..0x1a3f` (contains writes `0x19d5/0x19db` to `0x0e38/0x0e36`).',
        '',
        '## Primary Results',
        f"- Capstone direct branch/call references to `0x1997`: {len(direct_entry_refs)}",
        f"- External inbound references into `0x1997..0x1a3f`: {len(inbound_block_refs)}",
        f"- Raw opcode-pattern hits targeting `0x1997`: {len(raw_hits)}",
        '- Interpretation: this block is statically isolated in current image-level evidence.',
        '',
        '## Dispatcher Window (`0x1c60..0x1cb1`) Direct Calls',
    ]
    for a, m, o in disp_rows:
        md_lines.append(f'- `0x{a:04x}: {m} {o}`')

    md_lines.extend([
        '',
        '## Notes',
        '- The dispatcher shows direct cases to `0x1511/0x165e/0x1771/0x1868/0x193b/0x1969/0x12ca` and then returns to common tail.',
        '- No direct case to `0x1997` is present in this window.',
        f'- MZ `e_ovno` is `{ovno}` (`0` in this sample), so classic EXE overlay indicator is not set.',
        '- This does not prove runtime impossibility (e.g., overlay/loader mutation), but no static in-image transfer is observed.',
    ])

    Path('analysis/ws56_mdmgr_1997_reachability.md').write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    with open('analysis/ws56_mdmgr_1997_reachability.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['kind', 'addr', 'insn', 'extra'])
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws56_mdmgr_1997_reachability.md and .csv')


if __name__ == '__main__':
    main()
