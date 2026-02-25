#!/usr/bin/env python3
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32


def mz_entry(path: Path):
    b = path.read_bytes()
    if b[:2] != b'MZ':
        return None
    e_cparhdr = struct.unpack_from('<H', b, 0x08)[0]
    ip = struct.unpack_from('<H', b, 0x14)[0]
    cs = struct.unpack_from('<H', b, 0x16)[0]
    # Approximation for MZ exe raw file offset of entry
    off = e_cparhdr * 16 + cs * 16 + ip
    return off


def le_ddb_offset(path: Path):
    b = path.read_bytes()
    le = struct.unpack_from('<I', b, 0x3C)[0]
    if b[le:le+2] != b'LE':
        return None
    data_pages_off = struct.unpack_from('<I', b, le + 0x80)[0]
    entry_off = struct.unpack_from('<I', b, le + 0x5C)[0]
    ent = le + entry_off
    # expected: 01 03 [5-byte entry] 00
    # use bytes 3..4 of 5-byte entry as LE offset candidate
    raw = b[ent+2:ent+7]
    if len(raw) != 5:
        return None
    ddb = int.from_bytes(raw[3:5], 'little')
    return data_pages_off + ddb


def disasm(path: Path, off: int, size: int, mode):
    b = path.read_bytes()
    code = b[off:off+size]
    md = Cs(CS_ARCH_X86, mode)
    out = []
    for i, insn in enumerate(md.disasm(code, off)):
        out.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}".rstrip())
        if i >= 39:
            break
    return out


def main():
    lines = ["# Disassembly Probe", "", "Date: 2026-02-16", ""]

    dos = [
        'w31/extract/mdfsex.exe',
        'w31/extract/mdfsck.exe',
        'w31/extract/mdformat.exe',
        'w31/extract/mdcache.exe',
        'w31/extract/mdmgr.exe',
    ]
    for f in dos:
        p = Path(f)
        off = mz_entry(p)
        lines.append(f"## {f}")
        lines.append(f"- entry_off_guess: 0x{off:08x}" if off is not None else "- entry_off_guess: (none)")
        if off is not None:
            lines.append("```asm")
            lines.extend(disasm(p, off, 256, CS_MODE_16))
            lines.append("```")
        lines.append("")

    vxds = [
        'w95/extract/us/mdmgr.vxd',
        'w95/extract/us/mdhlp.vxd',
        'w95/extract/us/mdfsd.vxd',
    ]
    for f in vxds:
        p = Path(f)
        off = le_ddb_offset(p)
        lines.append(f"## {f}")
        lines.append(f"- ddb_off_guess: 0x{off:08x}" if off is not None else "- ddb_off_guess: (none)")
        if off is not None:
            lines.append("```asm")
            lines.extend(disasm(p, off, 256, CS_MODE_32))
            lines.append("```")
        lines.append("")

    Path('analysis/disasm_probe.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print('wrote analysis/disasm_probe.md')


if __name__ == '__main__':
    main()
