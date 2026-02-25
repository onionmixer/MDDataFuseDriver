#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import struct
import csv

from capstone import Cs, CS_ARCH_X86, CS_MODE_16


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from('<H', b, o)[0]


def disasm_mz(path: Path):
    b = path.read_bytes()
    hdr = u16(b, 0x08) * 16
    code = b[hdr:]
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    return list(md.disasm(code, 0))


def prev_window(ins, idx, n=10):
    s = max(0, idx - n)
    return ins[s:idx]


def collect_push_seq(window):
    seq = []
    for w in window:
        if w.mnemonic == 'push':
            seq.append(f"0x{w.address:04x}:{w.op_str}")
    return '<br>'.join(seq)


def collect_header_writes(window):
    hits = []
    for w in window:
        s = f"{w.mnemonic} {w.op_str}".lower()
        if 'mov byte ptr [bp - ' in s or 'mov word ptr [bp - ' in s:
            hits.append(f"0x{w.address:04x}:{w.mnemonic} {w.op_str}")
    return '<br>'.join(hits)


def main() -> None:
    targets = [
        ('w31/extract/mdcache.exe', 'ioctl_wrapper', 0x15B6),
        ('w31/extract/mdformat.exe', 'ioctl_wrapper', 0x2439),
        ('w31/extract/mdfsck.exe', 'transport_tx', 0x1396),
        ('w31/extract/mdfsck.exe', 'transport_rx', 0x1298),
    ]

    rows = []
    md = [
        '# WS24 MDCTL Callsite Lift',
        '',
        'Date: 2026-02-17',
        '',
        '| file | channel | target | call_site | push_sequence_before_call | local_header_writes_before_call |',
        '| --- | --- | --- | --- | --- | --- |',
    ]

    for fp, ch, tgt in targets:
        p = Path(fp)
        ins = disasm_mz(p)
        for i, x in enumerate(ins):
            if x.mnemonic not in ('call', 'lcall'):
                continue
            dest = None
            if x.mnemonic == 'call':
                if not x.op_str.startswith('0x'):
                    continue
                try:
                    dest = int(x.op_str, 16)
                except ValueError:
                    continue
            else:
                # e.g. "0x3f7, 0x1396"
                parts = [p.strip() for p in x.op_str.split(',')]
                if len(parts) != 2 or not parts[1].startswith('0x'):
                    continue
                try:
                    dest = int(parts[1], 16)
                except ValueError:
                    continue
            if dest != tgt:
                continue

            w = prev_window(ins, i, 12)
            push_seq = collect_push_seq(w)
            hdr_w = collect_header_writes(w)
            row = {
                'file': fp,
                'channel': ch,
                'target': f'0x{tgt:04x}',
                'call_site': f'0x{x.address:04x}',
                'push_sequence_before_call': push_seq,
                'local_header_writes_before_call': hdr_w,
            }
            rows.append(row)
            md.append(
                f"| {row['file']} | {row['channel']} | {row['target']} | {row['call_site']} | "
                f"{row['push_sequence_before_call']} | {row['local_header_writes_before_call']} |"
            )

    # focus notes
    md.extend([
        '',
        '## Notes',
        '- DOS wrappers (`mdcache`/`mdformat`) show caller-supplied push lanes into wrapper callsites.',
        '- `mdfsck` rows capture transport callsites and nearby local frame writes as static schema candidates.',
        '- This is static lift only; definitive field semantics require WS25 runtime buffer capture.',
    ])

    Path('analysis/ws24_mdctl_callsite_lift.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    with open('analysis/ws24_mdctl_callsite_lift.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                'file',
                'channel',
                'target',
                'call_site',
                'push_sequence_before_call',
                'local_header_writes_before_call',
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print('wrote analysis/ws24_mdctl_callsite_lift.md and .csv')


if __name__ == '__main__':
    main()
