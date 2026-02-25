#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import struct
from pathlib import Path


def u16(b: bytes, off: int) -> int:
    return struct.unpack_from('<H', b, off)[0]


def u32(b: bytes, off: int) -> int:
    return struct.unpack_from('<I', b, off)[0]


def parse_name_table(buf: bytes, start: int, max_len: int | None = None):
    names = []
    if start <= 0 or start >= len(buf):
        return names
    end = len(buf) if max_len is None else min(len(buf), start + max_len)
    off = start
    while off < end:
        ln = buf[off]
        off += 1
        if ln == 0:
            break
        if off + ln + 2 > end:
            break
        name = buf[off:off + ln].decode('latin1', 'replace')
        off += ln
        ordv = u16(buf, off)
        off += 2
        names.append((name, ordv))
    return names


def parse_entry_table(buf: bytes, start: int):
    bundles = []
    ordinal = 1
    off = start
    while off < len(buf):
        cnt = buf[off]
        off += 1
        if cnt == 0:
            break
        if off >= len(buf):
            break
        btype = buf[off]
        off += 1

        # LE/LX entry bundle (minimal parser):
        # type 0: unused range (no payload)
        # type 3: 32-bit entry, payload assumed [flags(1), value32(4)] * cnt
        if btype == 0:
            bundles.append({
                'ordinal_start': ordinal,
                'ordinal_end': ordinal + cnt - 1,
                'count': cnt,
                'type': btype,
                'raw': b'',
            })
            ordinal += cnt
            continue

        if btype == 3:
            ent_size = 5
        elif btype == 1:
            ent_size = 3
        elif btype == 2:
            ent_size = 5
        elif btype == 4:
            ent_size = 7
        else:
            # Unknown bundle type; stop to avoid overrun/misparse.
            break

        need = cnt * ent_size
        if off + need > len(buf):
            break
        raw = buf[off:off + need]
        off += need
        bundles.append({
            'ordinal_start': ordinal,
            'ordinal_end': ordinal + cnt - 1,
            'count': cnt,
            'type': btype,
            'raw': raw,
        })
        ordinal += cnt
    return bundles


def decode_type3_raw(raw: bytes):
    # Keep multiple hypotheses because LE VxD bundle type-3 layouts vary by tooling/doc set.
    if len(raw) != 5:
        return {}
    b0, b1, b2, b3, b4 = raw
    return {
        'flags': b0,
        'u32_le_b1_4': int.from_bytes(raw[1:5], 'little'),
        'u32_be_b1_4': int.from_bytes(raw[1:5], 'big'),
        'u16_le_b1_2': int.from_bytes(raw[1:3], 'little'),
        'u16_be_b1_2': int.from_bytes(raw[1:3], 'big'),
        'u16_le_b3_4': int.from_bytes(raw[3:5], 'little'),
        'u16_be_b3_4': int.from_bytes(raw[3:5], 'big'),
        'bytes_hex': raw.hex(),
        'bytes_split': f'{b0:02x} {b1:02x} {b2:02x} {b3:02x} {b4:02x}',
    }


def parse_file(path: Path):
    data = path.read_bytes()
    if data[:2] != b'MZ':
        raise ValueError(f'{path}: not MZ')
    le_off = u32(data, 0x3C)
    if data[le_off:le_off + 2] != b'LE':
        raise ValueError(f'{path}: missing LE signature at 0x{le_off:x}')

    h = {}
    h['file'] = str(path)
    h['le_offset'] = le_off
    h['byte_order'] = data[le_off + 2]
    h['word_order'] = data[le_off + 3]
    h['exe_format_level'] = u32(data, le_off + 0x04)
    h['cpu_type'] = u16(data, le_off + 0x08)
    h['os_type'] = u16(data, le_off + 0x0A)
    h['module_version'] = u32(data, le_off + 0x0C)
    h['module_flags'] = u32(data, le_off + 0x10)
    h['num_pages'] = u32(data, le_off + 0x14)
    h['eip_object'] = u32(data, le_off + 0x18)
    h['eip'] = u32(data, le_off + 0x1C)
    h['esp_object'] = u32(data, le_off + 0x20)
    h['esp'] = u32(data, le_off + 0x24)
    h['page_size'] = u32(data, le_off + 0x28)
    h['bytes_on_last_page'] = u32(data, le_off + 0x2C)
    h['fixup_section_size'] = u32(data, le_off + 0x30)
    h['loader_section_size'] = u32(data, le_off + 0x38)
    h['object_table_off'] = u32(data, le_off + 0x40)
    h['object_count'] = u32(data, le_off + 0x44)
    h['object_page_map_off'] = u32(data, le_off + 0x48)
    h['resource_table_off'] = u32(data, le_off + 0x50)
    h['resource_table_entries'] = u32(data, le_off + 0x54)
    h['resident_names_off'] = u32(data, le_off + 0x58)
    h['entry_table_off'] = u32(data, le_off + 0x5C)
    h['fixup_page_table_off'] = u32(data, le_off + 0x68)
    h['fixup_record_table_off'] = u32(data, le_off + 0x6C)
    h['import_module_table_off'] = u32(data, le_off + 0x70)
    h['import_module_count'] = u32(data, le_off + 0x74)
    h['import_proc_table_off'] = u32(data, le_off + 0x78)
    h['data_pages_off'] = u32(data, le_off + 0x80)
    h['preload_page_count'] = u32(data, le_off + 0x84)
    h['nonresident_names_off'] = u32(data, le_off + 0x88)
    h['nonresident_names_len'] = u32(data, le_off + 0x8C)
    h['debug_info_off'] = u32(data, le_off + 0x98)
    h['debug_info_len'] = u32(data, le_off + 0x9C)

    obj_tbl_abs = le_off + h['object_table_off']
    objects = []
    for i in range(h['object_count']):
        o = obj_tbl_abs + i * 24
        if o + 24 > len(data):
            break
        objects.append({
            'index': i + 1,
            'virtual_size': u32(data, o + 0x00),
            'reloc_base_addr': u32(data, o + 0x04),
            'flags': u32(data, o + 0x08),
            'page_table_idx': u32(data, o + 0x0C),
            'page_count': u32(data, o + 0x10),
            'reserved': u32(data, o + 0x14),
        })

    # LE object page map: one 32-bit entry per page.
    # For these VxDs, values are sequential physical page numbers.
    page_map = []
    pg_abs = le_off + h['object_page_map_off']
    for i in range(h['num_pages']):
        o = pg_abs + i * 4
        if o + 4 > len(data):
            break
        raw = u32(data, o)
        # For these LE VxDs, page map stores page-number in the high 16 bits.
        # Example sequence: 0x00010000, 0x00020000, ...
        pidx = raw >> 16
        file_off = None
        if pidx != 0:
            file_off = h['data_pages_off'] + (pidx - 1) * h['page_size']
        page_map.append({
            'page_index_1based': i + 1,
            'raw': raw,
            'physical_page': pidx,
            'file_off': file_off,
        })

    fixup_page_offsets = []
    fxp_abs = le_off + h['fixup_page_table_off']
    # fixup page table generally has num_pages + 1 entries.
    for i in range(h['num_pages'] + 1):
        o = fxp_abs + i * 4
        if o + 4 > len(data):
            break
        fixup_page_offsets.append(u32(data, o))

    res_names = parse_name_table(data, le_off + h['resident_names_off'])
    nonres_names = parse_name_table(data, h['nonresident_names_off'], h['nonresident_names_len'])

    entry_abs = le_off + h['entry_table_off']
    bundles = parse_entry_table(data, entry_abs)

    return h, objects, page_map, fixup_page_offsets, res_names, nonres_names, bundles


def fmt_hex(v: int) -> str:
    return f'0x{v:08X}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    ap.add_argument('--out-csv', default='analysis/ws2_le_headers.csv')
    ap.add_argument('--out-md', default='analysis/ws2_le_headers.md')
    ap.add_argument('--out-exports-csv', default='analysis/ws2_le_exports.csv')
    ap.add_argument('--out-exports-md', default='analysis/ws2_le_exports.md')
    ap.add_argument('--out-entry-hyp-csv', default='analysis/ws2_le_entry_hypotheses.csv')
    ap.add_argument('--out-entry-hyp-md', default='analysis/ws2_le_entry_hypotheses.md')
    ap.add_argument('--out-ddb-csv', default='analysis/ws2_vxd_ddb_candidates.csv')
    ap.add_argument('--out-ddb-md', default='analysis/ws2_vxd_ddb_candidates.md')
    ap.add_argument('--out-pagemap-csv', default='analysis/ws2_le_pagemap.csv')
    ap.add_argument('--out-pagemap-md', default='analysis/ws2_le_pagemap.md')
    ap.add_argument('--out-fixup-csv', default='analysis/ws2_le_fixup_summary.csv')
    ap.add_argument('--out-fixup-md', default='analysis/ws2_le_fixup_summary.md')
    args = ap.parse_args()

    rows = []
    md_lines = ['# WS2 LE Header Parse', '', 'Date: 2026-02-16', '']
    export_rows = []
    export_md = ['# WS2 LE Exports/Ordinals', '', 'Date: 2026-02-16', '']
    hyp_rows = []
    hyp_md = ['# WS2 LE Entry Hypotheses', '', 'Date: 2026-02-16', '']
    ddb_rows = []
    ddb_md = ['# WS2 VxD DDB Candidate Mapping', '', 'Date: 2026-02-16', '']
    pagemap_rows = []
    pagemap_md = ['# WS2 LE Page Map', '', 'Date: 2026-02-16', '']
    fixup_rows = []
    fixup_md = ['# WS2 LE Fixup Summary', '', 'Date: 2026-02-16', '']

    for fp in args.files:
        p = Path(fp)
        file_bytes = p.read_bytes()
        h, objs, page_map, fixup_page_offsets, rnames, nrnames, bundles = parse_file(p)
        rows.append({
            'file': h['file'],
            'le_offset_hex': fmt_hex(h['le_offset']),
            'cpu_type': h['cpu_type'],
            'os_type': h['os_type'],
            'module_flags_hex': fmt_hex(h['module_flags']),
            'num_pages': h['num_pages'],
            'eip_object': h['eip_object'],
            'eip_hex': fmt_hex(h['eip']),
            'esp_object': h['esp_object'],
            'esp_hex': fmt_hex(h['esp']),
            'page_size': h['page_size'],
            'object_count': h['object_count'],
            'object_table_off_hex': fmt_hex(h['object_table_off']),
            'entry_table_off_hex': fmt_hex(h['entry_table_off']),
            'resident_names_off_hex': fmt_hex(h['resident_names_off']),
            'nonresident_names_off_hex': fmt_hex(h['nonresident_names_off']),
            'nonresident_names_len': h['nonresident_names_len'],
        })

        md_lines.append(f"## {h['file']}")
        md_lines.append(f"- LE header offset: `{fmt_hex(h['le_offset'])}`")
        md_lines.append(f"- CPU type: `{h['cpu_type']}` OS type: `{h['os_type']}`")
        md_lines.append(f"- Module flags: `{fmt_hex(h['module_flags'])}`")
        md_lines.append(f"- Entry EIP: object `{h['eip_object']}` offset `{fmt_hex(h['eip'])}`")
        md_lines.append(f"- Entry ESP: object `{h['esp_object']}` offset `{fmt_hex(h['esp'])}`")
        md_lines.append(f"- Object count: `{h['object_count']}`, page size: `{h['page_size']}`")
        md_lines.append('- Object table:')
        for o in objs:
            start_page = o['page_table_idx']
            end_page = o['page_table_idx'] + o['page_count'] - 1 if o['page_count'] else o['page_table_idx']
            start_file = None
            end_file = None
            if 1 <= start_page <= len(page_map):
                start_file = page_map[start_page - 1]['file_off']
            if 1 <= end_page <= len(page_map):
                end_file = page_map[end_page - 1]['file_off']
            md_lines.append(
                f"  - obj{o['index']}: vsize={fmt_hex(o['virtual_size'])} base={fmt_hex(o['reloc_base_addr'])} flags={fmt_hex(o['flags'])} page_idx={o['page_table_idx']} pages={o['page_count']} file_start={fmt_hex(start_file) if start_file is not None else '-'} file_end={fmt_hex(end_file) if end_file is not None else '-'}"
            )
        md_lines.append('- Resident names (first 20):')
        for n, ordv in rnames[:20]:
            md_lines.append(f'  - ord {ordv}: `{n}`')
        md_lines.append('- Non-resident names (first 20):')
        for n, ordv in nrnames[:20]:
            md_lines.append(f'  - ord {ordv}: `{n}`')
        md_lines.append('- Entry bundles:')
        for b in bundles[:20]:
            md_lines.append(
                f"  - ord {b['ordinal_start']}-{b['ordinal_end']}: type={b['type']} count={b['count']} raw_len={len(b['raw'])}"
            )
        md_lines.append('')

        pagemap_md.append(f"## {h['file']}")
        pagemap_md.append(f"- num pages: `{h['num_pages']}`, page size: `{h['page_size']}`")
        pagemap_md.append("- first 24 page map entries:")
        for pe in page_map[:24]:
            pagemap_md.append(
                f"  - page {pe['page_index_1based']}: raw={fmt_hex(pe['raw'])} phys={pe['physical_page']} file_off={fmt_hex(pe['file_off']) if pe['file_off'] is not None else '-'}"
            )
            pagemap_rows.append({
                'file': h['file'],
                'page_index_1based': pe['page_index_1based'],
                'raw': pe['raw'],
                'physical_page': pe['physical_page'],
                'file_off': pe['file_off'] if pe['file_off'] is not None else '',
            })
        pagemap_md.append('')

        fixup_md.append(f"## {h['file']}")
        fixup_md.append(f"- fixup table entries: `{len(fixup_page_offsets)}` (expected `{h['num_pages'] + 1}`)")
        nonzero_pages = 0
        for i in range(max(0, len(fixup_page_offsets) - 1)):
            cur = fixup_page_offsets[i]
            nxt = fixup_page_offsets[i + 1]
            sz = max(0, nxt - cur)
            if sz > 0:
                nonzero_pages += 1
            if i < 24:
                fixup_md.append(f"  - page {i+1}: fixup_rec_off={cur} next={nxt} span={sz}")
            fixup_rows.append({
                'file': h['file'],
                'page_index_1based': i + 1,
                'fixup_rec_off': cur,
                'fixup_next_off': nxt,
                'span': sz,
            })
        fixup_md.append(f"- nonzero fixup pages: `{nonzero_pages}`")
        fixup_md.append('')

        names_by_ord = {}
        for n, ordv in rnames:
            names_by_ord.setdefault(ordv, []).append(('resident', n))
        for n, ordv in nrnames:
            names_by_ord.setdefault(ordv, []).append(('nonresident', n))

        export_md.append(f'## {h["file"]}')
        export_md.append('- Entry bundle summary:')
        for b in bundles:
            export_md.append(
                f"  - ord {b['ordinal_start']}-{b['ordinal_end']} type={b['type']} raw={b['raw'].hex() if b['raw'] else '-'}"
            )
            if b['type'] == 3 and b['count'] == 1 and len(b['raw']) == 5:
                d = decode_type3_raw(b['raw'])
                hyp_rows.append({
                    'file': h['file'],
                    'ordinal_start': b['ordinal_start'],
                    'ordinal_end': b['ordinal_end'],
                    'flags': d['flags'],
                    'raw_hex': d['bytes_hex'],
                    'u32_le_b1_4': d['u32_le_b1_4'],
                    'u32_be_b1_4': d['u32_be_b1_4'],
                    'u16_le_b1_2': d['u16_le_b1_2'],
                    'u16_be_b1_2': d['u16_be_b1_2'],
                    'u16_le_b3_4': d['u16_le_b3_4'],
                    'u16_be_b3_4': d['u16_be_b3_4'],
                })
                hyp_md.append(f'## {h["file"]} ord {b["ordinal_start"]}-{b["ordinal_end"]}')
                hyp_md.append(f"- raw: `{d['bytes_split']}`")
                hyp_md.append(f"- flags: `{d['flags']}`")
                hyp_md.append(f"- candidate `u32_le(raw[1:5])`: `{d['u32_le_b1_4']}` (`0x{d['u32_le_b1_4']:08x}`)")
                hyp_md.append(f"- candidate `u32_be(raw[1:5])`: `{d['u32_be_b1_4']}` (`0x{d['u32_be_b1_4']:08x}`)")
                hyp_md.append(f"- candidate pairs:")
                hyp_md.append(f"  - b1..2 LE `{d['u16_le_b1_2']}` / BE `{d['u16_be_b1_2']}`")
                hyp_md.append(f"  - b3..4 LE `{d['u16_le_b3_4']}` / BE `{d['u16_be_b3_4']}`")
                hyp_md.append('')

                # DDB candidate heuristic:
                # - data pages begin at h['data_pages_off']
                # - object #1 starts at page index 1 in all 3 observed VxDs
                # - type3 raw tail (b3..4 LE) resolves to a plausible offset where DDB-like
                #   struct places module name at +0x0c (e.g., MDMGR/MDHlp/MDFSD).
                obj1_file_base = h['data_pages_off']
                ddb_off = d['u16_le_b3_4']
                cand_file_off = obj1_file_base + ddb_off
                name_probe_off = cand_file_off + 0x0C
                name_probe = b''
                name_probe_txt = ''
                if 0 <= name_probe_off < len(file_bytes):
                    name_probe = file_bytes[name_probe_off:name_probe_off + 8]
                    name_probe_txt = name_probe.decode('latin1', 'replace')
                resident0 = rnames[0][0] if rnames else ''
                name_match = resident0[:5].upper() in name_probe_txt.upper() if resident0 else False

                ddb_rows.append({
                    'file': h['file'],
                    'ordinal_start': b['ordinal_start'],
                    'raw_hex': d['bytes_hex'],
                    'ddb_offset_le_b3_4': ddb_off,
                    'candidate_file_offset': cand_file_off,
                    'name_probe_offset': name_probe_off,
                    'name_probe_ascii': name_probe_txt,
                    'resident_name0': resident0,
                    'name_match': int(bool(name_match)),
                })
                ddb_md.append(f"## {h['file']} ord {b['ordinal_start']}")
                ddb_md.append(f"- raw: `{d['bytes_split']}`")
                ddb_md.append(f"- candidate DDB offset (LE b3..4): `0x{ddb_off:04x}`")
                ddb_md.append(f"- candidate file offset: `0x{cand_file_off:08x}`")
                ddb_md.append(f"- probe @ +0x0c: `{name_probe_txt}`")
                ddb_md.append(f"- resident name[0]: `{resident0}`")
                ddb_md.append(f"- name match: `{name_match}`")
                ddb_md.append('')

        export_md.append('- Named ordinals:')
        for ordv in sorted(names_by_ord.keys()):
            tagged = ', '.join([f'{kind}:{name}' for kind, name in names_by_ord[ordv]])
            export_md.append(f'  - ord {ordv}: {tagged}')
            export_rows.append({
                'file': h['file'],
                'ordinal': ordv,
                'name_sources': tagged,
            })
        if not names_by_ord:
            export_md.append('  - (none)')
        export_md.append('')

    with open(args.out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    with open(args.out_exports_csv, 'w', newline='') as f:
        fieldnames = ['file', 'ordinal', 'name_sources']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(export_rows)

    with open(args.out_entry_hyp_csv, 'w', newline='') as f:
        fieldnames = [
            'file', 'ordinal_start', 'ordinal_end', 'flags', 'raw_hex',
            'u32_le_b1_4', 'u32_be_b1_4',
            'u16_le_b1_2', 'u16_be_b1_2', 'u16_le_b3_4', 'u16_be_b3_4',
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(hyp_rows)

    with open(args.out_ddb_csv, 'w', newline='') as f:
        fieldnames = [
            'file', 'ordinal_start', 'raw_hex',
            'ddb_offset_le_b3_4', 'candidate_file_offset', 'name_probe_offset',
            'name_probe_ascii', 'resident_name0', 'name_match',
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(ddb_rows)

    Path(args.out_md).write_text('\n'.join(md_lines) + '\n', encoding='utf-8')
    Path(args.out_exports_md).write_text('\n'.join(export_md) + '\n', encoding='utf-8')
    Path(args.out_entry_hyp_md).write_text('\n'.join(hyp_md) + '\n', encoding='utf-8')
    Path(args.out_ddb_md).write_text('\n'.join(ddb_md) + '\n', encoding='utf-8')
    Path(args.out_pagemap_md).write_text('\n'.join(pagemap_md) + '\n', encoding='utf-8')
    Path(args.out_fixup_md).write_text('\n'.join(fixup_md) + '\n', encoding='utf-8')

    with open(args.out_pagemap_csv, 'w', newline='') as f:
        fieldnames = ['file', 'page_index_1based', 'raw', 'physical_page', 'file_off']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(pagemap_rows)

    with open(args.out_fixup_csv, 'w', newline='') as f:
        fieldnames = ['file', 'page_index_1based', 'fixup_rec_off', 'fixup_next_off', 'span']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(fixup_rows)


if __name__ == '__main__':
    main()
