#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import csv, struct


def u16(b,o): return struct.unpack_from('<H',b,o)[0]
def u32(b,o): return struct.unpack_from('<I',b,o)[0]


def parse(path: Path):
    b=path.read_bytes()
    le=u32(b,0x3c)
    if b[le:le+2]!=b'LE':
        raise ValueError(f'not LE: {path}')
    entry=le+u32(b,le+0x5c)
    data_pages=u32(b,le+0x80)

    off=entry
    ordinal=1
    bundles=[]
    while off < len(b):
        cnt=b[off]; off+=1
        if cnt==0:
            break
        btype=b[off]; off+=1
        obj=u16(b,off); off+=2

        if btype==3:
            ent_size=3  # x86 hypothesis: flags1 + off16
        elif btype==1:
            ent_size=3
        elif btype==2:
            ent_size=5
        else:
            break

        ents=[]
        for i in range(cnt):
            raw=b[off:off+ent_size]
            off += ent_size
            rec={'raw':raw.hex()}
            if btype==3 and len(raw)==3:
                flags=raw[0]
                ofs=int.from_bytes(raw[1:3],'little')
                rec.update({'flags':flags,'offset16':ofs,'file_off':data_pages+ofs})
            ents.append(rec)

        bundles.append({'ordinal_start':ordinal,'ordinal_end':ordinal+cnt-1,'type':btype,'obj':obj,'entries':ents})
        ordinal += cnt

    return bundles


def main():
    files=[
        Path('w95/extract/us/mdmgr.vxd'),
        Path('w95/extract/us/mdhlp.vxd'),
        Path('w95/extract/us/mdfsd.vxd'),
    ]
    rows=[]
    md=['# LE Entry x86 Interpretation', '', 'Date: 2026-02-16', '']
    for f in files:
        bs=parse(f)
        md.append(f'## {f}')
        for b in bs:
            md.append(f"- ord {b['ordinal_start']}-{b['ordinal_end']} type={b['type']} obj={b['obj']}")
            for i,e in enumerate(b['entries'],1):
                if 'offset16' in e:
                    md.append(f"  - entry{i}: raw={e['raw']} flags={e['flags']} offset16=0x{e['offset16']:04x} file_off=0x{e['file_off']:08x}")
                    rows.append({
                        'file':str(f),
                        'ordinal_start':b['ordinal_start'],
                        'ordinal_end':b['ordinal_end'],
                        'type':b['type'],
                        'obj':b['obj'],
                        'raw':e['raw'],
                        'flags':e['flags'],
                        'offset16':e['offset16'],
                        'file_off':e['file_off'],
                    })
                else:
                    md.append(f"  - entry{i}: raw={e['raw']}")
        md.append('')

    Path('analysis/ws2_le_entry_x86.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
    with open('analysis/ws2_le_entry_x86.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['file','ordinal_start','ordinal_end','type','obj','raw','flags','offset16','file_off'])
        w.writeheader(); w.writerows(rows)
    print('wrote analysis/ws2_le_entry_x86.md and .csv')

if __name__=='__main__':
    main()
