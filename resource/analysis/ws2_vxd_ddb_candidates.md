# WS2 VxD DDB Candidate Mapping

Date: 2026-02-16

## w95/extract/us/mdmgr.vxd ord 1
- raw: `01 00 03 20 03`
- candidate DDB offset (LE b3..4): `0x0320`
- candidate file offset: `0x00001320`
- probe @ +0x0c: `MDMGR   `
- resident name[0]: `MDMGR`
- name match: `True`

## w95/extract/us/mdhlp.vxd ord 1
- raw: `01 00 03 bc 02`
- candidate DDB offset (LE b3..4): `0x02bc`
- candidate file offset: `0x000012bc`
- probe @ +0x0c: `MDHlp   `
- resident name[0]: `MDHLP`
- name match: `True`

## w95/extract/us/mdfsd.vxd ord 1
- raw: `01 00 03 00 52`
- candidate DDB offset (LE b3..4): `0x5200`
- candidate file offset: `0x00006200`
- probe @ +0x0c: `MDFSD   `
- resident name[0]: `MDFSD`
- name match: `True`

