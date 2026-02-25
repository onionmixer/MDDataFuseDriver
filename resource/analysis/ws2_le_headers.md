# WS2 LE Header Parse

Date: 2026-02-16

## w95/extract/us/mdmgr.vxd
- LE header offset: `0x00000080`
- CPU type: `2` OS type: `4`
- Module flags: `0x00038000`
- Entry EIP: object `0` offset `0x00000000`
- Entry ESP: object `0` offset `0x00000000`
- Object count: `2`, page size: `512`
- Object table:
  - obj1: vsize=0x00003F78 base=0x00000000 flags=0x00002045 page_idx=1 pages=32 file_start=0x00001000 file_end=0x00004E00
  - obj2: vsize=0x0000005B base=0x00000000 flags=0x00002015 page_idx=33 pages=1 file_start=0x00005000 file_end=0x00005000
- Resident names (first 20):
  - ord 0: `MDMGR`
- Non-resident names (first 20):
  - ord 0: `VxD MDMGR (VtoolsD)`
  - ord 1: `_The_DDB`
- Entry bundles:
  - ord 1-1: type=3 count=1 raw_len=5

## w95/extract/us/mdhlp.vxd
- LE header offset: `0x00000080`
- CPU type: `2` OS type: `4`
- Module flags: `0x00038000`
- Entry EIP: object `0` offset `0x00000000`
- Entry ESP: object `0` offset `0x00000000`
- Object count: `2`, page size: `512`
- Object table:
  - obj1: vsize=0x0000188C base=0x00000000 flags=0x00002045 page_idx=1 pages=13 file_start=0x00001000 file_end=0x00002800
  - obj2: vsize=0x00000084 base=0x00000000 flags=0x00002015 page_idx=14 pages=1 file_start=0x00002A00 file_end=0x00002A00
- Resident names (first 20):
  - ord 0: `MDHLP`
- Non-resident names (first 20):
  - ord 0: `DOS386 MDHlp Device  (Version 4.0)`
  - ord 1: `MDHlp_DDB`
- Entry bundles:
  - ord 1-1: type=3 count=1 raw_len=5

## w95/extract/us/mdfsd.vxd
- LE header offset: `0x00000080`
- CPU type: `2` OS type: `4`
- Module flags: `0x00038000`
- Entry EIP: object `0` offset `0x00000000`
- Entry ESP: object `0` offset `0x00000000`
- Object count: `2`, page size: `512`
- Object table:
  - obj1: vsize=0x000122F4 base=0x00000000 flags=0x00002045 page_idx=1 pages=146 file_start=0x00001000 file_end=0x00013200
  - obj2: vsize=0x0000005B base=0x00000000 flags=0x00002015 page_idx=147 pages=1 file_start=0x00013400 file_end=0x00013400
- Resident names (first 20):
  - ord 0: `MDFSD`
- Non-resident names (first 20):
  - ord 0: `VxD MDFSD (VtoolsD)`
  - ord 1: `_The_DDB`
- Entry bundles:
  - ord 1-1: type=3 count=1 raw_len=5

