# mdfsck Attribute Flag Tables

Date: 2026-02-16

- relocation_count: 386
- pointer_groups_detected: 2

## table_1
- pointer_table_file_off: 0x0eb22
- entry_count: 8
- names_start_file_off: 0x0ead8
- flags_array_file_off: 0x0eac8

| idx | flag_hex | name | ptr_file_off |
| --- | --- | --- | --- |
| 1 | 0x0001 | AMIRROR | 0x0ead8 |
| 2 | 0x0002 | AINVISIBLE | 0x0eae0 |
| 3 | 0x0040 | APROTECT | 0x0eaeb |
| 4 | 0x0080 | ABACKUP | 0x0eaf4 |
| 5 | 0x0100 | AINHFORMAT | 0x0eafc |
| 6 | 0x0200 | AINHRENAME | 0x0eb07 |
| 7 | 0x0400 | AINHCOPY | 0x0eb12 |
| 8 | 0x8000 | AEXT32 | 0x0eb1b |

## table_2
- pointer_table_file_off: 0x0ebc6
- entry_count: 12
- names_start_file_off: 0x0eb5a
- flags_array_file_off: 0x0eb42

| idx | flag_hex | name | ptr_file_off |
| --- | --- | --- | --- |
| 1 | 0x0001 | ADIR | 0x0eb5a |
| 2 | 0x0002 | AINVISIBLE | 0x0eb5f |
| 3 | 0x0004 | ASYSTEM | 0x0eb6a |
| 4 | 0x0008 | ADELETED | 0x0eb72 |
| 5 | 0x0040 | APROTECT | 0x0eb7b |
| 6 | 0x0080 | ABACKUP | 0x0eb84 |
| 7 | 0x0100 | AINHDELETE | 0x0eb8c |
| 8 | 0x0200 | AINHRENAME | 0x0eb97 |
| 9 | 0x0400 | AINHCOPY | 0x0eba2 |
| 10 | 0x2000 | AEXTTYPE | 0x0ebab |
| 11 | 0x4000 | AFXTREC | 0x0ebb4 |
| 12 | 0x8000 | AAEXTREC | 0x0ebbc |

