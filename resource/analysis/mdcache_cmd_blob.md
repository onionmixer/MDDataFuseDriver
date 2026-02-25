# mdcache Command Blob Notes

Date: 2026-02-16

## 1) Token Blob Slice
- file_off: `0x0d050`
```text
...:\mdctl.ON.ERROR:.OFF.ERROR:.IS.ERROR:.FLUSH.ERROR:.?..Abnormal program termination..........................................
```

## 2) Relocation hits near blob
| rel# | ptr_cell | far(off:seg) | target | preview |
| --- | --- | --- | --- | --- |
| 115 | 0x0d03a | 07b2:0b8a | 0x0d052 | .:\mdctl.ON.ERROR:.OFF.ERROR:.IS.ERROR:.FLUSH.ER |
| 127 | 0x0d0b4 | 03a9:0000 | 0x013a9 | VW_^.U..VW.~..u"................\..>...u....o... |
| 128 | 0x0d0b0 | 03a9:0000 | 0x013a9 | VW_^.U..VW.~..u"................\..>...u....o... |
| 129 | 0x0d0ac | 03a9:0000 | 0x013a9 | VW_^.U..VW.~..u"................\..>...u....o... |

## 3) Candidate descriptor words (`0x0d0c8..`)
| idx | file_off | word_hex |
| --- | --- | --- |
| 00 | 0x0d0c8 | 0x0000 |
| 01 | 0x0d0ca | 0x0818 |
| 02 | 0x0d0cc | 0x0000 |
| 03 | 0x0d0ce | 0x020a |
| 04 | 0x0d0d0 | 0x0001 |
| 05 | 0x0d0d2 | 0x0000 |
| 06 | 0x0d0d4 | 0x0000 |
| 07 | 0x0d0d6 | 0x0000 |
| 08 | 0x0d0d8 | 0x0000 |
| 09 | 0x0d0da | 0x0000 |
| 10 | 0x0d0dc | 0x0000 |
| 11 | 0x0d0de | 0x082c |
| 12 | 0x0d0e0 | 0x0000 |
| 13 | 0x0d0e2 | 0x0202 |
| 14 | 0x0d0e4 | 0x0002 |
| 15 | 0x0d0e6 | 0x0000 |
| 16 | 0x0d0e8 | 0x0000 |
| 17 | 0x0d0ea | 0x0000 |
| 18 | 0x0d0ec | 0x0000 |
| 19 | 0x0d0ee | 0x0000 |
| 20 | 0x0d0f0 | 0x0000 |
| 21 | 0x0d0f2 | 0x0840 |
| 22 | 0x0d0f4 | 0x0000 |
| 23 | 0x0d0f6 | 0x0243 |
| 24 | 0x0d0f8 | 0x0003 |
| 25 | 0x0d0fa | 0x0000 |
| 26 | 0x0d0fc | 0x0000 |
| 27 | 0x0d0fe | 0x0000 |
| 28 | 0x0d100 | 0x0000 |
| 29 | 0x0d102 | 0x0000 |
| 30 | 0x0d104 | 0x0000 |
| 31 | 0x0d106 | 0x0854 |
| 32 | 0x0d108 | 0x0000 |
| 33 | 0x0d10a | 0x0242 |
| 34 | 0x0d10c | 0x0004 |
| 35 | 0x0d10e | 0x0000 |
| 36 | 0x0d110 | 0x0000 |
| 37 | 0x0d112 | 0x0000 |
| 38 | 0x0d114 | 0x0000 |
| 39 | 0x0d116 | 0x0000 |

## 4) Candidate descriptor dwords by alignment
| idx | a0_file_off | a0_dword | a2_file_off | a2_dword |
| --- | --- | --- | --- | --- |
| 00 | 0x0d0c8 | 0x08180000 | 0x0d0ca | 0x00000818 |
| 01 | 0x0d0cc | 0x020a0000 | 0x0d0ce | 0x0001020a |
| 02 | 0x0d0d0 | 0x00000001 | 0x0d0d2 | 0x00000000 |
| 03 | 0x0d0d4 | 0x00000000 | 0x0d0d6 | 0x00000000 |
| 04 | 0x0d0d8 | 0x00000000 | 0x0d0da | 0x00000000 |
| 05 | 0x0d0dc | 0x082c0000 | 0x0d0de | 0x0000082c |
| 06 | 0x0d0e0 | 0x02020000 | 0x0d0e2 | 0x00020202 |
| 07 | 0x0d0e4 | 0x00000002 | 0x0d0e6 | 0x00000000 |
| 08 | 0x0d0e8 | 0x00000000 | 0x0d0ea | 0x00000000 |
| 09 | 0x0d0ec | 0x00000000 | 0x0d0ee | 0x00000000 |
| 10 | 0x0d0f0 | 0x08400000 | 0x0d0f2 | 0x00000840 |
| 11 | 0x0d0f4 | 0x02430000 | 0x0d0f6 | 0x00030243 |

Interpretation (conservative):
- Blob clearly contains command tokens: `ON`, `OFF`, `IS`, `FLUSH`, `?`.
- Relocation #115 points to this parser-related blob region.
- Relocations #127..#129 point to code offset `0x13a9` (stub-like `retf` body).
- Adjacent lanes likely represent parser/dispatch descriptors,
  but exact struct alignment/field semantics are not yet proven.
