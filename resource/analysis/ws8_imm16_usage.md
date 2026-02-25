# imm16 Usage Scan (WS8)

Date: 2026-02-17

Targets: `0x0209`, `0x020A`, `0x0202`, `0x0243`, `0x0242`

## w31/extract/mdcache.exe
- header_size: `0x1000`
- target `0x0209`:
  typed_hits=0 raw_hits=5 raw_only=5
- target `0x020a`:
  typed_hits=0 raw_hits=5 raw_only=5
- target `0x0202`:
  typed_hits=0 raw_hits=9 raw_only=9
- target `0x0243`:
  typed_hits=0 raw_hits=1 raw_only=1
- target `0x0242`:
  typed_hits=0 raw_hits=2 raw_only=2
- typed opcode hits: none

## w31/extract/mdformat.exe
- header_size: `0x1c00`
- target `0x0209`:
  typed_hits=0 raw_hits=1 raw_only=1
- target `0x020a`:
  typed_hits=0 raw_hits=12 raw_only=12
- target `0x0202`:
  typed_hits=0 raw_hits=9 raw_only=9
- target `0x0243`:
  typed_hits=0 raw_hits=1 raw_only=1
- target `0x0242`:
  typed_hits=0 raw_hits=1 raw_only=1
- typed opcode hits: none

## w31/extract/mdfsck.exe
- header_size: `0x0800`
- target `0x0209`:
  typed_hits=0 raw_hits=0 raw_only=0
- target `0x020a`:
  typed_hits=0 raw_hits=4 raw_only=4
- target `0x0202`:
  typed_hits=0 raw_hits=2 raw_only=2
- target `0x0243`:
  typed_hits=0 raw_hits=0 raw_only=0
- target `0x0242`:
  typed_hits=0 raw_hits=0 raw_only=0
- typed opcode hits: none

## w31/extract/mdfsex.exe
- header_size: `0x0200`
- target `0x0209`:
  typed_hits=0 raw_hits=0 raw_only=0
- target `0x020a`:
  typed_hits=0 raw_hits=1 raw_only=1
- target `0x0202`:
  typed_hits=12 raw_hits=15 raw_only=15
  - push imm16 @ `0x0440c`
  - push imm16 @ `0x08297`
  - push imm16 @ `0x08e15`
  - push imm16 @ `0x097a4`
  - push imm16 @ `0x097ac`
  - push imm16 @ `0x097c1`
  - push imm16 @ `0x09ba6`
  - push imm16 @ `0x09bd6`
  - push imm16 @ `0x09c26`
  - push imm16 @ `0x09c79`
  - push imm16 @ `0x09c84`
  - push imm16 @ `0x09c9d`
- target `0x0243`:
  typed_hits=0 raw_hits=0 raw_only=0
- target `0x0242`:
  typed_hits=0 raw_hits=0 raw_only=0

