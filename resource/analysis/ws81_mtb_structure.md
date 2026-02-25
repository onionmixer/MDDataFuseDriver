# WS81 MTB 구조 분석 — CONFIRMED

Date: 2026-02-24
Source: WS80 VSB 2-bit/AU + LBA 1060 원시 데이터 + VD 카운터 교차 검증
Method: VSB 섹터별 FREE AU 수 카운트 → MTB 0x90 값 비교

## 1. MTB 개요

**MTB (Management Table Block)** = VSB 섹터별 FREE AU 카운트 테이블 `CONFIRMED`

위치: VMALoc + MTBLoc = 1056 + 4 = **LBA 1060** (1 sector)

역할: 각 VSB 섹터가 커버하는 AU 범위에서 FREE 상태인 AU 수를 기록.
VSB 비트맵 전체를 스캔하지 않고도 빠르게 여유 공간을 파악할 수 있는 요약 테이블.

## 2. 온디스크 구조

### 2.1 원시 데이터

```
LBA 1060 (MTB):
0000: 80 00 00 00 90 00 1d f0 90 00 20 00 90 00 04 d0
0010: a0 00 00 00 00 00 00 02
0018: 00 00 00 00 ... (전부 0x00, 2048바이트까지)
```

유효 데이터: **24 bytes** (0x00–0x17), 나머지 2024 bytes = 0x00.

### 2.2 TLV 레코드 구조

4-byte TLV 레코드: `[tag(1)] [value(BE24, 3 bytes)]`

```
+0x00: [0x80] value=0x000000      START (헤더)
+0x04: [0x90] value=0x001DF0      DATA  (VSB[0] FREE = 7,664)
+0x08: [0x90] value=0x002000      DATA  (VSB[1] FREE = 8,192)
+0x0C: [0x90] value=0x0004D0      DATA  (VSB[2] FREE = 1,232)
+0x10: [0xA0] value=0x000000      END   (종료)
+0x14: [0x00] value=0x000002      TRAILER (의미 미확정)
```

참고: value의 내부 구조가 `[sub(1)][BE16(2)]`일 가능성도 있으나,
현재 디스크에서 byte[1]이 항상 0x00이므로 구분 불가. BE24 해석을 기본으로 채택.

### 2.3 태그 바이트 패턴

| Tag | Binary | 의미 | 신뢰도 |
|-----|--------|------|--------|
| 0x80 | 1000_0000 | 시작 마커 (value=0) | `CONFIRMED` |
| 0x90 | 1001_0000 | 데이터 엔트리 (VSB 섹터별 FREE AU 수) | `CONFIRMED` |
| 0xA0 | 1010_0000 | 종료 마커 (value=0) | `CONFIRMED` |
| 0x00 | 0000_0000 | 트레일러 (value=2) | `UNKNOWN` |

태그 bit 패턴: bit7 = 1 (항상 set), bit4-5 순차 증가 (0→1→2).

## 3. 교차 검증

### 3.1 VSB 섹터별 FREE AU 수 대조

VSB 2-bit/AU (WS80 CONFIRMED) 기반으로 각 VSB 섹터의 FREE(00) AU를 카운트:

| VSB 섹터 | AU 범위 | 유효 AU | FREE AU (VSB) | MTB 0x90 value | 일치 |
|----------|---------|---------|---------------|----------------|------|
| VSB[0] (LBA 1057) | 0–8191 | 8,192 | 7,664 | 7,664 | ✓ |
| VSB[1] (LBA 1058) | 8192–16383 | 8,192 | 8,192 | 8,192 | ✓ |
| VSB[2] (LBA 1059) | 16384–17615 | 1,232 | 1,232 | 1,232 | ✓ |
| **합계** | | **17,616** | **17,088** | **17,088** | ✓ |

### 3.2 VD 카운터 검증

| 항목 | MTB 값 | VD 값 | 필드명 | 일치 |
|------|--------|-------|--------|------|
| FREE 합계 | 17,088 | 17,088 | NumAvailable | ✓ |
| 엔트리 수 | 3 | 3 | VSBNum | ✓ |

**5/5 일치 — CONFIRMED**

### 3.3 VSB[0] 내역

```
VSB[0] (AU 0–8191, 8192 AU):
  RESERVED = 256 (AU 0–255, lead-in 영역)
  USED     = 272 (AU 256–527, VMA 구조 + Z920.EXE)
  FREE     = 7664 (AU 528–8191)
  계산: 256 + 272 + 7664 = 8192 ✓
```

## 4. TRAILER 값 (0x000002) 분석

`UNKNOWN` — 단일 디스크로는 의미 확정 불가.

후보:
| 후보 | VD/DRB 값 | 일치 |
|------|----------|------|
| DRB 엔트리 수 | 2 (root dir + Z920.EXE) | ✓ |
| NumDir + NumFile | 1 + 1 = 2 | ✓ |
| NumDir | 1 | ✗ |
| NumFile | 1 | ✗ |
| VSBNum | 3 | ✗ |
| MaxIdNum | 16 | ✗ |

DRB 엔트리 수와 NumDir+NumFile이 모두 2이므로, 다중 디스크 비교가 필요.

## 5. WS78 보정

| 항목 | WS78 (이전) | WS81 (확정) |
|------|-------------|-------------|
| MTB 역할 | "태그 구조, 의미 미확정" | **VSB 섹터별 FREE AU 카운트 테이블** |
| 0x80 tag | "헤더/시작 마커" | **START marker** (확정) |
| 0x90 tag | "extent 시작/길이/크기?" | **DATA: VSB 섹터별 FREE AU 수** |
| 0xA0 tag | "종료 마커?" | **END marker** (확정) |
| 7,664 | "extent 시작?" | **VSB[0] FREE AU 수** |
| 8,192 | "extent 길이/끝?" | **VSB[1] FREE AU 수** (= 전부 FREE) |
| 1,232 | "extent 크기?" | **VSB[2] FREE AU 수** (= 유효 AU 전부 FREE) |
| 0x000002 | "엔트리 수?" | **UNKNOWN** (DRB 엔트리 수와 일치하나 미확정) |

## 6. FUSE 구현 사양

```
// MTB TLV 파싱
const MTB_TAG_START: u8 = 0x80;
const MTB_TAG_DATA: u8 = 0x90;
const MTB_TAG_END: u8 = 0xA0;

struct MtbEntry {
    tag: u8,
    value: u32,  // BE24 (max 16,777,215 AU)
}

fn parse_mtb(sector: &[u8]) -> Vec<MtbEntry> {
    let mut entries = Vec::new();
    let mut off = 0;
    while off + 4 <= sector.len() {
        let tag = sector[off];
        let val = ((sector[off+1] as u32) << 16)
                | ((sector[off+2] as u32) << 8)
                | (sector[off+3] as u32);
        entries.push(MtbEntry { tag, value: val });
        if tag == MTB_TAG_END { break; }
        off += 4;
    }
    entries
}

// MTB 검증: DATA 엔트리 합계 == NumAvailable
fn validate_mtb(entries: &[MtbEntry], num_available: u32) -> bool {
    let sum: u32 = entries.iter()
        .filter(|e| e.tag == MTB_TAG_DATA)
        .map(|e| e.value)
        .sum();
    sum == num_available
}
```

## 7. 미해결 사항

- TRAILER (tag=0x00) 값의 정확한 의미 (다중 디스크 비교 필요)
- value 내부가 `[sub(1)][BE16(2)]` 구조인지 여부 (byte[1]이 0x00이 아닌 케이스 필요)
- 다중 extent 파일(fragmented) 상태에서 MTB 동작 확인
- DEFECTIVE AU가 있는 디스크에서 MTB 값 검증
