# WS80 VSB 비트맵 인코딩 — CONFIRMED

Date: 2026-02-25
Source: WS78 live media hex + VD 카운터 교차 검증
Method: 가설 검증 (1-bit/AU vs 2-bit/AU) + VD 4개 카운터 동시 일치 확인

## 1. 인코딩 사양

### 1.1 포맷

**2-bit per AU, MSB-first within byte** `CONFIRMED`

```
1 byte = 4 AU:  [AU₀ AU₁ AU₂ AU₃]
                 bit7-6  bit5-4  bit3-2  bit1-0

상태 코드:
  00 = FREE       (할당 가능)
  01 = USED       (파일/관리 데이터에 할당됨)
  10 = DEFECTIVE  (결함 AU)
  11 = RESERVED   (시스템 예약)
```

### 1.2 레이아웃

VSB는 VSBNum 섹터로 구성, 연속 배치. 각 섹터는 8192 AU를 커버.

```
VSBNum = ceil(NumAlloc / 8192)

VSB[0]: AU 0 – 8191
VSB[1]: AU 8192 – 16383
VSB[2]: AU 16384 – 24575 (유효: 16384–NumAlloc-1, 패딩: NumAlloc–24575)
```

NumAlloc을 초과하는 슬롯은 0xFF (= RESERVED 값)로 패딩.

### 1.3 바이트 패턴 역해석

| 바이트 | 2-bit 분해 | 의미 |
|--------|-----------|------|
| 0xFF | [11][11][11][11] | 4 AU 모두 RESERVED |
| 0x55 | [01][01][01][01] | 4 AU 모두 USED |
| 0x00 | [00][00][00][00] | 4 AU 모두 FREE |
| 0xAA | [10][10][10][10] | 4 AU 모두 DEFECTIVE |

## 2. 검증 결과

### 2.1 VD 카운터 교차 검증

유효 AU (0 – NumAlloc-1) 범위 내에서만 카운트:

| 상태 | VSB count | VD 값 | 필드명 | 일치 |
|------|-----------|-------|--------|------|
| 00 (FREE) | 17,088 | 17,088 | NumAvailable | ✓ |
| 01 (USED) | 272 | 272 | NumUsed | ✓ |
| 10 (DEFECTIVE) | 0 | 0 | NumDefective | ✓ |
| 11 (RESERVED) | 256 | 256 | Reserved† | ✓ |
| **합계** | **17,616** | **17,616** | **NumAlloc** | ✓ |

† Reserved = NumAlloc − NumUsed − NumAvailable = 17616 − 272 − 17088 = 256

**5/5 일치 — CONFIRMED**

### 2.2 패딩 영역 검증

| 범위 | 슬롯 수 | 값 | 일치 |
|------|---------|-----|------|
| AU 17616–24575 | 6,960 | 전부 11 (0xFF) | ✓ |

### 2.3 AU 영역별 상태 맵

| AU 범위 | AU 수 | 상태 | LBA 범위 | 내용 |
|---------|-------|------|----------|------|
| 0–255 | 256 | RESERVED | 0–1023 | Lead-in 영역 |
| 256–263 | 8 | USED | 1024–1055 | Pre-VMA (zeros) |
| 264–265 | 2 | USED | 1056–1063 | VD/VSB/MTB/DRB |
| 266–391 | 126 | USED | 1064–1567 | VMA 예약 공간 |
| 392–527 | 136 | USED | 1568–2111 | Z920.EXE |
| 528–17615 | 17,088 | FREE | 2112–70463 | 미할당 |

USED 272 AU 내역: VMA 오버헤드 136 AU (AU 256–391) + Z920.EXE 136 AU (AU 392–527)

### 2.4 가설 기각

| 가설 | set bits | 기대값 | 결과 |
|------|----------|--------|------|
| 1-bit/AU | 14,704 | NumUsed=272 또는 528 | ✗ 기각 |
| 2-bit/AU (패딩 포함) | 11=7,216 | Reserved=256 | ✗ 불일치 |
| **2-bit/AU (유효 AU만)** | **11=256** | **Reserved=256** | **✓ 채택** |

기각 이유: 1-bit/AU는 어떤 카운터와도 일치하지 않음. 2-bit/AU에서 패딩(NumAlloc 초과 0xFF)을 포함하면 RESERVED 카운트 불일치.

## 3. WS78 보정

WS78에서의 비트맵 해석을 보정:

| 항목 | WS78 (이전) | WS80 (확정) |
|------|-------------|-------------|
| 인코딩 | 1-bit/AU 추정 | **2-bit/AU** |
| bit ordering | LSB/MSB 미확정 | **MSB-first** (bit7-6 = 첫 AU) |
| 0xFF 의미 | "reserved/관리 AU" | **RESERVED 상태 (11)** |
| 0x55 의미 | "짝수 비트만 set" | **USED 상태 (01) × 4 AU** |
| 0x00 의미 | "미할당" | **FREE 상태 (00)** |
| LBA 1059 0xFF | "bitmap 미확정" | **NumAlloc 초과 패딩** |
| VSB[1] all 0x00 | 미해석 | **AU 8192-16383 전부 FREE** |

## 4. FUSE 구현 사양

```
// AU 상태 읽기
fn get_au_state(vsb: &[u8], au: u32) -> u8 {
    let byte_idx = (au / 4) as usize;
    let pair_idx = 3 - (au % 4);
    (vsb[byte_idx] >> (pair_idx * 2)) & 0x03
}

// 상태 코드
const AU_FREE: u8 = 0;      // 00
const AU_USED: u8 = 1;      // 01
const AU_DEFECTIVE: u8 = 2; // 10
const AU_RESERVED: u8 = 3;  // 11

// VSBNum 계산
fn vsb_sectors_needed(num_alloc: u32) -> u16 {
    ((num_alloc + 8191) / 8192) as u16  // 1 sector = 2048 bytes = 8192 AU
}
```
