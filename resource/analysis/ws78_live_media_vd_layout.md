# WS78 Live Media VD/DRB On-Disk Layout (CONFIRMED)

Date: 2026-02-24
Source: Sony MDH-10 (FW 1.11) + Adaptec USBXChange + Linux sg generic
Media: MD DATA 140MB disc, Quick Format by MDFMT ver1.01

## 1. 장치 접속 경로

```
Adaptec USBXChange (03f3:2000)
  → fxload 펌웨어 업로드 (usbxchange.ihex)
  → 재열거 (03f3:2001 "Adaptec USBXchange Adapter")
  → usb-storage new_id 등록
  → SCSI Generic (/dev/sg5)
```

### SCSI INQUIRY
```
Vendor:  SONY
Product: MDH-10
Revision: 1.11
PDT: 16 (Bridge Controller)
ANSI: SCSI-2
RMB: 1 (Removable)
```

### READ CAPACITY
```
Last LBA: 70463 (0x1133F)
Block count: 70464
Block size: 2048 bytes
Total: 144,310,272 bytes = 137.6 MiB
```

### MODE SENSE (6)
```
Medium type: 0x03
Block descriptor: 00 00 00 00 00 00 08 00 (block length=2048)

Page 0x01 (Error Recovery): AWRE=1, read retry=5, write retry=5
Page 0x07 (Verify): verify retry=3
Page 0x08 (Caching): IC=1
Page 0x20 (Vendor): 20 0e 00 00 00 20 08 00 25 00 00 00 00 00 00 00
Page 0x21 (Vendor): 21 0e 04 00 00 00 00 00 01 10 02 10 00 00 00 00
  → 0x0110 = 272 = NumUsed (VD 값과 일치)
```

## 2. 디스크 섹터 맵 (LBA 0–3807 readable)

MO 디스크 특성: 미기록 영역은 L-EC uncorrectable error 반환 (정상 동작).

| LBA 범위 | 섹터 수 | 내용 |
|-----------|---------|------|
| 0–1055 | 1056 | 전부 0x00 (lead-in / 예약 영역) |
| 1056–1057 | 2 | **VD (Volume Descriptor)** |
| 1058 | 1 | 0x00 |
| 1059 | 1 | 비트맵/결함맵 (0x00 + 0xFF 패턴) |
| 1060 | 1 | **MTB 추정** (0x80/0x90/0xA0 태그 구조) |
| 1061 | 1 | **DRB** (디렉토리 레코드, 42바이트/엔트리) |
| 1062–1567 | 506 | 전부 0x00 |
| 1568–2110 | 543 | 파일 데이터 (Z920.EXE, MZ header) |
| 2112–3702 | 1591 | 파일 데이터 (바이너리) |
| 3704–3787 | 84 | 파일 데이터 (JPEG/Exif, "plasq skitch") |
| 3788–3807 | 20 | 전부 0x00 |
| 3808+ | — | L-EC error (미기록 영역) |

## 3. Volume Descriptor (LBA 1056) 구조 — CONFIRMED

빅엔디안 포맷 (WS37 endian-normalization 분석과 일치).

### 3.1 확정 필드

| 오프셋 | 크기 | 값 (hex) | 값 (dec) | 필드명 | 신뢰도 |
|--------|------|----------|----------|--------|--------|
| 0x00 | 1 | `00` | 0 | 레코드 타입/패딩 | CONFIRMED |
| 0x01 | 5 | `4D443030 31` | "MD001" | Identifier | CONFIRMED |
| 0x06 | 1 | `01` | 1 | Version | CONFIRMED |
| 0x07–0x0F | 9 | `00...` | 0 | 예약 | CONFIRMED |
| 0x10 | 2 | `08 00` | 2048 | BlockSize (bytes) | CONFIRMED |
| 0x12 | 2 | `00 20` | 32 | ClusterSize (sectors) | CONFIRMED |
| 0x14 | 2 | `00 04` | 4 | AllocSize (sectors) | CONFIRMED |
| 0x16 | 2 | `00 00` | 0 | 예약/패딩 | CONFIRMED |
| 0x18 | 4 | `00 00 44 D0` | 17,616 | NumAlloc (AU) | CONFIRMED |
| 0x1C | 4 | `00 00 44 D0` | 17,616 | NumRecordable (AU) | CONFIRMED |
| 0x20 | 4 | `00 00 42 C0` | 17,088 | NumAvailable (AU) | CONFIRMED |
| 0x24 | 4 | `00 00 01 10` | 272 | NumUsed (AU) | CONFIRMED |

검증: 17,616 AU × 4 sectors × 2048 bytes = 144,310,272 = READ CAPACITY 값과 정확히 일치.
검증: NumUsed + NumAvailable = 17,360, AllReserved = 17,616 − 17,360 = 256 AU (= 1,024 sectors).

### 3.2 파일시스템 카운터 (0x28–0x3B) — CONFIRMED (WS79)

매핑 근거: `on-disk offset = mdfsck global address - 0x5b30` (WS37 rep movsw + WS36 xref)

| 오프셋 | 크기 | 타입 | 값 | 필드명 | 신뢰도 |
|--------|------|------|-----|--------|--------|
| 0x28 | 4 | BE32 | 0 | NumDefective | CONFIRMED |
| 0x2C | 4 | — | 0 | Reserved | CONFIRMED |
| 0x30 | 2 | BE16 | 1 | NumDir | CONFIRMED |
| 0x32 | 2 | BE16 | 1 | NumFile | CONFIRMED |
| 0x34 | 4 | BE32 | 16 | MaxIdNum | CONFIRMED |
| 0x38 | 2 | BE16 | 0x0082 | VolAttr | CONFIRMED |
| 0x3A | 2 | — | 0 | Reserved | CONFIRMED |

### 3.3 VMA 위치 정보 (0x3C–0x53) — CONFIRMED (WS79)

| 오프셋 | 크기 | 타입 | 값 | 필드명 | 신뢰도 |
|--------|------|------|-----|--------|--------|
| 0x3C | 4 | BE32 | 12288 | VMALen | CONFIRMED |
| 0x40 | 4 | BE32 | 1056 | VMALoc | CONFIRMED |
| 0x44 | 2 | BE16 | 1 | VSBLoc | CONFIRMED |
| 0x46 | 2 | BE16 | 3 | VSBNum | CONFIRMED |
| 0x48 | 2 | BE16 | 4 | MTBLoc | CONFIRMED |
| 0x4A | 2 | BE16 | 1 | MTBNum | CONFIRMED |
| 0x4C | 2 | BE16 | 0 | ERBLoc | CONFIRMED |
| 0x4E | 2 | BE16 | 0 | ERBNum | CONFIRMED |
| 0x50 | 2 | BE16 | 5 | DRBLoc | CONFIRMED |
| 0x52 | 2 | BE16 | 1 | DRBNum | CONFIRMED |

### 3.4 디렉토리 정보 (0x54–0x59) — CONFIRMED (WS79)

| 오프셋 | 크기 | 타입 | 값 | 필드명 | 신뢰도 |
|--------|------|------|-----|--------|--------|
| 0x54 | 4 | BE32 | 2048 | DirLen | CONFIRMED |
| 0x58 | 2 | BE16 | 1 | NumChild | CONFIRMED |

위치 참조: VSBLoc/MTBLoc/ERBLoc/DRBLoc는 VMALoc(LBA 1056) 기준 상대 섹터 오프셋.
- VSBLoc=1 → LBA 1057 ✓, MTBLoc=4 → LBA 1060 ✓, DRBLoc=5 → LBA 1061 ✓

상세 분석: `analysis/ws79_vd_field_boundary_map.md`

### 3.3 볼륨 라벨 및 포맷터 ID

| 오프셋 | 내용 |
|--------|------|
| 0x80 | `01 00` + `"MD DATA"` (볼륨 이름) |
| 0x1A6 | `01 00` + `"MDFMT ver1.01 (c)Sony Corporation 1996 author ..."` |
| 0x1D0 | 일본어 문자열 (Shift-JIS) + `"; with Quick Format"` |
| 0x280 | `5C 59 0F 76` = Unix time 1549504374 = 2019-02-07 02:12:54 UTC |
| 0x284 | `5C 59 10 C7` = Unix time 1549504711 = 2019-02-07 02:18:31 UTC |

## 4. VSB 비트맵 (LBA 1057) — CONFIRMED

할당 비트맵. 1비트 = 1 AU (4 sectors).

| 오프셋 범위 | 패턴 | 비트 해석 |
|------------|-------|----------|
| 0x00–0x3F | `0xFF` (64 bytes) | 512비트 모두 1 (reserved/관리 AU) |
| 0x40–0x83 | `0x55` (68 bytes) | 01010101 패턴, set bits = 68×4 = **272 = NumUsed** ✓ |
| 0x84–0x7FF | `0x00` | 모두 0 (미할당) |

비트맵 해석:
- 0xFF 영역 (512비트): 관리/예약 영역 표시 (256 reserved AU × 2 = 512? 또는 bitmap encoding 차이)
- 0x55 영역: 짝수 비트만 set = 파일 데이터가 비연속 AU에 할당된 패턴

## 5. MTB (LBA 1060) — INFERRED

```
0000: 80 00 00 00 90 00 1d f0 90 00 20 00 90 00 04 d0
0010: a0 00 00 00 00 00 00 02
```

태그 바이트 구조 (1-byte tag + 3-byte BE value):

| Tag | Value | 해석 후보 |
|-----|-------|----------|
| 0x80 | 0x000000 | 헤더/시작 마커 |
| 0x90 | 0x001DF0 = 7,664 | extent 시작? |
| 0x90 | 0x002000 = 8,192 | extent 길이/끝? |
| 0x90 | 0x0004D0 = 1,232 | extent 크기? |
| 0xA0 | 0x000000 | 종료 마커? |
| 0x00 | 0x000002 | 엔트리 수? |

참고: 8192 − 7664 = 528 = 0x0210 (MODE SENSE Page 0x21의 두번째 값과 일치).

## 6. DRB 레코드 구조 (LBA 1061) — CONFIRMED

레코드 크기: **42 bytes (0x2A)** per entry.
파일명: **7+3 형식** (7바이트 이름 + 3바이트 확장자), 공백 패딩.
타임스탬프: **Unix time**, 빅엔디안 32비트.
바이트 순서: **빅엔디안**.

### 6.1 레코드 필드 맵

| 오프셋 | 크기 | 타입 | 필드명 | 신뢰도 |
|--------|------|------|--------|--------|
| +0x00 | 2 | BE16 | ID/시퀀스 | INFERRED |
| +0x02 | 2 | BE16 | 타입/플래그 | INFERRED |
| +0x04 | 2 | BE16 | 속성 | INFERRED |
| +0x06 | 10 | ASCII | 파일명 (7+3) | CONFIRMED |
| +0x10 | 4 | BE32 | 생성 타임스탬프 (Unix time) | CONFIRMED |
| +0x14 | 4 | BE32 | 수정 타임스탬프 (Unix time) | CONFIRMED |
| +0x18 | 4 | BE32 | 접근 타임스탬프 (Unix time) | CONFIRMED |
| +0x1C | 4 | BE32 | 미확인 (children 수?) | INFERRED |
| +0x20 | 4 | BE32 | 파일 크기 (bytes) | CONFIRMED |
| +0x24 | 2 | BE16 | 미확인 | UNKNOWN |
| +0x26 | 2 | BE16 | 시작 AU 번호 | CONFIRMED |
| +0x28 | 2 | BE16 | 미확인 | UNKNOWN |

### 6.2 실측 엔트리

**Entry 0 (Root Directory):**
```
00 2a 03 01 02 01 20 20 20 20 20 20 20 20 20 20
5c 59 0f 76 5c 59 10 c6 5c 59 10 c6 00 00 00 02
00 00 08 00 00 05 00 01 00 00
```
- 파일명: (공백 10자 = 루트 디렉토리)
- 타임스탬프: 2019-02-07
- +0x1C: 0x00000002 (자식 엔트리 수 = 2 추정)
- +0x20: 0x00000800 = 2048 (디렉토리 크기)
- +0x26: 0x0001 (AU 1)

**Entry 1 (Z920.EXE):**
```
00 3a 00 40 01 37 5a 39 32 30 20 20 20 45 58 45
5c 59 10 c6 5c 59 10 cd 5c 59 10 cd 00 00 00 10
00 10 f1 cc 00 00 01 88 00 00
```
- 파일명: `Z920   EXE` → **Z920.EXE**
- 생성: 2019-02-07 02:18:30 UTC
- 수정: 2019-02-07 02:18:37 UTC
- +0x20: 0x0010F1CC = **1,110,476 bytes** (파일 크기)
- +0x26: 0x0188 = **AU 392** → LBA 392×4 = **1568** ✓ (MZ header 위치와 일치)

## 7. 미해결 사항

- VD 0x28–0x5A 영역의 정확한 필드 경계 (특히 VMALen, VSBNum, MTBNum, ERBNum, DRBLoc, DRBNum)
- LBA 1060 MTB 태그 구조의 정확한 의미
- LBA 1059 비트맵의 역할 (결함맵? 확장 할당맵?)
- 0x55 비트맵의 bit ordering (LSB-first vs MSB-first)
- DRB +0x00/+0x02/+0x04 헤더 필드의 정확한 의미
- DRB +0x1C 필드의 의미 (children 수? 또는 시작 클러스터?)
- 다중 extent 파일의 extent chain 메커니즘
- LBA 2112–3702, 3704–3787 데이터의 정체 (삭제된 파일? 또는 Z920.EXE의 추가 extent?)

## 8. 크로스 검증 요약

| 항목 | VD 값 | 하드웨어 값 | 일치 |
|------|-------|------------|------|
| 총 용량 | 17616×4×2048 = 144,310,272 | READ CAPACITY: 144,310,272 | ✓ |
| NumUsed | 272 | 비트맵 0x55 set bits: 272 | ✓ |
| NumUsed | 272 | MODE SENSE 0x21: 0x0110 = 272 | ✓ |
| 블록 크기 | 2048 | READ CAPACITY block size: 2048 | ✓ |
| 파일 위치 | AU 392 → LBA 1568 | 섹터 스캔: LBA 1568에 MZ header | ✓ |
| 타임스탬프 | 0x5C590F76 | Unix time → 2019-02-07 | ✓ |
