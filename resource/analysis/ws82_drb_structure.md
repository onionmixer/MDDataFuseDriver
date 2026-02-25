# WS82 DRB 구조 분석

Date: 2026-02-24
Source: LBA 1061 DRB 원시 데이터 + VD 필드 교차 검증 + mdfsck 속성 플래그 분석
Method: 가변/고정 레코드 파싱 비교, 속성 위치 A/B 테스트, 미지 필드 VD 교차 대조

## 1. DRB 개요

**DRB (Directory Record Block)** = 디렉토리 엔트리 테이블 `CONFIRMED`

위치: VMALoc + DRBLoc = 1056 + 5 = **LBA 1061** (1 sector)

역할: 파일/디렉토리의 메타데이터(이름, 속성, 타임스탬프, 크기, 할당 위치) 저장.

## 2. 원시 데이터

```
LBA 1061 (DRB), 유효 86 bytes:
0000: 00 2a 03 01 02 01 20 20 20 20 20 20 20 20 20 20   .*....
0010: 5c 59 0f 76 5c 59 10 c6 5c 59 10 c6 00 00 00 02   \Y.v\Y..\Y......
0020: 00 00 08 00 00 05 00 01 00 00 00 3a 00 40 01 37   ...........:.@.7
0030: 5a 39 32 30 20 20 20 45 58 45 5c 59 10 c6 5c 59   Z920   EXE\Y..\Y
0040: 10 cd 5c 59 10 cd 00 00 00 10 00 10 f1 cc 00 00   ..\Y............
0050: 01 88 00 00 00 88 00 00 00 00 00 00 00 00 00 00   ................
```

이후 2048바이트까지 0x00.

## 3. 레코드 구조

### 3.1 가변 길이 레코드 `CONFIRMED`

byte[1]이 레코드 길이를 나타냄. 고정 42바이트 파싱 시 Z920.EXE의 확장 데이터가
3번째 엔트리로 잘못 해석되므로 가변 길이가 정확.

| Entry | Offset | byte[1] | 길이 | 내용 |
|-------|--------|---------|------|------|
| 0 (root) | 0x0000 | 0x2A | 42 bytes | 루트 디렉토리 |
| 1 (Z920) | 0x002A | 0x3A | 58 bytes | Z920.EXE (42 base + 16 ext) |
| — | 0x0064 | 0x00... | — | 종료 (4+ null bytes) |

검증: 고정 42바이트 파싱은 offset 0x54에서 phantom entry 생성 → 가변 길이 파싱이 유일하게 정합.

### 3.2 기본 레코드 필드 (42 bytes)

```
+0x00 [1B]  RecType     레코드 타입 (항상 0x00)          CONFIRMED
+0x01 [1B]  RecLen      레코드 길이 (가변)               CONFIRMED
+0x02 [2B]  Attributes  속성 플래그 (BE16)               CONFIRMED
+0x04 [1B]  EntryType   엔트리 타입 (아래 참조)          INFERRED
+0x05 [1B]  Unknown05   미확정 (아래 참조)               UNKNOWN
+0x06 [10B] FileName    파일명 7+3, 공백 패딩            CONFIRMED
+0x10 [4B]  CreateTime  생성 시각 (Unix UTC, BE32)       CONFIRMED
+0x14 [4B]  ModifyTime  수정 시각 (Unix UTC, BE32)       CONFIRMED
+0x18 [4B]  AccessTime  접근 시각 (Unix UTC, BE32)       CONFIRMED
+0x1C [4B]  EntryID     엔트리 ID (BE32)                 INFERRED
+0x20 [4B]  DataSize    데이터 크기 (bytes, BE32)        CONFIRMED
+0x24 [2B]  DRBLoc/0    디렉토리: DRBLoc, 파일: 0       INFERRED
+0x26 [2B]  DRBNum/SAU  디렉토리: DRBNum, 파일: StartAU INFERRED
+0x28 [2B]  Unknown28   미확정 (항상 0)                  UNKNOWN
```

### 3.3 확장 데이터 (RecLen > 42일 때)

```
+0x2A [2B]  ExtentAUCnt  익스텐트 AU 수 (BE16)          CONFIRMED
+0x2C [14B] Reserved     미사용? (전부 0x00)             UNKNOWN
```

Z920.EXE: +0x2A = 136 = ceil(1110476 / 8192) = 필요 AU 수 `CONFIRMED`

확장 영역 = RecLen - 42 = 16 bytes. 향후 fragmented 파일에서 추가 extent descriptor가
사용될 가능성 있음 (AFXTREC/AAEXTREC 플래그와 연관 추정).

## 4. 속성 플래그 (+0x02, BE16) `CONFIRMED`

속성 필드 위치 결정 근거:

| Entry | +0x02 (BE16) | ADIR bit | 예상 | 결과 |
|-------|-------------|----------|------|------|
| Root (dir) | 0x0301 | set (0x0001) | dir → ADIR ✓ | **정합** |
| Z920 (file) | 0x0040 | clear | file → !ADIR ✓ | **정합** |

+0x04를 속성으로 해석 시 Z920에 ADIR가 set되어 **부정합** → +0x02가 속성 필드 확정.

### 속성 플래그 정의 (mdfsck 기반)

| Bit | 값 | 이름 | 설명 |
|-----|------|------|------|
| 0 | 0x0001 | ADIR | 디렉토리 |
| 1 | 0x0002 | AINVISIBLE | 숨김 |
| 2 | 0x0004 | ASYSTEM | 시스템 |
| 3 | 0x0008 | ADELETED | 삭제됨 |
| 6 | 0x0040 | APROTECT | 보호 |
| 7 | 0x0080 | ABACKUP | 백업 |
| 8 | 0x0100 | AINHDELETE | 삭제 금지 |
| 9 | 0x0200 | AINHRENAME | 이름변경 금지 |
| 10 | 0x0400 | AINHCOPY | 복사 금지 |
| 13 | 0x2000 | AEXTTYPE | 확장 타입 |
| 14 | 0x4000 | AFXTREC | 고정 익스텐트 레코드 |
| 15 | 0x8000 | AAEXTREC | 추가 익스텐트 레코드 |

Root 속성: 0x0301 = ADIR | AINHDELETE | AINHRENAME → 루트 디렉토리에 적합
Z920 속성: 0x0040 = APROTECT → 보호된 파일에 적합

## 5. 엔트리 타입 (+0x04) `INFERRED`

| Entry | +0x04 | 해석 |
|-------|-------|------|
| Root (dir) | 0x02 | 디렉토리 |
| Z920 (file) | 0x01 | 일반 파일 |

Attributes에 이미 ADIR가 있으므로 중복 정보이나, 파일시스템이 타입 바이트를 별도로 관리할 수 있음. 다중 디스크 비교 필요.

## 6. 필드별 교차 검증

### 6.1 파일명 (+0x06, 10 bytes) `CONFIRMED`

7+3 포맷, 공백(0x20) 패딩:

| Entry | 원시 바이트 | 해석 |
|-------|------------|------|
| Root | `20 20 20 20 20 20 20 20 20 20` | (빈 이름) |
| Z920 | `5A 39 32 30 20 20 20 45 58 45` | "Z920.EXE" |

파싱: `name[:7].rstrip() + "." + name[7:10].rstrip()`, 양쪽 모두 빈 경우 구분자 생략.

### 6.2 타임스탬프 (+0x10/+0x14/+0x18) `CONFIRMED`

| Entry | 생성 | 수정 | 접근 |
|-------|------|------|------|
| Root | 2019-02-05 04:22:14 | 2019-02-05 04:27:50 | 2019-02-05 04:27:50 |
| Z920 | 2019-02-05 04:27:50 | 2019-02-05 04:27:57 | 2019-02-05 04:27:57 |

시간 순서 논리적: 루트 생성 → Z920 생성(=루트 수정) → Z920 수정.

### 6.3 EntryID (+0x1C, BE32) `INFERRED`

| Entry | +0x1C | VD 대조 |
|-------|-------|---------|
| Root | 2 | — (고정 ID?) |
| Z920 | 16 | = MaxIdNum(16) ✓ |

max(모든 EntryID) = 16 = VD MaxIdNum → **일치**.

Root ID = 2는 ext2/3/4의 root inode = 2와 유사한 관례.
MaxIdNum = 16은 "최대 할당 ID"이며, 사이 번호(3-15)는 삭제된 파일이나
내부 구조에 사용되었을 가능성.

### 6.4 DataSize (+0x20, BE32) `CONFIRMED`

| Entry | +0x20 | 검증 |
|-------|-------|------|
| Root | 2,048 | = VD DirLen(2,048) ✓ |
| Z920 | 1,110,476 | MZ 헤더 + 파일 크기 일치 ✓ |

### 6.5 DRBLoc/StartAU (+0x24/+0x26) `INFERRED`

**디렉토리 엔트리:**

| 필드 | Root 값 | VD 대조 |
|------|---------|---------|
| +0x24 | 5 | = DRBLoc(5) ✓ |
| +0x26 | 1 | = DRBNum(1) ✓ |

→ +0x24 = 이 디렉토리의 DRB 섹터 시작 오프셋 (VMA 기준)
→ +0x26 = 이 디렉토리의 DRB 섹터 수

**파일 엔트리:**

| 필드 | Z920 값 | 검증 |
|------|---------|------|
| +0x24 | 0 | (디렉토리 아님) |
| +0x26 | 392 | AU 392 → LBA 1568, MZ 헤더 확인 ✓ |

→ +0x24 = 0 (파일에는 DRBLoc 불필요)
→ +0x26 = 파일 데이터 시작 AU

AU 1 (root의 +0x26)은 VSB에서 RESERVED 상태이므로 파일 데이터 시작 AU가 아닌
DRBNum으로 해석하는 것이 정합.

### 6.6 ExtentAUCnt (+0x2A) `CONFIRMED`

Z920.EXE 확장 데이터:

```
+0x2A: 0x0088 = 136 = ceil(1110476 / 8192) = 필요 AU 수
+0x2C–0x39: 전부 0x00 (미사용 슬롯)
```

검증:
- StartAU(392) + ExtentAUCnt(136) - 1 = AU 527
- AU 범위 392–527은 VSB에서 USED 상태 ✓
- LBA 1568에서 MZ 헤더 확인 ✓

## 7. Unknown 필드

### 7.1 +0x05 `UNKNOWN`

| Entry | 값 | 비고 |
|-------|-----|------|
| Root | 0x01 | 의미 미확정 |
| Z920 | 0x37 (55) | 파일명 바이트 합 mod 256 = 55와 일치, 그러나 root 불일치 |

다중 디스크 비교 필요.

### 7.2 +0x28 `UNKNOWN`

양 엔트리 모두 0x0000. 다중 디스크 / fragmented 파일에서 값 확인 필요.

## 8. WS78 보정

| 항목 | WS78 (이전) | WS82 (확정) |
|------|-------------|-------------|
| 레코드 길이 | "42 bytes 고정" | **가변 (byte[1] = RecLen)** |
| 속성 위치 | +0x04 | **+0x02 (BE16)** |
| +0x04 의미 | "attributes" | **EntryType (0x01=file, 0x02=dir)** (INFERRED) |
| +0x1C 의미 | "unknown" | **EntryID** (INFERRED) |
| +0x20 의미 | "file size" | **DataSize** (dir=DirLen, file=FileSize) CONFIRMED |
| +0x24 의미 | "unknown" | **DRBLoc** (dir) / 0 (file) (INFERRED) |
| +0x26 의미 | "start AU" | **DRBNum** (dir) / **StartAU** (file) (INFERRED) |
| 확장 데이터 | 미인식 | **+0x2A = ExtentAUCnt** (CONFIRMED) |

## 9. FUSE 구현 사양

```rust
// DRB 레코드 파싱
const RECTYPE_NORMAL: u8 = 0x00;

struct DrbEntry {
    rec_type: u8,       // +0x00
    rec_len: u8,        // +0x01
    attributes: u16,    // +0x02, BE16
    entry_type: u8,     // +0x04
    unknown_05: u8,     // +0x05
    filename: [u8; 10], // +0x06, 7+3 space-padded
    create_time: u32,   // +0x10, Unix UTC BE32
    modify_time: u32,   // +0x14
    access_time: u32,   // +0x18
    entry_id: u32,      // +0x1C, BE32
    data_size: u32,     // +0x20, BE32
    drb_loc_or_zero: u16, // +0x24, BE16 (dir: DRBLoc, file: 0)
    drb_num_or_sau: u16,  // +0x26, BE16 (dir: DRBNum, file: StartAU)
    unknown_28: u16,    // +0x28, BE16
}

// 속성 플래그
const ADIR: u16        = 0x0001;
const AINVISIBLE: u16  = 0x0002;
const ASYSTEM: u16     = 0x0004;
const ADELETED: u16    = 0x0008;
const APROTECT: u16    = 0x0040;
const ABACKUP: u16     = 0x0080;
const AINHDELETE: u16  = 0x0100;
const AINHRENAME: u16  = 0x0200;
const AINHCOPY: u16    = 0x0400;
const AEXTTYPE: u16    = 0x2000;
const AFXTREC: u16     = 0x4000;
const AAEXTREC: u16    = 0x8000;

fn parse_drb_entries(sector: &[u8]) -> Vec<DrbEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos + 4 < sector.len() {
        if sector[pos..pos+4] == [0, 0, 0, 0] { break; }
        let rec_len = sector[pos + 1] as usize;
        if rec_len < 42 || pos + rec_len > sector.len() { break; }
        // parse base 42 bytes...
        pos += rec_len;
    }
    entries
}

fn format_filename(raw: &[u8; 10]) -> String {
    let base = std::str::from_utf8(&raw[..7])
        .unwrap_or("").trim_end();
    let ext = std::str::from_utf8(&raw[7..10])
        .unwrap_or("").trim_end();
    if ext.is_empty() { base.to_string() }
    else { format!("{}.{}", base, ext) }
}
```

## 10. 미해결 사항

- +0x05 바이트의 정확한 의미 (다중 디스크 비교 필요)
- +0x28 필드 (항상 0, fragmented 파일에서 확인 필요)
- +0x24/+0x26의 디렉토리/파일 이중 해석 확정 (서브디렉토리 있는 디스크 필요)
- +0x2C 이후 확장 슬롯의 구조 (fragmented 파일 필요)
- AFXTREC/AAEXTREC 플래그가 set된 레코드의 실제 구조
- 서브디렉토리의 DRB 레코드 구조 (다중 DRB 섹터)
- EntryID 할당 규칙 (root=2, Z920=16, 중간 번호 사용 패턴)
- 삭제된 파일(ADELETED)의 레코드 처리 방식
