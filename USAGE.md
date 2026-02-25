# USAGE — mdfs-tools 빌드 및 사용법

Sony MD DATA (MDFS) 파일시스템용 Linux 도구 모음.
FUSE 드라이버(`mdfs-fuse`)로 MDFS 이미지 또는 실제 MD DATA 디스크를 마운트하고,
포맷 도구(`mdfsformat`)로 빈 이미지를 생성합니다.

---

## 1. 사전 준비: Linux FUSE 모듈

mdfs-fuse는 libfuse3 (FUSE 3.x) 기반입니다.
커널 FUSE 모듈과 유저스페이스 라이브러리가 모두 필요합니다.

### 커널 FUSE 모듈 확인

대부분의 배포판에서 `fuse` 커널 모듈은 기본 포함되어 있습니다.

```bash
# 모듈 로드 확인
lsmod | grep fuse

# 로드되어 있지 않으면 수동 로드
sudo modprobe fuse

# 부팅 시 자동 로드 설정
echo "fuse" | sudo tee /etc/modules-load.d/fuse.conf
```

커널 모듈이 없는 경우 (최소 설치/커스텀 커널):

```bash
# Ubuntu/Debian — 커널 모듈 패키지 설치
sudo apt install linux-modules-$(uname -r)
sudo modprobe fuse

# 커스텀 커널 빌드 시 menuconfig 경로:
#   File systems → FUSE (Filesystem in Userspace) support
#   CONFIG_FUSE_FS=m (또는 =y)
```

### libfuse3 설치

```bash
# Ubuntu/Debian
sudo apt install libfuse3-dev pkg-config

# Fedora/RHEL
sudo dnf install fuse3-devel pkgconf-pkg-config

# Arch Linux
sudo pacman -S fuse3 pkgconf
```

`/dev/fuse` 장치 파일과 `fusermount3` 바이너리가 존재하면 준비 완료:

```bash
ls -la /dev/fuse
which fusermount3
```

### 일반 사용자 FUSE 마운트 허용

`allow_other` 옵션을 사용하려면 `/etc/fuse.conf`에서 주석 해제:

```
user_allow_other
```

---

## 2. mdfs-tools 빌드

### 의존성

| 패키지 | 용도 |
|--------|------|
| `gcc` | C11 컴파일러 |
| `make` | 빌드 시스템 |
| `libfuse3-dev` | FUSE 3.x 헤더 + 라이브러리 |
| `pkg-config` | libfuse3 플래그 자동 탐지 |

```bash
# Ubuntu/Debian 일괄 설치
sudo apt install gcc make libfuse3-dev pkg-config
```

### 빌드

```bash
cd mdfs-tools
make              # mdfs-fuse, mdfsformat 빌드
```

빌드 산출물:

| 파일 | 설명 |
|------|------|
| `mdfs-fuse` | FUSE 드라이버 실행 파일 |
| `mdfsformat` | 포맷 도구 실행 파일 |
| `libmdfs.a` | 정적 라이브러리 (io, vd, vsb, mtb, drb, extent, endian) |

### 테스트

```bash
make test         # VD 31건 + DRB 27건 = 58건
                  # resource/work_scripts/mddata_mgmt.bin 필요
```

### 정리

```bash
make clean        # .o, .a, 실행 파일 삭제
```

### 소스 구조

```
mdfs-tools/
├── include/mdfs.h         공용 헤더 (온디스크 구조체, 상수, API)
├── lib/
│   ├── io.c               블록 I/O (FILE* + SG_IO 듀얼 백엔드)
│   ├── vd.c               Volume Descriptor 파싱/생성
│   ├── vsb.c              Volume Space Bitmap (2-bit/AU)
│   ├── mtb.c              Management Table Block (TLV)
│   ├── drb.c              Directory Record Block (가변 길이)
│   ├── extent.c           파일 데이터 읽기/쓰기 (AU 연속 할당)
│   └── endian.c           BE↔LE 변환
├── fuse/mdfs_fuse.c       FUSE 드라이버 (libfuse3, FUSE_USE_VERSION 31)
├── format/mdfsformat.c    포맷 도구
└── test/                  VD/DRB 파싱 테스트
```

I/O 레이어가 경로를 자동 감지합니다:
- 일반 파일 (`*.img`, `*.bin`) → FILE* (fseek/fread/fwrite)
- SCSI Generic (`/dev/sg*`) → SG_IO ioctl (SCSI READ(10)/WRITE(10))

---

## 3. mdfs-fuse — FUSE 드라이버

MDFS 이미지 파일 또는 SCSI Generic 장치(`/dev/sg*`)를 Linux 파일시스템으로 마운트합니다.

### 기본 사용법

```
mdfs-fuse <image-or-device> <mountpoint> [옵션]
```

### 옵션

| 옵션 | 설명 |
|------|------|
| `-o ro` | 읽기 전용 마운트 |
| `-o allow_other` | 다른 사용자 접근 허용 (sudo 실행 시 필요) |
| `-f` | 포그라운드 실행 (디버그용, Ctrl+C로 종료) |
| `-d` | FUSE 디버그 모드 (모든 FUSE 호출 출력) |

### 예제: 이미지 파일 마운트

```bash
# 읽기 전용 마운트
mkdir -p /tmp/mdfs
./mdfs-fuse image.img /tmp/mdfs -o ro -f

# 읽기/쓰기 마운트
./mdfs-fuse image.img /tmp/mdfs -f

# 백그라운드 마운트
./mdfs-fuse image.img /tmp/mdfs

# 언마운트
fusermount3 -u /tmp/mdfs
```

### 예제: 실제 MDH-10 장치 마운트

MDH-10은 `/dev/sg*` (SCSI Generic) 장치로 인식되며, SG_IO ioctl로 직접 접근합니다.

```bash
# Adaptec USBXChange 펌웨어 로드
sudo ./adaptec_usbxchange/load_usbxchange.sh

# 장치 확인
lsscsi -g              # SONY MDH-10 → /dev/sgN 확인

# 읽기 전용 마운트 (sudo 필요: /dev/sg* 권한)
mkdir -p /tmp/mdfs_real
sudo ./mdfs-fuse /dev/sg5 /tmp/mdfs_real -o ro,allow_other -f &

# 파일 확인
ls -la /tmp/mdfs_real/
df -h /tmp/mdfs_real/
file /tmp/mdfs_real/Z920.EXE

# 언마운트
sudo fusermount3 -u /tmp/mdfs_real
```

### 테스트 결과 (실제 장치)

```
$ sudo ./mdfs-fuse /dev/sg5 /tmp/mdfs_real -o ro,allow_other -f &
MDFS: VD at LBA 1056, ident=MD001 version=1
MDFS: 17616 AU total, 272 used, 17088 available, 0 defective
MDFS: 1 dirs, 1 files, AllocSize=4 sectors/AU
MDFS: DRB loaded, 2 entries
  [0] id=2 csc=2 name='' size=2048
  [1] id=16 csc=1 name='Z920.EXE' size=1110476 floc=392 fnum=136

$ ls -la /tmp/mdfs_real/
합계 1183
drwxr-xr-x   2 root root    2048  2월  5  2019 .
drwxrwxrwt 264 root root   69632  2월 25 13:03 ..
-r--r--r--   1 root root 1110476  2월  5  2019 Z920.EXE

$ df -h /tmp/mdfs_real/
파일 시스템     크기  사용  가용 사용% 마운트위치
mdfs-fuse       138M  4.2M  134M    3% /tmp/mdfs_real

$ file /tmp/mdfs_real/Z920.EXE
PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive

$ md5sum /tmp/mdfs_real/Z920.EXE
b3fdf6e7b0aecd48ca7e4921773fb606  /tmp/mdfs_real/Z920.EXE
```

### RW 기능

이미지 파일에 대해 읽기/쓰기가 가능합니다 (`-o ro` 없이 마운트).

```bash
# RW 마운트
./mdfs-fuse image.img /tmp/mdfs -f &

# 파일 생성
echo "Hello MDFS" > /tmp/mdfs/TEST.TXT
dd if=/dev/urandom of=/tmp/mdfs/DATA.BIN bs=1024 count=1024   # 1MB

# 파일 삭제
rm /tmp/mdfs/DATA.BIN

# 언마운트 (메타데이터 자동 플러시)
fusermount3 -u /tmp/mdfs
```

### 제약 사항

- 파일명: 8.3 형식 (7+3 바이트, 대소문자 무시)
- 디렉토리: 단일 레벨 (루트 디렉토리만 지원)
- Extent: 연속 AU 할당만 지원 (AFXTREC/AAEXTREC 미지원)
- 장치 쓰기: `/dev/sg*` 경로에 RW 마운트 시 실제 미디어에 기록 — 주의 필요

---

## 4. mdfsformat — 포맷 도구

빈 MDFS 이미지 파일을 생성하거나 기존 이미지를 포맷합니다.

### 기본 사용법

```
mdfsformat <image-or-device> [옵션]
```

### 옵션

| 옵션 | 설명 |
|------|------|
| `-s <sectors>` | 총 섹터 수 (기본: 70464 = 140MB MD DATA) |
| `-l <label>` | 볼륨 레이블 |
| `-q` | 빠른 포맷 (데이터 영역 제로화 생략) |
| `-v` | 상세 출력 |
| `-n` | dry-run (쓰기 없이 파라미터 확인만) |

### 예제: 이미지 생성 및 포맷

```bash
# 기본 140MB 이미지 생성 (빠른 포맷)
./mdfsformat new_disk.img -q -v

# 크기 지정 (10MB = 5120 sectors)
./mdfsformat small.img -s 5120 -q -v

# dry-run (파라미터 확인)
./mdfsformat test.img -n -v
```

### 예제: 포맷 후 마운트 확인

```bash
# 이미지 생성
./mdfsformat fresh.img -q -v

# 마운트
mkdir -p /tmp/mdfs_fresh
./mdfs-fuse fresh.img /tmp/mdfs_fresh -f &

# 빈 디스크 확인
ls -la /tmp/mdfs_fresh/
df -h /tmp/mdfs_fresh/

# 파일 쓰기 테스트
echo "test" > /tmp/mdfs_fresh/HELLO.TXT
cat /tmp/mdfs_fresh/HELLO.TXT

fusermount3 -u /tmp/mdfs_fresh
```

### 출력 예시

```
$ ./mdfsformat new_disk.img -q -v
mdfsformat: 파라미터 계산
  총 섹터: 70464 (17616 AU)
  AllocSize: 4 sectors/AU (8192 bytes/AU)
  VSBNum: 3 (covers 24576 AU)
  VMA: LBA 1024, 7 sectors (VD+VSB+MTB+DRB)
  Reserved AU: 0-257 (258 AU)
  Available AU: 17358
  새 이미지 생성: 70464 sectors (144310272 bytes)
  VD written at LBA 1024
  VSB written: 3 sectors
  MTB written at LBA 1028
  DRB written at LBA 1029
mdfsformat: 완료 — new_disk.img (70464 sectors, 17616 AU, 17358 available)
```

---

## 5. 디스크 이미지 덤프 (실제 장치)

실제 MDH-10 장치에서 디스크 이미지를 덤프하는 방법입니다.

```bash
# Adaptec USBXChange 펌웨어 로드
sudo ./adaptec_usbxchange/load_usbxchange.sh

# 관리 영역 + 파일 데이터 덤프 (권장, ~30초)
sudo sg_dd if=/dev/sg5 of=mddata_mgmt.bin bs=2048 count=3808 bpt=16

# 전체 크기 이미지 생성 (미기록 영역 0 패딩)
cp mddata_mgmt.bin mddata_full.img
truncate -s $((70464 * 2048)) mddata_full.img
```

상세 SCSI 명령어: `SCSI_COMMAND.txt` 참조

---

## 6. 디스크 레이아웃 참조

```
LBA 0                                    LBA 70463
├── Lead-in (Reserved AU) ──┤── VMA ──┤── Data Area ──────────────────┤
    AU 0-255 (LBA 0-1023)   │         │
                             │         └ 파일 데이터 (AU 단위 연속 할당)
                             ├ VD  (1 sector)
                             ├ VSB (3 sectors, 2-bit/AU 비트맵)
                             ├ MTB (1 sector, TLV 형식)
                             └ DRB (1+ sectors, 가변 길이 레코드)
```

| 구조 | 설명 |
|------|------|
| VD (Volume Descriptor) | 디스크 파라미터, AU 카운터, VMA 위치 |
| VSB (Volume Space Bitmap) | AU 할당 상태 (FREE/USED/DEFECTIVE/RESERVED) |
| MTB (Media Table) | VSB 섹터별 FREE AU 요약 |
| DRB (Directory Record) | 파일/디렉토리 엔트리 (이름, 크기, 위치, 타임스탬프) |
