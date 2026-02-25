Adaptec USBXChange 펌웨어 로더
================================

Adaptec USBXChange / USB2Xchange USB-SCSI 변환 동글을 Linux에서 사용하기
위한 펌웨어 로더 및 관련 파일.

개요
----
USBXChange는 Cypress EZ-USB FX 기반 장치로, 호스트에서 펌웨어를 업로드해야
동작한다.

  연결 시 (03f3:2000)  →  펌웨어 업로드  →  재열거 (03f3:2001)
                                           →  USB Mass Storage (SCSI bulk transport)

메인라인 커널에는 이 장치의 드라이버가 포함되어 있지 않다.
2005년 Rene Rebe가 커널 패치를 제출했으나 머지되지 않았다
(usbxchange-v4.patch, usbxchange-v5.patch 참조).
03f3:0001 (USBConnect 2000, 별개 제품)만 mainline에 있다.

의존성
------
  sudo apt install fxload

파일 목록
---------
  load_usbxchange.sh    펌웨어 로드 + usb-storage 등록 자동화 스크립트
  usbxchange.fw         USBXChange 바이너리 펌웨어 (28바이트/레코드, LE)
  usb2xchange.fw        USB2Xchange 바이너리 펌웨어
  usbxchange.ihex       usbxchange.fw를 Intel HEX로 변환한 것 (fxload 입력용)
  fw2ihex.py            .fw → .ihex 변환 스크립트
  usbxchange-v4.patch   Rene Rebe 커널 패치 v4 (linux-2.6.14, 참고용)
  usbxchange-v5.patch   Rene Rebe 커널 패치 v5 (linux-2.6.15, 참고용)

사용법
------
1. 펌웨어 로드 (자동)

   sudo ./load_usbxchange.sh

   스크립트가 다음을 순서대로 수행한다:
   - 03f3:2000 장치 탐색
   - fxload로 usbxchange.ihex 업로드
   - 03f3:2001 재열거 대기 (최대 10초)
   - usb-storage 드라이버에 장치 ID 등록

2. 펌웨어 로드 (수동)

   # USB 장치 경로 확인
   lsusb -d 03f3:2000
   # Bus 003 Device 031: ID 03f3:2000 Adaptec, Inc. ...

   # 펌웨어 업로드
   sudo fxload -t fx -D /dev/bus/usb/003/031 -I usbxchange.ihex

   # 재열거 확인 (03f3:2001로 변경)
   lsusb | grep 03f3

   # usb-storage 수동 등록
   echo "03f3 2001" | sudo tee /sys/bus/usb/drivers/usb-storage/new_id

3. SCSI 장치 확인

   lsscsi -g
   # [6:0:0:0]  process SONY     MDH-10           1.11  -      /dev/sg5

.fw → .ihex 변환
-----------------
usbxchange.ihex가 이미 포함되어 있으므로 통상 불필요하다.
다른 .fw 파일을 변환해야 할 경우:

  python3 fw2ihex.py usbxchange.fw usbxchange.ihex

.fw 바이너리 포맷 (레코드당 28바이트, LE):
  u32 length    데이터 길이 (최대 16)
  u32 address   타겟 주소
  u32 type      0=데이터, 비0=종료
  u8  data[16]

참고
----
- 펌웨어 원본 출처: http://dl.exactcode.de/adaptec-usbxchange/
- USBXChange와 USB2Xchange는 동일 프로토콜, 다른 펌웨어 바이너리
- 펌웨어 로드 후 PDT=16 (Bridge Controller)로 인식되어 /dev/sd* 미생성,
  /dev/sg*로만 접근 가능 (SG_IO ioctl 사용)
