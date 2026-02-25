#!/bin/bash
# Adaptec USBXchange 펌웨어 로더
# Cypress EZ-USB FX 기반 장치에 펌웨어를 업로드하고 usb-storage에 등록
#
# 사용법: sudo ./load_usbxchange.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FW_IHEX="$SCRIPT_DIR/usbxchange.ihex"

VENDOR_PRE="03f3"
PRODUCT_PRE="2000"
PRODUCT_POST="2001"

if [[ $EUID -ne 0 ]]; then
    echo "root 권한이 필요합니다: sudo $0" >&2
    exit 1
fi

if [[ ! -f "$FW_IHEX" ]]; then
    echo "펌웨어 파일을 찾을 수 없습니다: $FW_IHEX" >&2
    exit 1
fi

# 이미 펌웨어 로드된 장치(2001) 확인
post_line=$(lsusb -d "${VENDOR_PRE}:${PRODUCT_POST}" 2>/dev/null || true)
if [[ -n "$post_line" ]]; then
    echo "이미 펌웨어가 로드된 USBXchange가 있습니다:"
    echo "  $post_line"
    echo ""

    # usb-storage 바인딩 확인
    if lsusb -t 2>/dev/null | grep -q "Driver=usb-storage"; then
        echo "usb-storage 드라이버 바인딩 완료."
    else
        echo "usb-storage에 장치 ID 등록 중..."
        echo "${VENDOR_PRE} ${PRODUCT_POST}" > /sys/bus/usb/drivers/usb-storage/new_id 2>/dev/null || true
        sleep 2
        echo "완료. dmesg | tail -10 으로 SCSI 장치 확인하세요."
    fi
    exit 0
fi

# 펌웨어 미로드 장치(2000) 검색
pre_line=$(lsusb -d "${VENDOR_PRE}:${PRODUCT_PRE}" 2>/dev/null || true)
if [[ -z "$pre_line" ]]; then
    echo "USBXchange 장치를 찾을 수 없습니다 (${VENDOR_PRE}:${PRODUCT_PRE} / ${VENDOR_PRE}:${PRODUCT_POST})." >&2
    exit 1
fi

echo "펌웨어 미로드 USBXchange 발견:"
echo "  $pre_line"

# lsusb 출력에서 Bus/Device 번호 추출 → /dev/bus/usb 경로
bus=$(echo "$pre_line" | grep -oP 'Bus \K[0-9]+')
dev=$(echo "$pre_line" | grep -oP 'Device \K[0-9]+')
devpath="/dev/bus/usb/${bus}/${dev}"

if [[ ! -c "$devpath" ]]; then
    echo "USB 장치 노드를 찾을 수 없습니다: $devpath" >&2
    exit 1
fi

echo "펌웨어 업로드 중: $devpath ← $FW_IHEX"
fxload -t fx -D "$devpath" -I "$FW_IHEX"

echo "장치 재열거 대기 중..."
for i in $(seq 1 10); do
    sleep 1
    post_line=$(lsusb -d "${VENDOR_PRE}:${PRODUCT_POST}" 2>/dev/null || true)
    if [[ -n "$post_line" ]]; then
        echo "펌웨어 로드 성공:"
        echo "  $post_line"

        echo "usb-storage에 장치 ID 등록 중..."
        echo "${VENDOR_PRE} ${PRODUCT_POST}" > /sys/bus/usb/drivers/usb-storage/new_id 2>/dev/null || true

        sleep 3
        echo ""
        echo "=== SCSI 장치 확인 ==="
        dmesg | grep -i -E "scsi|usb-storage" | tail -10
        echo ""
        echo "sg 장치: $(ls /dev/sg* 2>/dev/null || echo '없음')"
        exit 0
    fi
done

echo "재열거 타임아웃 (10초). dmesg를 확인하세요." >&2
exit 1
