/*
 * drb.c — DRB (Directory Record Block) 가변 길이 레코드 파싱/생성
 *
 * WS82+85 CONFIRMED:
 * - 공통 헤더 36 bytes (RecType, RecLen, Attr, CSC, NLen, Name, timestamps, EntryID, DataSize)
 * - 디렉토리 확장: +0x24 DLoc(BE16) + +0x26 CNum(BE16)
 * - 파일 확장: +0x24 FLoc(BE32) + +0x28 FNum(BE32) + +0x2C ALen(BE32) + +0x30 ALoc(BE32) + +0x34 ANum(BE32)
 */
#include "mdfs.h"
#include <string.h>
#include <stdio.h>

/* 이름 변환: "BASE   EXT" (10 bytes) → "BASE.EXT" (null-terminated) */
void mdfs_name_decode(const char raw[10], char out[13])
{
    /* base: raw[0..6], strip trailing spaces */
    int base_len = 7;
    while (base_len > 0 && raw[base_len - 1] == ' ')
        base_len--;

    /* ext: raw[7..9], strip trailing spaces */
    int ext_len = 3;
    while (ext_len > 0 && raw[7 + ext_len - 1] == ' ')
        ext_len--;

    int pos = 0;
    for (int i = 0; i < base_len; i++)
        out[pos++] = raw[i];

    if (ext_len > 0) {
        out[pos++] = '.';
        for (int i = 0; i < ext_len; i++)
            out[pos++] = raw[7 + i];
    }
    out[pos] = '\0';
}

int mdfs_name_encode(const char *str, char raw[10])
{
    memset(raw, ' ', 10);

    const char *dot = NULL;
    int slen = 0;
    for (int i = 0; str[i]; i++) {
        if (str[i] == '.' && !dot)
            dot = &str[i];
        slen++;
    }

    int base_len;
    if (dot) {
        base_len = (int)(dot - str);
    } else {
        base_len = slen;
    }

    if (base_len > 7)
        return MDFS_ERR_INVAL;

    for (int i = 0; i < base_len; i++)
        raw[i] = str[i];

    if (dot) {
        int ext_len = slen - base_len - 1;
        if (ext_len > 3)
            return MDFS_ERR_INVAL;
        for (int i = 0; i < ext_len; i++)
            raw[7 + i] = dot[1 + i];
    }

    return MDFS_OK;
}

/* BE16/BE32 읽기 헬퍼 (비정렬 안전) */
static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void put_be16_buf(uint8_t *p, uint16_t val)
{
    p[0] = (uint8_t)(val >> 8);
    p[1] = (uint8_t)(val);
}

static void put_be32_buf(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)(val >> 24);
    p[1] = (uint8_t)(val >> 16);
    p[2] = (uint8_t)(val >> 8);
    p[3] = (uint8_t)(val);
}

/* 단일 DRB 레코드 파싱 */
static int parse_entry(const uint8_t *data, int avail, mdfs_entry_t *entry)
{
    if (avail < 2)
        return 0;

    /* 종료 조건: 4바이트 연속 0 */
    if (avail >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0)
        return 0;

    uint8_t rec_len = data[1];
    if (rec_len < MDFS_DRB_COMMON_SIZE || rec_len > avail)
        return 0;

    memset(entry, 0, sizeof(*entry));
    entry->rec_len = rec_len;
    entry->attr = get_be16(data + 0x02);
    entry->csc = data[0x04];
    entry->nlen = data[0x05];
    memcpy(entry->raw_name, data + 0x06, 10);
    mdfs_name_decode(entry->raw_name, entry->name);
    entry->create_time = get_be32(data + 0x10);
    entry->modify_time = get_be32(data + 0x14);
    entry->access_time = get_be32(data + 0x18);
    entry->entry_id = get_be32(data + 0x1C);
    entry->data_size = get_be32(data + 0x20);

    if (entry->csc == MDFS_CSC_DIR && rec_len >= MDFS_DRB_DIR_MIN) {
        entry->dloc = get_be16(data + 0x24);
        entry->cnum = get_be16(data + 0x26);
    } else if (entry->csc == MDFS_CSC_FILE && rec_len >= MDFS_DRB_FILE_MIN) {
        entry->floc = get_be32(data + 0x24);
        entry->fnum = get_be32(data + 0x28);
        entry->alen = get_be32(data + 0x2C);
        entry->aloc = get_be32(data + 0x30);
        entry->anum = get_be32(data + 0x34);
    }

    return rec_len;
}

int mdfs_drb_read(mdfs_io_t *io, const mdfs_vd_t *vd,
                  uint32_t drb_lba, uint16_t drb_num,
                  mdfs_entry_t *entries, int *count, int max_entries)
{
    (void)vd;
    *count = 0;

    for (uint16_t s = 0; s < drb_num; s++) {
        uint8_t sector[MDFS_SECTOR_SIZE];
        int rc = mdfs_io_read_sector(io, drb_lba + s, sector);
        if (rc != MDFS_OK)
            return rc;

        int pos = 0;
        while (pos < MDFS_SECTOR_SIZE && *count < max_entries) {
            int avail = MDFS_SECTOR_SIZE - pos;
            mdfs_entry_t entry;
            int consumed = parse_entry(sector + pos, avail, &entry);
            if (consumed == 0)
                break;

            /* ADELETED 엔트리 건너뛰기 */
            if (!(entry.attr & MDFS_ATTR_ADELETED)) {
                entries[*count] = entry;
                (*count)++;
            }
            pos += consumed;
        }
    }

    return MDFS_OK;
}

/* 단일 엔트리 직렬화 */
static int serialize_entry(const mdfs_entry_t *entry, uint8_t *buf, int avail)
{
    int rec_len;
    if (entry->csc == MDFS_CSC_DIR) {
        rec_len = MDFS_DRB_DIR_MIN;
    } else {
        rec_len = MDFS_DRB_FILE_MIN;
    }

    if (rec_len > avail)
        return 0;

    memset(buf, 0, rec_len);
    buf[0x00] = 0;              /* RecType */
    buf[0x01] = (uint8_t)rec_len;
    put_be16_buf(buf + 0x02, entry->attr);
    buf[0x04] = entry->csc;
    buf[0x05] = entry->nlen;
    memcpy(buf + 0x06, entry->raw_name, 10);
    put_be32_buf(buf + 0x10, entry->create_time);
    put_be32_buf(buf + 0x14, entry->modify_time);
    put_be32_buf(buf + 0x18, entry->access_time);
    put_be32_buf(buf + 0x1C, entry->entry_id);
    put_be32_buf(buf + 0x20, entry->data_size);

    if (entry->csc == MDFS_CSC_DIR) {
        put_be16_buf(buf + 0x24, entry->dloc);
        put_be16_buf(buf + 0x26, entry->cnum);
    } else {
        put_be32_buf(buf + 0x24, entry->floc);
        put_be32_buf(buf + 0x28, entry->fnum);
        put_be32_buf(buf + 0x2C, entry->alen);
        put_be32_buf(buf + 0x30, entry->aloc);
        put_be32_buf(buf + 0x34, entry->anum);
    }

    return rec_len;
}

int mdfs_drb_write(mdfs_io_t *io, const mdfs_vd_t *vd,
                   uint32_t drb_lba, uint16_t drb_num,
                   const mdfs_entry_t *entries, int count)
{
    (void)vd;

    /* 전체 DRB 영역을 0으로 초기화 */
    uint8_t sector[MDFS_SECTOR_SIZE];
    int entry_idx = 0;
    int pos = 0;

    for (uint16_t s = 0; s < drb_num; s++) {
        memset(sector, 0, MDFS_SECTOR_SIZE);
        pos = 0;

        while (entry_idx < count && pos < MDFS_SECTOR_SIZE) {
            int avail = MDFS_SECTOR_SIZE - pos;
            int written = serialize_entry(&entries[entry_idx], sector + pos, avail);
            if (written == 0)
                break; /* 다음 섹터로 */
            pos += written;
            entry_idx++;
        }

        int rc = mdfs_io_write_sector(io, drb_lba + s, sector);
        if (rc != MDFS_OK)
            return rc;
    }

    if (entry_idx < count)
        return MDFS_ERR_NOSPC; /* DRB 섹터 부족 */

    return MDFS_OK;
}
