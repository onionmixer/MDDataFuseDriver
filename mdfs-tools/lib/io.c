/*
 * io.c — 블록 I/O 추상화 (이미지 파일 / SG 디바이스)
 *
 * 파일 경로가 /dev/sg* 패턴이면 SG_IO ioctl 백엔드 사용,
 * 그 외는 기존 FILE* 백엔드 사용.
 */
#define _GNU_SOURCE
#include "mdfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

/* SG_IO 타임아웃 (초) */
#define SG_TIMEOUT_SEC  10

struct mdfs_io {
    /* 공통 */
    int      readonly;
    uint64_t size;
    int      is_sg;       /* SG 디바이스 여부 */

    /* FILE* 백엔드 (is_sg == 0) */
    FILE    *fp;

    /* SG_IO 백엔드 (is_sg == 1) */
    int      sg_fd;
};

/* ===================================================================
 * SG 디바이스 감지
 * =================================================================== */

static int is_sg_device(const char *path)
{
    /* /dev/sg[0-9] 패턴 */
    if (strncmp(path, "/dev/sg", 7) == 0 && path[7] >= '0' && path[7] <= '9')
        return 1;
    return 0;
}

/* ===================================================================
 * SG_IO: SCSI READ CAPACITY (디스크 크기 조회)
 * =================================================================== */

static int sg_read_capacity(int fd, uint32_t *last_lba, uint32_t *block_size)
{
    uint8_t cdb[10] = { 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; /* READ CAPACITY(10) */
    uint8_t resp[8];
    uint8_t sense[32];

    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.interface_id = 'S';
    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmd_len = sizeof(cdb);
    hdr.cmdp = cdb;
    hdr.dxfer_len = sizeof(resp);
    hdr.dxferp = resp;
    hdr.mx_sb_len = sizeof(sense);
    hdr.sbp = sense;
    hdr.timeout = SG_TIMEOUT_SEC * 1000;

    if (ioctl(fd, SG_IO, &hdr) < 0)
        return MDFS_ERR_IO;
    if (hdr.status != 0)
        return MDFS_ERR_IO;

    *last_lba   = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                  ((uint32_t)resp[2] << 8)  |  (uint32_t)resp[3];
    *block_size = ((uint32_t)resp[4] << 24) | ((uint32_t)resp[5] << 16) |
                  ((uint32_t)resp[6] << 8)  |  (uint32_t)resp[7];
    return MDFS_OK;
}

/* ===================================================================
 * SG_IO: SCSI TEST UNIT READY (Unit Attention 클리어)
 * =================================================================== */

static void sg_clear_unit_attention(int fd)
{
    uint8_t cdb[6] = { 0x00, 0, 0, 0, 0, 0 }; /* TEST UNIT READY */
    uint8_t sense[32];

    for (int i = 0; i < 3; i++) {
        sg_io_hdr_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.interface_id = 'S';
        hdr.dxfer_direction = SG_DXFER_NONE;
        hdr.cmd_len = sizeof(cdb);
        hdr.cmdp = cdb;
        hdr.mx_sb_len = sizeof(sense);
        hdr.sbp = sense;
        hdr.timeout = SG_TIMEOUT_SEC * 1000;

        if (ioctl(fd, SG_IO, &hdr) < 0)
            break;
        if (hdr.status == 0)
            break; /* Unit ready */
    }
}

/* ===================================================================
 * SG_IO: SCSI READ(10) / WRITE(10)
 * =================================================================== */

static int sg_read_sector(int fd, uint32_t lba, void *buf)
{
    uint8_t cdb[10] = {
        0x28, 0,                                    /* READ(10) */
        (lba >> 24) & 0xFF, (lba >> 16) & 0xFF,
        (lba >> 8) & 0xFF,  lba & 0xFF,
        0, 0, 1, 0                                  /* 1 sector */
    };
    uint8_t sense[32];

    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.interface_id = 'S';
    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmd_len = sizeof(cdb);
    hdr.cmdp = cdb;
    hdr.dxfer_len = MDFS_SECTOR_SIZE;
    hdr.dxferp = buf;
    hdr.mx_sb_len = sizeof(sense);
    hdr.sbp = sense;
    hdr.timeout = SG_TIMEOUT_SEC * 1000;

    if (ioctl(fd, SG_IO, &hdr) < 0)
        return MDFS_ERR_IO;
    if (hdr.status != 0)
        return MDFS_ERR_IO;

    return MDFS_OK;
}

static int sg_write_sector(int fd, uint32_t lba, const void *buf)
{
    uint8_t cdb[10] = {
        0x2A, 0,                                    /* WRITE(10) */
        (lba >> 24) & 0xFF, (lba >> 16) & 0xFF,
        (lba >> 8) & 0xFF,  lba & 0xFF,
        0, 0, 1, 0                                  /* 1 sector */
    };
    uint8_t sense[32];

    sg_io_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.interface_id = 'S';
    hdr.dxfer_direction = SG_DXFER_TO_DEV;
    hdr.cmd_len = sizeof(cdb);
    hdr.cmdp = cdb;
    hdr.dxfer_len = MDFS_SECTOR_SIZE;
    hdr.dxferp = (void *)buf;
    hdr.mx_sb_len = sizeof(sense);
    hdr.sbp = sense;
    hdr.timeout = SG_TIMEOUT_SEC * 1000;

    if (ioctl(fd, SG_IO, &hdr) < 0)
        return MDFS_ERR_IO;
    if (hdr.status != 0)
        return MDFS_ERR_IO;

    return MDFS_OK;
}

/* ===================================================================
 * 공개 API
 * =================================================================== */

mdfs_io_t *mdfs_io_open(const char *path, int readonly)
{
    mdfs_io_t *io = calloc(1, sizeof(*io));
    if (!io)
        return NULL;

    io->readonly = readonly;
    io->sg_fd = -1;

    if (is_sg_device(path)) {
        /* SG 디바이스 백엔드 */
        io->is_sg = 1;
        io->sg_fd = open(path, readonly ? O_RDONLY : O_RDWR);
        if (io->sg_fd < 0) {
            free(io);
            return NULL;
        }

        /* Unit Attention 클리어 */
        sg_clear_unit_attention(io->sg_fd);

        /* READ CAPACITY로 디스크 크기 조회 */
        uint32_t last_lba, blk_size;
        if (sg_read_capacity(io->sg_fd, &last_lba, &blk_size) != MDFS_OK) {
            close(io->sg_fd);
            free(io);
            return NULL;
        }
        io->size = (uint64_t)(last_lba + 1) * blk_size;
    } else {
        /* FILE* 백엔드 */
        io->is_sg = 0;
        io->fp = fopen(path, readonly ? "rb" : "r+b");
        if (!io->fp) {
            free(io);
            return NULL;
        }

        if (fseek(io->fp, 0, SEEK_END) == 0) {
            long pos = ftell(io->fp);
            io->size = (pos > 0) ? (uint64_t)pos : 0;
            fseek(io->fp, 0, SEEK_SET);
        }
    }

    return io;
}

void mdfs_io_close(mdfs_io_t *io)
{
    if (io) {
        if (io->is_sg) {
            if (io->sg_fd >= 0)
                close(io->sg_fd);
        } else {
            if (io->fp)
                fclose(io->fp);
        }
        free(io);
    }
}

int mdfs_io_read_sector(mdfs_io_t *io, uint32_t lba, void *buf)
{
    if (io->is_sg)
        return sg_read_sector(io->sg_fd, lba, buf);

    /* FILE* 백엔드 */
    uint64_t offset = (uint64_t)lba * MDFS_SECTOR_SIZE;
    if (offset + MDFS_SECTOR_SIZE > io->size)
        return MDFS_ERR_IO;

    if (fseek(io->fp, (long)offset, SEEK_SET) != 0)
        return MDFS_ERR_IO;

    if (fread(buf, MDFS_SECTOR_SIZE, 1, io->fp) != 1)
        return MDFS_ERR_IO;

    return MDFS_OK;
}

int mdfs_io_write_sector(mdfs_io_t *io, uint32_t lba, const void *buf)
{
    if (io->readonly)
        return MDFS_ERR_IO;

    if (io->is_sg)
        return sg_write_sector(io->sg_fd, lba, buf);

    /* FILE* 백엔드 */
    uint64_t offset = (uint64_t)lba * MDFS_SECTOR_SIZE;
    if (offset + MDFS_SECTOR_SIZE > io->size)
        return MDFS_ERR_IO;

    if (fseek(io->fp, (long)offset, SEEK_SET) != 0)
        return MDFS_ERR_IO;

    if (fwrite(buf, MDFS_SECTOR_SIZE, 1, io->fp) != 1)
        return MDFS_ERR_IO;

    fflush(io->fp);
    return MDFS_OK;
}

uint64_t mdfs_io_size(mdfs_io_t *io)
{
    return io->size;
}
