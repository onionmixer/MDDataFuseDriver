/*
 * mdfsformat.c — MDFS 포맷 도구 (Phase 3 구현 예정)
 *
 * 사용법: mdfsformat <image-or-device> [options]
 *   -s <sectors>  총 섹터 수 (기본: 70464 = 140MB MD DATA)
 *   -l <label>    볼륨 레이블
 *   -q            빠른 포맷 (데이터 영역 제로화 생략)
 *   -v            상세 출력
 *   -n            dry-run
 */
#include "mdfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_TOTAL_SECTORS  70464  /* 140MB MD DATA */

static void usage(const char *prog)
{
    fprintf(stderr,
            "사용법: %s <image-or-device> [options]\n"
            "  -s <sectors>  총 섹터 수 (기본: %d)\n"
            "  -l <label>    볼륨 레이블\n"
            "  -q            빠른 포맷\n"
            "  -v            상세 출력\n"
            "  -n            dry-run\n",
            prog, DEFAULT_TOTAL_SECTORS);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *path = argv[1];
    uint32_t total_sectors = DEFAULT_TOTAL_SECTORS;
    const char *label = NULL;
    int quick = 0, verbose = 0, dry_run = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            total_sectors = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            label = argv[++i];
        } else if (strcmp(argv[i], "-q") == 0) {
            quick = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-n") == 0) {
            dry_run = 1;
        } else {
            fprintf(stderr, "알 수 없는 옵션: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    /* 파라미터 계산 */
    uint16_t alloc_size = MDFS_DEFAULT_ALLOC_SIZE;
    uint32_t num_alloc = total_sectors / alloc_size;
    uint16_t vsb_num = (uint16_t)((num_alloc + MDFS_VSB_AU_PER_SECTOR - 1) / MDFS_VSB_AU_PER_SECTOR);
    uint16_t mtb_num = 1;
    uint16_t erb_num = 0;
    uint16_t drb_num = 1;
    uint32_t vma_sectors = 1 + vsb_num + mtb_num + erb_num + drb_num;

    /* VMA 위치: lead-in 후 (AU 256 = LBA 1024 기준) */
    uint32_t vma_loc = 256 * alloc_size; /* LBA 1024 */
    /* VMA가 충분한 공간을 확보하도록 조정 */
    uint32_t vma_end_lba = vma_loc + vma_sectors;
    uint32_t reserved_au = (vma_end_lba + alloc_size - 1) / alloc_size;

    if (verbose || dry_run) {
        printf("mdfsformat: 파라미터 계산\n");
        printf("  총 섹터: %u (%u AU)\n", total_sectors, num_alloc);
        printf("  AllocSize: %u sectors/AU (%u bytes/AU)\n",
               alloc_size, alloc_size * MDFS_DEFAULT_BLOCK_SIZE);
        printf("  VSBNum: %u (covers %u AU)\n", vsb_num, vsb_num * MDFS_VSB_AU_PER_SECTOR);
        printf("  VMA: LBA %u, %u sectors (VD+VSB+MTB+DRB)\n", vma_loc, vma_sectors);
        printf("  Reserved AU: 0-%u (%u AU)\n", reserved_au - 1, reserved_au);
        printf("  Available AU: %u\n", num_alloc - reserved_au);
        if (label)
            printf("  Label: %s\n", label);
    }

    if (dry_run) {
        printf("dry-run: 실제 쓰기 없음\n");
        return 0;
    }

    /* 이미지 열기 (또는 생성) */
    mdfs_io_t *io = mdfs_io_open(path, 0);
    if (!io) {
        /* 이미지 생성 시도 */
        FILE *fp = fopen(path, "w+b");
        if (!fp) {
            fprintf(stderr, "오류: '%s' 열기/생성 실패\n", path);
            return 1;
        }
        /* 빈 이미지 생성 */
        uint8_t zero[MDFS_SECTOR_SIZE];
        memset(zero, 0, sizeof(zero));
        for (uint32_t s = 0; s < total_sectors; s++) {
            if (fwrite(zero, MDFS_SECTOR_SIZE, 1, fp) != 1) {
                fprintf(stderr, "오류: 이미지 생성 중 쓰기 실패\n");
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
        io = mdfs_io_open(path, 0);
        if (!io) {
            fprintf(stderr, "오류: 생성된 이미지 열기 실패\n");
            return 1;
        }
        if (verbose)
            printf("  새 이미지 생성: %u sectors (%u bytes)\n",
                   total_sectors, total_sectors * MDFS_SECTOR_SIZE);
    }

    /* VD 초기화 */
    mdfs_vd_t vd;
    memset(&vd, 0, sizeof(vd));
    vd.rec_type = 0;
    memcpy(vd.ident, MDFS_IDENT, MDFS_IDENT_LEN);
    vd.ident[5] = '\0';
    vd.version = 1;
    vd.block_size = MDFS_DEFAULT_BLOCK_SIZE;
    vd.cluster_size = MDFS_DEFAULT_CLUSTER_SIZE;
    vd.alloc_size = alloc_size;
    vd.num_alloc = num_alloc;
    vd.num_recordable = num_alloc - reserved_au;
    vd.num_available = num_alloc - reserved_au;
    vd.num_used = 0;  /* VMA 자체의 USED는 reserved에 포함 */
    vd.num_defective = 0;
    vd.num_dir = 1;
    vd.num_file = 0;
    vd.max_id_num = 2; /* root = ID 2 */
    vd.vol_attr = 0;
    vd.vma_len = vma_sectors;
    vd.vma_loc = vma_loc;
    vd.vsb_loc = 1;
    vd.vsb_num = vsb_num;
    vd.mtb_loc = 1 + vsb_num;
    vd.mtb_num = mtb_num;
    vd.erb_loc = 0;
    vd.erb_num = 0;
    vd.drb_loc = 1 + vsb_num + mtb_num;
    vd.drb_num = drb_num;
    vd.dir_len = MDFS_SECTOR_SIZE;
    vd.num_child = 0;
    vd.au_bytes = (uint32_t)alloc_size * vd.block_size;

    /* VD 쓰기 */
    int rc = mdfs_vd_write(io, vma_loc, &vd);
    if (rc != MDFS_OK) {
        fprintf(stderr, "오류: VD 쓰기 실패\n");
        mdfs_io_close(io);
        return 1;
    }
    if (verbose)
        printf("  VD written at LBA %u\n", vma_loc);

    /* VSB 초기화 */
    for (uint16_t s = 0; s < vsb_num; s++) {
        uint8_t sector[MDFS_SECTOR_SIZE];
        uint32_t base_au = s * MDFS_VSB_AU_PER_SECTOR;

        for (uint32_t b = 0; b < MDFS_SECTOR_SIZE; b++) {
            uint8_t byte_val = 0;
            for (int bit = 3; bit >= 0; bit--) {
                uint32_t au = base_au + b * 4 + (3 - bit);
                int state;
                if (au >= num_alloc)
                    state = MDFS_AU_RESERVED; /* 패딩 */
                else if (au < reserved_au)
                    state = MDFS_AU_RESERVED;
                else
                    state = MDFS_AU_FREE;
                byte_val |= (state & 0x03) << (bit * 2);
            }
            sector[b] = byte_val;
        }

        uint32_t vsb_lba = vma_loc + vd.vsb_loc + s;
        rc = mdfs_io_write_sector(io, vsb_lba, sector);
        if (rc != MDFS_OK) {
            fprintf(stderr, "오류: VSB sector %u 쓰기 실패\n", s);
            mdfs_io_close(io);
            return 1;
        }
    }
    if (verbose)
        printf("  VSB written: %u sectors\n", vsb_num);

    /* MTB 재구축 */
    rc = mdfs_mtb_rebuild(io, &vd);
    if (rc != MDFS_OK) {
        fprintf(stderr, "오류: MTB 쓰기 실패\n");
        mdfs_io_close(io);
        return 1;
    }
    if (verbose)
        printf("  MTB written at LBA %u\n", vma_loc + vd.mtb_loc);

    /* DRB 초기화: 루트 디렉토리 엔트리 */
    mdfs_entry_t root;
    memset(&root, 0, sizeof(root));
    root.rec_len = MDFS_DRB_DIR_MIN;
    root.attr = MDFS_ATTR_ADIR | MDFS_ATTR_AINHDELETE | MDFS_ATTR_AINHRENAME;
    root.csc = MDFS_CSC_DIR;
    root.nlen = 1;
    memset(root.raw_name, ' ', 10);
    mdfs_name_decode(root.raw_name, root.name);
    uint32_t now = (uint32_t)time(NULL);
    root.create_time = now;
    root.modify_time = now;
    root.access_time = now;
    root.entry_id = 2;
    root.data_size = MDFS_SECTOR_SIZE;
    root.dloc = vd.drb_loc;
    root.cnum = vd.drb_num;

    uint32_t drb_lba = vma_loc + vd.drb_loc;
    rc = mdfs_drb_write(io, &vd, drb_lba, vd.drb_num, &root, 1);
    if (rc != MDFS_OK) {
        fprintf(stderr, "오류: DRB 쓰기 실패\n");
        mdfs_io_close(io);
        return 1;
    }
    if (verbose)
        printf("  DRB written at LBA %u\n", drb_lba);

    /* 데이터 영역 제로화 (빠른 포맷 시 생략) */
    if (!quick) {
        uint32_t data_start_lba = reserved_au * alloc_size;
        uint32_t data_end_lba = total_sectors;
        uint8_t zero[MDFS_SECTOR_SIZE];
        memset(zero, 0, sizeof(zero));

        if (verbose)
            printf("  데이터 영역 제로화: LBA %u-%u...\n", data_start_lba, data_end_lba - 1);

        for (uint32_t lba = data_start_lba; lba < data_end_lba; lba++) {
            mdfs_io_write_sector(io, lba, zero);
        }
    }

    mdfs_io_close(io);

    printf("mdfsformat: 완료 — %s (%u sectors, %u AU, %u available)\n",
           path, total_sectors, num_alloc, vd.num_available);
    if (label)
        printf("  볼륨 레이블: %s (TODO: VD 0x80+ 영역에 기록 필요)\n", label);

    return 0;
}
