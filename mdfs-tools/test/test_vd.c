/*
 * test_vd.c — VD 파싱 테스트 (work/mddata_mgmt.bin 기준)
 *
 * 테스트 미디어 기대값 (WS78/79 CONFIRMED):
 *   VD at LBA 1056, ident="MD001", version=1
 *   BlockSize=2048, ClusterSize=32, AllocSize=4
 *   NumAlloc=17616, NumUsed=272, NumAvailable=17088, NumDefective=0
 *   VSBLoc=1, VSBNum=3, MTBLoc=4, MTBNum=1
 *   ERBLoc=0, ERBNum=0, DRBLoc=5, DRBNum=1
 *   NumDir=1, NumFile=1, MaxIdNum=16
 */
#include "mdfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST_IMAGE "../resource/work_scripts/mddata_mgmt.bin"

static int tests_passed = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { tests_passed++; } \
    else { tests_failed++; fprintf(stderr, "FAIL: %s\n", msg); } \
} while(0)

int main(void)
{
    printf("test_vd: VD 파싱 검증 (%s)\n", TEST_IMAGE);

    mdfs_io_t *io = mdfs_io_open(TEST_IMAGE, 1);
    if (!io) {
        fprintf(stderr, "오류: %s 열기 실패\n", TEST_IMAGE);
        return 1;
    }

    /* VD 탐색 */
    uint32_t vd_lba = mdfs_vd_find(io);
    CHECK(vd_lba == 1056, "VD at LBA 1056");

    /* VD 읽기 */
    mdfs_vd_t vd;
    int rc = mdfs_vd_read(io, vd_lba, &vd);
    CHECK(rc == MDFS_OK, "VD read success");

    /* 시그니처 */
    CHECK(vd.rec_type == 0, "RecType == 0");
    CHECK(memcmp(vd.ident, "MD001", 5) == 0, "ident == MD001");

    /* 디스크 파라미터 */
    CHECK(vd.block_size == 2048, "BlockSize == 2048");
    CHECK(vd.cluster_size == 32, "ClusterSize == 32");
    CHECK(vd.alloc_size == 4, "AllocSize == 4");
    CHECK(vd.au_bytes == 8192, "AU bytes == 8192");

    /* 할당 카운터 */
    CHECK(vd.num_alloc == 17616, "NumAlloc == 17616");
    CHECK(vd.num_used == 272, "NumUsed == 272");
    CHECK(vd.num_available == 17088, "NumAvailable == 17088");
    CHECK(vd.num_defective == 0, "NumDefective == 0");

    /* 카운터 합계 */
    uint32_t reserved = vd.num_alloc - vd.num_used - vd.num_available - vd.num_defective;
    CHECK(reserved == 256, "Reserved AU == 256");

    /* 파일시스템 카운터 */
    CHECK(vd.num_dir == 1, "NumDir == 1");
    CHECK(vd.num_file == 1, "NumFile == 1");
    CHECK(vd.max_id_num == 16, "MaxIdNum == 16");

    /* VMA 위치 */
    CHECK(vd.vma_loc == 1056, "VMALoc == 1056");
    CHECK(vd.vsb_loc == 1, "VSBLoc == 1");
    CHECK(vd.vsb_num == 3, "VSBNum == 3");
    CHECK(vd.mtb_loc == 4, "MTBLoc == 4");
    CHECK(vd.mtb_num == 1, "MTBNum == 1");
    CHECK(vd.erb_loc == 0, "ERBLoc == 0");
    CHECK(vd.erb_num == 0, "ERBNum == 0");
    CHECK(vd.drb_loc == 5, "DRBLoc == 5");
    CHECK(vd.drb_num == 1, "DRBNum == 1");

    /* 디렉토리 정보 */
    CHECK(vd.dir_len == 2048, "DirLen == 2048");
    CHECK(vd.num_child == 1, "NumChild == 1");

    /* 유효성 검증 */
    CHECK(mdfs_vd_validate(&vd) == MDFS_OK, "VD validation pass");

    /* 절대 LBA 계산 확인 */
    CHECK(vd.vma_loc + vd.vsb_loc == 1057, "VSB LBA == 1057");
    CHECK(vd.vma_loc + vd.mtb_loc == 1060, "MTB LBA == 1060");
    CHECK(vd.vma_loc + vd.drb_loc == 1061, "DRB LBA == 1061");

    mdfs_io_close(io);

    printf("\ntest_vd: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
