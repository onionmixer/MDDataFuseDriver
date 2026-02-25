/*
 * mdfs_fuse.c — MDFS FUSE 드라이버 (libfuse3 low-level API)
 *
 * 사용법: mdfs-fuse <image-or-device> <mountpoint> [-o ro] [-f] [-d]
 *
 * Phase 1: RO (getattr, readdir, open, read, statfs)
 * Phase 2: RW (write, create, unlink, mkdir, rmdir, rename, truncate, utimens)
 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "mdfs.h"

/* ===================================================================
 * 글로벌 상태
 * =================================================================== */

static struct {
    mdfs_io_t  *io;
    mdfs_vd_t   vd;
    uint32_t     vd_lba;
    int          readonly;

    /* 인메모리 DRB 엔트리 캐시 */
    mdfs_entry_t entries[MDFS_MAX_ENTRIES];
    int          entry_count;
} g_mdfs;

/* ===================================================================
 * 엔트리 검색
 * =================================================================== */

/* inode(=entry_id) 또는 경로명으로 엔트리 찾기 */
static mdfs_entry_t *find_by_ino(uint32_t ino)
{
    for (int i = 0; i < g_mdfs.entry_count; i++) {
        if (g_mdfs.entries[i].entry_id == ino)
            return &g_mdfs.entries[i];
    }
    return NULL;
}

/* 경로에서 엔트리 찾기: "/" = root, "/FILE.EXT" = root 하위 */
static mdfs_entry_t *find_by_path(const char *path)
{
    if (strcmp(path, "/") == 0) {
        /* root 엔트리 찾기 (CSC=DIR, 첫번째) */
        for (int i = 0; i < g_mdfs.entry_count; i++) {
            if (g_mdfs.entries[i].csc == MDFS_CSC_DIR)
                return &g_mdfs.entries[i];
        }
        return NULL;
    }

    /* "/NAME.EXT" 형식 — 단일 레벨 */
    const char *name = path + 1; /* '/' 건너뛰기 */
    if (strchr(name, '/'))
        return NULL; /* 서브디렉토리 미지원 (Phase 1) */

    /* 대소문자 무시 비교 */
    for (int i = 0; i < g_mdfs.entry_count; i++) {
        if (g_mdfs.entries[i].csc == MDFS_CSC_DIR)
            continue; /* root 엔트리 건너뛰기 */
        if (strcasecmp(g_mdfs.entries[i].name, name) == 0)
            return &g_mdfs.entries[i];
    }
    return NULL;
}

/* ===================================================================
 * FUSE 콜백
 * =================================================================== */

static int mdfs_getattr(const char *path, struct stat *st,
                        struct fuse_file_info *fi)
{
    (void)fi;
    memset(st, 0, sizeof(*st));

    mdfs_entry_t *e = find_by_path(path);
    if (!e)
        return -ENOENT;

    if (e->csc == MDFS_CSC_DIR) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        st->st_size = e->data_size;
    } else {
        st->st_mode = S_IFREG | 0644;
        if (e->attr & MDFS_ATTR_APROTECT)
            st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = e->data_size;
    }

    st->st_ino = e->entry_id;
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = e->access_time;
    st->st_mtime = e->modify_time;
    st->st_ctime = e->create_time;
    st->st_blksize = MDFS_SECTOR_SIZE;
    st->st_blocks = (e->data_size + 511) / 512;

    return 0;
}

static int mdfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
    (void)offset;
    (void)fi;
    (void)flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    for (int i = 0; i < g_mdfs.entry_count; i++) {
        mdfs_entry_t *e = &g_mdfs.entries[i];
        if (e->csc == MDFS_CSC_DIR)
            continue; /* root 자체는 건너뛰기 */
        filler(buf, e->name, NULL, 0, 0);
    }

    return 0;
}

static int mdfs_open(const char *path, struct fuse_file_info *fi)
{
    mdfs_entry_t *e = find_by_path(path);
    if (!e)
        return -ENOENT;
    if (e->csc == MDFS_CSC_DIR)
        return -EISDIR;

    if (g_mdfs.readonly && (fi->flags & O_ACCMODE) != O_RDONLY)
        return -EROFS;

    fi->fh = e->entry_id;
    return 0;
}

static int mdfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
    (void)path;

    mdfs_entry_t *e = find_by_ino((uint32_t)fi->fh);
    if (!e)
        return -ENOENT;

    size_t bytes_read = 0;
    int rc = mdfs_data_read(g_mdfs.io, &g_mdfs.vd, e,
                            (uint64_t)offset, buf, size, &bytes_read);
    if (rc != MDFS_OK)
        return -EIO;

    return (int)bytes_read;
}

static int mdfs_statfs(const char *path, struct statvfs *st)
{
    (void)path;
    memset(st, 0, sizeof(*st));

    st->f_bsize = g_mdfs.vd.au_bytes;
    st->f_frsize = g_mdfs.vd.au_bytes;
    st->f_blocks = g_mdfs.vd.num_alloc;
    st->f_bfree = g_mdfs.vd.num_available;
    st->f_bavail = g_mdfs.vd.num_available;
    st->f_files = g_mdfs.vd.num_dir + g_mdfs.vd.num_file;
    st->f_ffree = MDFS_MAX_ENTRIES - st->f_files;
    st->f_namemax = 12; /* "BASE.EXT" */

    return 0;
}

/* === Phase 2: 쓰기 오퍼레이션 === */

static int mdfs_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)
{
    (void)path;

    if (g_mdfs.readonly)
        return -EROFS;

    mdfs_entry_t *e = find_by_ino((uint32_t)fi->fh);
    if (!e)
        return -ENOENT;

    size_t written = 0;
    int rc = mdfs_data_write(g_mdfs.io, &g_mdfs.vd, e,
                             (uint64_t)offset, buf, size, &written);
    if (rc != MDFS_OK)
        return -EIO;

    /* 타임스탬프 업데이트 */
    e->modify_time = (uint32_t)time(NULL);

    return (int)written;
}

/* DRB + VD + MTB 플러시 */
static int flush_metadata(void)
{
    /* root DRB 쓰기 */
    uint32_t drb_lba = g_mdfs.vd.vma_loc + g_mdfs.vd.drb_loc;
    int rc = mdfs_drb_write(g_mdfs.io, &g_mdfs.vd, drb_lba, g_mdfs.vd.drb_num,
                            g_mdfs.entries, g_mdfs.entry_count);
    if (rc != MDFS_OK)
        return rc;

    /* MTB 재구축 */
    rc = mdfs_mtb_rebuild(g_mdfs.io, &g_mdfs.vd);
    if (rc != MDFS_OK)
        return rc;

    /* VD 쓰기 */
    return mdfs_vd_write(g_mdfs.io, g_mdfs.vd_lba, &g_mdfs.vd);
}

static int mdfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)mode;

    if (g_mdfs.readonly)
        return -EROFS;

    if (g_mdfs.entry_count >= MDFS_MAX_ENTRIES)
        return -ENOSPC;

    const char *name = path + 1;
    if (!name[0] || strchr(name, '/'))
        return -EINVAL;

    /* 중복 확인 */
    if (find_by_path(path))
        return -EEXIST;

    mdfs_entry_t *e = &g_mdfs.entries[g_mdfs.entry_count];
    memset(e, 0, sizeof(*e));
    e->csc = MDFS_CSC_FILE;
    e->nlen = 1;
    e->attr = 0;
    if (mdfs_name_encode(name, e->raw_name) != MDFS_OK)
        return -EINVAL;
    mdfs_name_decode(e->raw_name, e->name);

    uint32_t now = (uint32_t)time(NULL);
    e->create_time = now;
    e->modify_time = now;
    e->access_time = now;

    /* EntryID 할당 */
    g_mdfs.vd.max_id_num++;
    e->entry_id = g_mdfs.vd.max_id_num;
    e->data_size = 0;

    g_mdfs.entry_count++;
    g_mdfs.vd.num_file++;

    fi->fh = e->entry_id;

    int rc = flush_metadata();
    if (rc != MDFS_OK)
        return -EIO;

    return 0;
}

static int mdfs_unlink(const char *path)
{
    if (g_mdfs.readonly)
        return -EROFS;

    mdfs_entry_t *e = find_by_path(path);
    if (!e)
        return -ENOENT;
    if (e->csc == MDFS_CSC_DIR)
        return -EISDIR;

    /* 파일 데이터 AU 해제 */
    if (e->fnum > 0 && !(e->attr & MDFS_ATTR_AFXTREC)) {
        for (uint32_t i = 0; i < e->fnum; i++) {
            mdfs_vsb_free(g_mdfs.io, &g_mdfs.vd, e->floc + i);
        }
    }

    /* 엔트리 제거 (배열 압축) */
    int idx = (int)(e - g_mdfs.entries);
    g_mdfs.entry_count--;
    if (idx < g_mdfs.entry_count)
        memmove(&g_mdfs.entries[idx], &g_mdfs.entries[idx + 1],
                (g_mdfs.entry_count - idx) * sizeof(mdfs_entry_t));

    g_mdfs.vd.num_file--;

    return flush_metadata() == MDFS_OK ? 0 : -EIO;
}

static int mdfs_truncate(const char *path, off_t size,
                         struct fuse_file_info *fi)
{
    (void)fi;

    if (g_mdfs.readonly)
        return -EROFS;

    mdfs_entry_t *e = find_by_path(path);
    if (!e)
        return -ENOENT;
    if (e->csc != MDFS_CSC_FILE)
        return -EISDIR;

    /* 축소: 초과 AU 해제 */
    if ((uint64_t)size < e->data_size && e->fnum > 0) {
        uint32_t new_au = ((uint32_t)size + g_mdfs.vd.au_bytes - 1) / g_mdfs.vd.au_bytes;
        if (new_au == 0) new_au = 0; /* 크기 0 파일 */
        for (uint32_t i = new_au; i < e->fnum; i++) {
            mdfs_vsb_free(g_mdfs.io, &g_mdfs.vd, e->floc + i);
        }
        e->fnum = new_au;
        if (new_au == 0)
            e->floc = 0;
    }

    e->data_size = (uint32_t)size;
    e->modify_time = (uint32_t)time(NULL);

    return flush_metadata() == MDFS_OK ? 0 : -EIO;
}

static int mdfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi)
{
    (void)fi;

    if (g_mdfs.readonly)
        return -EROFS;

    mdfs_entry_t *e = find_by_path(path);
    if (!e)
        return -ENOENT;

    if (tv[0].tv_nsec != UTIME_OMIT)
        e->access_time = (uint32_t)tv[0].tv_sec;
    if (tv[1].tv_nsec != UTIME_OMIT)
        e->modify_time = (uint32_t)tv[1].tv_sec;

    return flush_metadata() == MDFS_OK ? 0 : -EIO;
}

static int mdfs_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;

    if (!g_mdfs.readonly) {
        flush_metadata();
    }
    return 0;
}

static void mdfs_destroy(void *private_data)
{
    (void)private_data;

    if (!g_mdfs.readonly) {
        flush_metadata();
    }
    if (g_mdfs.io) {
        mdfs_io_close(g_mdfs.io);
        g_mdfs.io = NULL;
    }
}

/* ===================================================================
 * FUSE 오퍼레이션 테이블
 * =================================================================== */

static const struct fuse_operations mdfs_ops = {
    .getattr  = mdfs_getattr,
    .readdir  = mdfs_readdir,
    .open     = mdfs_open,
    .read     = mdfs_read,
    .write    = mdfs_write,
    .create   = mdfs_create,
    .unlink   = mdfs_unlink,
    .truncate = mdfs_truncate,
    .utimens  = mdfs_utimens,
    .release  = mdfs_release,
    .statfs   = mdfs_statfs,
    .destroy  = mdfs_destroy,
};

/* ===================================================================
 * 메인
 * =================================================================== */

static void usage(const char *prog)
{
    fprintf(stderr,
            "사용법: %s <image-or-device> <mountpoint> [FUSE options]\n"
            "  -o ro     읽기 전용 마운트\n"
            "  -f        포그라운드\n"
            "  -d        디버그\n", prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *image_path = argv[1];

    /* -o ro 확인 */
    g_mdfs.readonly = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            if (strstr(argv[i + 1], "ro"))
                g_mdfs.readonly = 1;
        }
    }

    /* 이미지 열기 */
    g_mdfs.io = mdfs_io_open(image_path, g_mdfs.readonly);
    if (!g_mdfs.io) {
        fprintf(stderr, "오류: '%s' 열기 실패\n", image_path);
        return 1;
    }

    /* VD 찾기 및 읽기 */
    g_mdfs.vd_lba = mdfs_vd_find(g_mdfs.io);
    if (g_mdfs.vd_lba == 0) {
        fprintf(stderr, "오류: MDFS VD를 찾을 수 없음\n");
        mdfs_io_close(g_mdfs.io);
        return 1;
    }

    if (mdfs_vd_read(g_mdfs.io, g_mdfs.vd_lba, &g_mdfs.vd) != MDFS_OK) {
        fprintf(stderr, "오류: VD 읽기 실패\n");
        mdfs_io_close(g_mdfs.io);
        return 1;
    }

    if (mdfs_vd_validate(&g_mdfs.vd) != MDFS_OK) {
        fprintf(stderr, "오류: VD 유효성 검증 실패\n");
        mdfs_io_close(g_mdfs.io);
        return 1;
    }

    fprintf(stderr, "MDFS: VD at LBA %u, ident=%s version=%u\n",
            g_mdfs.vd_lba, g_mdfs.vd.ident, g_mdfs.vd.version);
    fprintf(stderr, "MDFS: %u AU total, %u used, %u available, %u defective\n",
            g_mdfs.vd.num_alloc, g_mdfs.vd.num_used,
            g_mdfs.vd.num_available, g_mdfs.vd.num_defective);
    fprintf(stderr, "MDFS: %u dirs, %u files, AllocSize=%u sectors/AU\n",
            g_mdfs.vd.num_dir, g_mdfs.vd.num_file, g_mdfs.vd.alloc_size);

    /* DRB 로드 */
    uint32_t drb_lba = g_mdfs.vd.vma_loc + g_mdfs.vd.drb_loc;
    if (mdfs_drb_read(g_mdfs.io, &g_mdfs.vd, drb_lba, g_mdfs.vd.drb_num,
                      g_mdfs.entries, &g_mdfs.entry_count, MDFS_MAX_ENTRIES) != MDFS_OK) {
        fprintf(stderr, "오류: DRB 읽기 실패\n");
        mdfs_io_close(g_mdfs.io);
        return 1;
    }

    fprintf(stderr, "MDFS: DRB loaded, %d entries\n", g_mdfs.entry_count);
    for (int i = 0; i < g_mdfs.entry_count; i++) {
        mdfs_entry_t *e = &g_mdfs.entries[i];
        fprintf(stderr, "  [%d] id=%u csc=%u name='%s' size=%u",
                i, e->entry_id, e->csc, e->name, e->data_size);
        if (e->csc == MDFS_CSC_FILE)
            fprintf(stderr, " floc=%u fnum=%u", e->floc, e->fnum);
        fprintf(stderr, "\n");
    }

    /* argv 재구성: image_path 제거 */
    char **fuse_argv = malloc(sizeof(char *) * argc);
    fuse_argv[0] = argv[0];
    int fuse_argc = 1;
    for (int i = 2; i < argc; i++)
        fuse_argv[fuse_argc++] = argv[i];

    int ret = fuse_main(fuse_argc, fuse_argv, &mdfs_ops, NULL);

    free(fuse_argv);

    if (g_mdfs.io) {
        mdfs_io_close(g_mdfs.io);
        g_mdfs.io = NULL;
    }

    return ret;
}
