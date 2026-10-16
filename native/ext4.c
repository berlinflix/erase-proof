/* Offline image cleanup through libext2fs. Never opens a block device.
 * File removal and metadata checksums use the filesystem's reference library.
 * Cleanup deliberately clears ALL unallocated history on the selected volume.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static ext2_filsys fs;
static unsigned long long free_blocks, free_inodes, slack_bytes, journal_blocks;

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static void check(errcode_t error, const char *stage) {
    if (error) {
        fprintf(stderr, "%s: %s\n", stage, error_message(error));
        exit(1);
    }
}

static void read_inode(ext2_ino_t ino, struct ext2_inode *inode) {
    check(ext2fs_read_inode(fs, ino, inode), "Read inode");
}

static void open_image(const char *path, int writable) {
    struct stat st;
    if (stat(path, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1)
        fail("Only a single-link regular image descriptor is accepted.");
    check(ext2fs_open(path, EXT2_FLAG_64BITS | (writable ? EXT2_FLAG_RW : 0),
                      0, 0, unix_io_manager, &fs), "Open ext4");
    if (ext2fs_blocks_count(fs->super) > (unsigned long long)st.st_size/fs->blocksize)
        fail("Truncated filesystem image.");
    if (fs->super->s_state != EXT2_VALID_FS || ext2fs_has_feature_journal_needs_recovery(fs->super))
        fail("Filesystem must be clean and require no journal replay.");
    if (fs->super->s_journal_dev || ext2fs_has_feature_bigalloc(fs->super) ||
        ext2fs_has_feature_quota(fs->super) || ext2fs_has_feature_inline_data(fs->super) ||
        ext2fs_has_feature_encrypt(fs->super) || ext2fs_has_feature_casefold(fs->super) ||
        ext2fs_has_feature_shared_blocks(fs->super))
        fail("External journals, bigalloc, quotas, inline data, encryption, casefold and shared blocks are refused.");
    check(ext2fs_read_bitmaps(fs), "Read allocation bitmaps");
}

/* Resolve components without following symlinks, even in parent directories. */
static ext2_ino_t resolve(const char *path, ext2_ino_t *parent, char **name) {
    ext2_ino_t ino = EXT2_ROOT_INO, previous = ino;
    struct ext2_inode inode;
    char *copy = strdup(path), *save, *part, *last = NULL;
    if (!copy || path[0] != '/' || strlen(path) > 4096) fail("Invalid internal path.");
    for (part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!strcmp(part, ".") || !strcmp(part, "..") || strlen(part) > 255)
            fail("Dot or oversized path components are refused.");
        read_inode(ino, &inode);
        if (!LINUX_S_ISDIR(inode.i_mode)) fail("Parent component is not a real directory.");
        previous = ino;
        check(ext2fs_lookup(fs, previous, part, strlen(part), NULL, &ino), "Resolve internal path");
        free(last);
        last = strdup(part);
        if (!last) fail("Out of memory.");
    }
    free(copy);
    if (!last || ino < EXT2_FIRST_INODE(fs->super)) fail("Root and reserved inodes are refused.");
    *parent = previous;
    *name = last;
    return ino;
}

static int nonempty(ext2_ino_t dir, int entry, struct ext2_dir_entry *de,
                    int offset, int size, char *buffer, void *data) {
    (void)dir; (void)offset; (void)size; (void)buffer;
    if (de->inode && entry != DIRENT_DOT_FILE && entry != DIRENT_DOT_DOT_FILE)
        *(int *)data = 1;
    return 0;
}

static void remove_path(const char *path) {
    ext2_ino_t parent, ino;
    struct ext2_inode inode, parent_inode;
    char *name, *empty;
    int isdir, occupied = 0;
    ino = resolve(path, &parent, &name);
    read_inode(ino, &inode);
    isdir = LINUX_S_ISDIR(inode.i_mode);
    if (!isdir && !LINUX_S_ISREG(inode.i_mode)) fail("Only ordinary files and empty directories can be removed.");
    if ((!isdir && inode.i_links_count != 1) || (isdir && inode.i_links_count > 2))
        fail("Hard-linked files and nonempty directories are refused.");
    if (ext2fs_file_acl_block(fs, &inode)) fail("Target with external extended attributes requires a supported dedicated adapter.");
    if (isdir) {
        check(ext2fs_dir_iterate2(fs, ino, 0, NULL, nonempty, &occupied), "Inspect directory");
        if (occupied) fail("Directory is not empty.");
    }
    /* Punch updates extent/indirect trees and the allocation bitmap together. */
    check(ext2fs_punch(fs, ino, &inode, NULL, 0, ~0ULL), "Release target extents");
    check(ext2fs_unlink(fs, parent, name, ino, 0), "Unlink target");
    if (isdir) {
        read_inode(parent, &parent_inode);
        if (parent_inode.i_links_count > 1) parent_inode.i_links_count--;
        check(ext2fs_write_inode(fs, parent, &parent_inode), "Update parent links");
    }
    empty = calloc(1, EXT2_INODE_SIZE(fs->super));
    if (!empty) fail("Out of memory.");
    check(ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)empty,
                                 EXT2_INODE_SIZE(fs->super)), "Clear target inode");
    ext2fs_inode_alloc_stats2(fs, ino, -1, isdir);
    free(empty); free(name);
}

struct slack_state { int indexed; };
static int clean_slack(ext2_ino_t dir, int entry, struct ext2_dir_entry *de,
                       int offset, int size, char *buffer, void *data) {
    struct slack_state *state = data;
    unsigned int record, used;
    (void)dir; (void)buffer;
    check(ext2fs_get_rec_len(fs, de, &record), "Directory record size");
    if (record < 8 || record > (unsigned)(size-offset)) fail("Invalid directory bounds.");
    if (entry == DIRENT_CHECKSUM) return 0;
    /* HTREE interior maps occupy fake empty entries or the dotdot tail. */
    if (state->indexed && entry == DIRENT_DOT_DOT_FILE) return 0;
    if (state->indexed && !de->inode && !offset && record == (unsigned)size &&
        ext2fs_dirent_name_len(de) == 0) {
        struct ext2_dx_countlimit *counts;
        if (!ext2fs_get_dx_countlimit(fs, (struct ext2_dir_entry *)buffer, &counts, NULL) &&
            ext2fs_le16_to_cpu(counts->count) > 0 && ext2fs_le16_to_cpu(counts->limit) > 0)
            return 0;
    }
    used = de->inode ? 8U+ext2fs_dirent_name_len(de) : 8U;
    if (used > record) fail("Invalid directory name length.");
    if (!de->inode) de->name_len = 0;
    if (record > used) {
        memset((char *)de+used, 0, record-used);
        slack_bytes += record-used;
        return DIRENT_CHANGED;
    }
    return 0;
}

struct journal_state { char *zero; };
static int clean_journal(ext2_filsys handle, blk64_t *block, e2_blkcnt_t logical,
                         blk64_t ref, int offset, void *data) {
    struct journal_state *state = data;
    (void)ref; (void)offset;
    if (logical == 0) {
        char *header = malloc(handle->blocksize);
        if (!header) fail("Out of memory.");
        check(io_channel_read_blk64(handle->io, *block, 1, header), "Read journal superblock");
        if (ntohl(*(uint32_t *)header) != 0xc03b3998U || ntohl(*(uint32_t *)(header+28)))
            fail("Journal is not clean; stale transactions must not be discarded.");
        free(header);
    } else if (logical > 0) {
        check(io_channel_write_blk64(handle->io, *block, 1, state->zero), "Clear inactive journal block");
        journal_blocks++;
    }
    return 0;
}

static void scrub(void) {
    unsigned long ino, maxino = fs->super->s_inodes_count;
    blk64_t block, count = ext2fs_blocks_count(fs->super);
    char *zero = calloc(1, fs->blocksize), *empty = calloc(1, EXT2_INODE_SIZE(fs->super));
    struct ext2_inode inode;
    struct journal_state journal = {zero};
    if (!zero || !empty) fail("Out of memory.");
    /* Validate the journal before any cleanup writes. */
    if (fs->super->s_journal_inum) {
        ext2_file_t file;
        unsigned int got;
        char header[32];
        check(ext2fs_file_open(fs, fs->super->s_journal_inum, 0, &file), "Open journal");
        check(ext2fs_file_read(file, header, sizeof(header), &got), "Read journal state");
        check(ext2fs_file_close(file), "Close journal");
        if (got != sizeof(header) || ntohl(*(uint32_t *)header) != 0xc03b3998U || ntohl(*(uint32_t *)(header+28)))
            fail("Journal requires replay or has an unsupported header.");
    }
    for (ino = EXT2_ROOT_INO; ino <= maxino; ino++) {
        if (!ext2fs_test_inode_bitmap2(fs->inode_map, ino)) {
            if (ino >= EXT2_FIRST_INODE(fs->super)) {
                check(ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)empty,
                                             EXT2_INODE_SIZE(fs->super)), "Clear unused inode");
                free_inodes++;
            }
            continue;
        }
        read_inode(ino, &inode);
        if (LINUX_S_ISDIR(inode.i_mode)) {
            struct slack_state state = {!!(inode.i_flags & EXT2_INDEX_FL)};
            check(ext2fs_dir_iterate2(fs, ino, DIRENT_FLAG_INCLUDE_EMPTY, NULL,
                                      clean_slack, &state), "Clear directory slack");
        }
    }
    if (fs->super->s_journal_inum)
        check(ext2fs_block_iterate3(fs, fs->super->s_journal_inum,
                                   BLOCK_FLAG_DATA_ONLY | BLOCK_FLAG_READ_ONLY,
                                   NULL, clean_journal, &journal), "Clear inactive journal");
    for (block = fs->super->s_first_data_block; block < count; block++) {
        if (!ext2fs_test_block_bitmap2(fs->block_map, block)) {
            check(io_channel_write_blk64(fs->io, block, 1, zero), "Clear unallocated block");
            free_blocks++;
        }
    }
    free(zero); free(empty);
}

int main(int argc, char **argv) {
    int writable;
    if (argc < 3 || argc > 4) fail("Usage: eraseproof-ext4 info|remove|scrub image-fd [internal-path]");
    writable = strcmp(argv[1], "info") != 0;
    if (strcmp(argv[1], "info") && strcmp(argv[1], "remove") && strcmp(argv[1], "scrub")) fail("Unknown operation.");
    open_image(argv[2], writable);
    if (!strcmp(argv[1], "info") && argc == 4) {
        ext2_ino_t ino, parent;
        struct ext2_inode inode;
        char *name;
        ino = resolve(argv[3], &parent, &name);
        read_inode(ino, &inode);
        printf("{\"inode\":%u,\"mode\":%u,\"links\":%u,\"flags\":%u,\"external_xattrs\":%llu}\n",
               ino, inode.i_mode, inode.i_links_count, inode.i_flags,
               (unsigned long long)ext2fs_file_acl_block(fs, &inode));
        free(name);
        check(ext2fs_close(fs), "Close filesystem");
        return 0;
    } else if (!strcmp(argv[1], "remove")) {
        if (argc != 4) fail("An internal path is required.");
        remove_path(argv[3]);
    } else if (!strcmp(argv[1], "scrub")) scrub();
    printf("{\"block_size\":%u,\"free_blocks_cleared\":%llu,\"free_inodes_cleared\":%llu,\"directory_slack_bytes\":%llu,\"journal_blocks_cleared\":%llu}\n",
           fs->blocksize, free_blocks, free_inodes, slack_bytes, journal_blocks);
    check(ext2fs_close(fs), "Commit filesystem");
    return 0;
}
