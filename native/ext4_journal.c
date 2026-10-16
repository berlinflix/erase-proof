/* Read-only recovery of deleted regular files from journal inode versions.
 * Never replays a journal. Recovered versions are forensic candidates, not a
 * guarantee that their current data blocks have not been reused.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ext2fs/ext2fs.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC 0xc03b3998U
#define MAX_FILE (256ULL*1024*1024)
#define MAX_TOTAL (8ULL*1024*1024*1024)
static ext2_filsys fs;
static ext2_file_t journal;
static uint32_t first, maximum, features, seed;
static unsigned long long recovered_bytes;
static unsigned int recovered_count, skipped, checksum_failures;
static int destination;

static uint32_t be32(const void *pointer) {
    uint32_t value;
    memcpy(&value, pointer, 4);
    return ntohl(value);
}

static uint16_t be16(const void *pointer) {
    uint16_t value;
    memcpy(&value, pointer, 2);
    return ntohs(value);
}

static void fail(const char *stage, errcode_t error) {
    fprintf(stderr, "%s: %s\n", stage, error_message(error));
    exit(1);
}

static void check(errcode_t error, const char *stage) {
    if (error) fail(stage, error);
}

static void read_journal(uint32_t block, void *buffer) {
    unsigned int got;
    check(ext2fs_file_llseek(journal, (uint64_t)block*fs->blocksize, SEEK_SET, NULL), "Seek journal");
    check(ext2fs_file_read(journal, buffer, fs->blocksize, &got), "Read journal");
    if (got != fs->blocksize) fail("Truncated journal", EIO);
}

static uint32_t next_block(uint32_t block) {
    return block+1 < maximum ? block+1 : first;
}

static void extract_inode(ext2_ino_t ino, struct ext2_inode *inode, uint32_t sequence) {
    uint64_t size = EXT2_I_SIZE(inode), done = 0;
    ext2_file_t file;
    unsigned int got;
    char name[100], partial[120], *buffer;
    struct stat existing;
    int fd, bad = 0;
    if (!LINUX_S_ISREG(inode->i_mode) || !inode->i_links_count || inode->i_dtime || !size ||
        inode->i_flags & (EXT4_INLINE_DATA_FL | EXT4_ENCRYPT_FL | EXT4_VERITY_FL) ||
        ext2fs_test_inode_bitmap2(fs->inode_map, ino)) return;
    if (size > MAX_FILE || recovered_bytes > MAX_TOTAL-size || recovered_count >= 10000) {
        skipped++;
        return;
    }
    if (ext2fs_has_feature_metadata_csum(fs->super) &&
        !ext2fs_inode_csum_verify(fs, ino, (struct ext2_inode_large *)inode)) {
        checksum_failures++;
        return;
    }
    snprintf(name, sizeof(name), "journal-inode-%u-transaction-%u.bin", ino, sequence);
    if (!fstatat(destination, name, &existing, AT_SYMLINK_NOFOLLOW)) return;
    if (errno != ENOENT) fail("Inspect output name", errno);
    snprintf(partial, sizeof(partial), "%s.partial", name);
    fd = openat(destination, partial, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 && errno == EEXIST) return;
    if (fd < 0) fail("Create recovered output", errno);
    if (ext2fs_file_open2(fs, ino, inode, 0, &file)) {
        close(fd); unlinkat(destination, partial, 0); skipped++; return;
    }
    buffer = malloc(1024*1024);
    if (!buffer) fail("Allocate recovery buffer", ENOMEM);
    while (done < size) {
        unsigned int count = size-done < 1024*1024 ? size-done : 1024*1024;
        if (ext2fs_file_read(file, buffer, count, &got) || got != count) { bad = 1; break; }
        unsigned int written = 0;
        while (written < got) {
            ssize_t amount = write(fd, buffer+written, got-written);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) fail("Write recovered output", errno ? errno : EIO);
            written += amount;
        }
        done += got;
    }
    free(buffer);
    if (ext2fs_file_close(file)) bad = 1;
    if (fsync(fd)) fail("Flush recovered output", errno);
    close(fd);
    if (bad) { unlinkat(destination, partial, 0); skipped++; return; }
    /* linkat publishes without overwriting an existing output. Only completed
     * candidates get the .bin name; a killed reader leaves .partial evidence. */
    if (linkat(destination, partial, destination, name, 0)) {
        if (errno != EEXIST) fail("Publish recovered output", errno);
        unlinkat(destination, partial, 0);
        return;
    }
    if (unlinkat(destination, partial, 0)) fail("Finish recovered output", errno);
    recovered_bytes += size;
    recovered_count++;
    printf("{\"inode\":%u,\"transaction\":%u,\"output\":\"%s\",\"bytes\":%llu,\"inode_checksum_checked\":%s}\n",
           ino, sequence, name, (unsigned long long)size,
           ext2fs_has_feature_metadata_csum(fs->super) ? "true" : "false");
    fflush(stdout);
}

static void inode_table(blk64_t target, char *data, uint32_t sequence) {
    unsigned int isize = EXT2_INODE_SIZE(fs->super);
    uint64_t per_group = fs->super->s_inodes_per_group;
    for (dgrp_t group = 0; group < fs->group_desc_count; group++) {
        blk64_t table = ext2fs_inode_table_loc(fs, group);
        uint64_t blocks = (per_group*isize+fs->blocksize-1)/fs->blocksize;
        if (target < table || target-table >= blocks) continue;
        uint64_t initial = group*per_group+(target-table)*(fs->blocksize/isize)+1;
        for (unsigned int at = 0; at+isize <= fs->blocksize; at += isize) {
            uint64_t ino = initial+at/isize;
            if (ino < EXT2_FIRST_INODE(fs->super) || ino > fs->super->s_inodes_count) continue;
            extract_inode(ino, (struct ext2_inode *)(data+at), sequence);
        }
        return;
    }
}

int main(int argc, char **argv) {
    struct stat st;
    char *header, *descriptor, *data;
    uint32_t *commits;
    size_t commit_count = 0;
    if (argc != 3) fail("Usage: eraseproof-ext4-journal source-image output-directory", EINVAL);
    if (stat(argv[1], &st) || !S_ISREG(st.st_mode)) fail("Select a regular volume image", EINVAL);
    destination = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (destination < 0) fail("Open output directory", errno);
    check(ext2fs_open(argv[1], EXT2_FLAG_64BITS, 0, 0, unix_io_manager, &fs), "Open source read-only");
    if (!fs->super->s_journal_inum || fs->super->s_journal_dev ||
        ext2fs_blocks_count(fs->super) > (uint64_t)st.st_size/fs->blocksize)
        fail("A complete ext4 volume with an internal journal is required", EINVAL);
    check(ext2fs_read_bitmaps(fs), "Read allocation state");
    check(ext2fs_file_open(fs, fs->super->s_journal_inum, 0, &journal), "Open internal journal");
    header = malloc(fs->blocksize); descriptor = malloc(fs->blocksize); data = malloc(fs->blocksize);
    if (!header || !descriptor || !data) fail("Allocate journal buffers", ENOMEM);
    read_journal(0, header);
    if (be32(header) != MAGIC || be32(header+12) != fs->blocksize) fail("Unsupported journal header", EINVAL);
    maximum = be32(header+16); first = be32(header+20); features = be32(header+40);
    if (!first || maximum <= first || maximum > 1024*1024 || features & ~0x3fU)
        fail("Unsupported or oversized journal geometry/features", EINVAL);
    if (EXT2_INODE_SIZE(fs->super) > fs->blocksize || fs->blocksize % EXT2_INODE_SIZE(fs->super))
        fail("Unsupported inode geometry", EINVAL);
    commits = malloc((size_t)maximum*sizeof(*commits));
    if (!commits) fail("Allocate transaction inventory", ENOMEM);
    seed = ext2fs_crc32c_le(~0U, (unsigned char *)header+48, 16);
    /* Collect transaction IDs with commit records; old transactions are useful
     * evidence even though they are no longer eligible for journal replay. */
    for (uint32_t block = first; block < maximum; block++) {
        read_journal(block, data);
        if (be32(data) == MAGIC && be32(data+4) == 2)
            commits[commit_count++] = be32(data+8);
    }
    for (uint32_t block = first; block < maximum; block++) {
        read_journal(block, descriptor);
        if (be32(descriptor) != MAGIC || be32(descriptor+4) != 1) continue;
        uint32_t sequence = be32(descriptor+8), location = next_block(block);
        int committed = 0;
        for (size_t i = 0; i < commit_count; i++) if (commits[i] == sequence) { committed = 1; break; }
        if (!committed) continue;
        unsigned int tail = features & 0x18 ? 4 : 0;
        if (tail) {
            uint32_t expected = be32(descriptor+fs->blocksize-4);
            memset(descriptor+fs->blocksize-4, 0, 4);
            if (ext2fs_crc32c_le(seed, (unsigned char *)descriptor, fs->blocksize) != expected) {
                checksum_failures++; continue;
            }
        }
        unsigned int at = 12;
        while (at+8 <= fs->blocksize-tail) {
            unsigned int size = features & 0x10 ? 16 : features & 2 ? 12 : 8;
            if (at+size > fs->blocksize-tail) break;
            uint32_t flags = features & 0x10 ? be32(descriptor+at+4) : be16(descriptor+at+6);
            blk64_t target = be32(descriptor+at);
            if (features & 2) target |= (uint64_t)be32(descriptor+at+8)<<32;
            uint32_t expected = features & 0x10 ? be32(descriptor+at+12) : be16(descriptor+at+4);
            at += size;
            if (!(flags & 2)) { if (at+16 > fs->blocksize-tail) break; at += 16; }
            if (flags & ~15U) break;
            if (!(flags & 4)) {
                read_journal(location, data);
                location = next_block(location);
                if (features & 0x18) {
                    uint32_t seq = htonl(sequence);
                    uint32_t crc = ext2fs_crc32c_le(seed, (unsigned char *)&seq, 4);
                    crc = ext2fs_crc32c_le(crc, (unsigned char *)data, fs->blocksize);
                    if ((features & 0x10 ? crc : crc & 0xffffU) != expected) {
                        checksum_failures++; if (flags & 8) break; else continue;
                    }
                }
                if (flags & 1) { uint32_t magic = htonl(MAGIC); memcpy(data, &magic, 4); }
                if (target < ext2fs_blocks_count(fs->super)) inode_table(target, data, sequence);
            }
            if (flags & 8) break;
        }
    }
    printf("{\"summary\":true,\"recovered_files\":%u,\"bytes\":%llu,\"skipped\":%u,\"checksum_failures\":%u,\"fast_commit_deltas_decoded\":false}\n",
           recovered_count, recovered_bytes, skipped, checksum_failures);
    check(ext2fs_file_close(journal), "Close journal");
    check(ext2fs_close(fs), "Close source");
    if (fsync(destination)) fail("Flush output directory", errno);
    close(destination);
    free(header); free(descriptor); free(data); free(commits);
    return 0;
}
