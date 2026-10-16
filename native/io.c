/* EraseProof Linux I/O primitives. No privilege changes or path-based writes.
 * The caller owns a pinned, policy-checked descriptor. Every operation is bounded.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define EP_ALIGN 4096
#define EP_MAX (4U * 1024U * 1024U)

static int bounds(int fd, uint64_t offset, uint64_t length) {
    struct stat st;
    uint64_t size;
    if (fstat(fd, &st)) return errno;
    if (S_ISREG(st.st_mode)) size = st.st_size;
    else if (S_ISBLK(st.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, &size)) return errno;
    } else return ENOTSUP;
    if (offset > size || length > size-offset || length > EP_MAX) return EINVAL;
    return 0;
}

/* direct=1 requires O_DIRECT. A failure is reported; no silent buffered retry.
 * direct=0 is used for the explicitly reported unaligned tail only.
 * Returns errno (0 on success); the caller must stop on any failure.
 */
int ep_zero(int fd, uint64_t offset, uint64_t length, int direct) {
    int error = bounds(fd, offset, length), flags, changed = 0;
    void *buffer = NULL;
    uint64_t done = 0;
    if (error || !length) return error;
    if (direct && ((offset % EP_ALIGN) || (length % EP_ALIGN))) return EINVAL;
    flags = fcntl(fd, F_GETFL);
    if (flags < 0) return errno;
    if (direct && !(flags & O_DIRECT)) {
        if (fsync(fd)) return errno;
        if (fcntl(fd, F_SETFL, flags | O_DIRECT)) return errno;
        changed = 1;
    } else if (!direct && (flags & O_DIRECT)) return EINVAL;
    error = posix_memalign(&buffer, EP_ALIGN, length);
    if (!error) {
        memset(buffer, 0, length);
        while (done < length) {
            ssize_t count = pwrite(fd, (char *)buffer+done, length-done, offset+done);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { error = count < 0 ? errno : EIO; break; }
            done += count;
        }
        if (!error && fdatasync(fd)) error = errno;
        free(buffer);
    }
    if (changed && fcntl(fd, F_SETFL, flags) && !error) error = errno;
    return error;
}

/* Physical extent inventory only. FIEMAP is never permission to raw-write a
 * mounted filesystem: delayed allocation/shared/encoded flags remain visible.
 */
int ep_fiemap(int fd, uint64_t start, uint32_t count, struct fiemap_extent *out,
              uint32_t *mapped) {
    struct fiemap *map;
    int error = 0;
    if (!out || !mapped || count < 1 || count > 1024) return EINVAL;
    map = calloc(1, sizeof(*map)+count*sizeof(struct fiemap_extent));
    if (!map) return ENOMEM;
    map->fm_start = start;
    map->fm_length = UINT64_MAX-start;
    map->fm_flags = FIEMAP_FLAG_SYNC;
    map->fm_extent_count = count;
    if (ioctl(fd, FS_IOC_FIEMAP, map)) error = errno;
    else {
        *mapped = map->fm_mapped_extents;
        memcpy(out, map->fm_extents, map->fm_mapped_extents*sizeof(*out));
    }
    free(map);
    return error;
}

/* Discard is deliberately not used by overwrite: reads after discard are not
 * universally defined as zeros. The planner must record discard separately.
 */
int ep_discard(int fd, uint64_t offset, uint64_t length, int secure) {
    struct stat st;
    uint64_t size, range[2] = {offset, length};
    if (fstat(fd, &st)) return errno;
    if (!S_ISBLK(st.st_mode)) return ENOTBLK;
    if (ioctl(fd, BLKGETSIZE64, &size)) return errno;
    if (!length || offset > size || length > size-offset || offset%512 || length%512) return EINVAL;
    if (ioctl(fd, secure ? BLKSECDISCARD : BLKDISCARD, range)) return errno;
    return 0;
}

int ep_trim(int fd, uint64_t minimum, uint64_t *trimmed) {
    struct stat st;
    struct fstrim_range range = {.start=0, .len=UINT64_MAX, .minlen=minimum};
    if (fstat(fd, &st)) return errno;
    if (!S_ISDIR(st.st_mode)) return ENOTDIR;
    if (ioctl(fd, FITRIM, &range)) return errno;
    *trimmed = range.len;
    return 0;
}
