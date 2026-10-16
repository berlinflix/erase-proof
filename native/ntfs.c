/* Offline NTFS image operations through libntfs-3g. No mount, no force flags,
 * no block devices, no privilege changes. Unused-space cleanup is delegated to
 * the independently maintained ntfswipe utility by the Python coordinator.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <locale.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ntfs-3g/types.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/device.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/unistr.h>
#include <ntfs-3g/volume.h>

static ntfs_volume *volume;

static void fail(const char *stage) {
    fprintf(stderr, "%s: %s\n", stage, strerror(errno));
    exit(1);
}

static void refuse(const char *reason) {
    errno = EINVAL;
    fail(reason);
}

static int directory(ntfs_inode *inode) {
    return !!(inode->mrec->flags & MFT_RECORD_IS_DIRECTORY);
}

/* Traverse real directories component-by-component; no reparse traversal. */
static ntfs_inode *parent(const char *path, char **name) {
    ntfs_inode *current, *child;
    char *copy, *part, *save, *next;
    if (!path || path[0] != '/' || strlen(path) > 4096) refuse("Invalid internal path");
    copy = strdup(path);
    if (!copy) fail("Allocate path");
    current = ntfs_inode_open(volume, FILE_root);
    if (!current) fail("Open root");
    part = strtok_r(copy, "/", &save);
    if (!part) refuse("Root directory is protected");
    while (part) {
        if (!strcmp(part, ".") || !strcmp(part, "..") || part[0] == '$' || strchr(part, ':'))
            refuse("Dot components, system files and stream selection are refused");
        next = strtok_r(NULL, "/", &save);
        if (!next) {
            *name = strdup(part);
            if (!*name) fail("Allocate filename");
            free(copy);
            return current;
        }
        child = ntfs_pathname_to_inode(volume, current, part);
        if (!child) fail("Resolve parent");
        if (!directory(child) || child->flags & FILE_ATTR_REPARSE_POINT)
            refuse("A parent is not an ordinary directory");
        if (ntfs_inode_close(current)) fail("Close parent");
        current = child;
        part = next;
    }
    refuse("Invalid path");
    return NULL;
}

static int user_links(ntfs_inode *inode) {
    int count = 0, error;
    ntfs_attr_search_ctx *context = ntfs_attr_get_search_ctx(inode, NULL);
    if (!context) fail("Read filename attributes");
    while (!(error = ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE,
                                      0, NULL, 0, context))) {
        FILE_NAME_ATTR *name = (FILE_NAME_ATTR *)((char *)context->attr+
                                                 le16_to_cpu(context->attr->value_offset));
        if (name->file_name_type != FILE_NAME_DOS) count++;
    }
    if (errno != ENOENT) fail("Enumerate filenames");
    ntfs_attr_put_search_ctx(context);
    return count;
}

static void target(const char *operation, const char *path) {
    char *name;
    ntfschar *unicode = NULL;
    ntfs_inode *dir = parent(path, &name), *inode;
    int length = ntfs_mbstoucs(name, &unicode);
    if (length < 1 || length > 255) refuse("Invalid Unicode filename");
    if (!strcmp(operation, "mkdir")) {
        inode = ntfs_create(dir, const_cpu_to_le32(0), unicode, length, S_IFDIR);
        if (!inode) fail("Create image directory");
        if (ntfs_inode_close(inode) || ntfs_inode_close(dir)) fail("Commit new directory");
        printf("{\"directory_created\":true}\n");
    } else {
        inode = ntfs_pathname_to_inode(volume, dir, name);
        if (!inode) fail("Resolve image target");
        if (inode->mft_no < 16 || inode->flags & (FILE_ATTR_REPARSE_POINT | FILE_ATTR_ENCRYPTED))
            refuse("Reserved, reparse or EFS-encrypted target is refused");
        int links = user_links(inode);
        if (!strcmp(operation, "info")) {
            printf("{\"inode\":%llu,\"directory\":%s,\"links\":%d,\"flags\":%u,\"size\":%lld}\n",
                   (unsigned long long)inode->mft_no, directory(inode) ? "true" : "false",
                   links, le32_to_cpu(inode->flags), (long long)inode->data_size);
            if (ntfs_inode_close(inode) || ntfs_inode_close(dir)) fail("Close target");
        } else {
            if (links != 1) refuse("Hard-linked targets are refused");
            if (directory(inode) && ntfs_check_empty_dir(inode)) fail("Directory must be empty");
            /* ntfs_delete closes BOTH target and parent, including on error. */
            if (ntfs_delete(volume, path, inode, dir, unicode, length)) fail("Delete selected image target");
            printf("{\"unlinked\":true}\n");
        }
    }
    free(unicode); free(name);
}

static s64 usn_range(ntfs_attr *attribute, s64 at, s64 stop, int clear,
                     char *buffer, unsigned long long *nonzero) {
    s64 total = 0;
    while (at < stop) {
        s64 count = stop-at < 1024*1024 ? stop-at : 1024*1024;
        s64 done = clear ? ntfs_attr_pwrite(attribute, at, count, buffer)
                         : ntfs_attr_pread(attribute, at, count, buffer);
        if (done <= 0) fail(clear ? "Clear USN payload" : "Verify USN payload");
        if (!clear) for (s64 i = 0; i < done; i++) *nonzero += buffer[i] != 0;
        at += done;
        total += done;
    }
    return total;
}

static s64 usn_payload(int clear, unsigned long long *nonzero) {
    ntfs_inode *inode = ntfs_pathname_to_inode(volume, NULL, "/$Extend/$UsnJrnl");
    s64 bytes = 0;
    if (!inode && errno != ENOENT) fail("Inspect USN journal");
    if (inode) {
        /* Zero payload without changing USN offsets, IDs or $Max semantics. */
        ntfschar *name = NULL;
        int length = ntfs_mbstoucs("$J", &name);
        ntfs_attr *attribute = ntfs_attr_open(inode, AT_DATA, name, length);
        free(name);
        if (!attribute && errno != ENOENT) fail("Open USN payload");
        if (attribute) {
            char *zero = calloc(1, 1024*1024);
            s64 end = attribute->data_size;
            if (!zero) fail("Allocate USN buffer");
            if (end < 0) refuse("Invalid USN data size");
            if (!NAttrNonResident(attribute)) {
                bytes = usn_range(attribute, 0, end, clear, zero, nonzero);
            } else {
            if (ntfs_attr_map_whole_runlist(attribute)) fail("Map USN allocated runs");
            size_t runs = 0;
            while (attribute->rl && attribute->rl[runs].length) {
                if (++runs > (size_t)volume->nr_clusters) refuse("Too many USN runs");
            }
            runlist_element *snapshot = malloc(runs*sizeof(*snapshot));
            if (runs && !snapshot) fail("Copy USN allocation runs");
            if (runs) memcpy(snapshot, attribute->rl, runs*sizeof(*snapshot));
            /* Skip sparse holes: writing them would allocate space and can
             * expand a tiny journal into an enormous file or exhaust a volume. */
            for (size_t index = 0; index < runs; index++) {
                runlist_element *run = snapshot+index;
                if (run->lcn == LCN_HOLE) continue;
                if (run->lcn < 0 || run->vcn < 0 || run->length < 0 ||
                    run->lcn > volume->nr_clusters || run->length > volume->nr_clusters-run->lcn ||
                    run->vcn > LLONG_MAX/volume->cluster_size ||
                    run->length > LLONG_MAX/volume->cluster_size-run->vcn)
                    refuse("Invalid USN allocation run");
                s64 at = run->vcn*volume->cluster_size;
                s64 stop = (run->vcn+run->length)*volume->cluster_size;
                if (stop > end) stop = end;
                bytes += usn_range(attribute, at, stop, clear, zero, nonzero);
            }
            free(snapshot);
            }
            free(zero);
            ntfs_attr_close(attribute);
        }
        if (ntfs_inode_close(inode)) fail("Close USN journal");
    }
    return bytes;
}

static void clean_usn(void) {
    printf("{\"usn_bytes_cleared\":%lld}\n", (long long)usn_payload(1, NULL));
}

static void verify_free(void) {
    unsigned char bitmap[8192], *buffer = malloc(volume->cluster_size);
    unsigned long long checked = 0, nonzero = 0, dirty = 0;
    if (!buffer) fail("Allocate free-space verification buffer");
    for (s64 base = 0; base < volume->nr_clusters; base += sizeof(bitmap)*8) {
        s64 bits = volume->nr_clusters-base;
        if (bits > (s64)sizeof(bitmap)*8) bits = sizeof(bitmap)*8;
        s64 bytes = (bits+7)/8;
        if (ntfs_attr_pread(volume->lcnbmp_na, base/8, bytes, bitmap) != bytes)
            fail("Read allocation bitmap for verification");
        for (s64 index = 0; index < bits; index++) {
            if (bitmap[index/8] & (1U << (index%8))) continue;
            if (ntfs_pread(volume->dev, (base+index)*volume->cluster_size,
                           volume->cluster_size, buffer) != (s64)volume->cluster_size)
                fail("Read unallocated cluster for verification");
            unsigned int count = 0;
            for (unsigned int i = 0; i < volume->cluster_size; i++) count += buffer[i] != 0;
            nonzero += count;
            dirty += count != 0;
            checked++;
        }
    }
    free(buffer);
    unsigned long long usn_nonzero = 0;
    s64 usn_bytes = usn_payload(0, &usn_nonzero);
    printf("{\"passed\":%s,\"free_clusters_checked\":%llu,\"nonzero_free_clusters\":%llu,\"nonzero_free_bytes\":%llu,\"usn_bytes_checked\":%lld,\"nonzero_usn_bytes\":%llu}\n",
           nonzero || usn_nonzero ? "false" : "true", checked, dirty, nonzero,
           (long long)usn_bytes, usn_nonzero);
}

int main(int argc, char **argv) {
    struct stat st;
    int readonly;
    if (argc < 3 || argc > 4) refuse("Usage: eraseproof-ntfs info|remove|mkdir|clean-usn image-fd [internal-path]");
    if (strcmp(argv[1], "info") && strcmp(argv[1], "remove") && strcmp(argv[1], "mkdir") && strcmp(argv[1], "clean-usn") && strcmp(argv[1], "verify-free"))
        refuse("Unknown operation");
    if (((!strcmp(argv[1], "remove") || !strcmp(argv[1], "mkdir")) && argc != 4) ||
        ((!strcmp(argv[1], "clean-usn") || !strcmp(argv[1], "verify-free")) && argc != 3))
        refuse("Unexpected command arguments");
    if (stat(argv[2], &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1)
        refuse("Only a single-link regular image descriptor is accepted");
    if (!setlocale(LC_ALL, "C.UTF-8")) fail("Set Unicode locale");
    readonly = !strcmp(argv[1], "info") || !strcmp(argv[1], "verify-free");
    volume = ntfs_mount(argv[2], readonly ? NTFS_MNT_RDONLY | NTFS_MNT_FORENSIC : NTFS_MNT_EXCLUSIVE);
    if (!volume) fail("Open clean NTFS image (hibernated/dirty volumes must be repaired elsewhere)");
    if (volume->flags & VOLUME_IS_DIRTY) refuse("Dirty NTFS volumes are refused");
    if ((unsigned long long)volume->nr_clusters*volume->cluster_size > (unsigned long long)st.st_size)
        refuse("Truncated NTFS image");
    if (argc == 4) target(argv[1], argv[3]);
    else if (!strcmp(argv[1], "clean-usn")) clean_usn();
    else if (!strcmp(argv[1], "verify-free")) verify_free();
    else if (readonly) printf("{\"cluster_size\":%u,\"clusters\":%lld,\"ntfs_major\":%u,\"ntfs_minor\":%u}\n",
                              volume->cluster_size, (long long)volume->nr_clusters,
                              volume->major_ver, volume->minor_ver);
    else refuse("An internal path is required");
    if (!readonly && ntfs_device_sync(volume->dev)) fail("Flush NTFS image");
    if (ntfs_umount(volume, FALSE)) fail("Close NTFS image");
    return 0;
}
