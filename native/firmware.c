/* Restricted Linux NVMe admin ioctls on policy-checked, pinned descriptors.
 * No path opens, namespace creation/deletion, reset, or arbitrary passthrough.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/nvme_ioctl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <scsi/sg.h>

static int controller(int fd) {
    struct stat st;
    if (fstat(fd, &st)) return errno;
    return S_ISCHR(st.st_mode) ? 0 : ENOTTY;
}

static int submit(int fd, struct nvme_admin_cmd *cmd, uint32_t *status) {
    int error = controller(fd), result;
    if (error || !status) return error ? error : EINVAL;
    *status = 0;
    result = ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
    if (result < 0) return errno;
    *status = (uint32_t)result;
    return 0;
}

int ep_nvme_identify(int fd, uint32_t nsid, uint32_t cns, void *out, uint32_t *status) {
    struct nvme_admin_cmd cmd = {0};
    if (!out || cns > 1 || (cns == 0 && !nsid) || (cns == 1 && nsid)) return EINVAL;
    memset(out, 0, 4096);
    cmd.opcode = 0x06;
    cmd.nsid = nsid;
    cmd.cdw10 = cns;
    cmd.addr = (uint64_t)(uintptr_t)out;
    cmd.data_len = 4096;
    cmd.timeout_ms = 30000;
    return submit(fd, &cmd, status);
}

/* Pure encoding is exported to test the exact wire fields without a device. */
int ep_nvme_format_fields(uint32_t nsid, uint32_t lbaf, uint32_t ses, uint32_t *cdw10) {
    if (!nsid || lbaf > 15 || (ses != 1 && ses != 2) || !cdw10) return EINVAL;
    *cdw10 = lbaf | (ses << 9); /* metadata/protection disabled by policy */
    return 0;
}

int ep_nvme_format(int fd, uint32_t nsid, uint32_t lbaf, uint32_t ses, uint32_t *status) {
    struct nvme_admin_cmd cmd = {0};
    int error = ep_nvme_format_fields(nsid, lbaf, ses, &cmd.cdw10);
    if (error) return error;
    cmd.opcode = 0x80;
    cmd.nsid = nsid;
    cmd.timeout_ms = 3600000;
    return submit(fd, &cmd, status);
}

int ep_nvme_sanitize(int fd, uint32_t action, uint32_t *status) {
    struct nvme_admin_cmd cmd = {0};
    if (action != 2 && action != 4) return EINVAL;
    cmd.opcode = 0x84;
    cmd.cdw10 = action;
    cmd.timeout_ms = 30000;
    return submit(fd, &cmd, status);
}

/* SAT ATA PASS-THROUGH (16). Whitelisted operations only; security credentials
 * remain in a 512-byte memory buffer, never argv, stdout, or the audit log. */
int ep_ata_fields(uint32_t operation, uint64_t value, unsigned char *cdb) {
    uint64_t lba = 0;
    int extend = 0, data = 0, write = 0;
    if (!cdb || operation > 15) return EINVAL;
    memset(cdb, 0, 16);
    cdb[0] = 0x85;
    cdb[13] = 0x40;
    switch (operation) {
        case 0: cdb[14] = 0xec; data = 1; break; /* IDENTIFY */
        case 1: cdb[14] = 0x27; extend = 1; break; /* native max ext */
        case 2: cdb[14] = 0xb1; cdb[4] = 0xc2; data = 1; break;
        case 3: cdb[14] = 0xb4; extend = 1; break; /* sanitize status */
        case 4: cdb[14] = 0xb4; cdb[4] = 0x12; lba = 0x426b4572; extend = 1; break;
        case 5: cdb[14] = 0xb4; cdb[4] = 0x11; lba = 0x43727970; extend = 1; break;
        case 6: cdb[14] = 0x37; extend = 1; goto capacity;
        case 7: cdb[14] = 0xb1; cdb[4] = 0xc0; break; /* DCO restore */
        case 8: cdb[14] = 0xf1; data = write = 1; break;
        case 9: cdb[14] = 0xf4; data = write = 1; break;
        case 10: cdb[14] = 0xf6; data = write = 1; break;
        case 11: cdb[14] = 0x78; extend = 1; break; /* GET NATIVE MAX ACS3 */
        case 12: cdb[14] = 0x78; cdb[4] = 1; extend = 1; goto capacity;
        case 13: cdb[14] = 0xf8; break;
        case 14: cdb[14] = 0xf9;
        capacity:
            if (!value || value > (UINT64_C(1)<<48) || (operation == 14 && value > (UINT64_C(1)<<28))) return EINVAL;
            lba = value-1;
            /* Volatile SET MAX; never reduce capacity in the policy layer. */
            break;
        case 15: cdb[14] = 0xf2; data = write = 1; break;
    }
    cdb[1] = (data ? (write ? 5 : 4) : 3) << 1;
    cdb[1] |= extend;
    cdb[2] = data ? (write ? 0x06 : 0x0e) : 0x20;
    cdb[6] = data ? 1 : 0;
    cdb[8] = lba;
    cdb[10] = lba >> 8;
    cdb[12] = lba >> 16;
    if (extend) {
        cdb[7] = lba >> 24;
        cdb[9] = lba >> 32;
        cdb[11] = lba >> 40;
    } else cdb[13] |= (lba >> 24) & 0x0f;
    return 0;
}

static int ata_execute(int fd, unsigned char *cdb, void *data, uint32_t timeout,
                       unsigned char *registers) {
    struct stat st;
    unsigned char sense[64] = {0};
    sg_io_hdr_t io = {0};
    if (fstat(fd, &st)) return errno;
    if (!S_ISBLK(st.st_mode) || !registers) return ENOTBLK;
    memset(registers, 0, 14);
    io.interface_id = 'S';
    io.cmd_len = 16;
    io.mx_sb_len = sizeof(sense);
    io.dxfer_direction = data ? ((cdb[2]&8) ? SG_DXFER_FROM_DEV : SG_DXFER_TO_DEV) : SG_DXFER_NONE;
    io.dxfer_len = data ? 512 : 0;
    io.dxferp = data;
    io.cmdp = cdb;
    io.sbp = sense;
    io.timeout = timeout;
    if (ioctl(fd, SG_IO, &io) < 0) return errno;
    if (io.host_status || (io.driver_status && io.driver_status != 8) ||
        (io.status && io.status != 2) || io.resid) return EIO;
    if (io.sb_len_wr >= 22 && (sense[0]&0x7f) == 0x72 && sense[7] >= 14 && sense[8] == 9 && sense[9] >= 12) {
        memcpy(registers, sense+8, 14);
        if (registers[13] & 0xa9) return EIO; /* BSY, DF, DRQ, ERR */
    } else if (!data || io.status || io.driver_status) return ENOMSG;
    return 0;
}

int ep_ata(int fd, uint32_t operation, uint64_t value, void *data,
           uint32_t timeout, unsigned char *registers) {
    unsigned char cdb[16];
    int error = ep_ata_fields(operation, value, cdb), transfer;
    if (error) return error;
    transfer = (cdb[2] & 3) != 0;
    if (transfer != (data != NULL) || timeout < 1000 || timeout > 4000000000U) return EINVAL;
    if (operation == 9) {
        /* The required ERASE PREPARE immediately precedes ERASE UNIT. */
        unsigned char prepare[16] = {0x85, 6, 0x20};
        prepare[13] = 0x40;
        prepare[14] = 0xf3;
        error = ata_execute(fd, prepare, NULL, 30000, registers);
        if (error) return error;
    }
    return ata_execute(fd, cdb, data, timeout, registers);
}

/* Read-only TCG Level 0 Discovery: protocol 1, protocol-specific 1 only. */
int ep_tcg_discovery(int fd, void *out, uint32_t *status) {
    struct stat st;
    if (!out || !status) return EINVAL;
    if (fstat(fd, &st)) return errno;
    memset(out, 0, 2048);
    *status = 0;
    if (S_ISCHR(st.st_mode)) {
        struct nvme_admin_cmd cmd = {0};
        cmd.opcode = 0x82; /* Security Receive; never Security Send */
        cmd.cdw10 = (1U << 24) | (1U << 8);
        cmd.cdw11 = 2048;
        cmd.addr = (uint64_t)(uintptr_t)out;
        cmd.data_len = 2048;
        cmd.timeout_ms = 30000;
        return submit(fd, &cmd, status);
    }
    if (S_ISBLK(st.st_mode)) {
        unsigned char cdb[12] = {0xa2, 1, 0, 1, 0, 0, 0, 0, 8, 0, 0, 0};
        unsigned char sense[64] = {0};
        sg_io_hdr_t io = {0};
        io.interface_id = 'S';
        io.cmd_len = sizeof(cdb);
        io.mx_sb_len = sizeof(sense);
        io.dxfer_direction = SG_DXFER_FROM_DEV;
        io.dxfer_len = 2048;
        io.dxferp = out;
        io.cmdp = cdb;
        io.sbp = sense;
        io.timeout = 30000;
        if (ioctl(fd, SG_IO, &io) < 0) return errno;
        if (io.status || io.host_status || io.driver_status || io.resid) return EIO;
        return 0;
    }
    return ENOTTY;
}
