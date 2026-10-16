# Ubuntu / Oracle VirtualBox demonstration

## Prepare

- Use an Ubuntu desktop VM. Extract EraseProof into your Linux home directory, rather than running it from a read-only VirtualBox shared folder.
- For the source package, run `bash scripts/setup-ubuntu.sh`, then `bash scripts/launch-ubuntu.sh`.
- For the bundled Linux application, install the documented Ubuntu tool dependencies and run `./EraseProof`.
- The default demonstration uses a new 64 MiB filesystem image. It does not require a secondary virtual disk, root privileges, loop mounting or changes to the VM's installed system.

## Show the actual OS behavior

1. Create an experiment. Explain that the volume contains four ordinary files, each with a known hash.
2. Delete the files normally. This uses `mdel`, leaving file contents in freed FAT32 clusters.
3. Run both recovery methods. Open the recovered PDF/PNG. Compare a recovered file hash against its original:

   ```bash
   sha256sum /path/to/original/REPORT.PDF /path/to/recovered/PDF
   ```

4. Run read-only verification before erasure: it must fail and show remaining candidates/reference residue.
5. Prepare overwrite. Point out the exact target image filename and byte count, then type the filename to confirm. This overwrites the actual image file.
6. Show the successful full read-back, zero known-reference RRS and signed record. Run signature carving again: it should find no supported candidates.
7. Export the signed JSON and verify it. Changing a field makes signature validation fail.

## State the research boundary accurately

The result is about guest-visible logical bytes. Snapshots and host storage are outside the guest's reach. A zero fixture score is bounded by the known reference set. Real flash sanitization requires device commands and tests on spare physical hardware, often from a bootable live environment.

## Optional secondary-disk acceptance test

After the image demo is stable, power off the VM and attach a new disposable virtual disk. Boot Ubuntu, inspect `eraseproof devices`, confirm its model/serial/size and ensure neither it nor a child partition is mounted. The CLI's explicit allowlist plus serial confirmation are required for a write. Keep the evidence directory on the VM's system disk. Do not use a pass-through host disk.

This secondary-device route is implemented but has not been exercised against your VirtualBox VM. The image workflow and safety refusal paths are tested under WSL.

## Supplemental QEMU block-device acceptance

The shipped 0.11 executable also passed actual block-device recovery and erasure
in a disposable QEMU/KVM guest. The host harness creates its own 64 MiB FAT32
file, adds fresh random unknown-format data and deletes the file using mtools.
It attaches that new file as the guest's only writable disk. The guest selects
it by a unique generated serial, model and exact size, then calls the shipped
CLI's existing plan/recover/erase methods. Recovery receives no reference list.

Recovery matched the original SHA-256 without changing the source. Erasure
completed 67,108,864 bytes of native direct writes, full zero readback, a zero
known-reference RRS, signed-record verification and audit checks. After QEMU
closed, the host independently read every byte of the backing file as zero.
PhotoRec and bulk_extractor completed; Sleuth Kit's expected failure on the
overwritten filesystem stayed recorded and was superseded by complete zero
readback. [Exact result](validation/virtual-block-0.11.json).

Developer reproduction on Linux with QEMU/KVM:

```bash
sudo /path/to/project-venv/bin/python scripts/verify-virtual-disk.py \
  artifacts/EraseProof-Live-Ubuntu24.04-x86_64-0.11.0.iso \
  --kernel /var/tmp/eraseproof-live.BUILD_ID/iso/casper/vmlinuz \
  --initrd /var/tmp/eraseproof-live.BUILD_ID/iso/casper/initrd \
  --output qa/NEW-virtual-block-check
```

The harness accepts no target-device or existing writable-image argument. It
uses a temporary serial debug shell only inside its isolated test guest, with
no NIC or host-device passthrough. Default release boot settings are unchanged.
The script and result are supplemental validation on GitHub main; the frozen
0.11 release archives retain their original build provenance. This is QEMU
evidence, not Oracle VirtualBox acceptance or physical-media validation.

The final 0.12 release repeats the secondary-disk test and adds a real virtual
NVMe Format/attack/certify run. Both recover a fresh arbitrary-format deleted
file exactly, preserve the source during recovery, and pass complete host-side
zero readback after the operation. The NVMe run exercises SES=1 user-data Format
through the native ioctl; it does not validate physical crypto erase. Exact
results: [logical overwrite](validation/virtual-block-0.12.json),
[NVMe workflow](validation/virtual-nvme-0.12.json).
