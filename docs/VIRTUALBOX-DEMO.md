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
