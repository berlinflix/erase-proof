# Reproducible generated-image evaluation

All measurements below used generated volume images in WSL Ubuntu 22.04 on
16 October 2026. No physical drives were erased. Timings include local I/O and
independent tools; they are observations on this development machine, not
portable performance guarantees.

## Ordinary permanent deletion

```bash
sudo /path/to/project-venv/bin/python scripts/verify-normal-deletion.py \
  --image-mib 1024 --user-activity --output /path/to/NEW-results
```

The script creates fresh random PNG/JPEG/PDF/ZIP/text/unknown-format files,
creates prior versions, saves through atomic rename, copies and deletes backups,
and finally unlinks the current files through mounted Linux filesystem drivers.
Recovery receives only the source image and a separate output folder. No
original file names, reference manifest or ground-truth bytes enter recovery.

| Filesystem | Volume | Exact current-file recoveries | Source unchanged |
| --- | --- | --- | --- |
| FAT32 | 1 GiB | 6/6 | SHA-256 checked |
| ext4 | 1 GiB | 6/6 | SHA-256 checked |
| NTFS | 1 GiB | 6/6 | SHA-256 checked |
| exFAT | 1 GiB | 6/6 | SHA-256 checked |

An actual `gio trash` move is separately tested for Ubuntu file-manager Trash,
including exact unknown-format recovery and the native Qt selection flow.
See [Trash recovery](UBUNTU-TRASH.md).

## Offline targeted erasure and history

```bash
# Store evidence on a Linux filesystem supporting private key permissions.
sudo /path/to/project-venv/bin/python scripts/evaluate-offline.py \
  --image-mib 1024 --output /path/on/linux/NEW-results
```

Each image is formatted and mounted through real drivers. A random unknown-format
file is edited using an atomic save; a current copy is backed up and that backup
deleted. Another unrelated file remains allocated. EraseProof removes the
selected folder and all deleted volume history. The script independently checks
preserved contents through `icat`, searches for both current target bytes and a
distinct prior version, and validates the signed record.

| Filesystem | Volume | Cleanup + verification | RRS | PhotoRec / TSK / bulk_extractor | Preserved file |
| --- | --- | --- | --- | --- | --- |
| FAT32 | 1 GiB | 71.158 s | 0 | All completed | Exact |
| ext4 | 1 GiB | 48.418 s | 0 | All completed | Exact |
| NTFS | 1 GiB | 43.930 s | 0 | All completed | Exact |
| exFAT | 1 GiB | 31.244 s | 0 | All completed | Exact |
| exFAT | 8 GiB | 234.741 s | 0 | All completed | Exact |

These are the repeated runs after replacing Python's per-byte zero tests with
bounded zero-block comparisons. The earlier complete 1 GiB run also passed on
all four filesystems; an earlier 8 GiB exFAT run passed in 345.168 seconds.
Other validation jobs ran concurrently, so these timings are not a controlled
performance comparison.

The larger FAT32 run exposed PhotoRec extracting a whole filesystem container
beyond the former 256 MiB file limit. The operation correctly refused a
certificate. The bounded container allowance was corrected and the complete
four-filesystem run above then passed; no scanner or recovered output was
disabled to obtain that result. See [worker limits](ATTACK-VERIFICATION.md).

## Mutation and refusal checks

The [supplemental block-device test](VIRTUALBOX-DEMO.md) additionally exercised
the existing shipped executable on a uniquely identified generated QEMU disk.
It recovered fresh unknown-format content from the raw block device without
references, preserved the source during recovery, then performed a complete
64 MiB direct overwrite with signed evidence. A separate host read verified
the backing file was entirely zero. No existing or physical disks were attached.

The regression suite deliberately reintroduces known and unknown bytes into
free allocation, deleted directory/MFT/journal/USN history and file slack.
Affected checks must refuse certification. Other cases include retained live
duplicates, corrupt allocation/boot/checksum metadata, missing or incomplete
independent scanners, changed sources, timeouts/cancellation, and child-process
cleanup. Hardware command boundaries use synthetic inventories; they never
submit destructive commands to a developer drive.

## Limits of these results

The corpus is fresh randomly generated data, not a Govdocs1 evaluation. This
does not compare every third-party deletion utility or measure flash remanence.
Fragment recovery depends on surviving allocation maps or the documented bounded
carvers. There are no measured HPA/DCO mutations or physical firmware claims.
The proposed physical-media study, ssdeep version matching and independent
standards assessment remain research work. Actual VirtualBox acceptance is
deferred by the user.
