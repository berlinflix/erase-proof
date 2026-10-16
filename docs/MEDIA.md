# Media operations and assurance

The native Media methods page shows a read-only method table and shell-quoted
commands. Execution rechecks identity, capacity, mounts/swap, read-only state
and kernel holders. Firmware/device writes require an explicit root CLI call,
matching allowlist, exact nonempty serial and evidence on another device.

## NVMe

Discovery uses Identify Controller/Namespace, all allocated namespaces, sysfs
ancestry and sanitize status. Device numbering does not establish ownership.
Multi-controller/port, SR-IOV, missing namespaces and ambiguous multipath are
refused. All namespaces are held exclusively. The native C adapter reads identity
again from the pinned controller descriptor and sends restricted admin ioctls.

`nvme-plan` / `nvme-submit` implement block/crypto sanitize; `nvme-status` observes
completion. Firmware can continue after cancellation, timeout, exit or reboot.

`nvme-format-plan` / `nvme-format-submit` implement crypto/user-data Format NVM.
OACS/FNA and namespace layouts are checked; existing sector formats are retained.
Metadata/protection layouts are refused. Broadcast/per-namespace scope follows
FNA, including its all-namespace-ID restriction. Unintended format conversion
is refused. Identity, capacity and formats must agree after completion.

`nvme-workflow-plan` / `nvme-run` implement the confirmed closed loop. The operator
chooses an ordered method chain and supplies retained target references. Complete
readback and PhotoRec/TSK/bulk_extractor attacks cover every namespace. Observed
remaining logical data can advance to the next pre-confirmed method. Unknown
status, incomplete attacks, read errors, cancellation and identity changes stop
without automatic retry. Firmware success alone never issues a certificate.

```bash
sudo eraseproof nvme-format-plan /dev/nvmeX --method crypto \
  --allow-controller /dev/nvmeX --confirm EXACT_SERIAL
sudo eraseproof nvme-workflow-plan /dev/nvmeX \
  --methods crypto-erase block-erase --allow-controller /dev/nvmeX \
  --confirm EXACT_SERIAL
```

## ATA and hidden capacity

`ata-status` reads IDENTIFY, native maximum capacity, DCO and sanitize/security
state through restricted C SG_IO. Corrupt/contradictory/unknown capacity blocks
execution. Direct ATA/SATA attachment is required; bridges/partitions/mappers
are refused. `ata-plan` / `ata-submit` support advertised block sanitize, crypto
scramble and Enhanced Secure Erase, with frozen/busy/locked/expired gates.

Enhanced erase refuses an existing password, saves/fsyncs a private mode-0600
recovery credential before enabling security, and sends ERASE PREPARE immediately
before ERASE UNIT. Passwords never enter argv, logs or receipts. Success requires
disabled/unlocked readback; interruption retains the key and an uncertainty event.
`ata-recover-security` explicitly unlocks/disables that saved password using its
private key file. It performs no erasure and issues no erasure certificate.

HPA/DCO changes require `--open-hidden --capacity-sectors FACTORY_COUNT` as well
as device/serial confirmation. HPA opens to the known native range before DCO
restore, followed by any remaining HPA expansion. Legacy/ACS3 commands support
verified 48-bit layouts. No deliberate capacity reduction is offered. Identity
and all three capacities must agree afterward. DCO restore permanently resets
configuration; a kernel re-probe/reboot may be required before block I/O sees
the expanded range. Rejected/frozen changes remain failures.

## Overwrite, discard and encryption

`device-plan` / `device-erase` add explicitly allowlisted complete host-visible
disk overwrite. Booted/mounted disks, swap and holders are refused; ATA hidden
capacity is checked before and after. Direct writes, fsync, full readback and
mandatory independent attacks remain required. USB/SD hidden flash pages, FTL,
remapped blocks and chip-off remanence are outside logical assurance. Prefer a
supported firmware primitive for SSDs, as shown in the media plan.

`device-discard` uses BLKDISCARD, or BLKSECDISCARD with `--secure`. It produces a
separate signed receipt: indeterminate post-discard bytes are never represented
as a zero-readback proof.

`luks-erase` removes active keyslots from an unattached supported LUKS2 image,
verifies metadata and issues a receipt. External header/key backups and cached
keys remain outside scope. Logical overwrite can follow as a separate operation.

## Acceptance

Software tests cover command encoding, regular-file ioctl refusal, state/identity
gates, hidden-capacity sequencing, private credentials/interruption, closed-loop
stopping and certificate gates. No destructive firmware command has been run on
the user's physical storage. Spare ATA/NVMe/USB/SD hardware evaluation remains a
separate acceptance requirement. VirtualBox acceptance is deferred by the user.

References: [Format NVM](https://github.com/linux-nvme/nvme-cli/blob/master/Documentation/nvme-format.1),
[FNA definitions](https://github.com/linux-nvme/libnvme/blob/master/src/nvme/types.h),
[hdparm](https://sourceforge.net/projects/hdparm/),
[hdparm manual](https://man7.org/linux/man-pages/man8/hdparm.8.html).
