# Media operations and assurance

The native Media methods page and `media-probe` inspect actual Linux tool
responses. ATA inspection reads IDENTIFY, native capacity (HPA) and DCO data.
Queries that fail stay unknown; this version never changes HPA/DCO or sets an
ATA security password. ATA destructive commands need a separately evaluated
adapter before they can be enabled.

`media-plan TARGET` applies a read-only method matrix. The native Media methods
page displays the same plan. It prefers advertised, eligible NVMe crypto sanitize
then block sanitize, lists disabled Format NVM/ATA methods explicitly, and
provides a separate guarded command for an executable method. An image can use
verified logical overwrite; a LUKS2 image also offers scoped keyslot removal.
ATA visible/native/DCO capacities must agree before the planner reports no
capacity reduction. Missing or contradictory queries remain unknown. USB/SD
visible overwrite does not imply access to hidden flash pages. Recovery failure
never automatically broadens a confirmed file/image operation into a device wipe.

NVMe sanitize is controller-wide. The CLI supports planning and explicit
submission for a local, single-controller device with all allocated namespaces
attached and visible. It refuses mounted/read-only children, kernel holders,
missing namespaces, multi-controller/port configurations, unsupported actions,
busy/failing sanitize logs, missing serials and unmatched allowlists. It holds
all namespace devices with Linux exclusive opens during submission and checks
the identity/inventory again. Evidence must reside on another device.
Namespace ownership is resolved through sysfs controller ancestry, **not** by
matching the number in `/dev/nvmeXnY` to `/dev/nvmeX`. Native multipath heads
without unambiguous ownership are refused by the inventory gate.

```bash
eraseproof media-probe /path/to/experiment.img
# Read-only inspection, with Linux permissions for the selected controller:
sudo eraseproof media-probe /dev/nvmeX
sudo eraseproof nvme-plan /dev/nvmeX --method block-erase \
  --allow-controller /dev/nvmeX --confirm EXACT_SERIAL
```

The separate `nvme-submit` command accepts the same arguments plus `--case`.
It sends an actual firmware command and is for disposable hardware only.
It never uses a force flag. Firmware jobs can continue after process exit,
timeout or reboot. `nvme-status /dev/nvmeX` reads the sanitize log without
resubmitting anything. A submission receipt or a firmware-reported success
does **not** issue an erasure certificate or establish physical assurance.
Acquisition, independent attacks, hidden-area checks and physical evaluation
remain necessary for that assurance. These adapters have policy/command-boundary
tests; no physical sanitize command was executed during development.

For software LUKS2 images:

```bash
eraseproof luks-erase /path/to/encrypted.img --confirm encrypted.img \
  --case ~/EraseProof/luks-evidence
```

This removes active keyslots through cryptsetup, reads the LUKS2 metadata back,
and records the result in the audit chain. It rejects attached loop images and
unsupported segment/keyslot types. It does not remove payload ciphertext,
cached keys or external header/key backups. It therefore returns a keyslot
removal receipt, not a verified-overwrite certificate. A real generated LUKS2
fixture test confirms that its original passphrase stops working. Whole-image
logical overwrite remains available for complete zero read-back.

References: [nvme-cli sanitize](https://github.com/linux-nvme/nvme-cli/blob/master/Documentation/nvme-sanitize.1),
[hdparm manual](https://man7.org/linux/man-pages/man8/hdparm.8.html),
[cryptsetup erase](https://man7.org/linux/man-pages/man8/cryptsetup-erase.8.html).
