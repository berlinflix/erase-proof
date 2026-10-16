# Signed records and offline verification

An Ed25519 record binds its target, operation, measurements, scope and preceding
audit hash. Only successful scoped engine verification can be certified.
Logical file-byte erasure is explicitly narrower than a whole-image overwrite;
the operation and scope remain in the signed payload and PDF. Firmware command
acceptance and LUKS keyslot removal produce separate receipts, not certificates.

The case stores its raw Ed25519 key in a private regular file with mode 0600.
Use a Linux filesystem for evidence; Windows shared folders may not enforce
Unix permissions. Signing readiness is checked before destructive writes.
Keep the private key private. The public-key fingerprint can be shared.

```bash
eraseproof record record.epcert.json --trusted-fingerprint EXPECTED_64_HEX_SHA256
eraseproof pdf record.epcert.json --output report.pdf
eraseproof pdf-record report.pdf --trusted-fingerprint EXPECTED_64_HEX_SHA256
```

Without an expected fingerprint, verification establishes integrity under the
embedded key only. Obtain the expected fingerprint through a trusted channel;
copying it from an untrusted record does not authenticate an operator.

PDFs contain a readable summary, an offline QR reference and the exact signed
JSON attachment. The QR carries the record ID, payload hash and signer
fingerprint. It is not a standalone signature or online verification service.
`pdf-record` verifies the attachment, **not the PDF wrapper's visual content**.
The attached signed JSON is authoritative. The PDF itself has no PDF digital
signature and makes no NIST/IEEE compliance claim.

SQLite commits certificates and their audit event together. Audit validation
checks event order/hashes, every stored record's signature, and links between
records and certification events. A valid local prefix alone cannot expose
deletion of its tail or replacement of the entire database.

```bash
eraseproof audit-export /path/to/case --output /separate/location/checkpoint.json
eraseproof audit /path/to/case --anchor /separate/location/checkpoint.json \
  --trusted-fingerprint EXPECTED_64_HEX_SHA256
```

Export runs in one database transaction. Store the signed checkpoint separately
from the case, ideally on another machine or protected medium. The anchor
detects deletion/replacement of the history it covers; legitimate later events
are allowed. A checkpoint cannot establish events that happened after it.

Every new destructive logical job has a stable identifier. Audit inspection
lists starts that lack a completion or recorded incomplete event. This detects
process/power interruptions without inventing a successful resume or rollback.
Inspect the target and start a fresh verification before making any assurance.

The compatibility field `all_filesystem_copies_verified` is deliberately false
for scoped file/offline records. It does not invalidate successful recorded
checks; it prevents an assertion about every unknown, changed or external copy.
Use the operation scope, history readback, preserved-file measurements and
independent tool results to assess the current-image evidence.
