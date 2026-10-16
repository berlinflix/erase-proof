"""Separate discard receipts: undefined post-discard bytes are never zero proof."""
import json
import os
import uuid

from . import nativeio
from .evidence import EvidenceStore, now
from .media import outside_devices
from .models import EraseProofError
from .targets import device_policy, find_device, open_target


def discard(path, allow_device, confirmation, evidence_dir, secure=False):
    target = device_policy(path, confirmation, allow_device)
    outside_devices(evidence_dir, [find_device(path)[0]])
    store = EvidenceStore(evidence_dir)
    if not store.check():
        raise EraseProofError('Audit history is damaged; discard was not submitted.')
    store.key()
    job = 'discard-'+uuid.uuid4().hex
    with open_target(path, writable=True) as source:
        if os.fstat(source.fileno()).st_rdev != os.stat(path, follow_symlinks=False).st_rdev or device_policy(path, confirmation, allow_device) != target:
            raise EraseProofError('Device identity or capacity changed.')
        store.append('device.discard-started', {'job': job, 'target': target, 'secure': secure})
        try:
            nativeio.discard(source.fileno(), target['size'], secure)
            os.fsync(source.fileno())
        except BaseException as error:
            store.append('device.discard-incomplete', {'job': job, 'reason': str(error)})
            raise
        receipt = store.sign({'schema': 'eraseproof.firmware-receipt.v1', 'job': job, 'at': now(), 'target': target,
                              'method': 'BLKSECDISCARD' if secure else 'BLKDISCARD', 'state': 'ioctl-completed',
                              'certificate_issued': False,
                              'scope': 'Discard ioctl accepted for the host-visible disk. Read values after discard may be indeterminate. No zero-readback or physical erasure assertion.'})
        store.append('device.discard-completed', {'job': job, 'receipt_sha256': receipt['payload_sha256']})
    with (store.root/(job+'.json')).open('x') as file:
        json.dump(receipt, file, indent=2)
    return receipt
