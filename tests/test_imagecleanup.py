import copy
import hashlib
import os

import pytest

from eraseproof import imagecleanup
from eraseproof.evidence import EvidenceStore, now, verify_record
from eraseproof.models import Cancelled, EraseProofError


def zero_record(image, store):
    data = image.read_bytes()
    return store.certify({
        'schema': 'eraseproof.native-evidence.v1', 'id': 'ep-zero-image',
        'issued_at': now(),
        'target': {'kind': 'image', 'path': str(image), 'size': len(data)},
        'plan': {'method': 'single-pass-zero-overwrite'},
        'verification': {'passed': True, 'bytes_checked': len(data),
                         'nonzero_bytes': 0, 'sha256': hashlib.sha256(bytes(len(data))).hexdigest(),
                         'rrs': 0, 'independent_attack': {'passed': True}},
    })


@pytest.fixture
def zero_image(tmp_path):
    image = tmp_path/'overwritten.img'
    image.write_bytes(bytes(8192))
    store = EvidenceStore(tmp_path/'evidence')
    record = zero_record(image, store)
    return image, store, record


def test_removes_only_the_verified_image_and_preserves_all_evidence(zero_image, tmp_path):
    image, store, record = zero_image
    neighbor = tmp_path/'preserve.img'
    data = os.urandom(1537)
    neighbor.write_bytes(data)
    before = {p.name: p.read_bytes() for p in store.root.iterdir() if p.is_file()}
    prepared = imagecleanup.prepare(record, store.root)
    result = imagecleanup.remove(record, prepared, image.name, store.root)
    assert not image.exists()
    assert result['record_id'] == record['payload']['id']
    assert result['bytes_checked'] == 8192
    assert neighbor.read_bytes() == data
    assert {p.name: p.read_bytes() for p in store.root.iterdir() if p.is_file()} == before
    assert store.check() and verify_record(store.records()[0])


def test_nonzero_content_is_never_removed_even_with_a_signed_zero_claim(zero_image):
    image, store, record = zero_image
    image.write_bytes(b'x'+bytes(8191))
    prepared = imagecleanup.prepare(record, store.root)
    with pytest.raises(EraseProofError, match='verified zeros'):
        imagecleanup.remove(record, prepared, image.name, store.root)
    assert image.read_bytes() == b'x'+bytes(8191)


def test_replaced_path_after_confirmation_is_not_removed(zero_image):
    image, store, record = zero_image
    prepared = imagecleanup.prepare(record, store.root)
    original = image.with_suffix('.original')
    image.rename(original)
    image.write_bytes(bytes(8192))
    with pytest.raises(EraseProofError, match='changed after confirmation'):
        imagecleanup.remove(record, prepared, image.name, store.root)
    assert image.exists() and original.exists()


def test_change_to_already_read_bytes_blocks_removal(zero_image):
    image, store, _ = zero_image
    image.write_bytes(bytes(4*1024*1024+512))
    # Use a separate record store instead of replacing any signed history.
    other = EvidenceStore(store.root.parent/'other-evidence')
    record = zero_record(image, other)
    prepared = imagecleanup.prepare(record, other.root)
    def modify(stage, fraction, message):
        if fraction < 1:
            with image.open('r+b') as stream:
                stream.write(b'x')
    with pytest.raises(EraseProofError, match='changed during the final read'):
        imagecleanup.remove(record, prepared, image.name, other.root, progress=modify)
    assert image.exists() and image.read_bytes().startswith(b'x')


@pytest.mark.parametrize('link', ['symbolic', 'hard'])
def test_links_are_refused(zero_image, link):
    image, store, record = zero_image
    alias = image.with_suffix('.alias')
    if link == 'hard':
        os.link(image, alias)
    else:
        image.rename(alias)
        image.symlink_to(alias)
    with pytest.raises(EraseProofError, match='[Ss]ymlink|[Hh]ard.link'):
        imagecleanup.prepare(record, store.root)
    assert alias.exists()


def test_attached_images_are_refused(zero_image, monkeypatch):
    image, store, record = zero_image
    def attached(path):
        raise EraseProofError('Attached image refused')
    monkeypatch.setattr(imagecleanup, 'require_unattached_image', attached)
    with pytest.raises(EraseProofError, match='Attached image'):
        imagecleanup.prepare(record, store.root)
    assert image.exists()


def test_confirmation_and_cancellation_leave_image_untouched(zero_image):
    image, store, record = zero_image
    prepared = imagecleanup.prepare(record, store.root)
    with pytest.raises(EraseProofError, match='Confirmation'):
        imagecleanup.remove(record, prepared, 'wrong', store.root)
    with pytest.raises(Cancelled):
        imagecleanup.remove(record, prepared, image.name, store.root, cancel=lambda: True)
    assert image.read_bytes() == bytes(8192)


@pytest.mark.parametrize('change', ['device', 'failed', 'partial', 'no-independent-check', 'bad-signature'])
def test_ineligible_records_never_enable_removal(zero_image, change):
    image, store, record = zero_image
    payload = copy.deepcopy(record['payload'])
    if change == 'device':
        payload['target']['kind'] = 'block-device'
    elif change == 'failed':
        payload['verification']['passed'] = False
    elif change == 'partial':
        payload['verification']['bytes_checked'] -= 1
    elif change == 'no-independent-check':
        payload['verification']['independent_attack']['passed'] = False
    modified = store.sign(payload)
    if change == 'bad-signature':
        modified['signature'] = 'not a valid signature'
    assert not imagecleanup.eligible(modified)
    with pytest.raises(EraseProofError, match='whole-image'):
        imagecleanup.prepare(modified, store.root)
    assert image.exists()


def test_evidence_folder_is_excluded(zero_image):
    image, store, _ = zero_image
    image = store.root/'signed-evidence.img'
    image.write_bytes(bytes(8192))
    other = EvidenceStore(store.root.parent/'signer')
    record = zero_record(image, other)
    with pytest.raises(EraseProofError, match='Evidence files'):
        imagecleanup.prepare(record, store.root)
    assert image.exists()
