import struct

import pytest

from eraseproof.encryption import volume_signature, tcg_features
from eraseproof.models import EraseProofError


def test_bitlocker_luks_signatures_and_unknown_are_distinct():
    header = bytearray(512)
    header[3:11], header[510:512] = b'-FVE-FS-', b'\x55\xaa'
    assert volume_signature(header)['type'] == 'BitLocker'
    assert volume_signature(b'LUKS\xba\xbe\x00\x02')['type'] == 'LUKS2'
    assert volume_signature(bytes(512))['type'] == 'unknown'
    assert 'plaintext' in volume_signature(bytes(512))['scope']


def test_tcg_locking_and_media_encryption_features_and_bounds():
    data = bytearray(2048)
    data[:4] = (53).to_bytes(4, 'big')
    data[48:53] = b'\x00\x02\x10\x01\x0f'
    result = tcg_features(data)
    assert result['self_encrypting_drive_reported']
    assert result['locking']['locking_enabled'] and result['locking']['locked']
    data[51] = 250
    with pytest.raises(EraseProofError, match='bounds'):
        tcg_features(data)
