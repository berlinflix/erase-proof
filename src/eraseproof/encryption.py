"""Read-only encrypted-volume signatures and bounded TCG feature discovery."""
from .models import EraseProofError


def volume_signature(header):
    if header[:6] == b'LUKS\xba\xbe' and len(header) >= 8:
        version = int.from_bytes(header[6:8], 'big')
        if version in (1, 2):
            return {'type': 'LUKS'+str(version), 'state': 'signature-detected', 'key_copies': 'unknown'}
    if len(header) >= 512 and header[3:11] == b'-FVE-FS-' and header[510:512] == b'\x55\xaa':
        return {'type': 'BitLocker', 'state': 'signature-detected', 'key_copies': 'unknown',
                'scope': 'Recognized volume header; active protection/key backups are not established by this signature.'}
    return {'type': 'unknown', 'state': 'no-supported-signature', 'scope': 'Absence of a recognized header does not prove plaintext.'}


def tcg_features(data):
    if len(data) < 48:
        raise EraseProofError('Short TCG Level 0 Discovery response.')
    end = int.from_bytes(data[:4], 'big')
    if not 48 <= end <= len(data):
        raise EraseProofError('TCG Level 0 Discovery exceeds the received buffer; SED state is unknown.')
    position, features, locking = 48, [], None
    while position < end:
        if position+4 > end:
            raise EraseProofError('Truncated TCG feature descriptor.')
        code, length = int.from_bytes(data[position:position+2], 'big'), data[position+3]
        if position+4+length > end or len(features) >= 256:
            raise EraseProofError('TCG feature bounds/count exceeded.')
        features.append(code)
        if code == 2:
            if length < 1 or locking is not None:
                raise EraseProofError('Malformed/duplicate TCG Locking feature.')
            flags = data[position+4]
            locking = {'locking_supported': bool(flags & 1), 'locking_enabled': bool(flags & 2),
                       'locked': bool(flags & 4), 'media_encryption': bool(flags & 8)}
        position += 4+length
    return {'state': 'features-read', 'feature_codes': features, 'locking': locking,
            'self_encrypting_drive_reported': bool(locking and locking['media_encryption']),
            'scope': 'Device-reported TCG features; key destruction, firmware correctness and physical remanence are not verified.'}


def inspect_sed(fd):
    from .firmware import tcg_discovery
    try:
        return tcg_features(tcg_discovery(fd))
    except (EraseProofError, OSError) as error:
        return {'state': 'unknown', 'detail': str(error), 'scope': 'Failed or unsupported discovery does not establish the absence of encryption.'}
