"""Explicit unlink of an unchanged, independently verified zero-filled image.

This does not erase anything further or change the existing signed evidence.
The file is read again before its host directory entry is removed.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import stat

from .evidence import verify_record
from .carve import checkpoint
from .files import plan_files
from .models import EraseProofError
from .targets import require_unattached_image


def eligible(record):
    if not record or not verify_record(record):
        return False
    payload = record['payload']
    target = payload.get('target', {})
    verification = payload.get('verification', {})
    return (target.get('kind') == 'image'
            and payload.get('plan', {}).get('method') == 'single-pass-zero-overwrite'
            and verification.get('passed') is True
            and verification.get('nonzero_bytes') == 0
            and verification.get('bytes_checked') == target.get('size')
            and isinstance(target.get('size'), int) and target['size'] > 0
            and isinstance(verification.get('sha256'), str)
            and len(verification['sha256']) == 64
            and verification.get('independent_attack', {}).get('passed') is True)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def prepare(record, evidence_root):
    if not eligible(record):
        raise EraseProofError('Select a signed, successful whole-image zero-overwrite record first.')
    target = Path(record['payload']['target']['path'])
    if target.suffix.lower() not in ('.img', '.raw', '.dd', '.bin'):
        raise EraseProofError('Only ordinary raw image files can be removed here.')
    # Reuse file-erasure planning guards without performing an overwrite:
    # protected paths, symlinks, hard links and special files are refused.
    planned = plan_files(target)
    path = Path(planned['root'])
    evidence = Path(evidence_root).resolve()
    if path == evidence or evidence in path.parents:
        raise EraseProofError('Evidence files cannot be removed by image cleanup.')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise EraseProofError('Select an ordinary image file with a single link.')
    if info.st_size != record['payload']['verification']['bytes_checked']:
        raise EraseProofError('Image size differs from its signed verification; removal refused.')
    require_unattached_image(path)
    return {'path': str(path), 'identity': identity(info),
            'record_id': record['payload']['id'], 'confirmation': path.name}


def remove(record, prepared, confirmation, evidence_root, progress=None, cancel=None):
    fresh = prepare(record, evidence_root)
    if fresh != prepared:
        raise EraseProofError('The image changed after confirmation was prepared; removal refused.')
    if confirmation != prepared['confirmation']:
        raise EraseProofError('Confirmation must exactly match the image filename.')
    path = Path(prepared['path'])
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(descriptor, 'rb', buffering=0) as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            opened = os.fstat(stream.fileno())
            if identity(opened) != prepared['identity'] or opened.st_nlink != 1:
                raise EraseProofError('Image identity changed; removal refused.')
            digest, checked = hashlib.sha256(), 0
            while checked < opened.st_size:
                checkpoint(cancel)
                data = stream.read(min(4*1024*1024, opened.st_size-checked))
                if not data or data.strip(b'\0'):
                    raise EraseProofError('Image no longer contains the verified zeros; removal refused.')
                checked += len(data)
                digest.update(data)
                if progress:
                    progress('Check before removal', checked/opened.st_size, f'Reading {path.name}: {checked:,} bytes')
            if digest.hexdigest() != record['payload']['verification']['sha256']:
                raise EraseProofError('Image digest differs from its signed verification; removal refused.')
            require_unattached_image(path)
            checkpoint(cancel)
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (identity(current) != prepared['identity'] or current.st_nlink != 1
                    or identity(os.fstat(stream.fileno())) != prepared['identity']):
                raise EraseProofError('Image changed during the final read; removal refused.')
            os.unlink(path.name, dir_fd=parent)
            os.fsync(parent)
    finally:
        os.close(parent)
    return {'removed': str(path), 'bytes_checked': checked, 'record_id': prepared['record_id']}
