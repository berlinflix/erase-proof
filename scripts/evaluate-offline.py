"""Larger real-driver history/preservation evaluation on generated images only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--image-mib', type=int, choices=[1024, 2048, 4096, 8192], default=1024)
parser.add_argument('--filesystems', nargs='+', choices=['fat32', 'ext4', 'ntfs', 'exfat'], default=['fat32', 'ext4', 'ntfs', 'exfat'])
args = parser.parse_args()
if os.geteuid() != 0:
    parser.error('Root is needed for disposable image mounts; no physical drives are selected.')
if os.environ.get('ERASEPROOF_EVALUATION_NAMESPACE') != '1':
    os.execvpe('unshare', ['unshare', '--mount', '--propagation', 'private', sys.executable,
                         str(Path(__file__).resolve()), *sys.argv[1:]],
              {**os.environ, 'ERASEPROOF_EVALUATION_NAMESPACE': '1'})
sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'src'))
from eraseproof.evidence import verify_record
from eraseproof.offline import backend


def run(*arguments):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors='replace')[-4000:])
    return result.stdout


def write(path, data):
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


args.output.mkdir(parents=True, exist_ok=False)
results = []
for filesystem in args.filesystems:
    case = args.output.resolve()/filesystem
    case.mkdir()
    token = uuid.uuid4().hex
    secret, older, keep = os.urandom(65573), os.urandom(49037), os.urandom(17013)
    with tempfile.TemporaryDirectory(prefix='eraseproof-evaluate-', dir='/var/tmp') as temporary:
        managed = Path(temporary).resolve()
        image, mountpoint = managed/'volume.img', managed/'mnt'
        mountpoint.mkdir()
        with image.open('xb') as stream:
            stream.truncate(args.image_mib*1024*1024)
        tools = {'fat32': ['mkfs.fat', '-F', '32'], 'ext4': ['mkfs.ext4', '-q', '-F'],
                 'ntfs': ['mkfs.ntfs', '-F', '-Q'], 'exfat': ['mkfs.exfat']}
        run(*tools[filesystem], image)
        loop, mounted = None, False
        try:
            loop = run('losetup', '--find', '--show', image).decode().strip()
            association = json.loads(run('losetup', '--list', '--json', '--output', 'NAME,BACK-FILE', loop))['loopdevices'][0]
            if Path(association['back-file']).resolve() != image:
                raise RuntimeError('Unexpected loop backing identity; mount refused.')
            if filesystem == 'ntfs':
                run('ntfs-3g', loop, mountpoint)
            elif filesystem == 'exfat':
                run('mount.exfat-fuse', loop, mountpoint)
            else:
                run('mount', '-t', 'vfat' if filesystem == 'fat32' else 'ext4', loop, mountpoint)
            mounted = True
            folder = mountpoint/'private-case'
            folder.mkdir()
            active = folder/('draft-'+token+'.custom')
            write(active, older)
            run('sync', '-f', mountpoint)
            staged = folder/'.editor-save'
            write(staged, secret)
            os.replace(staged, active)
            history = mountpoint/('deleted-backup-'+token+'.custom')
            write(history, secret)
            write(mountpoint/'keep.custom', keep)
            run('sync', '-f', mountpoint)
            history.unlink()
            run('sync', '-f', mountpoint)
            run('umount', mountpoint)
            mounted = False
            run('losetup', '--detach', loop)
            loop = None
            deadline = time.monotonic()+5
            while run('losetup', '--associated', image).strip():
                if time.monotonic() >= deadline:
                    raise RuntimeError('Loop detach did not complete.')
                time.sleep(.05)
            adapter = backend(filesystem)
            prepared = adapter.plan_path(image, '/private-case')
            started = time.monotonic()
            record = adapter.erase_path(image, '/private-case', prepared['confirmation'], case/'evidence')
            elapsed = time.monotonic()-started
            assert verify_record(record)
            verification = record['payload']['verification']
            assert verification['rrs'] == 0 and verification['history_verification']['passed']
            assert verification['independent_attack']['passed'] and verification['preserved_files_hash_checked'] == 1
            listing = run('fls', '-u', '-r', '-p', image).decode()
            inode = next(re.search(r'(\d[\d-]*):\t', line)[1] for line in listing.splitlines() if line.endswith('\tkeep.custom'))
            assert run('icat', image, inode) == keep
            # Search raw bytes for both the fingerprinted current/backup data
            # and a distinct unreferenced prior version from the atomic save.
            pending = b''
            with image.open('rb') as source:
                while chunk := source.read(4*1024*1024):
                    window = pending+chunk
                    assert secret not in window and older not in window
                    pending = window[-max(len(secret), len(older)):]
            report = {'filesystem': filesystem, 'image_bytes': image.stat().st_size,
                      'activity': ['create', 'atomic-save-via-rename', 'copy', 'delete-backup', 'offline-EraseProof-cleanup'],
                      'target_and_unreferenced_prior_version_absent': True, 'preserved_file_sha256': hashlib.sha256(keep).hexdigest(),
                      'preserved_file_independent_icat_exact': True, 'rrs': verification['rrs'],
                      'history_readback_passed': True, 'independent_attack': verification['independent_attack'],
                      'signed_record_valid': True, 'erasure_and_verification_seconds': round(elapsed, 3),
                      'physical_drives_used': 0}
            (case/'result.json').write_text(json.dumps(report, indent=2)+'\n')
            results.append(report)
            print(json.dumps(report, indent=2), flush=True)
        finally:
            if mounted:
                run('umount', mountpoint)
            if loop:
                run('losetup', '--detach', loop)
(args.output/'results.json').write_text(json.dumps(results, indent=2)+'\n')
