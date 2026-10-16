"""E1 comparison on public files and owned disposable volume images only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'src'))
from eraseproof.offline import backend, fingerprint_data
from eraseproof.engine import validate_references, verify
from eraseproof import independent, attackgate

parser = argparse.ArgumentParser()
parser.add_argument('--corpus', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--image-mib', type=int, choices=[128, 1024], default=1024)
parser.add_argument('--filesystems', nargs='+', choices=['fat32', 'ext4', 'ntfs', 'exfat'], default=['fat32', 'ext4', 'ntfs', 'exfat'])
args = parser.parse_args()
if os.geteuid() != 0:
    parser.error('Root is needed only for the owned temporary loop-image mounts.')
if os.environ.get('ERASEPROOF_METHOD_NAMESPACE') != '1':
    os.execvpe('unshare', ['unshare', '--mount', '--propagation', 'private', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
              {**os.environ, 'ERASEPROOF_METHOD_NAMESPACE': '1'})
args.output.mkdir(parents=True, exist_ok=False)
manifest = json.loads((args.corpus/'manifest.json').read_text())
originals = []
for entry in manifest['files']:
    payload = (args.corpus/entry['local_name']).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == entry['sha256']
    originals.append((entry, payload))
token, results = uuid.uuid4().hex[:12], []


def run(*arguments):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, timeout=300)
    if result.returncode:
        raise RuntimeError((result.stdout+result.stderr).decode(errors='replace')[-3000:])
    return result.stdout.decode().strip()


def mount(image, point, filesystem):
    loop = run('losetup', '--find', '--show', image)
    association = json.loads(run('losetup', '--list', '--json', '--output', 'NAME,BACK-FILE', loop))['loopdevices'][0]
    assert Path(association['back-file']).resolve() == image.resolve()
    try:
        if filesystem == 'ntfs':
            run('ntfs-3g', loop, point)
        elif filesystem == 'exfat':
            run('mount.exfat-fuse', loop, point)
        else:
            run('mount', '-t', 'vfat' if filesystem == 'fat32' else 'ext4', loop, point)
    except BaseException:
        run('losetup', '--detach', loop)
        raise
    return loop


for filesystem in args.filesystems:
    with tempfile.TemporaryDirectory(prefix='eraseproof-methods-', dir='/var/tmp') as temporary:
        owned = Path(temporary)
        base, point = owned/'base.img', owned/'mnt'
        point.mkdir()
        with base.open('xb') as file:
            file.truncate(args.image_mib*1024*1024)
        formatter = {'fat32': ['mkfs.fat', '-F', '32'], 'ext4': ['mkfs.ext4', '-q', '-F'],
                     'ntfs': ['mkfs.ntfs', '-F', '-Q'], 'exfat': ['mkfs.exfat']}[filesystem]
        run(*formatter, base)
        loop, mounted = mount(base, point, filesystem), True
        references, block_hashes, patterns, measured = {}, set(), set(), []
        try:
            folder = point/'private-case'
            folder.mkdir()
            for entry, payload in originals:
                name = token+'-'+entry['local_name']
                current = folder/name
                # Prior version differs, then an atomic save replaces it.
                prior = b'PRIOR-'+token.encode()+b'\n'+payload
                current.write_bytes(prior)
                run('sync', '-f', point)
                staged = folder/('.save-'+name)
                staged.write_bytes(payload)
                run('sync', '-f', point)
                os.replace(staged, current)
                backup = point/('deleted-backup-'+name)
                backup.write_bytes(payload)
                run('sync', '-f', point)
                backup.unlink()
                item, blocks, samples = fingerprint_data({'path': '/private-case/'+name, 'inode': ''}, [payload])
                measured.append(item)
                block_hashes.update(blocks)
                patterns.update(samples)
                patterns.update(name.encode(encoding).hex() for encoding in ('utf-8', 'utf-16-le'))
            keep = os.urandom(7319)
            (point/'keep.custom').write_bytes(keep)
            run('sync', '-f', point)
        finally:
            run('umount', point)
            run('losetup', '--detach', loop)
        refs = validate_references({'block_size': 512, 'block_hashes': sorted(block_hashes), 'metadata_patterns': sorted(patterns),
                 'file_hashes': [f['sha256'] for f in measured], 'fuzzy_hashes': [f['ssdeep'] for f in measured],
                 'block_hashes_4096': sorted({h for f in measured for h in f['block_hashes_4096']})})
        for method in ('normal-delete', 'shred-u', 'single-file-overwrite', 'EraseProof'):
            case = args.output/(filesystem+'-'+method)
            case.mkdir()
            image = owned/(method+'.img')
            run('cp', '--reflink=auto', '--sparse=always', base, image)
            started, cpu = time.monotonic(), time.process_time()
            record = None
            if method == 'EraseProof':
                adapter = backend(filesystem)
                prepared = adapter.plan_path(image, '/private-case')
                record = adapter.erase_path(image, '/private-case', prepared['confirmation'], case/'evidence')
            else:
                loop = mount(image, point, filesystem)
                try:
                    folder = point/'private-case'
                    for file in folder.iterdir():
                        if method == 'shred-u':
                            run('shred', '-u', file)
                        elif method == 'single-file-overwrite':
                            with file.open('r+b', buffering=0) as stream:
                                stream.write(bytes(file.stat().st_size))
                                os.fsync(stream.fileno())
                            file.unlink()
                        else:
                            file.unlink()
                    folder.rmdir()
                    run('sync', '-f', point)
                finally:
                    run('umount', point)
                    run('losetup', '--detach', loop)
            operation_seconds = time.monotonic()-started
            before = hashlib.sha256(image.read_bytes()).hexdigest()
            # The same post-method attack is applied to every method. Native
            # contiguous findings and independent tools are recorded separately.
            native = verify(image, refs, fragment_search=False)
            with image.open('rb') as stream:
                independent_result = attackgate.check(image, case/'comparison-attack', refs, stream=stream,
                    length=image.stat().st_size, expected_sha256=before)
            after = hashlib.sha256(image.read_bytes()).hexdigest()
            assert before == after
            names = run('fls', '-u', '-r', '-p', image)
            import re
            inode = next(re.search(r'(\d[\d-]*):\t', line)[1] for line in names.splitlines() if line.endswith('\tkeep.custom'))
            output = subprocess.run(['icat', str(image), inode], capture_output=True, check=True).stdout
            assert output == keep
            result = {'filesystem': filesystem, 'method': method, 'image_bytes': image.stat().st_size,
                      'public_files': len(originals), 'operation_seconds': round(operation_seconds, 3),
                      'total_seconds': round(time.monotonic()-started, 3), 'parent_cpu_seconds': round(time.process_time()-cpu, 3),
                      'native_reference_block_fraction': native['matched_reference_blocks']/max(1, len(refs['block_hashes'])),
                      'native_metadata_patterns': native['metadata_residues'], 'native_fuzzy_findings': len(native['fuzzy_findings']),
                      'independent': independent_result, 'source_unchanged_by_attacks': True, 'unrelated_file_preserved': True,
                      'issued_certificate': bool(record and record['payload']['certificate_issued']), 'physical_drives_used': 0}
            (case/'result.json').write_text(json.dumps(result, indent=2)+'\n')
            results.append(result)
            (args.output/'results.json').write_text(json.dumps({'corpus': manifest, 'results': results,
                'limits': 'Small deterministic public subset; no physical firmware timings, chip-off results or population-wide recovery-rate claim. Parent CPU excludes subprocess CPU.'}, indent=2)+'\n')
            print(json.dumps({k:v for k,v in result.items() if k != 'independent'}), flush=True)
