"""Seal/verify prepared bundle contents before a live-image copy."""
import hashlib
import json
from pathlib import Path
import sys

NAME = 'BUNDLE-CONTENTS.json'


def contents(root):
    root = Path(root).resolve(strict=True)
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if relative in (NAME, NAME+'.tmp'):
            continue
        if path.is_symlink():
            if not path.resolve(strict=True).is_relative_to(root):
                raise RuntimeError('Bundle link escapes its root: '+relative)
            result[relative] = {'link': str(path.readlink())}
        elif path.is_file():
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(4*1024*1024), b''):
                    digest.update(chunk)
            result[relative] = {'sha256': digest.hexdigest(), 'bytes': path.stat().st_size}
        elif not path.is_dir():
            raise RuntimeError('Unsupported bundle entry: '+relative)
    return result


def seal(root):
    root = Path(root)
    manifest = {'schema': 'eraseproof.bundle-contents.v1', 'entries': contents(root)}
    temporary = root/(NAME+'.tmp')
    temporary.write_text(json.dumps(manifest, indent=2)+'\n')
    temporary.replace(root/NAME)
    return manifest


def verify(root):
    manifest = json.loads((Path(root)/NAME).read_text())
    if manifest.get('schema') != 'eraseproof.bundle-contents.v1' or manifest.get('entries') != contents(root):
        raise RuntimeError('Prepared bundle changed or is incomplete; prepare it again before copying.')
    return manifest


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('seal', 'verify'):
        raise SystemExit('Usage: bundle_manifest.py seal|verify BUNDLE')
    result = (seal if sys.argv[1] == 'seal' else verify)(sys.argv[2])
    print(json.dumps({'bundle_contents': 'verified', 'entries': len(result['entries'])}))
