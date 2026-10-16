"""Assemble owner-uploaded draft parts without rebuilding or executing them.

Manual workflow only. The caller supplies a manifest SHA-256; every part and
whole artifact must match before upload. Publication remains a separate action.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def api(path, binary=False, method='GET'):
    arguments = ['gh', 'api', path, '--method', method]
    if binary:
        arguments += ['--header', 'Accept: application/octet-stream']
    result = subprocess.run(arguments, capture_output=True, check=True, timeout=180)
    return result.stdout if binary else json.loads(result.stdout) if result.stdout else None


def asset_map(base):
    result = {}
    for page in range(1, 11):
        entries = api(base+f'/assets?per_page=100&page={page}')
        for entry in entries:
            if entry['name'] in result:
                raise ValueError('Ambiguous duplicate release asset name')
            result[entry['name']] = entry
        if len(entries) < 100:
            return result
    raise ValueError('Release asset inventory exceeds the bounded transfer scope')


def main():
    repo = os.environ['GITHUB_REPOSITORY']
    release = os.environ['RELEASE_ID']
    name, expected = os.environ['TRANSFER_MANIFEST'], os.environ['TRANSFER_MANIFEST_SHA256']
    if repo != 'berlinflix/erase-proof' or not release.isdecimal() or not re.fullmatch(r'ep-transfer-manifest-[0-9a-f]{16}\.json', name) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Invalid repository, release or manifest identity')
    base = f'repos/{repo}/releases/{release}'
    current = api(base)
    if not current['draft']:
        raise ValueError('Only draft release transfers are accepted')
    metadata = asset_map(base)
    manifest_asset = metadata[name]
    if not 0 < manifest_asset['size'] <= 1024*1024:
        raise ValueError('Unbounded manifest')
    raw = api(f'repos/{repo}/releases/assets/{manifest_asset["id"]}', binary=True)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Manifest SHA-256 mismatch')
    manifest = json.loads(raw)
    if manifest['schema'] != 'eraseproof.release-transfer.v1' or manifest['release_id'] != int(release) or manifest['repo'] != repo or manifest['version'] != '0.12.0':
        raise ValueError('Manifest scope mismatch')
    if current['tag_name'] != 'v'+manifest['version']:
        raise ValueError('Release tag mismatch')
    allowed = {'EraseProof-Ubuntu-x86_64-0.12.0.tar.gz', 'EraseProof-Live-Ubuntu24.04-x86_64-0.12.0.iso'}
    names, parts, completed = set(), set(), []
    prefix = 'ep-transfer-'+manifest['nonce']+'-'
    if not re.fullmatch('[0-9a-f]{16}', manifest['nonce']) or not 1 <= len(manifest['files']) <= 2:
        raise ValueError('Invalid transfer geometry')
    cleanup = {manifest_asset['id']}
    with tempfile.TemporaryDirectory(prefix='eraseproof-release-') as temporary:
        uploads = []
        for item in manifest['files']:
            filename = item['name']
            if filename not in allowed or filename in names or not 0 < item['bytes'] <= 2*1024**3 or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
                raise ValueError('Invalid artifact identity or size')
            names.add(filename)
            if not 1 <= len(item['parts']) <= 256 or sum(p['bytes'] for p in item['parts']) != item['bytes']:
                raise ValueError('Invalid part geometry')
            existing = metadata.get(filename)
            if existing and (existing['state'] != 'uploaded' or existing['size'] != item['bytes'] or existing.get('digest') != 'sha256:'+item['sha256']):
                raise ValueError('An existing whole artifact differs; refusing to overwrite it')
            target = Path(temporary)/filename
            digest = hashlib.sha256()
            with target.open('xb') as output:
                for part in item['parts']:
                    part_name = part['name']
                    if not part_name.startswith(prefix) or part_name in parts or not 0 < part['bytes'] <= 8*1024**2 or not re.fullmatch('[0-9a-f]{64}', part['sha256']):
                        raise ValueError('Invalid or duplicate part')
                    parts.add(part_name)
                    entry = metadata[part_name]
                    if entry['state'] != 'uploaded' or entry['size'] != part['bytes']:
                        raise ValueError('Part upload is incomplete')
                    cleanup.add(entry['id'])
                    data = api(f'repos/{repo}/releases/assets/{entry["id"]}', binary=True)
                    if len(data) != part['bytes'] or hashlib.sha256(data).hexdigest() != part['sha256']:
                        raise ValueError('Part SHA-256 mismatch')
                    digest.update(data)
                    output.write(data)
            if target.stat().st_size != item['bytes'] or digest.hexdigest() != item['sha256']:
                raise ValueError('Whole artifact SHA-256 mismatch')
            if not existing:
                uploads.append(target)
            completed.append(filename)
        for target in uploads:
            subprocess.run(['gh', 'release', 'upload', current['tag_name'], str(target), '--repo', repo], check=True, timeout=600)
        after = asset_map(base)
        for item in manifest['files']:
            entry = after[item['name']]
            if entry['state'] != 'uploaded' or entry['size'] != item['bytes'] or entry.get('digest') != 'sha256:'+item['sha256']:
                raise ValueError('Assembled server artifact does not match')
        print(json.dumps({'verified_whole_assets': completed, 'draft_preserved': True}), flush=True)
        # Stay below GitHub's secondary content-generating request limit.
        for identifier in sorted(cleanup):
            api(f'repos/{repo}/releases/assets/{identifier}', method='DELETE')
            time.sleep(1)
        print(json.dumps({'temporary_transfer_assets_removed': len(cleanup)}), flush=True)


if __name__ == '__main__':
    main()
