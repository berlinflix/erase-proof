"""Measured DFRWS accuracy. Ground truth is used only after each recovery run."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'src'))
from eraseproof import carve, external

parser = argparse.ArgumentParser()
parser.add_argument('--data', type=Path, required=True, help='Directory containing both original DFRWS 2006 ZIP downloads')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
root = args.output.resolve()
archive = args.data/'dfrws-2006-challenge-files.zip'
if hashlib.sha256(archive.read_bytes()).hexdigest() != '5629d0ad5583bc2e51554a53d3d068c480fd81774bfccd73f3bf39ccbe13b8c8':
    raise SystemExit('Organizer ground-truth archive SHA-256 mismatch.')
with zipfile.ZipFile(args.data/'dfrws-2006-challenge.zip') as source:
    raw = source.read('dfrws-2006-challenge.raw')
if hashlib.md5(raw).hexdigest() != 'bd09d612fc8b3f92662b98f9456f2ada':
    raise SystemExit('Organizer raw image MD5 mismatch.')
image = root/'challenge.raw'
image.write_bytes(raw)
source_sha = hashlib.sha256(raw).hexdigest()
del raw
truth, suffixes = {}, {}
with zipfile.ZipFile(archive) as source:
    for name in source.namelist():
        if name.startswith('fullfiles/') and not name.endswith('/'):
            payload = source.read(name)
            truth[hashlib.sha256(payload).hexdigest()] = Path(name).name
            suffixes[Path(name).name] = Path(name).suffix.lower()


def summarize(files):
    measured, exact = [], set()
    for path, confidence in files:
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        name = truth.get(sha)
        if name:
            exact.add(name)
        measured.append({'sha256': sha, 'bytes': path.stat().st_size, 'ground_truth_exact': name, 'confidence': confidence})
    return {'outputs': len(measured), 'exact_originals': sorted(exact), 'exact_original_count': len(exact),
            'exact_original_recall_all_32': len(exact)/len(truth),
            'exact_original_output_precision': sum(bool(f['ground_truth_exact']) for f in measured)/len(measured) if measured else None,
            'nonexact_outputs': sum(not f['ground_truth_exact'] for f in measured), 'findings': measured,
            'precision_scope': 'Exact original-file hashes only. Embedded members, valid partials and altered originals count as nonexact; this is stricter than semantic file validity.'}


results = {}
started = time.monotonic()
native = []
for candidate in carve.scan(image):
    recovered = carve.extract(image, candidate, root/'native')
    native.append((Path(recovered.output), recovered.confidence))
results['EraseProof-contiguous'] = {**summarize(native), 'seconds': time.monotonic()-started, 'status': 'completed'}
started = time.monotonic()
fragmented, fragment_error, fragment_warnings = [], None, []
try:
    for candidate in carve.scan(image, fragmented=True, warnings=fragment_warnings):
        recovered = carve.extract(image, candidate, root/'native-fragments')
        fragmented.append((Path(recovered.output), recovered.confidence))
except Exception as error:
    fragment_error = str(error)
results['EraseProof-fragments'] = {**summarize(fragmented), 'seconds': time.monotonic()-started,
                                 'status': 'incomplete' if fragment_error else 'completed-with-search-limits' if fragment_warnings else 'completed',
                                 'error': fragment_error, 'warnings': fragment_warnings}
for name, arguments, output_folder in (
    ('PhotoRec', ['photorec', '/log', '/logname', str(root/'photorec.log'), '/d', str(root/'photorec'), '/cmd', str(image),
                  'partition_none,options,mode_ext2,fileopt,everything,enable,wholespace,search'], 'photorec.*'),
    ('Foremost', ['foremost', '-q', '-i', str(image), '-o', str(root/'foremost')], 'foremost')):
    status = external.run(arguments, root, name.lower(), 180)
    files = [(file, None) for folder in root.glob(output_folder) if folder.is_dir()
             for file in folder.rglob('*') if file.is_file() and file.name not in ('audit.txt', 'report.xml')]
    results[name] = {**summarize(files), 'seconds': status['duration_seconds'], 'status': status['status']}
assert hashlib.sha256(image.read_bytes()).hexdigest() == source_sha
report = {'corpus': 'DFRWS 2006', 'source': 'https://github.com/dfrws/dfrws2006-challenge', 'image_sha256': source_sha,
          'ground_truth_archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'source_unchanged': True,
          'truth_files': len(truth), 'truth_types': suffixes, 'results': results,
          'limitations': 'No unsupported-type recall is hidden. Carving confidence is structural, not a probability of original-byte identity. This run establishes a baseline; fragmented and corpus-wide calibrated confidence remain separate measured experiments.'}
(root/'result.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({name: {k: v for k, v in result.items() if k != 'findings'} for name, result in results.items()}, indent=2))
