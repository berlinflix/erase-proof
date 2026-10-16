"""Publish measured summaries without private keys or machine-specific paths."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument('--primary', type=Path, required=True)
parser.add_argument('--remaining', type=Path, required=True)
parser.add_argument('--corpus-files', type=Path, required=True)
parser.add_argument('--overhead', type=Path, required=True)
parser.add_argument('--dfrws', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
manifest = json.loads((args.corpus_files/'manifest.json').read_text())
truth = {entry['local_name']: (args.corpus_files/entry['local_name']).read_bytes() for entry in manifest['files']}
rows = []
for filesystem in ('fat32', 'ext4', 'ntfs', 'exfat'):
    root = args.primary if filesystem == 'fat32' else args.remaining
    evidence = root/(filesystem+'-EraseProof')/'evidence'
    with sqlite3.connect((evidence/'evidence.sqlite3').as_uri()+'?mode=ro', uri=True) as connection:
        record = json.loads(connection.execute('select record from certificates').fetchone()[0])
    selected = record['payload']['plan']['target_files']
    token = Path(selected[0]['path']).name.split('-', 1)[0]
    filenames = {token+'-'+name for name in truth}
    current = {hashlib.sha256(data).hexdigest() for data in truth.values()}
    prior = {hashlib.sha256(b'PRIOR-'+token.encode()+b'\n'+data).hexdigest() for data in truth.values()}
    for method in ('normal-delete', 'shred-u', 'single-file-overwrite', 'EraseProof'):
        case = root/(filesystem+'-'+method)
        result = json.loads((case/'result.json').read_text())
        report = json.loads((case/'comparison-attack/attack.json').read_text())
        outputs = [entry for tool in report['tools'] for entry in tool.get('files', [])]
        hashes = {entry.get('sha256') for entry in outputs}
        names = {Path(entry.get('name', '')).name for tool in report['tools'] if tool['tool'] == 'Sleuth Kit' for entry in tool.get('files', [])}
        row = {key: value for key, value in result.items() if key != 'independent'}
        row.update({'independent_tools': {tool['tool']: tool['status'] for tool in report['tools']},
                    'independent_exact_current_file_hashes': len(current & hashes),
                    'independent_exact_prior_file_hashes': len(prior & hashes),
                    'sleuthkit_original_filenames_recovered': len(filenames & names),
                    'independent_reference_matches': result['independent']['target_reference_matches'],
                    'independent_attack_passed': result['independent']['passed']})
        if method == 'EraseProof':
            assert row['independent_attack_passed'] and row['native_reference_block_fraction'] == 0
            assert not row['independent_exact_current_file_hashes'] and not row['independent_exact_prior_file_hashes']
        rows.append(row)
assert len(rows) == 16
args.output.mkdir(parents=True, exist_ok=True)
study = {'corpus': manifest, 'cases': rows, 'physical_drives_used': 0,
         'limits': 'Deterministic 12-file subset, one run per method/filesystem, 1 GiB volumes. Native block fraction is unique nonzero 512-byte reference hashes; filename counts use actual TSK output names. Prior-file counts require exact independent-output SHA-256, not merely carved content contained within an older version. Parent CPU excludes scanner CPU; full child-inclusive overhead is separate. Concurrent jobs/caching affect timings. Unreferenced originals, journals and inode recovery can yield further data beyond the measured exact-output counts.'}
(args.output/'govdocs-0.12.json').write_text(json.dumps(study, indent=2)+'\n')
overhead = json.loads(args.overhead.read_text())
(args.output/'overhead-0.12.json').write_text(json.dumps(overhead, indent=2)+'\n')
dfrws = json.loads(args.dfrws.read_text())
buckets = {}
for name, result in dfrws['results'].items():
    if not name.startswith('EraseProof'):
        continue
    scores = []
    for lower, upper in ((0, 39), (40, 69), (70, 89), (90, 100)):
        findings = [f for f in result['findings'] if f['confidence'] is not None and lower <= f['confidence'] <= upper]
        exact = sum(bool(f['ground_truth_exact']) for f in findings)
        scores.append({'score_range': [lower, upper], 'outputs': len(findings), 'exact_original_outputs': exact,
                       'empirical_exact_match_fraction': exact/len(findings) if findings else None})
    buckets[name] = scores
(args.output/'confidence-0.12.json').write_text(json.dumps({'corpus': 'DFRWS 2006', 'buckets': buckets,
    'limits': 'Structural scores are not calibrated probabilities. Exact original-byte identity is a stricter label than decodability or semantic validity; embedded files count as nonexact. Small public corpus and fixed score rules do not establish population-wide calibration.'}, indent=2)+'\n')
print(json.dumps({'cases': len(rows), 'certified_erasure_cases': sum(row['issued_certificate'] for row in rows),
                  'all_preserved': all(row['unrelated_file_preserved'] for row in rows), 'outputs': str(args.output)}, indent=2))
