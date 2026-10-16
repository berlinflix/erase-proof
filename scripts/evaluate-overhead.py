"""E5 timings on newly generated files, never existing images or devices."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import resource
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent/'src'))
from eraseproof import nativeio
from eraseproof.engine import erase

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--image-mib', type=int, choices=[128, 1024], default=1024)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
size = args.image_mib*1024*1024


def cpu():
    parent, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return parent.ru_utime+parent.ru_stime+children.ru_utime+children.ru_stime


def result(started, cpu_started):
    seconds = time.monotonic()-started
    return {'seconds': round(seconds, 6), 'cpu_seconds_parent_and_reaped_children': round(cpu()-cpu_started, 6),
            'mib_per_second': round(args.image_mib/seconds, 3)}


with tempfile.TemporaryDirectory(prefix='eraseproof-overhead-', dir='/var/tmp') as temporary:
    root, measurements = Path(temporary), {}
    for label, flags in (('dd-direct-final-fsync', 'direct'), ('dd-direct-dsync', 'direct,dsync')):
        path = root/(label+'.img')
        started, cpu_started = time.monotonic(), cpu()
        subprocess.run(['dd', 'if=/dev/zero', 'of='+str(path), 'bs=4M', 'count='+str(args.image_mib//4),
                        'oflag='+flags, 'conv=fsync', 'status=none'], check=True, timeout=180)
        measurements[label] = result(started, cpu_started)
    path = root/'native-direct.img'
    with path.open('xb') as stream:
        stream.truncate(size)
    started, cpu_started = time.monotonic(), cpu()
    with path.open('r+b', buffering=0) as stream:
        for offset in range(0, size, 4*1024*1024):
            nativeio.zero(stream.fileno(), offset, 4*1024*1024)
        os.fsync(stream.fileno())
    measurements['C-direct-fdatasync-per-chunk'] = result(started, cpu_started)
    path = root/'verified-pipeline.img'
    original = os.urandom(4096)
    with path.open('xb') as stream:
        stream.write(original)
        stream.truncate(size)
        stream.flush()
        os.fsync(stream.fileno())
    timeline = {}
    def progress(stage, fraction, message):
        entry = timeline.setdefault(stage, {'first_seconds': time.monotonic()-started})
        entry['last_seconds'] = time.monotonic()-started
    started, cpu_started = time.monotonic(), cpu()
    record = erase(path, path.name, root/'evidence', {'block_size': 4096, 'block_hashes': [hashlib.sha256(original).hexdigest()]}, progress=progress)
    measurements['full-erasure-verification-pipeline'] = result(started, cpu_started)
    assert record['payload']['certificate_issued'] and record['payload']['verification']['rrs'] == 0
    verification_start = timeline.get('Verify', timeline.get('Attack', {})).get('first_seconds')
    total = measurements['full-erasure-verification-pipeline']['seconds']
    report = {'image_bytes': size, 'measurements': measurements, 'progress_callback_timeline': timeline,
              'approximate_verification_share': (total-verification_start)/total if verification_start is not None else None,
              'rrs': 0, 'independent_tools': record['payload']['verification']['independent_attack']['required_tools'],
              'physical_drives_used': 0,
              'limitations': 'Single-run generated sparse-file measurements, affected by caching, allocation and concurrent jobs. dd-final-fsync and C-per-chunk-fdatasync use different flush schedules; dd-dsync is also reported. Timeline uses the first/last progress callbacks, not instrumented syscall boundaries. CPU includes this process and reaped child descendants.'}
    (args.output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
