import os
from pathlib import Path
import subprocess
import sys


def test_native_rebuild_preserves_an_actively_mapped_fuzzy_library(tmp_path):
    root = Path(__file__).resolve().parent.parent
    stop = tmp_path/'stop'
    code = '''
from pathlib import Path
import sys
from eraseproof.fingerprints import FuzzyHash
stop = Path(sys.argv[1])
count = 0
with FuzzyHash() as fuzzy:
    print('ready', flush=True)
    while not stop.exists():
        fuzzy.update(b'continuous-library-use'*100)
        assert ':' in fuzzy.hexdigest()
        count += 1
print(count, flush=True)
'''
    worker = subprocess.Popen([sys.executable, '-c', code, str(stop)], cwd=root,
                              env={**os.environ, 'PYTHONPATH': str(root/'src')},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert worker.stdout.readline().strip() == 'ready'
        build = subprocess.run(['bash', str(root/'scripts/build-native.sh')], cwd=root, capture_output=True, text=True, timeout=60)
        assert build.returncode == 0, build.stderr
        stop.write_text('complete')
        out, err = worker.communicate(timeout=15)
        assert worker.returncode == 0, err
        assert int(out.strip()) > 0
    finally:
        if worker.poll() is None:
            worker.terminate()
            worker.wait(timeout=10)
