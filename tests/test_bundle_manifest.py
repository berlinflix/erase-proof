import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('bundle_manifest', Path(__file__).resolve().parents[1]/'scripts/bundle_manifest.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


@pytest.mark.parametrize('mutation', ['changed', 'missing', 'extra'])
def test_prepared_bundle_detects_incomplete_or_changed_copy(tmp_path, mutation):
    payload = tmp_path/'application'
    payload.write_bytes(b'verified executable bytes')
    bundle.seal(tmp_path)
    bundle.verify(tmp_path)
    if mutation == 'changed':
        payload.write_bytes(b'different executable bytes')
    elif mutation == 'missing':
        payload.unlink()
    else:
        (tmp_path/'unexpected').write_bytes(b'new contents')
    with pytest.raises(RuntimeError, match='changed or is incomplete'):
        bundle.verify(tmp_path)


def test_prepared_bundle_refuses_external_links(tmp_path):
    root = tmp_path/'bundle'
    root.mkdir()
    outside = tmp_path/'external'
    outside.write_bytes(b'outside bytes')
    (root/'link').symlink_to(outside)
    with pytest.raises(RuntimeError, match='escapes'):
        bundle.seal(root)
