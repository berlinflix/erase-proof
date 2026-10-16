import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from urllib.parse import quote

import pytest

from eraseproof.models import Cancelled, EraseProofError
from eraseproof.trash import listing, recover


def store(tmp_path, name='unrecognized.custom'):
    root = tmp_path/'Trash'
    (root/'info').mkdir(parents=True)
    (root/'files').mkdir()
    (root/'info'/(name+'.trashinfo')).write_text('[Trash Info]\nPath='+quote('/original/日本/notes.custom')+'\nDeletionDate=2026-10-16T11:12:00\n')
    return root, root/'files'/name


def test_arbitrary_trash_file_copy_keeps_original_and_metadata(tmp_path):
    root, item = store(tmp_path)
    data = os.urandom(13879)
    item.write_bytes(data)
    before = (root/'info'/(item.name+'.trashinfo')).read_bytes()
    found = listing(root)
    assert found['entries'][0]['original_path'] == '/original/日本/notes.custom'
    assert not found['warnings']
    report = recover(item.name, tmp_path/'output', root)
    assert report['complete'] and report['candidates'][0]['sha256'] == hashlib.sha256(data).hexdigest()
    assert Path(report['candidates'][0]['output']).read_bytes() == item.read_bytes() == data
    assert (root/'info'/(item.name+'.trashinfo')).read_bytes() == before
    assert json.loads((tmp_path/'output/recovery.json').read_text())['complete']
    with pytest.raises(FileExistsError):
        recover(item.name, tmp_path/'output', root)
    with pytest.raises(EraseProofError, match='outside'):
        recover(item.name, root/'output', root)


def test_original_metadata_is_never_an_output_path_and_report_name_cannot_collide(tmp_path):
    root, item = store(tmp_path, 'recovery.json')
    item.write_bytes(b'original content')
    outside = tmp_path/'valuable.txt'
    outside.write_bytes(b'keep me')
    (root/'info/recovery.json.trashinfo').write_text('[Trash Info]\nPath='+str(outside)+'\nPath=/ignored/duplicate\n')
    report = recover(item.name, tmp_path/'output', root)
    assert report['selected']['original_path'] == str(outside)
    assert Path(report['candidates'][0]['output']).read_bytes() == b'original content'
    assert outside.read_bytes() == b'keep me'


def test_directory_copy_and_nested_symlink_refusal(tmp_path):
    root, item = store(tmp_path, 'a folder')
    item.mkdir()
    (item/'nested').mkdir()
    (item/'nested/binary.custom').write_bytes(os.urandom(6717))
    first = recover(item.name, tmp_path/'copy', root)
    assert len(first['candidates']) == 1
    (item/'nested/link').symlink_to(tmp_path/'valuable')
    with pytest.raises(EraseProofError, match='symlink'):
        recover(item.name, tmp_path/'partial', root)
    assert json.loads((tmp_path/'partial/recovery-incomplete.json').read_text())['complete'] is False
    assert (item/'nested/link').is_symlink()


def test_invalid_trash_entries_and_cancellation_are_explicit(tmp_path):
    root, item = store(tmp_path)
    item.write_bytes(os.urandom(9000))
    (root/'info/bad.trashinfo').write_text('wrong header')
    assert len(listing(root)['warnings']) == 1
    with pytest.raises(EraseProofError):
        recover('../outside', tmp_path/'escape', root)
    with pytest.raises(Cancelled):
        recover(item.name, tmp_path/'cancelled', root, cancel=lambda: True)
    assert item.stat().st_size == 9000
    assert (tmp_path/'cancelled/recovery-incomplete.json').exists()


@pytest.mark.skipif(not shutil.which('gio'), reason='requires actual desktop Trash implementation')
def test_real_gio_normal_move_to_trash_and_arbitrary_recovery(tmp_path, monkeypatch):
    data_home = tmp_path/'data'
    data_home.mkdir()
    monkeypatch.setenv('XDG_DATA_HOME', str(data_home))
    original = tmp_path/'ordinary file 日本.custom'
    data = os.urandom(33017)
    original.write_bytes(data)
    subprocess.run(['gio', 'trash', str(original)], check=True, capture_output=True, timeout=20)
    assert not original.exists()
    found = listing()
    assert len(found['entries']) == 1 and found['entries'][0]['original_path'] == str(original)
    result = recover(found['entries'][0]['id'], tmp_path/'recovered')
    assert Path(result['candidates'][0]['output']).read_bytes() == data
    assert not original.exists()
    assert listing()['entries'] == found['entries']
