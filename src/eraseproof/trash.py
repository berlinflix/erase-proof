"""Read-only Freedesktop Trash discovery and copies to a separate destination.

Original paths are display metadata only. No restore ever writes to those paths,
removes Trash entries, follows symlinks or overwrites an existing destination.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
from urllib.parse import unquote

from .carve import CHUNK, checkpoint
from .models import EraseProofError


def default_root():
    data = Path(os.environ.get('XDG_DATA_HOME', ''))
    if not str(data).startswith('/'):
        data = Path.home()/'.local/share'
    return data/'Trash'


def _directory(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def listing(root=None):
    root = Path(root) if root is not None else default_root()
    if not root.exists():
        return {'root': str(root.absolute()), 'entries': [], 'warnings': []}
    entries, warnings = [], []
    return _listing(root, entries, warnings)


def _listing(root, entries, warnings):
    # Directory descriptors pin the requested store, including its files/info
    # children. .trashinfo paths never become filesystem access paths.
    root_fd = _directory(root)
    files, info = None, None
    try:
        files = os.open('files', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        info = os.open('info', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        for name in sorted(os.listdir(info)):
            if not name.endswith('.trashinfo'):
                continue
            if len(entries)+len(warnings) >= 100000:
                raise EraseProofError('Trash entry limit reached. Select a smaller Trash store.')
            item = name[:-10]
            try:
                _item_name(item)
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=info)
                with os.fdopen(descriptor, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise EraseProofError('Metadata is not a regular file.')
                    raw = stream.read(65537)
                if len(raw) > 65536:
                    raise EraseProofError('Metadata exceeds 64 KiB.')
                lines = raw.decode('utf-8', errors='strict').splitlines()
                if not lines or lines[0] != '[Trash Info]':
                    raise EraseProofError('Missing Trash Info header.')
                values = {}
                for line in lines[1:]:
                    key, separator, value = line.partition('=')
                    if separator and key in ('Path', 'DeletionDate') and key not in values:
                        values[key] = value
                original = unquote(values['Path'], errors='strict')
                if not original or '\x00' in original:
                    raise EraseProofError('Invalid original path metadata.')
                current = os.stat(item, dir_fd=files, follow_symlinks=False)
                if not (stat.S_ISREG(current.st_mode) or stat.S_ISDIR(current.st_mode)):
                    raise EraseProofError('Symlinks and special files are not copied.')
                entries.append({'id': item, 'original_path': original,
                                'deleted_at': values.get('DeletionDate', ''),
                                'kind': 'directory' if stat.S_ISDIR(current.st_mode) else 'file',
                                'size': current.st_size if stat.S_ISREG(current.st_mode) else None})
            except (OSError, ValueError, KeyError, EraseProofError) as error:
                warnings.append({'metadata': name, 'reason': str(error)})
    finally:
        if info is not None:
            os.close(info)
        if files is not None:
            os.close(files)
        os.close(root_fd)
    return {'root': str(root.absolute()), 'entries': entries, 'warnings': warnings}


def _item_name(name):
    if not name or name in ('.', '..') or '/' in name or '\x00' in name:
        raise EraseProofError('Select one exact Trash item ID from trash-list.')


def recover(item, output, root=None, progress=None, cancel=None):
    _item_name(item)
    store = Path(root) if root is not None else default_root()
    entries = listing(store)
    selected = next((e for e in entries['entries'] if e['id'] == item), None)
    if selected is None:
        raise EraseProofError('Trash item is absent, unsupported or has invalid metadata.')
    destination = Path(output).expanduser().absolute()
    resolved_store = store.resolve()
    resolved_output = destination.resolve()
    if resolved_output == resolved_store or resolved_store in resolved_output.parents:
        raise EraseProofError('Choose a recovery destination outside the Trash store.')
    # A new output directory makes partial/cancelled copies explicit and keeps
    # all pre-existing user files untouched.
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    payload = destination/'files'
    payload.mkdir(mode=0o700)
    root_fd = _directory(store)
    try:
        files_fd = os.open('files', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    outputs, count = [], 0
    try:
        source_device = os.fstat(files_fd).st_dev
        def copy_entry(parent, name, relative, depth=0):
            nonlocal count
            checkpoint(cancel)
            count += 1
            if count > 100000 or depth > 128:
                raise EraseProofError('Trash tree size/depth limit reached; output is incomplete.')
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if info.st_dev != source_device:
                raise EraseProofError('Trash tree crosses a filesystem boundary.')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    opened = os.fstat(child)
                    if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                        raise EraseProofError('Trash directory changed during copying.')
                    (payload/relative).mkdir(mode=0o700)
                    for member in sorted(os.listdir(child)):
                        copy_entry(child, member, relative/member, depth+1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                with os.fdopen(fd, 'rb') as source:
                    before = os.fstat(source.fileno())
                    if not stat.S_ISREG(before.st_mode) or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
                        raise EraseProofError('Trash file changed during copying.')
                    sha, size = hashlib.sha256(), 0
                    with (payload/relative).open('xb') as target:
                        remaining = before.st_size
                        while remaining:
                            checkpoint(cancel)
                            data = source.read(min(CHUNK, remaining))
                            if not data:
                                raise EraseProofError('Short read while copying a Trash file.')
                            target.write(data)
                            sha.update(data)
                            size += len(data)
                            remaining -= len(data)
                        target.flush()
                        os.fsync(target.fileno())
                    after = os.fstat(source.fileno())
                    if size != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise EraseProofError('Trash file changed during copying; output is incomplete.')
                outputs.append({'name': str(relative), 'output': str(payload/relative), 'length': size,
                                'sha256': sha.hexdigest(), 'method': 'ubuntu-trash-copy', 'confidence': 0,
                                'evidence': ['Read-only copy of an allocated Trash item; original paths are metadata only.']})
                if progress:
                    progress('Trash recovery', 0, f'Copied {len(outputs)} files')
            else:
                raise EraseProofError('Trash tree contains a symlink or special file; output is incomplete.')
        copy_entry(files_fd, item, Path(item))
    except BaseException as error:
        (destination/'recovery-incomplete.json').write_text(json.dumps({'complete': False, 'error': str(error), 'candidates': outputs}, indent=2)+'\n')
        raise
    finally:
        os.close(files_fd)
    report = {'source': entries['root'], 'selected': selected, 'mode': 'ubuntu-trash-copy',
              'complete': True, 'candidates': outputs, 'warnings': [],
              'scope': 'Copies existing Trash files to a new folder. Original paths, Trash entries and source contents are unchanged.'}
    (destination/'recovery.json').write_text(json.dumps(report, indent=2)+'\n')
    return report
