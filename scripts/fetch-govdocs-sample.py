"""Fetch a small deterministic Govdocs1 sample using verified HTTP byte ranges.

Corpus data is never executed. ZIP paths are not used as destination paths.
The 486 MB source archive need not be downloaded to obtain a few small files.
"""
import argparse
import io
import json
from pathlib import Path
import hashlib
import urllib.request
import zipfile

URL = 'https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles/000.zip'


class RangedZip(io.RawIOBase):
    def __init__(self):
        with urllib.request.urlopen(urllib.request.Request(URL, method='HEAD'), timeout=30) as response:
            self.length, self.etag = int(response.headers['Content-Length']), response.headers['ETag']
        self.position, self.downloaded = 0, 0

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position+offset if whence == 1 else self.length+offset
        if not 0 <= position <= self.length:
            raise ValueError('ZIP seek outside the remote object')
        self.position = position
        return position

    def read(self, size=-1):
        size = min(self.length-self.position, size if size >= 0 else self.length)
        if size == 0:
            return b''
        if size > 4*1024*1024 or self.downloaded+size > 32*1024*1024:
            raise ValueError('Corpus range download exceeds the bounded sample budget')
        first, last = self.position, self.position+size-1
        request = urllib.request.Request(URL, headers={'Range': f'bytes={first}-{last}', 'If-Match': self.etag})
        with urllib.request.urlopen(request, timeout=45) as response:
            if response.status != 206 or response.headers.get('Content-Range') != f'bytes {first}-{last}/{self.length}' or response.headers.get('ETag') != self.etag:
                raise ValueError('Server did not preserve the requested range/object identity')
            data = response.read(size+1)
        if len(data) != size:
            raise ValueError('Short or oversized corpus range response')
        self.position += size
        self.downloaded += size
        return data


parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
source, selected = RangedZip(), []
with zipfile.ZipFile(source) as archive:
    entries = sorted(archive.infolist(), key=lambda e: e.filename)
    for suffix in ('.pdf', '.jpg', '.png', '.txt', '.doc', '.xls', '.html', '.zip'):
        choices = [e for e in entries if Path(e.filename).suffix.lower() == suffix and 4096 <= e.file_size <= 256*1024 and not e.flag_bits & 1][:2]
        for entry in choices:
            payload = archive.read(entry)
            destination = args.output/(str(len(selected)).zfill(2)+suffix)
            destination.write_bytes(payload)
            selected.append({'corpus_name': entry.filename, 'local_name': destination.name,
                             'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload), 'zip_crc': entry.CRC})
report = {'corpus': 'Govdocs1 000.zip', 'url': URL, 'etag': source.etag, 'object_bytes': source.length,
          'downloaded_bytes': source.downloaded, 'selection': 'First two sorted entries per requested suffix, size 4–256 KiB; all selected entries retained without filtering on recovery results',
          'files': selected}
(args.output/'manifest.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
