import io
import os
import sqlite3
import zipfile

from PIL import Image
from reportlab.pdfgen.canvas import Canvas

from eraseproof.validators import isolated


def test_private_candidates_validate_after_root_privilege_drop(tmp_path):
    # When run as root these files/directories cannot be opened by nobody;
    # validation must use its sealed read-only anonymous copy.
    tmp_path.chmod(0o700)
    png = tmp_path/'private.png'
    Image.new('RGB', (17, 23), (2, 95, 11)).save(png)
    pdf = tmp_path/'private.pdf'
    canvas = Canvas(str(pdf))
    canvas.drawString(20, 500, 'Private parser fixture')
    canvas.save()
    archive = tmp_path/'private.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as file:
        file.writestr('fresh.custom', os.urandom(5123))
    database = tmp_path/'private.sqlite'
    with sqlite3.connect(database) as connection:
        connection.execute('create table files(name text)')
        connection.execute("insert into files values ('private')")
    for path, family in ((png, 'PNG'), (pdf, 'PDF'), (archive, 'ZIP'), (database, 'SQLITE')):
        path.chmod(0o600)
        result = isolated(path, family)
        assert result['status'] == 'valid', (family, result)
