"""Synthetic evidence only. Adapter integration tests; no user dumps or host capture."""
import base64
from contextlib import closing
import importlib.util
import json
import os
import pathlib
import sqlite3
import subprocess
import struct
import sys
import tempfile
import unittest
import zipfile
import uuid
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKER = ROOT / 'engines/forensics/worker.py'

def make_history(path):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript('''
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, visit_duration INTEGER, transition INTEGER);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT);
        INSERT INTO urls VALUES(1,'https://github.com/search?q=forensic+synthetic','SYNTHETIC TEST',1,1,13300000000000000,0);
        INSERT INTO visits VALUES(9,1,13300000000000000,0,0,1);
        INSERT INTO keyword_search_terms VALUES(1,1,'forensic synthetic');
        ''')

class Adapters(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kronos-forensic-synthetic-')
        self.root = pathlib.Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def run_worker(self, mode, source):
        output = self.root / 'results.json'
        subprocess.run([sys.executable, '-I', str(WORKER), mode, str(source), str(output)], check=True, capture_output=True)
        return json.loads(output.read_text(encoding='utf-8'))
    def test_history_source_and_github(self):
        source = self.root / 'History'
        make_history(source)
        before = source.read_bytes()
        rows = self.run_worker('browser', source)
        self.assertEqual(rows[0]['Busqueda_GitHub'], 'forensic synthetic')
        self.assertEqual(rows[0]['Fuente'], 'Chromium visits.id=9')
        self.assertEqual(source.read_bytes(), before)
    def test_zip_inventory_no_extraction(self):
        source = self.root / 'important.zip'
        with zipfile.ZipFile(source, 'w') as z:
            z.writestr('../outside.txt', 'SYNTHETIC')
            z.writestr('inside.txt', 'SYNTHETIC')
        rows = self.run_worker('zip', source)
        self.assertTrue(rows[0]['Ruta_peligrosa'])
        self.assertFalse((self.root / 'outside.txt').exists())
    def test_mbr_and_ntfs_signature(self):
        image = bytearray(1024*1024)
        image[510:512] = b'\x55\xaa'
        image[450] = 7
        struct.pack_into('<II', image, 454, 8, 100)
        image[4099:4107] = b'NTFS    '
        source = self.root / 'disk.raw'; source.write_bytes(image)
        rows = self.run_worker('disk', source)
        self.assertEqual(rows[0]['Offset_bytes'], 4096)
        self.assertIn('NTFS', rows[0]['Sistema'])
    def test_gpt_4k_and_crc_rejection(self):
        sector = 4096
        image = bytearray(128*sector)
        image[sector:sector+8] = b'EFI PART'
        struct.pack_into('<III', image, sector+8, 0x10000, 92, 0)
        entry = bytearray(128)
        entry[:16] = uuid.UUID('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7').bytes_le
        struct.pack_into('<QQ', entry, 32, 8, 15)
        name = 'SYNTHETIC'.encode('utf-16-le'); entry[56:56+len(name)] = name
        image[sector*2:sector*2+128] = entry
        struct.pack_into('<QIII', image, sector+72, 2, 1, 128, zlib.crc32(entry))
        struct.pack_into('<I', image, sector+16, zlib.crc32(image[sector:sector+92]))
        source = self.root / 'gpt.raw'; source.write_bytes(image)
        rows = self.run_worker('disk', source)
        self.assertEqual(rows[0]['Sector_bytes'], sector)
        self.assertEqual(rows[0]['Nombre'], 'SYNTHETIC')
        image[sector*2+56] ^= 1; source.write_bytes(image)
        with self.assertRaises(subprocess.CalledProcessError): self.run_worker('disk', source)
    def test_strings_offsets(self):
        source = self.root / 'strings.bin'
        source.write_bytes(b'\x00'*19 + b'https://github.com/SYNTHETIC\x00\x00' + 'SYNTHETIC UTF16'.encode('utf-16-le') + b'\x00\x00')
        rows = self.run_worker('strings', source)
        self.assertTrue(any(r['Offset'] == 19 and r['Tipo'] == 'URL (indicio)' for r in rows))
        self.assertTrue(any(r['Texto'] == 'SYNTHETIC UTF16' for r in rows))
    def test_floss_normalizes_provenance(self):
        source = self.root / 'raw.json'
        source.write_text(json.dumps({'strings': {'static_strings': [{'string': 'SYNTHETIC', 'offset': 33, 'encoding': 'ASCII'}]}}))
        rows = self.run_worker('floss', source)
        self.assertEqual(rows[0]['Fuente'], 'raw.json#/strings/static_strings/0')
    def test_strings_chunk_boundary(self):
        source = self.root / 'boundary.bin'
        source.write_bytes(b'\x00' * (1024 * 1024 - 12) + b'https://example.test/SYNTHETIC' + b'\x00')
        rows = self.run_worker('strings', source)
        self.assertEqual([r['Texto'] for r in rows if r['Codificacion'] == 'ascii'], ['https://example.test/SYNTHETIC'])
        source.write_bytes(b'\x00' * (1024 * 1024 - 20) + b'SYNTHETIC AT EOF    X')
        self.assertTrue(any('SYNTHETIC AT EOF' in r['Texto'] for r in self.run_worker('strings', source)))
    def test_leapp_tsv_is_plaintext(self):
        folder = self.root / 'mobile'
        folder.mkdir()
        (folder / 'synthetic.tsv').write_text('URL\tTitle\nhttps://example.test\t<script>test</script>\n', encoding='utf-8')
        rows = self.run_worker('aleapp', folder)
        self.assertIn('<script>', rows[0]['Datos'])
        self.assertEqual(rows[0]['Fuente'], 'synthetic.tsv: TSV línea 2')

def prepare_real_fixtures(destination):
    destination.mkdir(parents=True, exist_ok=True)
    history = destination / 'History'
    if history.exists(): history.unlink()
    make_history(history)
    png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a0Z8AAAAASUVORK5CYII=')
    with zipfile.ZipFile(destination / 'synthetic.zip', 'w') as z:
        z.writestr('SYNTHETIC.txt', 'SYNTHETIC KRONOS fixture, no user evidence')
    (destination / 'carving.bin').write_bytes(b'\x00'*4096 + png + b'\x00'*4096 + (destination / 'synthetic.zip').read_bytes() + b'\x00'*4096)
    with zipfile.ZipFile(destination / 'android.zip', 'w') as z:
        z.write(history, 'data/data/com.android.chrome/app_chrome/Default/History')
    safari = destination / 'History.db'
    if safari.exists(): safari.unlink()
    with closing(sqlite3.connect(safari)) as db, db:
        db.executescript('''CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT,visit_count INTEGER);
        CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item INTEGER,visit_time REAL,title TEXT,origin INTEGER,
        load_successful INTEGER,redirect_source INTEGER,redirect_destination INTEGER);
        INSERT INTO history_items VALUES(1,'https://example.test/SYNTHETIC',1);
        INSERT INTO history_visits VALUES(1,1,750000000,'SYNTHETIC SAFARI',0,1,NULL,NULL);''')
    with zipfile.ZipFile(destination / 'ios.zip', 'w') as z:
        z.write(safari, 'private/var/mobile/Library/Safari/History.db')
    if os.name == 'nt':
        zig = ROOT / '.tools/forensic-downloads/zig-x86_64-windows-0.15.2/zig.exe'
        if zig.exists():
            sample = destination / 'sample.c'
            sample.write_text('#include <stdio.h>\nint main(void){puts("KRONOS_SYNTHETIC_FLOSS_MARKER");return 0;}\n')
            compiler_env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(ROOT / '.tools/forensic-downloads/zig-cache'), ZIG_LOCAL_CACHE_DIR=str(ROOT / '.tools/forensic-downloads/zig-local-cache'))
            subprocess.run([str(zig), 'cc', '-target', 'x86_64-windows-gnu', '-O2', '-s', str(sample), '-o', str(destination / 'sample.exe')], check=True, env=compiler_env)

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--fixtures':
        prepare_real_fixtures(pathlib.Path(sys.argv[2]))
    else:
        unittest.main()
