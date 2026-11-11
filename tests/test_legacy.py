"""Pruebas sobre copias y artefactos sintéticos; nunca adquieren datos del host."""
import csv
from contextlib import closing
import hashlib
import json
from pathlib import Path
import runpy
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
correlator = runpy.run_path(str(ROOT / 'vendor/kronos-v1/Kronos.Correlate.py'))
browser = runpy.run_path(str(ROOT / 'vendor/kronos-v1/Kronos.Browser.py'))


class LegacyTests(unittest.TestCase):
    def test_browser_correlator_and_tampering(self):
        with tempfile.TemporaryDirectory(prefix='kronos-synthetic-') as temp:
            parent = Path(temp)
            case = parent / 'V1'
            history = case / 'RawArtifacts/Browsers/Synthetic/Chrome/Default/History'
            history.parent.mkdir(parents=True)
            with closing(sqlite3.connect(history)) as db:
                db.execute('CREATE TABLE urls (id INTEGER, url TEXT, title TEXT)')
                db.execute('CREATE TABLE visits (id INTEGER, url INTEGER, visit_time INTEGER, from_visit INTEGER)')
                db.execute("INSERT INTO urls VALUES (1, 'https://example.invalid/synthetic', 'Muestra')")
                db.execute('INSERT INTO visits VALUES (1, 1, 13380163200000000, 0)')
                db.commit()
            before = hashlib.sha256(history.read_bytes()).hexdigest()
            summary = browser['analyze'](case, 100)
            self.assertEqual(summary['Visits'], 1)
            self.assertEqual(before, hashlib.sha256(history.read_bytes()).hexdigest())
            manifest = case / 'MANIFEST_HASHES_SHA256.csv'
            with manifest.open('w', newline='', encoding='utf-8') as stream:
                writer = csv.DictWriter(stream, fieldnames=['RutaRelativa', 'TamanoBytes', 'Hash_SHA256'])
                writer.writeheader()
                for path in sorted(case.rglob('*')):
                    if path.is_file() and path != manifest:
                        writer.writerow(dict(RutaRelativa=path.relative_to(case).as_posix(), TamanoBytes=path.stat().st_size,
                                             Hash_SHA256=hashlib.sha256(path.read_bytes()).hexdigest()))
            snapshot = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in case.rglob('*') if p.is_file()}
            coverage = correlator['analyze'](case, [], parent / 'analysis')
            self.assertEqual(coverage['LocalObservations'], 1)
            self.assertTrue((parent / 'analysis/INFORME_INVESTIGACION.html').is_file())
            self.assertTrue(all(hashlib.sha256(p.read_bytes()).hexdigest() == h for p, h in snapshot.items()))
            history.write_bytes(b'altered')
            with self.assertRaises(ValueError):
                correlator['verify_case'](case.resolve())

    def test_provenance(self):
        with (ROOT / 'vendor/PROVENANCE_SHA256.csv').open(encoding='utf-8-sig', newline='') as stream:
            for row in csv.DictReader(stream):
                path = ROOT / 'vendor/kronos-v1' / row['File']
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest().upper(), row['Hash'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
