"""Valida la sincronizacion inicial en repositorios temporales, sin red ni datos reales."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]



class SyncGitTests(unittest.TestCase):
    def test_initial_sync_and_preservation(self):
        with tempfile.TemporaryDirectory(prefix='kronos-git-fixture-') as temp:
            parent = Path(temp)
            remote = parent / 'remote'
            remote.mkdir()

            def git(folder, *args, check=True):
                return subprocess.run(['git', '-C', str(folder), *args], capture_output=True,
                                      text=True, encoding='utf-8', errors='replace', check=check)

            git(remote, 'init', '-b', 'main')
            (remote / 'scripts').mkdir()
            script = (ROOT / 'scripts/sync_git.py').read_text(encoding='utf-8')
            script = script.replace('https://github.com/UlysesX12/KRONOS-V2.0.git', remote.as_posix())
            (remote / 'scripts/sync_git.py').write_text(script, encoding='utf-8')
            (remote / '.gitattributes').write_text('* text=auto eol=lf\n', encoding='utf-8')
            (remote / 'sample.txt').write_text('contenido conocido\n', encoding='utf-8')
            git(remote, 'add', '.')
            git(remote, '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
                'commit', '-m', 'fixture')

            def working_copy(name):
                folder = parent / name
                shutil.copytree(remote, folder, ignore=shutil.ignore_patterns('.git'))
                git(folder, 'init', '-b', 'main')
                git(folder, 'add', '.')
                return folder

            def run_sync(folder):
                return subprocess.run([sys.executable,
                                       str(folder / 'scripts/sync_git.py')], capture_output=True,
                                      text=True, encoding='utf-8', errors='replace')

            def snapshot(folder):
                return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in folder.rglob('*') if p.is_file() and '.git' not in p.relative_to(folder).parts}

            clean = working_copy('initial')
            before = snapshot(clean)
            result = run_sync(clean)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(snapshot(clean), before)
            self.assertEqual(git(clean, 'status', '--porcelain').stdout, '')
            self.assertEqual(git(clean, 'rev-parse', 'HEAD').stdout, git(remote, 'rev-parse', 'HEAD').stdout)
            self.assertEqual(git(clean, 'rev-parse', '--abbrev-ref', '@{upstream}').stdout.strip(), 'origin/main')

            (clean / 'sample.txt').write_text('edicion posterior\n', encoding='utf-8')
            existing = snapshot(clean)
            head = git(clean, 'rev-parse', 'HEAD').stdout
            self.assertNotEqual(run_sync(clean).returncode, 0)
            self.assertEqual(snapshot(clean), existing)
            self.assertEqual(git(clean, 'rev-parse', 'HEAD').stdout, head)

            (remote / 'sample.txt').write_text('contenido nuevo ya publicado\n', encoding='utf-8')
            git(remote, 'add', '.')
            git(remote, '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid', 'commit', '-m', 'published update')
            (clean / 'sample.txt').write_text('contenido nuevo ya publicado\n', encoding='utf-8')
            before_update = snapshot(clean)
            result = run_sync(clean)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(git(clean, 'rev-parse', 'HEAD').stdout, git(remote, 'rev-parse', 'HEAD').stdout)
            self.assertEqual(snapshot(clean), before_update)
            self.assertEqual(git(clean, 'status', '--porcelain').stdout, '')

            different = working_copy('different')
            (different / 'sample.txt').write_text('cambio local importante\n', encoding='utf-8')
            before = snapshot(different)
            index_before = git(different, 'ls-files', '--stage').stdout
            result = run_sync(different)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(snapshot(different), before)
            self.assertEqual(git(different, 'ls-files', '--stage').stdout, index_before)
            self.assertNotEqual(git(different, 'rev-parse', '--verify', '--quiet', 'HEAD', check=False).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
