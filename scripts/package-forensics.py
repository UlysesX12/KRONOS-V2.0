"""Reproducible Windows tool bundle. No system installation; verified official downloads."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / '.tools/forensic-downloads'
TOOLS = {
    'floss': ('3.2.0', 'https://github.com/mandiant/flare-floss/releases/download/v3.2.0/floss-v3.2.0-windows.zip', 'c0c73bb99d043fedd8e913038b65d1591fd6308cd938d8a91df87b733b369af5'),
    'aleapp': ('2026.4.5', 'https://github.com/abrignoni/ALEAPP/releases/download/v2026.4.5/ALEAPP-2026.4.5-windows-x64-portable.zip', '954b9603bee1b1a3eec841694d8ed3d6499aa9d9b5ddc0d5bd44783ca5ab949b'),
    'ileapp': ('2026.4.6', 'https://github.com/abrignoni/iLEAPP/releases/download/v2026.4.6/iLEAPP-2026.4.6-windows-x64-portable.zip', '531b1eecde0d71a10d6e5298ef565e3bc2110997ea5773761f4e46fcbe467e47'),
}

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def download(url, expected, name):
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / name
    if not path.exists():
        subprocess.run(['curl.exe', '-L', '--fail', '--retry', '2', '-sS', url, '-o', str(path)], check=True)
    if digest(path) != expected:
        raise ValueError(f'SHA-256 incorrecto: {path}')
    return path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--destination', type=pathlib.Path, default=ROOT / '.tools/forensic-tools')
    args = parser.parse_args()
    dest = args.destination.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    receipts = []
    for name, (version, url, sha) in TOOLS.items():
        archive = download(url, sha, url.rsplit('/', 1)[1])
        executable = dest / name / f'{name}.exe'
        executable.parent.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as package:
            members = [n for n in package.namelist() if n.lower().endswith(f'{name}.exe')]
            if len(members) != 1:
                raise ValueError(f'Paquete inesperado: {name}')
            with package.open(members[0]) as source, executable.open('wb') as output:
                shutil.copyfileobj(source, output)
        receipts.append(dict(id=name, version=version, url=url, archiveSha256=sha, executable=f'{name}/{name}.exe', sha256=digest(executable)))
    zig_archive = download('https://ziglang.org/download/0.15.2/zig-x86_64-windows-0.15.2.zip',
                           '3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c', 'zig-x86_64-windows-0.15.2.zip')
    zig = CACHE / 'zig-x86_64-windows-0.15.2/zig.exe'
    if not zig.exists():
        with zipfile.ZipFile(zig_archive) as package:
            package.extractall(CACHE)
    foremost = dest / 'foremost/foremost.exe'
    foremost.parent.mkdir(exist_ok=True)
    sources = sorted((ROOT / 'vendor/foremost').glob('*.c'))
    command = [str(zig), 'cc', '-target', 'x86_64-windows-gnu', '-std=gnu99', '-O2', '-fcommon', '-D__WIN32',
               '-DVERSION="1.5.7-kronos1"', '-o', str(foremost), *map(str, sources)]
    compiler_env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(CACHE / 'zig-cache'), ZIG_LOCAL_CACHE_DIR=str(CACHE / 'zig-local-cache'))
    result = subprocess.run(command, cwd=ROOT, capture_output=True, env=compiler_env)
    (CACHE / 'foremost-build.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace')[-6000:])
    receipts.append(dict(id='foremost', version='1.5.7-kronos1', url='https://foremost.sourceforge.net/pkg/foremost-1.5.7.tar.gz',
                         archiveSha256='502054ef212e3d90b292e99c7f7ac91f89f024720cd5a7e7680c3d1901ef5f34',
                         executable='foremost/foremost.exe', sha256=digest(foremost)))
    (dest / 'tools.json').write_text(json.dumps(receipts, indent=2), encoding='utf-8')
    print(f'4 herramientas verificadas y preparadas en {dest}')

if __name__ == '__main__':
    main()
