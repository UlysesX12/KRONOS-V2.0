"""Prepara el motor RAM en un venv local, sin instalar paquetes globales."""
# Copyright (c) 2026 Jose Luis Cabanas. Volatility Software License 1.0.
import argparse
from pathlib import Path
import subprocess
import sys
import venv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    args = parser.parse_args()
    target = args.target.resolve()
    executable = target / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
    if not executable.is_file():
        print('Creando entorno aislado del motor RAM...', flush=True)
        venv.EnvBuilder(with_pip=True).create(target)
    requirement = Path(__file__).with_name('requirements.lock')
    subprocess.run([str(executable), '-I', '-m', 'pip', 'install', '--only-binary=:all:',
                    '--require-hashes', '-r', str(requirement)], check=True)
    subprocess.run([str(executable), '-I', str(Path(__file__).with_name('volatility_entry.py')),
                    '--kronos-version'], check=True)
    print('Motor RAM preparado en ' + str(target), flush=True)


if __name__ == '__main__':
    main()
