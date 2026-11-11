"""Sincroniza la carpeta inicial con GitHub sin eliminar archivos locales."""
# Copyright (c) 2026 Jose Luis Cabanas. Volatility Software License 1.0.
from pathlib import Path
import subprocess
import sys

REMOTE = 'https://github.com/UlysesX12/KRONOS-V2.0.git'
ROOT = Path(__file__).resolve().parents[1]


def git(*args, check=True):
    result = subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True,
                            text=True, encoding='utf-8', errors='strict')
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or 'git fallo: ' + ' '.join(args))
    return result


def main():
    if Path(git('rev-parse', '--show-toplevel').stdout.strip()).resolve() != ROOT:
        raise RuntimeError('La raiz Git no corresponde al proyecto.')
    if git('rev-parse', '--verify', '--quiet', 'HEAD', check=False).returncode == 0:
        print('El repositorio ya tiene commits. No se modifica el historial ni los cambios locales.')
        print(git('status', '--short').stdout)
        return
    if 'origin' in git('remote').stdout.splitlines():
        if git('remote', 'get-url', 'origin').stdout.strip() != REMOTE:
            raise RuntimeError('El remoto origin no corresponde a KRONOS.')
    else:
        git('remote', 'add', 'origin', REMOTE)
    git('fetch', 'origin', 'main')
    paths = git('-c', 'core.quotepath=false', 'ls-tree', '-rz', '--name-only', 'origin/main').stdout.split('\0')
    differences = []
    for relative in filter(None, paths):
        path = (ROOT / relative).resolve()
        if ROOT not in path.parents:
            raise RuntimeError('Ruta remota fuera del proyecto.')
        if not path.is_file():
            differences.append(relative)
            continue
        expected = git('rev-parse', 'origin/main:' + relative).stdout.strip()
        actual = git('hash-object', '--path', relative, '--', relative).stdout.strip()
        if actual != expected:
            differences.append(relative)
    if differences:
        raise RuntimeError('Se conservan el historial, indice y archivos: hay diferencias locales en ' + ', '.join(differences))
    # --mixed establece HEAD e indice; conserva todos los archivos de trabajo.
    git('reset', '--mixed', 'origin/main')
    git('branch', '--set-upstream-to=origin/main')
    print('Historial sincronizado con GitHub; archivos locales conservados.')
    print(git('status', '--short').stdout)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError) as error:
        print('No se pudo sincronizar: ' + str(error), file=sys.stderr)
        sys.exit(1)
