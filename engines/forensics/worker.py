"""KRONOS forensic adapters. Input files are never executed or opened for writing.
Copyright 2026 JLC / UlysesX12. Volatility Software License 1.0.
"""
import argparse
import csv
from contextlib import closing
import datetime as dt
import hashlib
import json
import pathlib
import re
import sqlite3
import struct
import sys
import urllib.parse
import zipfile
import zlib

MAX_ROWS = 100000
ROWS = []
TRUNCATED = False

def add(**row):
    global TRUNCATED
    if len(ROWS) < MAX_ROWS:
        ROWS.append(row)
    else:
        TRUNCATED = True

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def zip_inventory(source):
    with zipfile.ZipFile(source) as archive:
        for index, item in enumerate(archive.infolist()):
            path = pathlib.PurePosixPath(item.filename.replace('\\', '/'))
            unsafe = path.is_absolute() or '..' in path.parts or ':' in item.filename
            add(Tipo='ZIP: inventario, sin ejecutar ni extraer', Nombre=item.filename,
                Bytes=item.file_size, Comprimido=item.compress_size, CRC32=f'{item.CRC:08x}',
                Cifrado=bool(item.flag_bits & 1), Metodo=item.compress_type,
                Ruta_peligrosa=unsafe, Fecha_sin_zona=str(item.date_time), Fuente=f'ZIP central directory #{index}')
    return 'Inventario del directorio ZIP. No determina si el contenido es malicioso ni recupera contraseñas.'

def strings(source):
    # Chunk overlap preserves offsets and strings crossing chunk boundaries. Long strings are capped.
    with source.open('rb') as stream:
        base = 0
        carry = b''
        while data := stream.read(1024 * 1024):
            chunk = carry + data
            start = base - len(carry)
            # Peek without consuming: also flush the last full-size block at EOF.
            final = not stream.peek(1)
            boundary = len(chunk) if final else max(0, len(chunk) - 4096)
            retained = boundary
            for pattern, encoding in [(rb'[\x20-\x7e]{6,4096}', 'ascii'), (rb'(?:[\x20-\x7e]\x00){6,2048}', 'utf-16-le')]:
                for match in re.finditer(pattern, chunk):
                    if not final and match.end() > boundary:
                        retained = min(retained, match.start())
                        continue
                    text = match.group().decode(encoding)
                    kind = 'Texto'
                    if re.search(r'https?://', text, re.I): kind = 'URL (indicio)'
                    elif re.search(r'password|passwd|contrase|github|important\.zip', text, re.I): kind = 'Texto de interés (indicio)'
                    add(Tipo=kind, Offset=start + match.start(), Codificacion=encoding, Texto=text,
                        Fuente=f'byte offset {start + match.start()}', Valoracion='No acredita historial, autoría ni contraseña válida')
                    if TRUNCATED:
                        return 'Límite de 100000 cadenas alcanzado; exploración parcial. Cadenas de hasta 4096 bytes.'
            carry = chunk[retained:]
            base += len(data)
    return 'Cadenas ASCII/UTF-16LE imprimibles, mínimo 6 caracteres, máximo 4096 bytes. No reconstruye estructuras.'

def browser(source):
    uri = source.resolve().as_uri() + '?mode=ro&immutable=1'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if {'urls', 'visits'} <= tables:
            query = 'SELECT visits.id, urls.url, urls.title, visits.visit_time FROM visits JOIN urls ON urls.id=visits.url ORDER BY visits.id'
            epoch, unit, label = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc), 1, 'Chromium visits.id'
        elif {'moz_places', 'moz_historyvisits'} <= tables:
            query = 'SELECT v.id,p.url,p.title,v.visit_date FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id ORDER BY v.id'
            epoch, unit, label = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc), 1, 'Firefox moz_historyvisits.id'
        elif {'history_items', 'history_visits'} <= tables:
            query = 'SELECT v.id,i.url,v.title,v.visit_time FROM history_visits v JOIN history_items i ON i.id=v.history_item ORDER BY v.id'
            epoch, unit, label = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc), 1000000, 'Safari history_visits.id'
        else:
            raise ValueError('No hay esquema de historial Chromium, Firefox o Safari compatible.')
        db.set_progress_handler(lambda: 1 if TRUNCATED else 0, 10000)
        for identity, url, title, timestamp in db.execute(query):
            try: utc = (epoch + dt.timedelta(microseconds=float(timestamp or 0) * unit)).isoformat()
            except (OverflowError, ValueError): utc = f'Fecha inválida: {timestamp}'
            parsed = urllib.parse.urlsplit(url or '')
            github = urllib.parse.parse_qs(parsed.query).get('q', [''])[0] if (parsed.hostname or '').lower() in ('github.com', 'www.github.com') else ''
            add(Tipo=label.split()[0], URL=url, Titulo=title, UTC=utc, Busqueda_GitHub=github,
                Fuente=f'{label}={identity}', Fecha_original=timestamp)
            if TRUNCATED: break
    return 'Historial SQLite confirmado por esquema. Base principal únicamente; WAL/SHM, borrados y visitas privadas no incluidos.'

def normalize_floss(source):
    with source.open(encoding='utf-8-sig') as stream:
        result = json.load(stream)
    for category, items in result.get('strings', {}).items():
        for index, item in enumerate(items):
            if not isinstance(item, dict): continue
            add(Tipo=f'FLOSS {category}', Texto=item.get('string', ''), Offset=item.get('offset', ''),
                Funcion=item.get('function', item.get('decoding_routine', '')), Codificacion=item.get('encoding', ''),
                Fuente=f'raw.json#/strings/{category}/{index}', Valoracion='Cadenas recuperadas; no es un veredicto de malware')
    return 'FLOSS recupera cadenas estáticas, de pila y descodificadas. No ejecuta el archivo como programa ni determina por sí solo malicia.'

def normalize_leapp(directory):
    # Keep every original report. Native preview uses TSV exports (untrusted text, never HTML).
    files = sorted(directory.rglob('*.tsv'))
    for file in files:
        relative = file.relative_to(directory).as_posix()
        with file.open(encoding='utf-8-sig', errors='replace', newline='') as stream:
            reader = csv.DictReader(stream, delimiter='\t')
            for index, row in enumerate(reader, start=2):
                add(Tipo='Artefacto móvil', Artefacto=file.stem, Datos=json.dumps(row, ensure_ascii=False),
                    Fuente=f'{relative}: TSV línea {index}')
                if TRUNCATED: break
        if TRUNCATED: break
    for metadata in sorted(directory.rglob('_lava_data.lava')):
        with metadata.open(encoding='utf-8-sig') as stream:
            lava = json.load(stream)
        for index, module in enumerate(lava.get('modules', [])):
            add(Tipo='Cobertura de plugin móvil', Artefacto=module.get('artifact_name', module.get('module_name', '')),
                Estado=module.get('module_status', ''), Archivos=module.get('file_count', ''),
                Fuente=f'{metadata.relative_to(directory).as_posix()}#/modules/{index}')
    for log in (directory.parent / 'raw.stdout.json', directory.parent / 'raw.stderr.log'):
        if log.exists():
            for number, line in enumerate(log.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                if re.search(r'error|exception|traceback|no such column|no such table', line, re.I):
                    add(Tipo='Incidencia del motor móvil', Datos=line[:4096], Fuente=f'{log.name}:{number}')
    # Logs include per-plugin outcomes; no claim of a fully covered handset on exit code 0.
    for log in sorted(directory.rglob('*')):
        if log.is_file() and log.suffix.lower() in ('.log', '.txt') and log.stat().st_size < 8 * 1024 * 1024:
            for number, line in enumerate(log.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                if re.search(r'error|exception|traceback|no files found', line, re.I):
                    add(Tipo='Cobertura / incidencia móvil', Artefacto=log.name, Datos=line[:4096],
                        Fuente=f'{log.relative_to(directory).as_posix()}:{number}')
    if not files:
        add(Tipo='Cobertura móvil', Datos='No hay exportaciones TSV. Revisa los registros y reportes originales; no implica ausencia de evidencias.', Fuente='Directorio de salida LEAPP')
    return 'Vista TSV de LEAPP. Cobertura limitada a la extracción aportada y plugins compatibles. Revisa logs y reportes originales: un código 0 no certifica que todos los plugins hayan funcionado.'

def normalize_foremost(directory):
    audit = directory / 'audit.txt'
    for file in sorted(directory.rglob('*')):
        if file.is_file() and file.name != 'audit.txt':
            add(Tipo='Archivo recuperado por firma', Nombre=file.relative_to(directory).as_posix(), Bytes=file.stat().st_size,
                SHA256=digest(file), Fuente='recovered/' + file.relative_to(directory).as_posix(),
                Valoracion='Candidato: puede estar truncado o fragmentado; validar antes de interpretar')
    if audit.exists():
        for number, line in enumerate(audit.read_text(errors='replace').splitlines(), 1):
            add(Tipo='Auditoría Foremost', Texto=line, Fuente=f'recovered/audit.txt:{number}')
    return 'Carving por firmas jpg,png,gif,pdf,zip,ole. No reconstruye el sistema de archivos ni garantiza integridad del contenido recuperado.'

def disk_inventory(source):
    size = source.stat().st_size
    with source.open('rb') as disk:
        def read(offset, count):
            if offset < 0 or offset + count > size: return b''
            disk.seek(offset)
            return disk.read(count)
        def filesystem(offset):
            boot = read(offset, 4096)
            if boot[3:11] == b'NTFS    ': return 'NTFS (firma de arranque)'
            if boot[3:11] == b'EXFAT   ': return 'exFAT (firma de arranque)'
            if boot[3:11] == b'-FVE-FS-': return 'BitLocker (firma; no descifrado)'
            if boot[:6] == b'LUKS\xba\xbe': return 'LUKS (firma; no descifrado)'
            if boot[:4] == b'XFSB': return 'XFS (firma)'
            if boot[1080:1082] == b'\x53\xef': return 'Familia ext2/3/4 (firma del superbloque)'
            if boot[82:90] == b'FAT32   ': return 'FAT32 (etiqueta de arranque)'
            if boot[54:62] in (b'FAT12   ', b'FAT16   '): return 'FAT12/16 (etiqueta de arranque)'
            return 'No identificado / sin firma compatible'
        first = read(0, min(4096, size))
        if first.startswith((b'EVF', b'LVF', b'vhdxfile', b'KDMV', b'conectix')) or source.suffix.lower() in ('.e01', '.ex01', '.vhd', '.vhdx', '.vmdk', '.qcow2'):
            raise ValueError('Contenedor de disco no compatible con este inventario RAW. Exporta una imagen RAW verificada con una herramienta compatible; no cambies solo la extensión.')
        found = False
        for sector in (512, 4096):
            header = read(sector, sector)
            if header[:8] != b'EFI PART': continue
            found = True
            header_size, expected_crc = struct.unpack_from('<II', header, 12)
            if not 92 <= header_size <= sector: raise ValueError('Tamaño de cabecera GPT inválido.')
            check = bytearray(header[:header_size]); check[16:20] = b'\x00'*4
            if zlib.crc32(check) != expected_crc: raise ValueError('CRC32 de cabecera GPT no coincide.')
            array_lba, count, entry_size, array_crc = struct.unpack_from('<QIII', header, 72)
            if entry_size < 128 or entry_size % 128 or count > 16384 or count * entry_size > 16*1024*1024:
                raise ValueError('Tabla GPT fuera de los límites del lector.')
            entries = read(array_lba * sector, count * entry_size)
            if len(entries) != count * entry_size or zlib.crc32(entries) != array_crc: raise ValueError('CRC32 de entradas GPT no coincide.')
            import uuid
            for index in range(count):
                entry = entries[index*entry_size:(index+1)*entry_size]
                if entry[:16] == b'\x00'*16: continue
                start, end = struct.unpack_from('<QQ', entry, 32)
                if end < start or (end+1)*sector > size: raise ValueError('Partición GPT fuera de la imagen.')
                add(Tipo='Partición GPT', Numero=index+1, Nombre=entry[56:128].decode('utf-16-le', errors='replace').rstrip('\x00'),
                    Tipo_GUID=str(uuid.UUID(bytes_le=entry[:16])), Sector_bytes=sector, Inicio_LBA=start, Fin_LBA=end,
                    Offset_bytes=start*sector, Bytes=(end-start+1)*sector, Sistema=filesystem(start*sector),
                    Fuente=f'GPT entry {index+1}; byte offset {array_lba*sector+index*entry_size}', Integridad='CRC32 cabecera y tabla coinciden')
            break
        if not found and len(first) >= 512 and first[510:512] == b'\x55\xaa':
            for index in range(4):
                entry = first[446+index*16:462+index*16]
                kind = entry[4]; start, count = struct.unpack_from('<II', entry, 8)
                if not kind or not count: continue
                if kind == 0xee: raise ValueError('MBR protector GPT presente, pero cabecera GPT no válida o sector no compatible.')
                if (start+count)*512 > size: raise ValueError('Partición MBR fuera de la imagen (lector MBR: sector de 512 bytes).')
                found = True
                add(Tipo='Partición MBR primaria', Numero=index+1, Tipo_hex=f'0x{kind:02x}', Sector_bytes=512,
                    Inicio_LBA=start, Fin_LBA=start+count-1, Offset_bytes=start*512, Bytes=count*512,
                    Sistema='Partición extendida: EBR no recorrido' if kind in (5, 15, 133) else filesystem(start*512),
                    Fuente=f'MBR entry {index+1}; byte offset {446+index*16}')
        if not found:
            add(Tipo='Imagen sin tabla de particiones reconocida', Bytes=size, Offset_bytes=0, Sistema=filesystem(0), Fuente='byte offset 0',
                Valoracion='Puede ser volumen, RAM, imagen dañada u otro formato; requiere identificación adicional')
    return 'Inventario RAW: particiones GPT (sectores 512/4096, CRC32 verificado), MBR primario (512) y firmas de volúmenes. No enumera archivos, EBR, RAID, LVM ni descifra volúmenes. Foremost permite recuperación adicional por firmas.'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['zip', 'strings', 'browser', 'floss', 'aleapp', 'ileapp', 'foremost', 'disk'])
    parser.add_argument('source', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    functions = dict(zip=zip_inventory, strings=strings, browser=browser, floss=normalize_floss,
                     aleapp=normalize_leapp, ileapp=normalize_leapp, foremost=normalize_foremost, disk=disk_inventory)
    coverage = functions[args.mode](args.source)
    args.output.write_text(json.dumps(ROWS, ensure_ascii=False, indent=2), encoding='utf-8')
    args.output.with_suffix('.coverage.json').write_text(json.dumps(dict(coverage=coverage, truncated=TRUNCATED, rows=len(ROWS)), ensure_ascii=False), encoding='utf-8')

if __name__ == '__main__':
    main()
