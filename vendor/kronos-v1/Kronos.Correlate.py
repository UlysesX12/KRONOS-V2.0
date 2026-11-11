"""Explorador local de casos KRONOS y correlación prudente con registros externos."""

import argparse
import bisect
import csv
import hashlib
import html
import json
import runpy
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse


OBS_FIELDS = (
    "ID", "FechaUTC", "Tipo", "Cuenta", "SID", "Sesion", "IPOrigen",
    "IPDestino", "Destino", "Proceso", "Objeto", "Detalle", "Evidencia", "Fila",
)
MATCH_FIELDS = (
    "AvisoID", "ObservacionID", "Estado", "DiferenciaSegundos", "Coincidencias",
    "AvisoUTC", "ObservacionUTC", "EvidenciaLocal", "Limite",
)
EXTERNAL_REQUIRED = ("TimestampUTC", "Source", "Event")
EXTERNAL_OPTIONAL = ("Account", "SourceIP", "Destination", "SessionID", "RequestID", "Details")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_case(folder):
    manifest = folder / "MANIFEST_HASHES_SHA256.csv"
    if not manifest.is_file():
        raise ValueError("Falta MANIFEST_HASHES_SHA256.csv")
    with manifest.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError("El manifiesto está vacío")
    seen = set()
    for row in rows:
        relative = row.get("RutaRelativa", "").replace("\\", "/")
        if not relative or relative.startswith("/") or ":" in relative:
            raise ValueError(f"Ruta inválida en manifiesto: {relative}")
        target = (folder / relative).resolve()
        if folder not in target.parents or not target.is_file():
            raise ValueError(f"Archivo ausente o fuera del caso: {relative}")
        canonical = target.relative_to(folder).as_posix().casefold()
        if canonical in seen:
            raise ValueError(f"Ruta duplicada: {relative}")
        seen.add(canonical)
        if target.stat().st_size != int(row["TamanoBytes"]):
            raise ValueError(f"Tamaño distinto: {relative}")
        if sha256(target).casefold() != row["Hash_SHA256"].casefold():
            raise ValueError(f"Hash distinto: {relative}")
    actual = {
        path.relative_to(folder).as_posix().casefold()
        for path in folder.rglob("*") if path.is_file() and path != manifest
    }
    if actual != seen:
        raise ValueError("El caso contiene archivos ausentes o no incluidos en el manifiesto")
    return len(seen)


def parse_utc(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        instant = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Fecha inválida: {raw}") from error
    if instant.tzinfo is None:
        raise ValueError(f"La fecha necesita zona horaria: {raw}")
    return instant.astimezone(timezone.utc)


def utc_text(instant):
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        yield from enumerate(csv.DictReader(stream), start=2)


def observation(record_id, timestamp, kind, source_file, line, **fields):
    return {
        "ID": record_id,
        "FechaUTC": utc_text(timestamp),
        "Tipo": kind,
        "Cuenta": fields.get("account", "") or "",
        "SID": fields.get("sid", "") or "",
        "Sesion": fields.get("session", "") or "",
        "IPOrigen": fields.get("source_ip", "") or "",
        "IPDestino": fields.get("destination_ip", "") or "",
        "Destino": fields.get("destination", "") or "",
        "Proceso": fields.get("process", "") or "",
        "Objeto": fields.get("object_name", "") or "",
        "Detalle": fields.get("detail", "") or "",
        "Evidencia": source_file,
        "Fila": line,
        "_time": timestamp,
    }


def load_local(case, browser_limit=20000):
    found = []
    problems = []
    offline_profiles = 0

    def load(filename, converter):
        path = case / filename
        if not path.is_file():
            return
        for line, row in read_csv(path):
            try:
                instant = parse_utc(converter[0](row))
                if instant is None:
                    continue
                fields = converter[1](row)
                found.append(observation(f"K{len(found)+1:07d}", instant, fields.pop("kind"),
                                         filename, line, **fields))
            except (ValueError, TypeError) as error:
                problems.append(f"{filename}:{line}: {error}")

    load("EventosAuditoria.csv", (
        lambda r: r.get("FechaUTC"),
        lambda r: dict(kind=r.get("Accion") or f"Seguridad {r.get('EventoID', '')}",
                       account=r.get("Usuario"), sid=r.get("SID"), session=r.get("LogonID"),
                       source_ip=r.get("IPOrigen"), process=r.get("Proceso"),
                       object_name=r.get("Objeto"),
                       detail=" ".join(str(r.get(k) or "") for k in
                                       ("EventoID", "TipoInicio", "Comando", "Valor", "NuevoValor", "Acceso")))
    ))
    load("SysmonEvents.csv", (
        lambda r: r.get("FechaUTC"),
        lambda r: dict(kind="Sysmon: " + (r.get("Accion") or r.get("EventoID", "")),
                       account=r.get("Usuario"), source_ip=r.get("IPOrigen"),
                       destination_ip=r.get("IPDestino"),
                       destination=r.get("HostDestino") or r.get("ConsultaDNS") or r.get("IPDestino"),
                       process=r.get("Proceso"), object_name=r.get("Archivo") or r.get("ObjetoRegistro"),
                       detail=" ".join(str(r.get(k) or "") for k in
                                       ("EventoID", "ProcessGuid", "ParentProcessGuid", "PuertoDestino", "Comando", "ValorRegistro")))
    ))
    load("BrowserVisits.csv", (
        lambda r: r.get("FechaUTC"),
        lambda r: dict(kind="Visita de navegador", account=r.get("Usuario"),
                       destination=r.get("URL"),
                       detail=f"{r.get('Navegador', '')}/{r.get('Perfil', '')} {r.get('Titulo', '')}")
    ))
    load("BrowserDownloads.csv", (
        lambda r: r.get("InicioUTC"),
        lambda r: dict(kind="Descarga registrada", account=r.get("Usuario"),
                       destination=r.get("URL"), object_name=r.get("RutaDestino"),
                       detail=f"{r.get('Navegador', '')}/{r.get('Perfil', '')} Estado={r.get('Estado', '')}")
    ))
    if not (case / "BrowserVisits.csv").is_file() or not (case / "BrowserDownloads.csv").is_file():
        browser_root = case / "RawArtifacts" / "Browsers"
        histories = sorted(browser_root.glob("*/*/*/History"))
        if histories:
            browser_reader = runpy.run_path(str(Path(__file__).with_name("Kronos.Browser.py")))["read_history"]
            with tempfile.TemporaryDirectory(prefix="kronos-browser-") as temp:
                temporary_case = Path(temp)
                for source in histories:
                    relative = source.relative_to(case)
                    destination = temporary_case / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        for suffix in ("", "-wal", "-shm"):
                            companion = Path(str(source) + suffix)
                            if companion.is_file():
                                shutil.copy2(companion, Path(str(destination) + suffix))
                        visits, downloads = browser_reader(destination, temporary_case, browser_limit)
                        offline_profiles += 1
                        if len(visits) >= browser_limit or len(downloads) >= browser_limit:
                            problems.append(f"{relative}: límite de {browser_limit} filas por tipo alcanzado")
                        if not (case / "BrowserVisits.csv").is_file():
                            for row in visits:
                                instant = parse_utc(row["FechaUTC"])
                                if instant:
                                    found.append(observation(
                                        f"K{len(found)+1:07d}", instant, "Visita de navegador",
                                        relative.as_posix(), f"visit:{row['VisitID']}",
                                        account=row["Usuario"], destination=row["URL"],
                                        detail=f"{row['Navegador']}/{row['Perfil']} {row['Titulo']}"))
                        if not (case / "BrowserDownloads.csv").is_file():
                            for row in downloads:
                                instant = parse_utc(row["InicioUTC"])
                                if instant:
                                    found.append(observation(
                                        f"K{len(found)+1:07d}", instant, "Descarga registrada",
                                        relative.as_posix(), f"download:{row['DownloadID']}",
                                        account=row["Usuario"], destination=row["URL"],
                                        object_name=row["RutaDestino"],
                                        detail=f"{row['Navegador']}/{row['Perfil']} Estado={row['Estado']}"))
                    except (OSError, ValueError, sqlite3.Error) as error:
                        problems.append(f"{relative}: {error}")
    if not (case / "EventosAuditoria.csv").is_file():
        load("Accesos.csv", (
            lambda r: r.get("FechaUTC"),
            lambda r: dict(kind=r.get("Tipo") or "Acceso", account=r.get("Usuario"),
                           session=r.get("LogonID"), source_ip=r.get("IP_Origen"),
                           detail=r.get("Host_Remoto"))
        ))
    skipped = {"EventosAuditoria.csv", "SysmonEvents.csv", "BrowserVisits.csv",
               "BrowserDownloads.csv", "Accesos.csv"}
    if (case / "Cronologia.csv").is_file():
        for line, row in read_csv(case / "Cronologia.csv"):
            if row.get("Fuente") in skipped:
                continue
            try:
                instant = parse_utc(row.get("FechaUTC"))
                if instant:
                    found.append(observation(f"K{len(found)+1:07d}", instant,
                                             row.get("Tipo", "Observación"),
                                             "Cronologia.csv", line, detail=row.get("Detalle")))
            except ValueError as error:
                problems.append(f"Cronologia.csv:{line}: {error}")
    return found, problems, offline_profiles


def load_external(paths):
    found = []
    for path in paths:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or any(name not in reader.fieldnames for name in EXTERNAL_REQUIRED):
                raise ValueError(f"Columnas externas obligatorias ausentes en {path}")
            for line, row in enumerate(reader, start=2):
                instant = parse_utc(row.get("TimestampUTC"))
                if instant is None:
                    raise ValueError(f"Falta TimestampUTC en {path}:{line}")
                found.append(observation(
                    f"E{len(found)+1:07d}", instant, row.get("Event") or "Aviso externo",
                    str(path), line, account=row.get("Account"), source_ip=row.get("SourceIP"),
                    destination=row.get("Destination"), session=row.get("SessionID"),
                    detail=f"{row.get('Source', '')} RequestID={row.get('RequestID', '')} {row.get('Details', '')}",
                ))
    return found


def destination_kind(left, right):
    if not left or not right:
        return ""
    a, b = left.strip().casefold(), right.strip().casefold()
    if a == b:
        return "destino exacto"
    a_url, b_url = urlparse(a), urlparse(b)
    a_host = (a_url.hostname or a).strip("[]")
    b_host = (b_url.hostname or b).strip("[]")
    if a_host == b_host:
        return "host de destino"
    return ""


def correlate(local, external, minutes, maximum):
    ordered = sorted(local, key=lambda row: row["_time"])
    timestamps = [item["_time"] for item in ordered]
    matches = []
    matched_ids = set()
    for notice in external:
        start = bisect.bisect_left(timestamps, notice["_time"] - timedelta(minutes=minutes))
        end = bisect.bisect_right(timestamps, notice["_time"] + timedelta(minutes=minutes))
        candidates = []
        for item in ordered[start:end]:
            hits = []
            if notice["Cuenta"] and notice["Cuenta"].casefold() == item["Cuenta"].casefold():
                hits.append("cuenta")
            if notice["IPOrigen"] and notice["IPOrigen"] == item["IPOrigen"]:
                hits.append("IP de origen")
            target = (destination_kind(notice["Destino"], item["Destino"])
                      or destination_kind(notice["Destino"], item["IPDestino"]))
            if target:
                hits.append(target)
            if hits:
                difference = abs((item["_time"] - notice["_time"]).total_seconds())
                candidates.append((-len(hits), difference, item["ID"], item, hits))
        candidates.sort()
        if not candidates:
            matches.append(dict(AvisoID=notice["ID"], ObservacionID="", Estado="SIN_COINCIDENCIA",
                                DiferenciaSegundos="", Coincidencias="", AvisoUTC=notice["FechaUTC"],
                                ObservacionUTC="", EvidenciaLocal="",
                                Limite="La ausencia de coincidencia no descarta actividad; revise cobertura y fuentes externas."))
        for _, difference, _, item, hits in candidates[:maximum]:
            matched_ids.add(item["ID"])
            matches.append(dict(
                AvisoID=notice["ID"], ObservacionID=item["ID"],
                Estado="COINCIDENCIA_MULTIPLE" if len(hits) > 1 else "COINCIDENCIA_PARCIAL",
                DiferenciaSegundos=difference, Coincidencias="; ".join(hits),
                AvisoUTC=notice["FechaUTC"], ObservacionUTC=item["FechaUTC"],
                EvidenciaLocal=f"{item['Evidencia']}:{item['Fila']}",
                Limite="Coincidencia de registros; requiere revisión de identidad, reloj, NAT y contexto.",
            ))
    return matches, matched_ids


def safe_cell(value):
    result = "" if value is None else str(value)
    if result.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + result
    return result


def write_csv(path, fields, rows):
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: safe_cell(row.get(field)) for field in fields})


def report_html(local, external, matches, coverage, matched_ids):
    selected = {row["ID"]: row for row in sorted(local, key=lambda item: item["_time"], reverse=True)[:3000]}
    matched_rows = sorted((row for row in local if row["ID"] in matched_ids),
                          key=lambda item: item["_time"], reverse=True)[:3000]
    selected.update({row["ID"]: row for row in matched_rows})
    external_display = sorted(external, key=lambda item: item["_time"], reverse=True)[:1000]
    display = sorted([*selected.values(), *external_display],
                     key=lambda row: row["_time"], reverse=True)
    public_rows = [{field: row.get(field, "") for field in OBS_FIELDS} for row in display]
    data = json.dumps(public_rows, ensure_ascii=False).replace("<", "\\u003c")
    matches_json = json.dumps(matches, ensure_ascii=False).replace("<", "\\u003c")
    coverage_json = html.escape(json.dumps(coverage, ensure_ascii=False, indent=2))
    return """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>KRONOS | Investigación</title><style>
body{font:14px system-ui;background:#09111d;color:#e2e8f0;margin:0;padding:24px}
h1{color:#38d9e6}h2{font-size:18px;color:#a5b4fc}p{line-height:1.5}
.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:#142238;border:1px solid #29415f;padding:14px;border-radius:8px}
input,select{background:#142238;color:#fff;border:1px solid #456;padding:9px;margin:4px}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:8px;border-bottom:1px solid #29415f;vertical-align:top;word-break:break-word}
th{position:sticky;top:0;background:#20334d}.scroll{max-height:520px;overflow:auto;background:#101c2d}
.note{color:#facc15}pre{white-space:pre-wrap;background:#101c2d;padding:12px}
</style></head><body><h1>KRONOS · Investigación de caso</h1>
<p class="note">Las coincidencias son pistas para revisar. No identifican por sí solas a una persona ni prueban causalidad.</p>
<div class="cards"><div class="card">Observaciones locales: <b id="localCount"></b></div>
<div class="card">Avisos externos: <b id="externalCount"></b></div>
<div class="card">Coincidencias propuestas: <b id="matchCount"></b></div></div>
<h2>Coincidencias con avisos externos</h2><div class="scroll"><table id="matches"><thead><tr><th>Aviso</th><th>Observación</th><th>Estado</th><th>Diferencia (s)</th><th>Campos coincidentes</th><th>Evidencia</th><th>Límite</th></tr></thead><tbody></tbody></table></div>
<h2>Cronología exploratoria</h2><p>La búsqueda cubre hasta 3 000 observaciones recientes, 3 000 relacionadas con avisos y 1 000 avisos externos. Se muestran hasta 1 000 filas por filtro. El CSV conserva todas.</p>
<input id="search" type="search" placeholder="Filtrar cuenta, IP, URL, proceso..." size="45"><select id="source"><option value="">Todas las fuentes</option><option value="K">Equipo</option><option value="E">Externo</option></select>
<label>Desde UTC <input id="from" type="datetime-local"></label><label>Hasta UTC <input id="to" type="datetime-local"></label>
<div class="scroll"><table id="timeline"><thead><tr><th>UTC</th><th>Origen</th><th>Tipo</th><th>Cuenta</th><th>IP</th><th>Destino</th><th>Proceso / objeto</th><th>Detalle</th><th>Evidencia: fila</th></tr></thead><tbody></tbody></table></div>
<h2>Cobertura y límites</h2><pre>""" + coverage_json + """</pre>
<script>const rows=""" + data + """;const matches=""" + matches_json + """;
const tl=document.querySelector('#timeline tbody'),mt=document.querySelector('#matches tbody');
function tr(parent,values){const row=document.createElement('tr');for(const value of values){const cell=document.createElement('td');cell.textContent=String(value??'');row.appendChild(cell)}parent.appendChild(row)}
document.getElementById('localCount').textContent=""" + str(coverage["LocalObservations"]) + """;
document.getElementById('externalCount').textContent=""" + str(coverage["ExternalObservations"]) + """;
document.getElementById('matchCount').textContent=matches.filter(x=>x.ObservacionID).length;
for(const item of matches.slice(0,500)){tr(mt,[item.AvisoID,item.ObservacionID,item.Estado,item.DiferenciaSegundos,item.Coincidencias,item.EvidenciaLocal,item.Limite])}
function render(){tl.replaceChildren();const q=document.getElementById('search').value.toLocaleLowerCase();const src=document.getElementById('source').value;
const from=document.getElementById('from').value,to=document.getElementById('to').value;
let n=0;for(const item of rows){if(src&&!item.ID.startsWith(src))continue;if(q&&!Object.values(item).join(' ').toLocaleLowerCase().includes(q))continue;
const when=Date.parse(item.FechaUTC);if(from&&when<Date.parse(from+'Z'))continue;if(to&&when>Date.parse(to+'Z'))continue;
tr(tl,[item.FechaUTC,item.ID,item.Tipo,item.Cuenta,item.IPOrigen||item.IPDestino,item.Destino,item.Proceso||item.Objeto,item.Detalle,item.Evidencia+':'+item.Fila]);if(++n>=1000)break}}
for(const id of ['search','source','from','to']){document.getElementById(id).addEventListener('input',render)}render();
</script></body></html>"""


def analyze(case, external_paths, output, minutes=10, maximum=20, browser_limit=20000):
    case = case.resolve()
    output = output.resolve()
    if output == case or case in output.parents:
        raise ValueError("La carpeta de análisis debe estar fuera del caso sellado")
    if output.exists():
        raise ValueError("La carpeta de análisis ya existe; indique una nueva")
    verified = verify_case(case)
    local, problems, offline_profiles = load_local(case, browser_limit)
    external_hashes = [sha256(path) for path in external_paths]
    external = load_external(external_paths)
    if any(sha256(path) != before for path, before in zip(external_paths, external_hashes)):
        raise ValueError("Un registro externo cambió mientras se analizaba")
    matches, matched_ids = correlate(local, external, minutes, maximum)
    metadata_path = case / "CASE_METADATA.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig")) if metadata_path.is_file() else {}
    collection_issues = []
    if (case / "Incidencias.csv").is_file():
        collection_issues = [row for _, row in read_csv(case / "Incidencias.csv")]
    datasets = ("EventosAuditoria.csv", "SysmonEvents.csv", "BrowserVisits.csv", "BrowserDownloads.csv",
                "Accesos.csv", "Cronologia.csv", "AUDIT_POLICY.txt")
    coverage = {
        "CaseVerifiedFiles": verified,
        "LocalObservations": len(local), "ExternalObservations": len(external),
        "Datasets": {name: (case / name).is_file() for name in datasets},
        "BrowserAnalysis": metadata.get("BrowserAnalysis", "UNKNOWN"),
        "OfflineBrowserProfiles": offline_profiles,
        "SysmonAvailable": metadata.get("SysmonAvailable", "UNKNOWN"),
        "SecurityEventLimit": metadata.get("SecurityEventLimit", "UNKNOWN"),
        "CollectionProfile": metadata.get("Profile", "UNKNOWN"),
        "CollectionStatus": metadata.get("Status", "UNKNOWN"),
        "CollectionIssues": collection_issues[:100],
        "CollectionIssuesTotal": len(collection_issues),
        "ParsingProblems": problems,
        "Interpretation": "Sin coincidencia no significa ausencia de actividad. Coincidencia no identifica autor físico.",
    }
    inputs = {
        "CaseManifestSHA256": sha256(case / "MANIFEST_HASHES_SHA256.csv"),
        "CorrelatorSHA256": sha256(Path(__file__).resolve()),
        "BrowserAnalyzerSHA256": sha256(Path(__file__).with_name("Kronos.Browser.py")),
        "ExternalFiles": [{"Path": str(path.resolve()), "SHA256": digest}
                          for path, digest in zip(external_paths, external_hashes)],
        "WindowMinutes": minutes, "MaxCandidatesPerNotice": maximum,
        "GeneratedUTC": utc_text(datetime.now(timezone.utc)),
    }
    output.mkdir(parents=True)
    write_csv(output / "Observaciones.csv", OBS_FIELDS,
              sorted([*local, *external], key=lambda row: row["_time"], reverse=True))
    write_csv(output / "Coincidencias.csv", MATCH_FIELDS, matches)
    (output / "Cobertura.json").write_text(json.dumps(coverage, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "ENTRADAS.json").write_text(json.dumps(inputs, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "INFORME_INVESTIGACION.html").write_text(
        report_html(local, external, matches, coverage, matched_ids), encoding="utf-8"
    )
    output_files = sorted(path for path in output.iterdir() if path.is_file())
    write_csv(output / "ANALYSIS_MANIFEST_SHA256.csv", ("Archivo", "TamanoBytes", "Hash_SHA256"),
              [{"Archivo": path.name, "TamanoBytes": path.stat().st_size, "Hash_SHA256": sha256(path)}
               for path in output_files])
    return coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-folder", required=True, type=Path)
    parser.add_argument("--external", action="append", type=Path, default=[])
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--max-candidates", type=int, default=20)
    parser.add_argument("--browser-row-limit", type=int, default=20000)
    args = parser.parse_args()
    if (not 1 <= args.window_minutes <= 1440 or not 1 <= args.max_candidates <= 100
            or not 1 <= args.browser_row_limit <= 200000):
        parser.error("ventana o máximo de filas/candidatos fuera de rango")
    try:
        result = analyze(args.case_folder, args.external, args.output_dir,
                         args.window_minutes, args.max_candidates, args.browser_row_limit)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"KRONOS_ANALYSIS_OK: {result['LocalObservations']} locales, "
          f"{result['ExternalObservations']} externos")


if __name__ == "__main__":
    main()
