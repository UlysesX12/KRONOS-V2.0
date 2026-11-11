"""Lee copias de History de navegadores Chromium sin modificar las fuentes."""

import argparse
import csv
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


VISIT_FIELDS = (
    "FechaUTC", "Usuario", "Navegador", "Perfil", "URL", "Titulo",
    "VisitID", "FromVisit", "Fuente",
)
DOWNLOAD_FIELDS = (
    "InicioUTC", "FinUTC", "Usuario", "Navegador", "Perfil", "URL",
    "DownloadID", "RutaDestino", "BytesRecibidos", "BytesTotales", "Estado", "Fuente",
)


def chrome_time(value):
    try:
        if value is None or int(value) <= 0:
            return ""
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))
        return moment.isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        return ""


def safe_cell(value):
    result = "" if value is None else str(value)
    if result.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + result
    return result


def write_csv(path, fields, rows):
    with path.open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: safe_cell(row.get(field)) for field in fields})


def read_history(path, case_folder, limit):
    relative = path.relative_to(case_folder)
    user, browser, profile = relative.parts[2:5]
    source = str(relative)
    visits, downloads = [], []
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only=ON")
        cursor = connection.execute(
            "SELECT visits.id, visits.visit_time, visits.from_visit, urls.url, urls.title "
            "FROM visits JOIN urls ON visits.url = urls.id "
            "ORDER BY visits.visit_time DESC LIMIT ?", (limit,)
        )
        for visit_id, visit_time, from_visit, url, title in cursor:
            visits.append({
                "FechaUTC": chrome_time(visit_time), "Usuario": user,
                "Navegador": browser, "Perfil": profile, "URL": url,
                "Titulo": title, "VisitID": visit_id, "FromVisit": from_visit,
                "Fuente": source,
            })

        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='downloads'"
        ).fetchone()
        if table_exists:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(downloads)")}
            order = "start_time" if "start_time" in columns else "id"
            has_chains = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='downloads_url_chains'"
            ).fetchone() is not None
            connection.row_factory = sqlite3.Row
            for item in connection.execute(
                "SELECT * FROM downloads ORDER BY " + order + " DESC LIMIT ?", (limit,)
            ):
                row = dict(item)
                url = row.get("tab_url") or row.get("referrer") or ""
                if has_chains:
                    chain = connection.execute(
                        "SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index LIMIT 1",
                        (row.get("id"),),
                    ).fetchone()
                    if chain:
                        url = chain[0]
                downloads.append({
                    "InicioUTC": chrome_time(row.get("start_time")),
                    "FinUTC": chrome_time(row.get("end_time")),
                    "Usuario": user, "Navegador": browser, "Perfil": profile,
                    "URL": url,
                    "DownloadID": row.get("id"),
                    "RutaDestino": row.get("target_path") or row.get("current_path") or "",
                    "BytesRecibidos": row.get("received_bytes"),
                    "BytesTotales": row.get("total_bytes"),
                    "Estado": row.get("state"), "Fuente": source,
                })
    finally:
        connection.close()
    return visits, downloads


def analyze(case_folder, limit):
    root = case_folder / "RawArtifacts" / "Browsers"
    all_visits, all_downloads, issues = [], [], []
    profiles = 0
    for path in sorted(root.glob("*/*/*/History")):
        profiles += 1
        try:
            visits, downloads = read_history(path, case_folder, limit)
            all_visits.extend(visits)
            all_downloads.extend(downloads)
            if len(visits) >= limit or len(downloads) >= limit:
                issues.append(f"Límite de {limit} filas alcanzado en {path.relative_to(case_folder)}")
        except (sqlite3.Error, OSError, ValueError, IndexError) as error:
            issues.append(f"{path.relative_to(case_folder)}: {error}")

    all_visits.sort(key=lambda row: row["FechaUTC"], reverse=True)
    all_downloads.sort(key=lambda row: row["InicioUTC"], reverse=True)
    write_csv(case_folder / "BrowserVisits.csv", VISIT_FIELDS, all_visits)
    write_csv(case_folder / "BrowserDownloads.csv", DOWNLOAD_FIELDS, all_downloads)
    summary = {
        "Status": "COMPLETE_WITH_ISSUES" if issues else "COMPLETE",
        "Profiles": profiles,
        "Visits": len(all_visits),
        "Downloads": len(all_downloads),
        "LimitPerProfile": limit,
        "Issues": issues,
        "Meaning": "Filas presentes en copias de perfiles; no identifican por sí solas a una persona física.",
    }
    (case_folder / "BrowserAnalysis.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-folder", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=50000)
    args = parser.parse_args()
    if not args.case_folder.is_dir() or not 1 <= args.limit <= 200000:
        parser.error("carpeta de caso o límite no válido")
    analyze(args.case_folder.resolve(), args.limit)


if __name__ == "__main__":
    main()
