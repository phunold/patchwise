import os, csv, requests, gzip, io, json
from pathlib import Path

# Daily CSV (gz): https://epss.cyentia.com/epss_scores-current.csv.gz
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CACHE = Path(os.getenv("PATCHWISE_CACHE_DIR", "data")) / "epss.json"

def fetch_epss():
    r = requests.get(EPSS_URL, timeout=60)
    r.raise_for_status()
    gz = gzip.GzipFile(fileobj=io.BytesIO(r.content))
    reader = csv.DictReader(io.TextIOWrapper(gz, encoding="utf-8"))
    epss = {}
    for row in reader:
        cve = row.get("cve")
        if not cve:
            continue
        try:
            epss[cve] = {
                "epss": float(row.get("epss", 0.0)),
                "percentile": float(row.get("percentile", 0.0)),
                "date": row.get("date")
            }
        except ValueError:
            continue
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(epss, indent=2))
    return epss

def get_epss():
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text())
        except Exception:
            pass
    return fetch_epss()
