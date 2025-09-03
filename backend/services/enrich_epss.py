import os, csv, requests, gzip, io, json
from pathlib import Path

# Daily CSV (gz): https://epss.cyentia.com/epss_scores-current.csv.gz

#EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CACHE = Path(os.getenv("PATCHWISE_CACHE_DIR", "data")) / "epss.json"

#csv sample file:
#model_version:v2025.03.14,score_date:2025-09-03T12:55:00Z
#cve,epss,percentile
#CVE-1999-0001,0.0142,0.7991

def fetch_epss():
    r = requests.get(EPSS_URL, timeout=60)
    r.raise_for_status()
    gz = gzip.GzipFile(fileobj=io.BytesIO(r.content))
    
    # extract score_date from this: #model_version:v2025.03.14,score_date:2025-09-03T12:55:00Z
    first_line = gz.readline().decode('utf-8').strip()
    score_date = first_line.split("score_date:")[1]

    # convert to ISO 8601 date (remove time and Z)
    iso_date = score_date.split("T")[0]
    
    # now the rest is a normal CSV
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
                # add current time
                "date": iso_date
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
