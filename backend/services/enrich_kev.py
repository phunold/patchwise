import os, csv, json, requests
from io import StringIO
from pathlib import Path

# Official CSV (CISA updates this regularly)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE = Path(os.getenv("PATCHWISE_CACHE_DIR", "data")) / "kev.json"

def fetch_kev():
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    data = r.json()
    kev = {}
    # CISA JSON format: top-level 'vulnerabilities' list
    for row in data.get("vulnerabilities", []):
        cve = row.get("cveID", "").strip()
        if cve:
            kev[cve] = {
                "vendorProject": row.get("vendorProject"),
                "product": row.get("product"),
                "vulnerabilityName": row.get("vulnerabilityName"),
                "dateAdded": row.get("dateAdded"),
                "shortDescription": row.get("shortDescription"),
                "requiredAction": row.get("requiredAction"),
                "dueDate": row.get("dueDate"),
            }
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(kev, indent=2))
    return kev

def get_kev():
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text())
        except Exception:
            pass
    return fetch_kev()
