import os, re, json, requests
from pathlib import Path
from xml.etree import ElementTree as ET

# MSRC CVRF v3.0: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-Mon}
BASE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"

CACHE_DIR = Path(os.getenv("PATCHWISE_CACHE_DIR", "data"))

NS = {"cvrf":"http://www.icasi.org/CVRF/schema/vuln/1.1"}

def _text(elem):
    return elem.text.strip() if elem is not None and elem.text else ""

def fetch_cvrf_xml(month: str) -> str:
    url = f"{BASE}/{month}"
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return r.text

def parse_cvrf(xml_text: str):
    root = ET.fromstring(xml_text)
    vulns = []
    for v in root.findall("cvrf:Vulnerability", NS):
        cve = _text(v.find("cvrf:CVE", NS))
        title = _text(v.find("cvrf:Title", NS))
        # Exploitability Index can appear in Notes/Threat sections; we keep a simple read:
        expl = "Unknown"
        for th in v.findall("cvrf:Threat", NS):
            ttype = th.get("Type") or ""
            desc = _text(th.find("cvrf:Description", NS))
            if "Exploitability" in ttype or "Exploit" in desc:
                expl = desc or ttype
        severity = "Unknown"
        for th in v.findall("cvrf:Threat", NS):
            if (th.get("Type") or "").lower() == "severity":
                severity = _text(th.find("cvrf:Description", NS)) or "Unknown"

        kb_refs = []
        for rem in v.findall("cvrf:Remediation", NS):
            for url in rem.findall("cvrf:URL", NS):
                u = _text(url)
                if "KB" in u:
                    kb_refs.append(u)

        vulns.append({
            "cve": cve,
            "title": title,
            "msrc": {
                "severity": severity,
                "exploitability": expl,
                "kb_urls": sorted(set(kb_refs))
            }
        })
    return vulns

def load_month_from_cache(month: str):
    fn = CACHE_DIR / f"{month}_msrc.json"
    if fn.exists():
        return json.loads(fn.read_text())
    return None

def save_month_to_cache(month: str, vulns):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{month}_msrc.json").write_text(json.dumps(vulns, indent=2))

def get_msrc_month(month: str):
    cached = load_month_from_cache(month)
    if cached:
        return cached
    xml_text = fetch_cvrf_xml(month)
    vulns = parse_cvrf(xml_text)
    save_month_to_cache(month, vulns)
    return vulns
