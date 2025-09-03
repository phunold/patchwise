from fastapi import FastAPI, Response, HTTPException
from datetime import datetime, timezone

from .services import ingest_msrc
from .services import enrich_kev
from .services import enrich_epss
from .services import enrich_exploit
from .services import summarize

app = FastAPI(title="Patchwise (MVP real feeds)")

def cloud_fixed_lookup(cve: str) -> bool:
    # MVP: none. (Later we’ll flag NVD “exclusively hosted service”.)
    return False

def compute_month(month: str):
    # 1) fetch sources (with local caching)
    msrc = ingest_msrc.get_msrc_month(month)
    kev = enrich_kev.get_kev()
    epss = enrich_epss.get_epss()
    expl = enrich_exploit.get_exploit_flags()

    enriched = summarize.attach_signals(msrc, kev, epss, expl, cloud_fixed_lookup)
    b = summarize.bundle(month, enriched)
    b["updated_at"] = datetime.now(timezone.utc).isoformat()
    return b

@app.get("/month/{month}/summary.json")
def summary_json(month: str):
    return compute_month(month)

@app.get("/month/{month}/summary.md")
def summary_md(month: str):
    b = compute_month(month)
    md = summarize.to_markdown(b)
    return Response(content=md, media_type="text/plain")
