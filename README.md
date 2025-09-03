# Patchwise
> Patch wisely, reduce risk quickly.

## What is Patchwise?
Every Patch Tuesday, Microsoft publishes 100+ security vulnerabilities (CVEs).  
Many of these can be handled through the **regular patch management process**.  
Only a few require urgent attention.

**Patchwise** cuts through the list and delivers a *small, clear set of actions* that reduce risk the most, right now.

- **Transparent signals** — Microsoft advisories, CISA KEV, FIRST EPSS, exploit availability, cloud-fixed filter.
- **Not a black box** — each decision (P0 / P1 / Monitor) includes an explanation and source links.
- **Minimal Risk-Reducing Actions (MRRA)** — usually 1–3 patches or mitigations that cover the most dangerous attack paths.
- **Delta engine** — when facts change (exploit code released, KEV updated), Patchwise shows what changed and what to do.

## MVP Features
- Ingest MSRC CVRF, CISA KEV, FIRST EPSS.
- Signals per CVE (exploited? likelihood? PoC present? cloud-fixed?).
- Decision engine:
  - Priority: P0 / P1 / Monitor
  - SSVC-style label: Act Fast / Act / Track
  - Disagreement badge when sources conflict
- Find the **smallest set of patches/mitigations** that reduces the most risk (MRRA).
- Export JSON + Markdown. Minimal web UI to view/download.
- Delta checks (watch KEV/EPSS/PoC changes).

## Tech / Hosting
- Python 3.12, FastAPI
- Minimal UI (server-rendered HTML)
- Hosted once as a public web app (e.g., Azure App Service)
- Automation via GitHub Actions (monthly ingest + daily delta checks)
- Optional access protection: header token or lightweight registration

## Run locally (dev)
```bash
# First time
uv venv --python 3.12
uv sync                     # installs from pyproject/uv.lock

# Start dev server (hot reload)
uv run uvicorn backend.main:app --reload
# open http://127.0.0.1:8000/

