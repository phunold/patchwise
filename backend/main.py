from fastapi import FastAPI, Response
from datetime import datetime

app = FastAPI(title="Patchwise (MVP)")

# --- hardcoded demo bundle (replace later with real logic) ---
AUG_SUMMARY = {
    "month": "2025-Aug",
    "updated_at": f"{datetime.utcnow().isoformat()}Z",
    "totals": {"p0": 1, "p1": 3, "monitor": 1, "all": 107},
    "mrra": [
        {
            "id": "A1",
            "title": "Patch Kerberos EoP on Domain Controllers",
            "why": "Identity chain; publicly disclosed; high likelihood",
            "mitigation": "Install KB5063875/KB5063876/KB5063877 on DCs",
            "verification": "Check installed updates (e.g., wmic qfe / PowerShell Get-HotFix)"
        }
    ],
    "decisions": [
        {
            "cve": "CVE-2025-53779",
            "priority": "P0",
            "ssvc": "Act Fast",
            "why": "AD Tier-0 impact, publicly disclosed, strong likelihood signals",
            "citations": {"msrc": "MSRC Aug 2025", "epss": "EPSS v4", "kev": "CISA KEV"}
        },
        {
            "cve": "CVE-2025-53778",
            "priority": "P1",
            "ssvc": "Act",
            "why": "NTLM EoP; likely to be exploited; SYSTEM on success",
            "citations": {"msrc": "MSRC Aug 2025"}
        },
        {
            "cve": "CVE-2025-50165",
            "priority": "P1",
            "ssvc": "Act",
            "why": "Graphics/file parser RCE on clients (user-open vector)",
            "citations": {"msrc": "MSRC Aug 2025"}
        },
        {
            "cve": "CVE-2025-53767",
            "priority": "Monitor",
            "ssvc": "Track",
            "why": "Cloud-fixed (exclusively hosted service); awareness only",
            "citations": {"nvd": "NVD hosted-service tag"}
        }
    ],
    "model_card": {
        "audience": "enterprise defender",
        "signals": ["MSRC", "CISA KEV", "FIRST EPSS", "Exploit presence", "Cloud-fixed"],
        "thresholds": {"epss_p0": 0.7, "epss_p1": 0.3},
        "assumptions": ["No tenant inventory in MVP"]
    }
}

def to_markdown(bundle: dict) -> str:
    lines = [
        f"# Patchwise — {bundle['month']}",
        f"Updated: {bundle['updated_at']}",
        f"- 🔴 P0: {bundle['totals']['p0']}  🟠 P1: {bundle['totals']['p1']}  🟢 Monitor: {bundle['totals']['monitor']}  │ Total: {bundle['totals']['all']}",
        "",
        "## Minimal Risk-Reducing Actions (MRRA)"
    ]
    for a in bundle["mrra"]:
        lines.append(f"- **{a['title']}** — {a['why']}")
        lines.append(f"  - Mitigation: {a['mitigation']}")
        lines.append(f"  - Verify: {a['verification']}")
    lines.append("")
    lines.append("## Decisions (P0/P1/Monitor)")
    for d in bundle["decisions"]:
        lines.append(f"- **{d['cve']}** — {d['priority']} ({d['ssvc']}): {d['why']}")
    return "\n".join(lines)

@app.get("/month/2025-Aug/summary.json")
def summary_json():
    return AUG_SUMMARY

@app.get("/month/2025-Aug/summary.md")
def summary_md():
    md = to_markdown(AUG_SUMMARY)
    return Response(content=md, media_type="text/plain")
