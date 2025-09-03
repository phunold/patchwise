from .classify_chain import classify_chain
from .decide import priority_and_ssvc, disagreement

def attach_signals(msrc_vulns, kev, epss, exploit_flags, cloud_fixed_lookup=None):
    cloud_fixed_lookup = cloud_fixed_lookup or (lambda cve: False)
    out = []
    for v in msrc_vulns:
        cve = v["cve"]
        v["kev"] = bool(kev.get(cve))
        e = epss.get(cve, {})
        v["epss"] = float(e.get("epss", 0.0))
        v["epss_date"] = e.get("date")
        v["exploit"] = exploit_flags.get(cve, {"poc": False, "metasploit": False})
        v["cloud_fixed"] = bool(cloud_fixed_lookup(cve))
        v["chain_class"] = classify_chain(v)
        prio, ssvc, why = priority_and_ssvc(v)
        v["priority"], v["ssvc"], v["decision_why"] = prio, ssvc, why
        v["disagreement"] = disagreement(v)
        out.append(v)
    return out

def mrra_from_decisions(vulns):
    """
    Pick 1–3 actions that cover the heaviest-risk classes.
    MVP heuristic:
    - If any P0 identity_eop -> action: patch Kerberos/identity KBs found
    - If any P0/P1 preauth_network -> action: patch server KBs found
    - If many client_lure P1 -> action: patch clients
    """
    actions = []
    def first_kb(vlist):
        for v in vlist:
            kbs = v.get("msrc", {}).get("kb_urls", [])
            if kbs:
                return ", ".join(sorted(set(kbs))[:3])
        return "See Microsoft Security Update Guide"
    p0 = [v for v in vulns if v["priority"] == "P0"]
    p1 = [v for v in vulns if v["priority"] == "P1"]

    ident = [v for v in p0+p1 if "identity_eop" in v["chain_class"]]
    preauth = [v for v in p0+p1 if "preauth_network" in v["chain_class"]]
    clients = [v for v in p0+p1 if "client_lure" in v["chain_class"]]

    if ident:
        actions.append({
            "id":"A1", "title":"Patch identity/AD-related updates",
            "why":"Identity chain risk (Kerberos/NTLM/LSA)", "covers":[v["cve"] for v in ident],
            "mitigation": first_kb(ident), "verification":"Verify KBs installed on DCs/AD-related servers"
        })
    if preauth:
        actions.append({
            "id":"A2", "title":"Patch pre-auth network services (RDP/RPC/SMB/HTTP)",
            "why":"Remote entry vectors", "covers":[v["cve"] for v in preauth],
            "mitigation": first_kb(preauth), "verification":"Verify KBs and service versions on servers"
        })
    if clients:
        actions.append({
            "id":"A3", "title":"Patch user endpoints (graphics/Office/file parsers)",
            "why":"User-open lure vectors", "covers":[v["cve"] for v in clients],
            "mitigation": first_kb(clients), "verification":"Verify KBs on Win10/11 clients"
        })
    return actions[:3]

def bundle(month: str, enriched):
    totals = {
        "p0": sum(1 for v in enriched if v["priority"]=="P0"),
        "p1": sum(1 for v in enriched if v["priority"]=="P1"),
        "monitor": sum(1 for v in enriched if v["priority"]=="Monitor"),
        "all": len(enriched)
    }
    actions = mrra_from_decisions(enriched)
    return {
        "month": month,
        "totals": totals,
        "mrra": actions,
        "decisions": [
            {
                "cve": v["cve"],
                "title": v["title"],
                "priority": v["priority"],
                "ssvc": v["ssvc"],
                "why": v["decision_why"],
                "signals": {
                    "msrc_exploitability": v["msrc"]["exploitability"],
                    "msrc_severity": v["msrc"]["severity"],
                    "kev": v["kev"],
                    "epss": v["epss"],
                    "cloud_fixed": v["cloud_fixed"],
                    "chain_class": v["chain_class"],
                    "disagreement": v["disagreement"]
                },
                "citations": {
                    "msrc": "MSRC Security Update Guide",
                    "kev": "CISA KEV Catalog",
                    "epss": "FIRST EPSS v4"
                }
            } for v in enriched if v["priority"] in ("P0","P1","Monitor")
        ],
        "model_card": {
            "audience": "enterprise defender",
            "signals": ["MSRC","CISA KEV","FIRST EPSS","Exploit presence","Cloud-fixed"],
            "thresholds": {"epss_p0":0.7,"epss_p1":0.3},
            "assumptions": ["No tenant inventory in MVP", "Heuristic chain classification"],
            "limitations": ["Exploit presence flags are MVP stubs"]
        }
    }

def to_markdown(b):
    lines = [
        f"# Patchwise — {b['month']}",
        f"- 🔴 P0: {b['totals']['p0']}  🟠 P1: {b['totals']['p1']}  🟢 Monitor: {b['totals']['monitor']}  │ Total: {b['totals']['all']}",
        "\n## Minimal Risk-Reducing Actions (MRRA)"
    ]
    for a in b["mrra"]:
        lines.append(f"- **{a['title']}** — {a['why']}")
        lines.append(f"  - Covers: {', '.join(a['covers'][:8])}")
        lines.append(f"  - Mitigation: {a['mitigation']}")
        lines.append(f"  - Verify: {a['verification']}")
    lines.append("\n## Decisions (P0/P1/Monitor)")
    for d in b["decisions"]:
        lines.append(f"- **{d['cve']}** — {d['priority']} ({d['ssvc']}): {d['why']}  "
                     f"[MSRC] [KEV:{'Y' if d['signals']['kev'] else 'N'}] [EPSS:{d['signals']['epss']:.2f}]")
    return "\n".join(lines)
