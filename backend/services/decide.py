def priority_and_ssvc(cve_doc: dict):
    """
    Minimal deterministic logic:
    - If cloud_fixed => Monitor
    - If KEV true => P0 + Act Fast
    - Else if EPSS >= 0.7 => P0 + Act Fast
    - Else if EPSS >= 0.3 or MSRC exploitability contains 'More' => P1 + Act
    - Else => Monitor + Track
    """
    cloud_fixed = cve_doc.get("cloud_fixed", False)
    if cloud_fixed:
        return ("Monitor", "Track", "Cloud-fixed (service-side)")

    kev = cve_doc.get("kev", False)
    epss = cve_doc.get("epss", 0.0)
    msrc_expl = (cve_doc.get("msrc", {}).get("exploitability") or "").lower()

    if kev:
        return ("P0", "Act Fast", "Known exploited (KEV)")
    if epss >= 0.7:
        return ("P0", "Act Fast", f"High likelihood (EPSS {epss:.2f})")
    if epss >= 0.3 or "more" in msrc_expl:
        reason = "More likely (MSRC)" if "more" in msrc_expl else f"Moderate likelihood (EPSS {epss:.2f})"
        return ("P1", "Act", reason)
    return ("Monitor", "Track", "Low likelihood at this time")

def disagreement(cve_doc: dict):
    flags = []
    epss = cve_doc.get("epss", 0.0)
    msrc_expl = (cve_doc.get("msrc", {}).get("exploitability") or "").lower()
    if epss >= 0.5 and "less" in msrc_expl:
        flags.append("EPSS high vs MSRC low")
    return flags
