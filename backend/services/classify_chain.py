def classify_chain(cve_doc: dict):
    """
    Very simple rule-based classes (MVP):
    - identity_eop if title mentions Kerberos / NTLM / LSA / Credential
    - client_lure if title mentions Graphics/Image/Font/Office
    - preauth_network if title mentions RDP/RPC/SMB/HTTP/Exchange/SharePoint
    """
    title = (cve_doc.get("title") or "").lower()
    classes = []
    if any(x in title for x in ["kerberos", "ntlm", "lsa", "credential"]):
        classes.append("identity_eop")
    if any(x in title for x in ["graphics", "image", "font", "office", "word", "excel", "powerpoint"]):
        classes.append("client_lure")
    if any(x in title for x in ["rdp", "rpc", "smb", "http", "iis", "exchange", "sharepoint"]):
        classes.append("preauth_network")
    return classes
