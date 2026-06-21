"""TLD registry operator + escalation contacts, via IANA's authoritative WHOIS (port 43).

Useful when a site is fronted by Cloudflare: the host won't act, but the registry
operator behind the TLD is an escalation path above the registrar.
"""
import socket


def _iana_whois(query, timeout=8.0):
    try:
        with socket.create_connection(("whois.iana.org", 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode("ascii", "ignore"))
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        return buf.decode("utf-8", "replace")
    except Exception as e:
        return f"%ERROR {e}"


def registry_for(domain, timeout=8.0):
    """Return registry operator + contact emails for a domain's TLD."""
    tld = domain.rsplit(".", 1)[-1]
    text = _iana_whois(tld, timeout=timeout)
    if not text or text.startswith("%ERROR"):
        return {"tld": tld, "error": "IANA WHOIS unavailable"}

    operator = whois_server = url = None
    emails, status = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("%") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if not val:
            continue
        if key == "organisation" and not operator:
            operator = val
        elif key == "whois" and not whois_server:
            whois_server = val
        elif key in ("e-mail", "email") and val not in emails:
            emails.append(val)
        elif key == "status":
            status.append(val)
        elif key in ("source", "url") and not url and val.startswith("http"):
            url = val
    return {
        "tld": tld,
        "operator": operator,
        "whois_server": whois_server,
        "contact_emails": emails,
        "status": status,
        "iana_url": url or f"https://www.iana.org/domains/root/db/{tld}.html",
    }
