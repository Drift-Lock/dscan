"""Cloudflare detection across NS, IP ranges, and HTTP headers."""
from . import util


def fetch_ranges(client):
    """Pull the current published Cloudflare ranges; empty list on failure (we fall back to bundled)."""
    extra = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        try:
            r = client.get(url)
            if r.status_code == 200:
                extra += [ln.strip() for ln in r.text.splitlines() if ln.strip() and "/" in ln]
        except Exception:
            pass
    return extra


def detect(dns_records, http_headers, nets):
    ns_cf = "cloudflare" in " ".join(dns_records.get("NS", [])).lower()
    ips = dns_records.get("A", []) + dns_records.get("AAAA", [])
    proxied_ips = [ip for ip in ips if util.ip_in_cf(ip, nets)]

    header_signals = []
    h = http_headers or {}
    if "cloudflare" in (h.get("server", "") or "").lower():
        header_signals.append("server: cloudflare")
    if h.get("cf-ray"):
        header_signals.append("cf-ray header present")
    if h.get("cf-cache-status"):
        header_signals.append("cf-cache-status header present")

    proxied = bool(proxied_ips) or bool(header_signals)
    if proxied:
        verdict = "Behind Cloudflare — proxied (origin IP hidden)"
    elif ns_cf:
        verdict = "Cloudflare DNS only — not proxied (A/AAAA likely the real origin)"
    else:
        verdict = "No Cloudflare detected"

    return {
        "ns_cloudflare": ns_cf,
        "proxied": proxied,
        "proxied_ips": proxied_ips,
        "header_signals": header_signals,
        "verdict": verdict,
    }
