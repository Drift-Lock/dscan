"""Local scan history + diffing, so repeated scans surface DNS / hosting changes."""
import datetime
import json
from pathlib import Path


def _dir(base, domain):
    p = Path(base).expanduser() / domain
    p.mkdir(parents=True, exist_ok=True)
    return p


def fingerprint(report):
    """The stable subset we track for change detection."""
    d = report.get("dns", {}) or {}
    rd = report.get("rdap_domain", {}) or {}
    return {
        "A": sorted(d.get("A", [])),
        "AAAA": sorted(d.get("AAAA", [])),
        "NS": sorted(d.get("NS", [])),
        "MX": sorted(d.get("MX", [])),
        "registrar": rd.get("registrar"),
        "nameservers": sorted(rd.get("nameservers", []) or []),
        "cloudflare": (report.get("cloudflare") or {}).get("verdict"),
        "asns": sorted({i.get("asn") for i in report.get("ips", []) if i.get("asn")}),
    }


def previous(base, domain):
    files = sorted(_dir(base, domain).glob("*.json"))
    if not files:
        return None
    try:
        return json.loads(files[-1].read_text("utf-8"))
    except Exception:
        return None


def save(base, domain, report):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = _dir(base, domain) / f"{ts}.json"
    path.write_text(json.dumps(
        {"scanned_at": report.get("scanned_at"), "fingerprint": fingerprint(report)},
        indent=2), "utf-8")
    return path


def diff(prev, report):
    if not prev or "fingerprint" not in prev:
        return None
    old, new = prev["fingerprint"], fingerprint(report)
    changes = {}
    for key in ("A", "AAAA", "NS", "MX", "nameservers", "asns"):
        o, n = set(old.get(key, []) or []), set(new.get(key, []) or [])
        if o != n:
            changes[key] = {"added": sorted(n - o), "removed": sorted(o - n)}
    for key in ("registrar", "cloudflare"):
        if old.get(key) != new.get(key):
            changes[key] = {"from": old.get(key), "to": new.get(key)}
    return {"since": prev.get("scanned_at"), "changes": changes}
