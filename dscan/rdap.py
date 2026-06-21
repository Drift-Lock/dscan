"""RDAP lookups (domain + IP) with abuse-contact extraction, plus optional raw WHOIS."""
import shutil
import subprocess

RDAP_BASE = "https://rdap.org"


def _get(client, url):
    try:
        r = client.get(url, headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return {"_error": "not found (404)"}
        return {"_error": f"HTTP {r.status_code}"}
    except Exception as e:  # network/JSON errors shouldn't kill the scan
        return {"_error": str(e)}


def _vcard(entity):
    out = {}
    va = (entity or {}).get("vcardArray")
    if not va or len(va) < 2:
        return out
    for item in va[1]:
        try:
            key, val = item[0], item[3]
        except (IndexError, TypeError):
            continue
        val = val[0] if isinstance(val, list) and val else val
        if key == "fn":
            out["name"] = val
        elif key == "email":
            out.setdefault("email", val)
        elif key == "tel":
            out.setdefault("tel", val)
    return out


def _find_role(entities, role):
    for e in entities or []:
        if role in (e.get("roles") or []):
            return e
        nested = _find_role(e.get("entities"), role)
        if nested:
            return nested
    return None


def _events(obj):
    out = {}
    for ev in obj.get("events", []) or []:
        if ev.get("eventAction") and ev.get("eventDate"):
            out[ev["eventAction"]] = ev["eventDate"]
    return out


def domain(client, name):
    data = _get(client, f"{RDAP_BASE}/domain/{name}")
    if "_error" in data:
        return data
    ev = _events(data)
    reg = _vcard(_find_role(data.get("entities"), "registrar"))
    abuse = _vcard(_find_role(data.get("entities"), "abuse"))
    return {
        "registrar": reg.get("name"),
        "registrar_abuse_email": abuse.get("email"),
        "registrar_abuse_tel": abuse.get("tel"),
        "status": data.get("status"),
        "created": ev.get("registration"),
        "updated": ev.get("last changed") or ev.get("last update of RDAP database"),
        "expires": ev.get("expiration"),
        "nameservers": [n.get("ldhName", "").rstrip(".") for n in data.get("nameservers", []) or []],
        "dnssec_signed": (data.get("secureDNS") or {}).get("delegationSigned"),
        "handle": data.get("handle"),
    }


def ip(client, addr):
    data = _get(client, f"{RDAP_BASE}/ip/{addr}")
    if "_error" in data:
        return data
    abuse = _vcard(_find_role(data.get("entities"), "abuse"))
    cidr = None
    cidrs = data.get("cidr0_cidrs")
    if cidrs:
        try:
            first = cidrs[0]
            pfx = first.get("v4prefix") or first.get("v6prefix")
            cidr = f"{pfx}/{first.get('length')}" if pfx else None
        except (IndexError, TypeError):
            cidr = None
    if not cidr and data.get("startAddress") and data.get("endAddress"):
        cidr = f"{data['startAddress']} - {data['endAddress']}"
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "cidr": cidr,
        "abuse_email": abuse.get("email"),
        "abuse_name": abuse.get("name"),
    }


def whois_raw(name, timeout=12):
    """Raw WHOIS text via the system `whois` binary, if installed."""
    exe = shutil.which("whois")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, name], capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip() or None
    except Exception:
        return None
