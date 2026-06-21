"""WhoisFreaks integration: live WHOIS and historical WHOIS.

Key comes from --whoisfreaks-key or the WHOISFREAKS_API_KEY environment variable.
Parsing is defensive (WhoisFreaks field names vary by plan/version); the raw
response is retained and surfaced under --json so output can be reconciled.
"""
import httpx

BASE = "https://api.whoisfreaks.com/v1.0/whois"


def _call(key, params, timeout=25.0):
    try:
        r = httpx.get(BASE, params={**params, "apiKey": key}, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        try:
            detail = r.json()
        except Exception:
            detail = r.text[:300]
        return {"_error": f"HTTP {r.status_code}", "_detail": detail}
    except Exception as e:
        return {"_error": str(e)}


def _first(d, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, "", [], {}):
            return d.get(k)
    return None


def _parse_live(d):
    # For thin/reserved domains the registrar nests under registry_data.
    rd = d.get("registry_data") or {}
    reg = d.get("domain_registrar") or rd.get("domain_registrar") or {}
    registrant = d.get("registrant_contact") or rd.get("registrant_contact") or {}
    return {
        # WhoisFreaks puts the registrar's complaints/abuse address in email_address.
        "registrar": _first(reg, "registrar_name", "name"),
        "abuse_email": _first(reg, "email_address", "abuse_contact_email"),
        "abuse_phone": _first(reg, "phone_number", "abuse_contact_phone"),
        "created": _first(d, "create_date") or _first(rd, "create_date"),
        "updated": _first(d, "update_date") or _first(rd, "update_date"),
        "expires": _first(d, "expiry_date") or _first(rd, "expiry_date"),
        "status": d.get("domain_status") or rd.get("domain_status"),
        "name_servers": d.get("name_servers") or rd.get("name_servers"),
        "registrant_org": _first(registrant, "company", "company_name", "organization", "org"),
        "registrant_country": _first(registrant, "country_name", "country"),
        "raw": d,
    }


def _parse_historical(d):
    records = (d.get("whois_domains_historical") or d.get("whois_records")
               or d.get("historical_whois_records") or d.get("records") or [])
    out = []
    for rec in records:
        reg = rec.get("domain_registrar") or {}
        registrant = rec.get("registrant_contact") or {}
        out.append({
            "date": _first(rec, "query_time", "update_date", "create_date"),
            "registrar": _first(reg, "registrar_name", "name"),
            "registrant_org": _first(registrant, "company", "company_name", "organization", "org"),
            "created": _first(rec, "create_date"),
            "expires": _first(rec, "expiry_date"),
        })
    out.sort(key=lambda r: r.get("date") or "", reverse=True)
    return {
        "count": d.get("total_records") or d.get("whois_records_count") or len(out),
        "history": out,
        "raw": d,
    }


def live_whois(key, domain):
    d = _call(key, {"whois": "live", "domainName": domain})
    return d if "_error" in d else _parse_live(d)


def historical_whois(key, domain):
    d = _call(key, {"whois": "historical", "domainName": domain})
    return d if "_error" in d else _parse_historical(d)
