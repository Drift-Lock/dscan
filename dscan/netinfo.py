"""ASN / origin lookups via Team Cymru's free DNS service."""
import ipaddress

import dns.exception


def _txt(resolver, name):
    try:
        ans = resolver.resolve(name, "TXT", raise_on_no_answer=False)
        if ans.rrset:
            return ans[0].to_text().strip('"')
    except dns.exception.DNSException:
        pass
    return None


def asn_for_ip(resolver, ip):
    """Return {asn, prefix, cc, rir, as_name} using *.asn.cymru.com TXT records."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version == 4:
        qname = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = list(addr.exploded.replace(":", ""))
        qname = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"

    rec = _txt(resolver, qname)
    if not rec:
        return {}
    # Format: "ASN(s) | prefix | CC | registry | date"
    parts = [p.strip() for p in rec.split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else None
    info = {
        "asn": asn,
        "prefix": parts[1] if len(parts) > 1 else None,
        "cc": parts[2] if len(parts) > 2 else None,
        "rir": parts[3] if len(parts) > 3 else None,
    }
    if asn:
        name_rec = _txt(resolver, f"AS{asn}.asn.cymru.com")
        if name_rec:
            np = [p.strip() for p in name_rec.split("|")]
            info["as_name"] = np[-1] if np else None
    return info
