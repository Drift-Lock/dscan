"""DNS record collection via dnspython (no `dig` binary required)."""
import dns.exception
import dns.resolver
import dns.reversename

RRTYPES = ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "CAA"]


def make_resolver(servers=None, timeout=4.0):
    r = dns.resolver.Resolver(configure=not servers)
    if servers:
        r.nameservers = list(servers)
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _query(resolver, name, rrtype):
    """Return list of record strings, [] for no answer, or None for NXDOMAIN."""
    try:
        ans = resolver.resolve(name, rrtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return []
        return [rd.to_text() for rd in ans]
    except dns.resolver.NXDOMAIN:
        return None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        return []


def reverse(resolver, ip):
    try:
        rev = dns.reversename.from_address(ip)
        ans = resolver.resolve(rev, "PTR", raise_on_no_answer=False)
        if ans.rrset:
            return ans[0].to_text().rstrip(".")
    except dns.exception.DNSException:
        pass
    return None


def gather(domain, resolver):
    out = {}
    nxdomain = False
    for t in RRTYPES:
        res = _query(resolver, domain, t)
        if res is None:
            nxdomain = True
            out[t] = []
        else:
            out[t] = res
    out["_nxdomain"] = nxdomain
    out["DNSSEC"] = bool(_query(resolver, domain, "DS")) or bool(_query(resolver, domain, "DNSKEY"))
    out["PTR"] = {ip: reverse(resolver, ip) for ip in (out.get("A", []) + out.get("AAAA", []))}
    return out
