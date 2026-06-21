"""Shared helpers: input normalisation (incl. de-fanging) and Cloudflare ranges."""
import ipaddress
import re

_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)

# Bundled fallback if the live lists can't be fetched. Source: cloudflare.com/ips
CF_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
CF_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


def refang(s: str) -> str:
    """Undo common defanging so `example[.]com` / `hxxps://x` are accepted."""
    s = s.strip()
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."),
                 ("(dot)", "."), (" dot ", "."), ("[:]", ":")):
        s = s.replace(a, b)
    s = re.sub(r"^h[x*]{2}p(s?)://", r"http\1://", s, flags=re.I)
    return s


def normalize_domain(raw: str) -> str:
    s = refang(raw or "")
    s = _SCHEME.sub("", s)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:                       # an email was pasted; keep the domain part
        s = s.split("@")[-1]
    s = s.strip().strip(".")
    if s.count(":") == 1:              # strip a :port (but leave bare IPv6 alone)
        s = s.split(":")[0]
    s = s.lower()
    try:
        s = s.encode("idna").decode("ascii")   # punycode unicode domains
    except Exception:
        pass
    return s


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def cf_networks(extra=None):
    nets = []
    for cidr in CF_V4 + CF_V6 + list(extra or []):
        try:
            nets.append(ipaddress.ip_network(cidr.strip()))
        except ValueError:
            pass
    return nets


def ip_in_cf(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets if addr.version == n.version)
