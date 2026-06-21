"""HTTP fingerprinting and TLS certificate inspection."""
import socket
import ssl

import httpx

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    from cryptography.hazmat.primitives import hashes
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

_UA = "dscan/0.1 (+passive OSINT)"
_INTERESTING = [
    "server", "cf-ray", "cf-cache-status", "x-powered-by", "via", "location",
    "content-type", "strict-transport-security", "x-served-by", "x-cache",
]


def http_probe(host, timeout=8.0):
    out = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                              headers={"User-Agent": _UA}) as c:
                try:
                    r = c.head(url)
                    if r.status_code >= 400:
                        r = c.get(url)
                except httpx.HTTPError:
                    r = c.get(url)
            hops = [str(h.url) for h in r.history] + [str(r.url)]
            out[scheme] = {
                "status": r.status_code,
                "final_url": str(r.url),
                "redirects": hops if len(hops) > 1 else [],
                "headers": {k: v for k, v in r.headers.items() if k.lower() in _INTERESTING},
            }
        except Exception as e:
            out[scheme] = {"error": str(e)}
    return out


def merged_headers(http):
    for scheme in ("https", "http"):
        h = (http or {}).get(scheme, {}).get("headers")
        if h:
            return {k.lower(): v for k, v in h.items()}
    return {}


def tls_cert(host, port=443, timeout=8.0):
    """Fetch the leaf certificate even if it fails validation (OSINT, not trust)."""
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                proto = ss.version()
    except Exception as e:
        return {"error": str(e)}

    info = {"tls_version": proto}
    if not der:
        return info
    if not _HAVE_CRYPTO:
        info["note"] = "install 'cryptography' for full certificate details"
        return info
    try:
        cert = x509.load_der_x509_certificate(der)

        def cn(name):
            try:
                return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except Exception:
                return name.rfc4514_string()

        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        info.update({
            "subject": cn(cert.subject),
            "issuer": cn(cert.issuer),
            "san": sans,
            "not_before": nb.isoformat(),
            "not_after": na.isoformat(),
            "serial": format(cert.serial_number, "x"),
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        })
    except Exception as e:
        info["error"] = f"certificate parse failed: {e}"
    return info
