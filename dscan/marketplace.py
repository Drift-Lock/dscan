"""Page-content analysis: detect vendor 'shoplist' marketplaces from public HTML.

Reads only the rendered page source (the same thing a browser receives) and flags
the tell-tale signs of a Telegram-vendor marketplace: multiple t.me vendor links or
@handles, vendor-card layout, crypto payment chips, and drug-category labels. Vendor
handles are extracted as reporting evidence; they are shown defanged so the tool's
output is not a working directory.
"""
import re
from html.parser import HTMLParser

# A real browser UA + Accept headers — many shoplists serve a stripped page or an
# anti-bot challenge to non-browser user-agents, which would hide the vendor grid.
_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.9",
}

# t.me / telegram.me links (optionally without scheme). Group 1 = path (handle or +invite).
_TG = re.compile(r"(?:https?://)?(?:www\.)?t(?:elegram)?\.me/(\+?[A-Za-z0-9_/]+)", re.I)
# Bare @handles (Telegram usernames). Lookbehind avoids matching inside emails / paths.
_HANDLE = re.compile(r"(?<![\w@/.])@([A-Za-z][A-Za-z0-9_]{3,31})\b")
_CARD = re.compile(r"vendor-card", re.I)
_VOID = {"img", "br", "hr", "input", "meta", "link", "source", "area", "base",
         "col", "embed", "param", "track", "wbr"}

# at-rules / common false-positive "@words" to drop from handle detection
_ATWORDS = {"media", "import", "keyframes", "font-face", "charset", "supports",
            "namespace", "page", "layer", "container", "scope", "property"}

_MARKERS = [
    ("vendor cards", re.compile(r"vendor-card", re.I)),
    ("vendor grid", re.compile(r"vendor-grid", re.I)),
    ("crypto payment chips", re.compile(r"payment-chip|payment-method", re.I)),
    ("'shoplist'", re.compile(r"shop\s*list", re.I)),
    ("'verified vendor'", re.compile(r"verified vendor", re.I)),
    ("'cut-off' times", re.compile(r"cut[\s-]?off", re.I)),
    ("sortable by sales/reviews", re.compile(r'data-sort="(?:sales|reviews|rating)"', re.I)),
]
_DRUG = re.compile(
    r"\b(stimulants?|dissociatives?|cannabis|ketamine|opiates?|benzos?|"
    r"psychedelics?|pingers?|cocaine|mdma|ecstasy|pharmas?|prescription medications?|"
    r"research chemicals?)\b", re.I)
# Coy shoplists often omit category words but leak intent through vendor handles/names
# (e.g. '@UBERFORDRUGS_QTBOT', 'India Meds', '3rd Eye Pharma', "Tol's Apothecary").
# Applied only to extracted handles+names, so generic page chrome can't trip it.
_DRUG_HINT = re.compile(
    r"(drug|weed|cannabis|cocaine|pharma|apothec|baccy|pinger|benzo|ketamine|"
    r"psychedel|mdma|dispensar|meds|plug)", re.I)
_CRYPTO = re.compile(r"\b(BTC|LTC|XMR|Monero|Bitcoin|Litecoin)\b")


class _VendorParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.names, self.usernames, self.tg_links = [], [], []
        self._kind = None
        self._depth = 0
        self._buf = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        href = (d.get("href") or "").lower()
        if "t.me/" in href or "telegram.me/" in href:
            self.tg_links.append(d.get("href"))
        if self._kind:
            if tag not in _VOID:
                self._depth += 1
            return
        cls = d.get("class") or ""
        if "vendor-username" in cls:
            self._kind, self._depth, self._buf = "user", 1, []
        elif "vendor-name" in cls:
            self._kind, self._depth, self._buf = "name", 1, []

    def handle_data(self, data):
        if self._kind:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if self._kind and tag not in _VOID:
            self._depth -= 1
            if self._depth <= 0:
                # space-join so adjacent element text (e.g. a 'verified' icon glyph)
                # doesn't fuse onto the name: "UKCAPONE" + "verified" -> "UKCAPONE verified"
                text = " ".join(s.strip() for s in self._buf if s.strip())
                if text:
                    (self.usernames if self._kind == "user" else self.names).append(text)
                self._kind, self._buf = None, []


def _clean_name(s):
    s = re.sub(r"\bverified\b", "", s, flags=re.I)
    return re.sub(r"\s+", " ", s).strip()


def page_title(html):
    if not html:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip() or None


def fetch_html(host, timeout=8.0, max_chars=2_000_000):
    import httpx
    last_error = None
    for scheme in ("https", "http"):
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                              headers=_HEADERS) as c:
                r = c.get(f"{scheme}://{host}/")
            html = r.text[:max_chars]
            return {
                "source": f"{scheme}://{host}/",
                "final_url": str(r.url),
                "status": r.status_code,
                "bytes": len(r.content),
                "title": page_title(html),
                "html": html,
            }
        except Exception as e:
            last_error = e
            continue
    return {"error": str(last_error) if last_error else "fetch failed"} if last_error else None


def analyze(html):
    empty = {"detected": False, "verdict": "no content retrieved", "vendor_count": 0,
             "vendor_handles": [], "vendor_names": [], "telegram_invites": 0,
             "markers": [], "drug_terms": [], "drug_hint": False, "cryptocurrencies": []}
    if not html:
        return empty

    parser = _VendorParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    handles, invites = set(), set()
    # paths from <a href> and from raw text
    paths = [m.group(1) for m in _TG.finditer(html)]
    paths += [m.group(1) for href in parser.tg_links for m in [_TG.search(href or "")] if m]
    for p in paths:
        p = p.rstrip("/").split("/")[0]
        if p.startswith("+"):
            invites.add(p)
        elif p:
            handles.add(p)
    # @handles from vendor-username elements and bare text
    for u in parser.usernames:
        for hm in re.finditer(r"@?([A-Za-z][A-Za-z0-9_]{3,31})", u):
            handles.add(hm.group(1))
    for hm in _HANDLE.finditer(html):
        h = hm.group(1)
        if h.lower() not in _ATWORDS:
            handles.add(h)

    names, seen = [], set()
    for n in parser.names:
        nn = _clean_name(n)
        if nn and nn.lower() not in seen:
            seen.add(nn.lower())
            names.append(nn)

    vendor_handles = sorted(handles, key=str.lower)
    vendor_cards = bool(_CARD.search(html))
    drug_terms = sorted({m.group(0).lower() for m in _DRUG.finditer(html)})
    # drug intent leaking through the vendor handles/names themselves
    drug_hint = bool(_DRUG_HINT.search(" ".join(vendor_handles + names)))
    cryptos = sorted({m.group(0).upper() for m in _CRYPTO.finditer(html)})
    markers = [label for label, rx in _MARKERS if rx.search(html)]
    n = len(vendor_handles)

    if n > 1 and vendor_cards and (drug_terms or drug_hint):
        verdict, detected = "Likely DRUG-VENDOR marketplace / shoplist", True
    elif n > 1 and (vendor_cards or names):
        verdict, detected = "Likely vendor marketplace / shoplist", True
    elif n > 1:
        verdict, detected = "Multiple Telegram links/handles present", True
    elif n == 1 and vendor_cards:
        verdict, detected = "Single vendor / shop page", True
    else:
        verdict, detected = "No marketplace indicators found", False

    return {
        "detected": detected,
        "verdict": verdict,
        "vendor_count": n,
        "vendor_handles": vendor_handles,
        "vendor_names": names,
        "telegram_invites": len(invites),
        "markers": markers,
        "drug_terms": drug_terms,
        "drug_hint": drug_hint,
        "cryptocurrencies": cryptos,
    }
