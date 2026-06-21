"""Abuse-report categories and email generation.

`generate()` produces a ready-to-send report *body* (no recipient addresses in it);
`recipients()` returns the contacts discovered during the scan, listed separately.
"""
import datetime
import textwrap

CATEGORIES = {
    "drugs": {
        "title": "Online sale of controlled substances",
        "summary": "The domain hosts or fronts a shop, vendor page, or Telegram-linked storefront "
                   "offering illegal drugs or other controlled substances for sale.",
        "harm": "The domain is being used to advertise and facilitate the sale and distribution of "
                "controlled substances to the public. This is a serious criminal offence in virtually "
                "every jurisdiction, endangers public health and safety, and is frequently connected to "
                "money laundering and organised crime.",
        "tos": "Selling controlled substances through a domain breaches the acceptable-use and "
               "registration policies of every mainstream registrar (which prohibit unlawful use of a "
               "domain), the registry operator's anti-abuse policy, and — for ICANN-accredited "
               "registrars — the obligation under the Registrar Accreditation Agreement to investigate "
               "and act on well-founded reports of illegal activity.",
        "action": "Please investigate this report and suspend or lock the domain. We also ask that you "
                  "preserve registration records and access logs so they remain available to law enforcement.",
    },
    "phishing": {
        "title": "Phishing / credential theft",
        "summary": "The domain hosts a page impersonating a legitimate brand, service, or login in "
                   "order to steal credentials, payment details, or other sensitive data.",
        "harm": "The domain is being used to deceive users into disclosing credentials or financial "
                "information, causing direct financial harm and account compromise to victims and "
                "reputational harm to the impersonated organisation.",
        "tos": "Phishing and impersonation are prohibited by every registrar acceptable-use policy, by "
               "registry anti-abuse policies, and by the acceptable-use policy of any reputable host or "
               "CDN. It is also unlawful fraud in most jurisdictions.",
        "action": "Please investigate and suspend the domain, and preserve registration and access logs "
                  "for the affected parties and law enforcement.",
    },
    "malware": {
        "title": "Malware distribution or command-and-control",
        "summary": "The domain distributes malicious software or operates as malware "
                   "command-and-control (C2) infrastructure.",
        "harm": "The domain is being used to compromise systems — by serving malware or by directing "
                "already-infected machines — causing data loss, financial harm, and onward compromise.",
        "tos": "Distributing malware or operating C2 infrastructure violates registrar and registry "
               "anti-abuse policies and the acceptable-use policy of any reputable provider, and "
               "constitutes unauthorised access / computer-misuse offences in most jurisdictions.",
        "action": "Please investigate and suspend the domain and preserve logs for incident responders "
                  "and law enforcement.",
    },
    "fraud": {
        "title": "Fraudulent storefront / scam",
        "summary": "The domain operates a fraudulent storefront or scam (for example non-delivery, "
                   "advance-fee, or fake-service fraud) designed to take payment without providing goods.",
        "harm": "The domain is being used to obtain money from victims under false pretences, causing "
                "direct financial loss to the public.",
        "tos": "Fraudulent commerce breaches registrar acceptable-use policies, registry anti-abuse "
               "policies, and provider terms of service, and is unlawful in essentially all jurisdictions.",
        "action": "Please investigate and suspend the domain, and preserve registration and payment-"
                  "related records for victims and law enforcement.",
    },
    "counterfeit": {
        "title": "Counterfeit goods / trademark infringement",
        "summary": "The domain sells counterfeit goods or otherwise infringes registered trademarks or "
                   "other intellectual-property rights.",
        "harm": "The domain is being used to sell counterfeit or infringing products, deceiving "
                "consumers and harming the rights-holder and legitimate market.",
        "tos": "Trademark/IP infringement and the sale of counterfeit goods breach registrar and "
               "registry policies and provider terms of service, and infringe applicable intellectual-"
               "property law.",
        "action": "Please investigate and suspend the domain. The rights-holder can supply proof of "
                  "ownership on request to support formal action.",
    },
    "csam": {
        "title": "Child sexual abuse material (CSAM)",
        "summary": "The domain appears to host or link to child sexual abuse material.",
        "harm": "Child sexual abuse material is illegal everywhere and documents the abuse of children; "
                "its continued availability causes ongoing, severe harm to victims.",
        "tos": "Hosting or linking to CSAM is a serious criminal offence and violates the acceptable-use "
               "policy of every provider, registrar, and registry without exception.",
        "action": "This must be reported to a specialist hotline and to law enforcement — not only to the "
                  "provider. Do not download, copy, store, or forward the material. The provider should "
                  "immediately disable access and preserve evidence for the authorities.",
    },
}


def list_categories():
    return [(k, v["title"], v["summary"]) for k, v in CATEGORIES.items()]


def _wrap(text):
    return textwrap.fill(text, width=78)


def _evidence(domain, report):
    lines = [f"- Domain: {domain}"]
    rd = report.get("rdap_domain") or {}
    if rd.get("registrar"):
        lines.append(f"- Registrar: {rd['registrar']}")
    dates = []
    if rd.get("created"):
        dates.append(f"registered {str(rd['created'])[:10]}")
    if rd.get("expires"):
        dates.append(f"expires {str(rd['expires'])[:10]}")
    if dates:
        lines.append(f"- Registration: {', '.join(dates)}")
    reg = report.get("tld") or {}
    if reg.get("operator"):
        lines.append(f"- Registry operator (.{reg.get('tld')}): {reg['operator']}")
    cf = report.get("cloudflare") or {}
    if cf.get("proxied"):
        lines.append("- Hosting: fronted by Cloudflare (AS13335); origin IP not publicly visible")
    else:
        for e in (report.get("ips") or [])[:4]:
            seg = f"- IP {e.get('ip')}"
            if e.get("asn"):
                seg += f" — AS{e['asn']} {e.get('as_name') or ''}".rstrip()
            lines.append(seg)
    ns = rd.get("nameservers") or (report.get("dns") or {}).get("NS")
    if ns:
        lines.append("- Nameservers: " + ", ".join(n.rstrip(".") for n in ns[:4]))
    tls = report.get("tls") or {}
    if tls.get("issuer"):
        lines.append(f"- TLS certificate: issuer {tls['issuer']}, valid "
                     f"{str(tls.get('not_before'))[:10]} to {str(tls.get('not_after'))[:10]}")
    hist = (report.get("whoisfreaks") or {}).get("history") or []
    if hist:
        lines.append(f"- WHOIS history: {len(hist)} record(s) on file (earliest {hist[-1].get('date')})")
    mk = report.get("marketplace") or {}
    if mk.get("detected"):
        ex = ", ".join("t[.]me/" + h for h in (mk.get("vendor_handles") or [])[:5])
        lines.append(f"- Site content: {mk.get('verdict')} — {mk.get('vendor_count')} Telegram vendor "
                     f"handle(s){' (e.g. ' + ex + ')' if ex else ''}")
    return "\n".join(lines)


def generate(domain, category, report, reporter="<your name / research identity>",
             contact="<your contact address>"):
    c = CATEGORIES[category]
    today = datetime.date.today().isoformat()
    proxied = (report.get("cloudflare") or {}).get("proxied")

    subject = f"Abuse report — {c['title']} — {domain}"
    action = c["action"]
    if proxied and category != "csam":
        action += (" Because the site is proxied through Cloudflare, the hosting origin is obscured; "
                   "as the registrar/registry you can act at the domain-registration level regardless "
                   "of the hosting arrangement.")

    parts = [
        "To the Abuse / Compliance Team,",
        _wrap(f"I am writing to report abuse involving the domain {domain}, observed on {today}. {c['summary']}"),
        "Findings (from publicly available sources):\n" + _evidence(domain, report),
        "Nature of the abuse:\n" + _wrap(c["harm"]),
        "Policy and Terms-of-Service violation:\n" + _wrap(c["tos"]),
        "Requested action:\n" + _wrap(action),
        _wrap("This report is based solely on publicly available information (WHOIS/RDAP, DNS, and "
              "public-facing content). I am happy to provide further detail on request."),
        f"Regards,\n{reporter}\n{contact}",
    ]
    return subject, "\n\n".join(parts)


def recipients(report):
    out = []
    rd = report.get("rdap_domain") or {}
    if rd.get("registrar_abuse_email"):
        out.append(("Registrar abuse", rd["registrar_abuse_email"]))
    live = (report.get("whoisfreaks") or {}).get("live") or {}
    if isinstance(live, dict) and live.get("abuse_email"):
        out.append(("Registrar abuse (WhoisFreaks)", live["abuse_email"]))
    reg = report.get("tld") or {}
    for e in reg.get("contact_emails") or []:
        out.append((f"Registry .{reg.get('tld')}", e))
    for e in report.get("ips") or []:
        if e.get("abuse_email"):
            out.append((f"Network AS{e.get('asn')}", e["abuse_email"]))
    if (report.get("cloudflare") or {}).get("proxied"):
        out.append(("Cloudflare (proxy — often low-yield; prefer registrar/registry)",
                    "https://abuse.cloudflare.com/"))
    seen, deduped = set(), []
    for label, val in out:
        if val in seen:
            continue
        seen.add(val)
        deduped.append((label, val))
    return deduped
