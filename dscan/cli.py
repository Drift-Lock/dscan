"""Command-line entry point: orchestrates the collectors into one report."""
import argparse
import datetime
import os
import sys

import httpx

from . import cloudflare, dnsq, history, httptls, marketplace, netinfo, rdap, render, tld, util, whoisfreaks
from . import report as reportgen
from . import __version__


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def scan(domain, args):
    report = {"domain": domain, "input": args.domain, "scanned_at": _now(), "errors": []}

    resolver = dnsq.make_resolver(args.resolver or ["1.1.1.1", "8.8.8.8"],
                                  timeout=min(args.timeout, 5.0))

    # --- DNS ---
    dns_rec = dnsq.gather(domain, resolver)
    report["dns"] = dns_rec
    report["exists"] = (not dns_rec.get("_nxdomain")) and bool(
        dns_rec.get("A") or dns_rec.get("AAAA") or dns_rec.get("NS") or dns_rec.get("SOA"))

    # --- HTTP (own client: TLS verification disabled for probing) ---
    http = None
    if not args.no_http:
        http = httptls.http_probe(domain, timeout=args.timeout)
        report["http"] = http
    headers = httptls.merged_headers(http or {})

    # --- Page content: vendor-marketplace / shoplist detection ---
    # Runs on a live fetch, or on a saved HTML file (--html-file) when the live page
    # is cloaked. A file is analysed regardless of --no-http / DNS resolution.
    if not args.no_content and (args.html_file or (not args.no_http and report["exists"])):
        page = None
        if args.html_file:
            try:
                from pathlib import Path
                html = Path(args.html_file).read_text(encoding="utf-8", errors="replace")
                page = {"source": args.html_file, "final_url": args.html_file, "status": None,
                        "bytes": len(html.encode("utf-8", "replace")),
                        "title": marketplace.page_title(html), "html": html}
            except Exception as e:
                report["errors"].append(f"html-file: {e}")
        else:
            page = marketplace.fetch_html(domain, timeout=args.timeout)
        if page and page.get("html") is not None:
            mk = marketplace.analyze(page["html"])
            mk["fetched"] = {k: page.get(k) for k in
                             ("source", "final_url", "status", "bytes", "title")}
            report["marketplace"] = mk
        elif page and page.get("error"):
            report["marketplace"] = {"detected": False, "vendor_count": 0,
                                     "verdict": f"page fetch failed ({page['error']})",
                                     "fetch_error": page["error"]}

    # --- RDAP (domain + IPs) and Cloudflare ranges share one client ---
    with httpx.Client(timeout=args.timeout, follow_redirects=True,
                      headers={"User-Agent": f"dscan/{__version__}"}) as client:
        report["rdap_domain"] = rdap.domain(client, domain)
        nets = util.cf_networks(cloudflare.fetch_ranges(client))
        report["cloudflare"] = cloudflare.detect(dns_rec, headers, nets)

        ips_info = []
        for ip in (dns_rec.get("A", []) + dns_rec.get("AAAA", [])):
            entry = {"ip": ip, "ptr": dns_rec.get("PTR", {}).get(ip),
                     "in_cloudflare": util.ip_in_cf(ip, nets)}
            entry.update(netinfo.asn_for_ip(resolver, ip))
            ipr = rdap.ip(client, ip)
            if "_error" not in ipr:
                entry.update(ipr)
            ips_info.append(entry)
        report["ips"] = ips_info

    # --- abuse summary ---
    rd = report["rdap_domain"]
    report["abuse"] = {
        "registrar": {} if "_error" in rd else {
            "name": rd.get("registrar"),
            "email": rd.get("registrar_abuse_email"),
            "tel": rd.get("registrar_abuse_tel"),
        },
        "networks": [{"ip": e["ip"], "network": e.get("name"), "abuse_email": e.get("abuse_email"),
                      "country": e.get("country"), "asn": e.get("asn"), "as_name": e.get("as_name")}
                     for e in report["ips"]],
    }

    # --- TLD registry (escalation contact, especially when Cloudflare-fronted) ---
    report["tld"] = tld.registry_for(domain, timeout=min(args.timeout, 8.0))

    # --- WhoisFreaks (live by default if a key is present; history on --wf-history) ---
    wf_key = args.whoisfreaks_key or os.environ.get("WHOISFREAKS_API_KEY")
    if wf_key:
        wf = {"live": whoisfreaks.live_whois(wf_key, domain)}
        if args.wf_history:
            hist = whoisfreaks.historical_whois(wf_key, domain)
            if "_error" in hist:
                wf["history_error"] = hist["_error"]
            else:
                wf["history"] = hist.get("history")
                wf["count"] = hist.get("count")
        report["whoisfreaks"] = wf

    # --- TLS ---
    if not args.no_tls and report["exists"]:
        report["tls"] = httptls.tls_cert(domain, timeout=args.timeout)

    if args.raw_whois:
        report["whois_raw"] = rdap.whois_raw(domain)

    # --- history / change tracking ---
    if not args.no_history:
        prev = history.previous(args.history_dir, domain)
        report["changes"] = history.diff(prev, report)
        try:
            history.save(args.history_dir, domain, report)
        except Exception as e:
            report["errors"].append(f"history: {e}")

    return report


def build_parser():
    p = argparse.ArgumentParser(
        prog="dscan",
        description="Passive domain OSINT: RDAP/WHOIS, DNS, Cloudflare, hosting & abuse contacts, "
                    "TLS, and change tracking. Uses only public data.")
    p.add_argument("domain", nargs="?",
                   help="domain to scan (defanged input like example[.]com is accepted)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a formatted report")
    p.add_argument("--resolver", action="append", metavar="IP",
                   help="DNS resolver IP (repeatable; default 1.1.1.1 and 8.8.8.8)")
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout in seconds (default 8)")
    p.add_argument("--no-http", action="store_true", help="skip HTTP fingerprinting")
    p.add_argument("--no-content", action="store_true",
                   help="skip page-content (vendor marketplace / shoplist) analysis")
    p.add_argument("--html-file", metavar="PATH",
                   help="analyse marketplace/shoplist indicators from a saved HTML file "
                        "instead of fetching the live page (useful when the live fetch is "
                        "served a stripped or anti-bot page)")
    p.add_argument("--no-tls", action="store_true", help="skip TLS certificate inspection")
    p.add_argument("--raw-whois", action="store_true", help="append raw WHOIS text (needs system 'whois')")
    p.add_argument("--no-history", action="store_true", help="don't read or write local scan history")
    p.add_argument("--history-dir", default="~/.dscan/history", help="where scan snapshots are stored")

    g = p.add_argument_group("WhoisFreaks (key via --whoisfreaks-key or $WHOISFREAKS_API_KEY)")
    g.add_argument("--whoisfreaks-key", metavar="KEY", help="enable WhoisFreaks live WHOIS for this run")
    g.add_argument("--wf-history", action="store_true",
                   help="also fetch historical WHOIS (uses more API credits)")

    a = p.add_argument_group("abuse reporting")
    a.add_argument("--report", choices=list(reportgen.CATEGORIES), metavar="CATEGORY",
                   help="generate an abuse-report email for this category (see --list-categories)")
    a.add_argument("--list-categories", action="store_true", help="list report categories and exit")
    a.add_argument("--report-out", metavar="PATH", help="also write the generated email body to a file")
    a.add_argument("--from-name", default="<your name / research identity>",
                   help="signature name used in the generated email")
    a.add_argument("--from-contact", default="<your contact address>",
                   help="signature contact used in the generated email")

    p.add_argument("--version", action="version", version=f"dscan {__version__}")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_categories:
        render.print_categories(reportgen.list_categories())
        return 0
    if not args.domain:
        parser.error("a domain is required (or use --list-categories)")

    domain = util.normalize_domain(args.domain)
    if not domain or "." not in domain:
        render.console.print(f"[red]Not a valid domain:[/red] {args.domain!r}")
        return 2
    try:
        report = scan(domain, args)
    except KeyboardInterrupt:
        return 130

    if args.report:
        subject, body = reportgen.generate(domain, args.report, report,
                                           args.from_name, args.from_contact)
        report["abuse_report"] = {"category": args.report, "subject": subject, "body": body,
                                  "recipients": reportgen.recipients(report)}
        if args.report_out:
            try:
                from pathlib import Path
                Path(args.report_out).write_text(f"Subject: {subject}\n\n{body}\n", encoding="utf-8")
            except Exception as e:
                report["errors"].append(f"report-out: {e}")

    try:
        if args.json:
            render.print_json(report)
        else:
            render.render_report(report)
            if args.report:
                render.print_email(report["abuse_report"], args.report, args.report_out)
    except BrokenPipeError:
        # downstream closed early (e.g. piped to `head`/`jq`) — exit quietly
        try:
            sys.stdout.close()
        except Exception:
            pass
    return 0
