"""Terminal (rich) and JSON rendering of a scan report."""
import json as _json
import sys

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Make output robust on terminals whose encoding isn't UTF-8 (e.g. legacy
# Windows consoles using cp1252) so a glyph like → never crashes a scan.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(legacy_windows=False)
ACCENT = "orange3"


def _fmt(v):
    if v in (None, "", [], {}):
        return "[dim]—[/dim]"
    if isinstance(v, bool):
        return "[green]yes[/green]" if v else "[dim]no[/dim]"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def _kv_panel(title, pairs, style=ACCENT):
    t = Table(box=None, show_header=False, expand=True, pad_edge=False)
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column(overflow="fold")
    for k, v in pairs:
        t.add_row(k, _fmt(v))
    console.print(Panel(t, title=f"[bold]{title}[/bold]", border_style=style, title_align="left"))


def print_json(report):
    print(_json.dumps(report, indent=2, default=str))


def render_report(r):
    dom = r["domain"]
    exists = r.get("exists")
    status = "[green]resolves[/green]" if exists else "[red]no DNS / NXDOMAIN[/red]"
    console.print(Panel(
        f"[bold {ACCENT}]{dom}[/bold {ACCENT}]   {status}\n[dim]scanned {r['scanned_at']}"
        + (f"  ·  input: {r['input']}" if r.get("input") != dom else "") + "[/dim]",
        border_style=ACCENT, box=box.HEAVY))

    # ---- Registration / RDAP ----
    rd = r.get("rdap_domain", {}) or {}
    if "_error" in rd:
        _kv_panel("Registration (RDAP)", [("lookup", f"[red]{rd['_error']}[/red]")])
    else:
        _kv_panel("Registration (RDAP / WHOIS)", [
            ("Registrar", rd.get("registrar")),
            ("Abuse email", rd.get("registrar_abuse_email")),
            ("Abuse phone", rd.get("registrar_abuse_tel")),
            ("Created", rd.get("created")),
            ("Updated", rd.get("updated")),
            ("Expires", rd.get("expires")),
            ("Status", rd.get("status")),
            ("DNSSEC (registry)", rd.get("dnssec_signed")),
        ])

    # ---- WhoisFreaks (optional) ----
    wf = r.get("whoisfreaks")
    if wf:
        live = wf.get("live")
        if isinstance(live, dict) and "_error" not in live:
            _kv_panel("WHOIS (WhoisFreaks)", [
                ("Registrar", live.get("registrar")),
                ("Abuse email", live.get("abuse_email")),
                ("Abuse phone", live.get("abuse_phone")),
                ("Created", live.get("created")),
                ("Updated", live.get("updated")),
                ("Expires", live.get("expires")),
                ("Registrant org", live.get("registrant_org")),
                ("Registrant country", live.get("registrant_country")),
            ], style="cyan")
        elif isinstance(live, dict):
            _kv_panel("WHOIS (WhoisFreaks)", [("lookup", f"[red]{live.get('_error')}[/red]")], style="cyan")
        hist = wf.get("history")
        if hist:
            ht = Table(box=box.SIMPLE, expand=True)
            for col in ("Date", "Registrar", "Registrant org", "Created", "Expires"):
                ht.add_column(col, overflow="fold")
            for rec in hist[:12]:
                ht.add_row(str(rec.get("date") or "—"), rec.get("registrar") or "—",
                           rec.get("registrant_org") or "—", str(rec.get("created") or "—"),
                           str(rec.get("expires") or "—"))
            console.print(Panel(ht, border_style="cyan", title_align="left",
                                title=f"[bold]WHOIS history — {wf.get('count', len(hist))} record(s) (WhoisFreaks)[/bold]"))
        elif wf.get("history_error"):
            console.print(f"[dim]WhoisFreaks history: {wf['history_error']}[/dim]")

    # ---- DNS ----
    d = r.get("dns", {}) or {}
    dt = Table(box=box.SIMPLE, expand=True)
    dt.add_column("Type", style="bold cyan", no_wrap=True)
    dt.add_column("Records", overflow="fold")
    for t in ("A", "AAAA", "NS", "MX", "CNAME", "TXT", "CAA", "SOA"):
        vals = d.get(t)
        if vals:
            dt.add_row(t, "\n".join(vals))
    ptr = {k: v for k, v in (d.get("PTR") or {}).items() if v}
    if ptr:
        dt.add_row("PTR", "\n".join(f"{k} → {v}" for k, v in ptr.items()))
    dt.add_row("DNSSEC", _fmt(bool(d.get("DNSSEC"))))
    console.print(Panel(dt, title="[bold]DNS records[/bold]", border_style=ACCENT, title_align="left"))

    # ---- Cloudflare ----
    cf = r.get("cloudflare", {}) or {}
    verdict = cf.get("verdict", "—")
    vstyle = "yellow" if cf.get("proxied") else ("cyan" if cf.get("ns_cloudflare") else "dim")
    _kv_panel("Cloudflare", [
        ("Verdict", f"[{vstyle}]{verdict}[/{vstyle}]"),
        ("NS on Cloudflare", cf.get("ns_cloudflare")),
        ("Proxied IPs", cf.get("proxied_ips")),
        ("Header signals", cf.get("header_signals")),
    ])

    if cf.get("proxied"):
        console.print("[yellow]↳ Cloudflare is a pass-through proxy — for takedown, escalate to the "
                      "registrar and the TLD registry (below), not Cloudflare.[/yellow]")

    # ---- Network / hosting / abuse ----
    ips = r.get("ips", []) or []
    if ips:
        nt = Table(box=box.SIMPLE, expand=True)
        for col in ("IP", "PTR", "ASN", "AS name", "Network", "CC", "CF", "Abuse"):
            nt.add_column(col, overflow="fold")
        for e in ips:
            nt.add_row(
                e.get("ip", ""), e.get("ptr") or "—",
                e.get("asn") or "—", (e.get("as_name") or "—"),
                e.get("name") or e.get("cidr") or "—", e.get("country") or "—",
                "[yellow]yes[/yellow]" if e.get("in_cloudflare") else "no",
                e.get("abuse_email") or "—",
            )
        console.print(Panel(nt, title="[bold]Hosting / network & abuse contacts[/bold]",
                            border_style=ACCENT, title_align="left"))

    # ---- TLD registry (escalation contact) ----
    reg = r.get("tld")
    if reg and not reg.get("error"):
        proxied = (r.get("cloudflare") or {}).get("proxied")
        _kv_panel("TLD registry — escalation contact", [
            ("TLD", "." + str(reg.get("tld"))),
            ("Registry operator", reg.get("operator")),
            ("Contact emails", reg.get("contact_emails")),
            ("Registry WHOIS", reg.get("whois_server")),
            ("IANA record", reg.get("iana_url")),
        ], style="green" if proxied else ACCENT)

    # ---- HTTP ----
    http = r.get("http")
    if http:
        rows = []
        for scheme in ("https", "http"):
            s = http.get(scheme)
            if not s:
                continue
            if "error" in s:
                rows.append((scheme, f"[red]{s['error']}[/red]"))
                continue
            line = f"{s['status']} → {s['final_url']}"
            if s.get("redirects"):
                line += f"  [dim]({len(s['redirects'])} hops)[/dim]"
            rows.append((scheme, line))
            for hk, hv in (s.get("headers") or {}).items():
                rows.append((f"  {hk}", hv))
        _kv_panel("HTTP", rows)

    # ---- Page content / marketplace ----
    mk = r.get("marketplace")
    if mk:
        drug = bool(mk.get("drug_terms") or mk.get("drug_hint"))
        style = ("red" if drug else "yellow") if mk.get("detected") else "dim"
        rows = [("Verdict", f"[{style}]{mk.get('verdict')}[/{style}]")]
        fetched = mk.get("fetched") or {}
        if fetched:
            meta = []
            if fetched.get("status") is not None:
                meta.append(f"HTTP {fetched['status']}")
            if fetched.get("bytes") is not None:
                meta.append(f"{fetched['bytes']:,} bytes")
            loc = fetched.get("final_url") or fetched.get("source") or "—"
            rows.append(("Fetched", loc + (f"  ({', '.join(meta)})" if meta else "")))
            if fetched.get("title"):
                rows.append(("Page title", fetched["title"]))
        elif mk.get("fetch_error"):
            rows.append(("Fetch error", f"[red]{mk['fetch_error']}[/red]"))
        rows.append(("Telegram vendor handles", mk.get("vendor_count")))
        handles = mk.get("vendor_handles") or []
        if handles:
            shown = ", ".join("t[.]me/" + h for h in handles[:50])
            if len(handles) > 50:
                shown += f"  … (+{len(handles) - 50} more)"
            rows.append(("Handles", shown))
        names = mk.get("vendor_names") or []
        if names:
            ns = ", ".join(names[:40])
            if len(names) > 40:
                ns += f"  … (+{len(names) - 40} more)"
            rows.append(("Vendor names", ns))
        if mk.get("telegram_invites"):
            rows.append(("Telegram invites", mk["telegram_invites"]))
        if mk.get("drug_terms"):
            rows.append(("Drug categories", mk["drug_terms"]))
        elif mk.get("drug_hint"):
            rows.append(("Drug signal", "vendor handles/names indicate drugs"))
        if mk.get("cryptocurrencies"):
            rows.append(("Crypto accepted", mk["cryptocurrencies"]))
        if mk.get("markers"):
            rows.append(("Signals", mk["markers"]))
        _kv_panel("Site content — marketplace scan", rows,
                  style="red" if (mk.get("detected") and drug) else ACCENT)

    # ---- TLS ----
    tls = r.get("tls")
    if tls:
        if "error" in tls and "subject" not in tls:
            _kv_panel("TLS certificate", [("connection", f"[red]{tls['error']}[/red]"),
                                          ("version", tls.get("tls_version"))])
        else:
            _kv_panel("TLS certificate", [
                ("TLS version", tls.get("tls_version")),
                ("Subject", tls.get("subject")),
                ("Issuer", tls.get("issuer")),
                ("SAN", tls.get("san")),
                ("Valid from", tls.get("not_before")),
                ("Valid to", tls.get("not_after")),
                ("SHA-256", tls.get("sha256")),
                ("Note", tls.get("note")),
            ])

    # ---- Changes since last scan ----
    ch = r.get("changes")
    if ch and ch.get("changes"):
        rows = []
        for key, delta in ch["changes"].items():
            if "added" in delta or "removed" in delta:
                bits = []
                if delta.get("added"):
                    bits.append("[green]+ " + ", ".join(delta["added"]) + "[/green]")
                if delta.get("removed"):
                    bits.append("[red]- " + ", ".join(delta["removed"]) + "[/red]")
                rows.append((key, "  ".join(bits)))
            else:
                rows.append((key, f"[red]{delta.get('from')}[/red] → [green]{delta.get('to')}[/green]"))
        _kv_panel(f"Changes since {ch.get('since')}", rows, style="yellow")
    elif ch is not None:
        console.print(f"[dim]No changes since last scan ({ch.get('since')}).[/dim]")
    else:
        console.print("[dim]First scan recorded — re-run later to see changes.[/dim]")

    raw = r.get("whois_raw")
    if raw:
        console.print(Panel(raw, title="[bold]Raw WHOIS[/bold]", border_style="grey50", title_align="left"))

    for err in r.get("errors", []):
        console.print(f"[red]! {err}[/red]")


def print_categories(cats):
    t = Table(box=box.SIMPLE, expand=True)
    t.add_column("Category", style="bold cyan", no_wrap=True)
    t.add_column("Title")
    t.add_column("What it covers", overflow="fold")
    for key, title, summary in cats:
        t.add_row(key, title, summary)
    console.print(Panel(t, border_style=ACCENT, title_align="left",
                        title="[bold]Abuse report categories[/bold] — use with --report <category>"))


def print_email(abuse, category, out_path=None):
    # plain print (not rich) so the email is copy-paste clean and unwrapped
    line = "=" * 72
    print("\n" + line)
    print(f"ABUSE REPORT EMAIL  ·  category: {category}")
    print(line)
    print("Subject: " + abuse["subject"])
    print("")
    print(abuse["body"])
    print(line)
    print("WHERE TO SEND  (not part of the email — choose your recipients):")
    if abuse.get("recipients"):
        for label, val in abuse["recipients"]:
            print(f"  - {label}: {val}")
    else:
        print("  (no abuse contacts were discovered in this scan)")
    if category == "csam":
        print("  ! CSAM must go to a hotline + law enforcement, not the registrar alone:")
        print("      UK: https://report.iwf.org.uk/     US: https://report.cybertip.org/")
        print("      Do not download, store, or forward the material.")
    if out_path:
        print(f"\n(email body also written to {out_path})")
    print(line + "\n")
