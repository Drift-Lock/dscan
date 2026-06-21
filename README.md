# dscan - Passive domain OSINT specifically for Telegram Bot Sites from a single command. Give it a domain and it pulls together everything reachable from **public** sources - Created by Driftlock.co.uk

**Requirements** Debian 12

- **Registration** — RDAP (modern WHOIS): registrar, **abuse email/phone**, created/updated/expiry, status, DNSSEC.
- **DNS** — A, AAAA, NS, MX, TXT, SOA, CNAME, CAA, reverse PTR, and DNSSEC presence (via dnspython — no `dig` needed).
- **Cloudflare** — detects it three ways (NS, live IP ranges, HTTP headers) and tells you whether it's
  **DNS-only** or **proxied** (origin IP hidden).
- **Hosting & abuse** — for each resolved IP: ASN + AS name (Team Cymru), RIR network, country, and the
  **network abuse contact** (the host you'd report to).
- **HTTP** — status, redirect chain, and fingerprinting headers (server, cf-ray, HSTS, …).
- **TLS** — leaf certificate: subject, issuer, SANs, validity window, SHA-256 (fetched even if invalid).
- **Change tracking** — every scan is snapshotted locally and diffed against the previous one, so
  re-running shows **DNS / NS / registrar / hosting changes over time**.
- **TLD registry escalation** — the registry operator and contact for the domain's TLD (authoritative,
  from IANA). When a site hides behind Cloudflare, this is who you escalate to *above* the registrar.
- **Abuse-report emails** — pick a category and `dscan` generates a ready-to-send report explaining the
  abuse and the Terms-of-Service / policy breach. The body carries **no addresses**; recipients are
  listed separately so you choose where to send.
- **WhoisFreaks (optional)** — with an API key, adds live WHOIS enrichment and **historical WHOIS**
  (ownership / registrar history over time).
- **Marketplace / shoplist detection** — reads the public page source and flags vendor "shoplist"
  sites: counts Telegram vendor links/handles, spots vendor-card layout + crypto chips + drug-category
  labels, and **lists the vendor handles** (defanged) as reporting evidence.

Everything is read-only and uses only publicly available data — no intrusion, no auth, no scanning of the target.

## Install

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   ·   Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt          # or:  pip install -e .   (adds a `dscan` command)
```

### Deploy on Debian 12

Copy the project to the server and run the installer as root — it installs to `/opt/dscan`,
builds a venv, and puts a `dscan` command on `PATH` (system-wide):

```bash
# on the server, from inside the copied project:
sudo bash deploy.sh

# to seed the WhoisFreaks key at install time (written to root-only /etc/dscan.env):
export WHOISFREAKS_API_KEY=xxxx
sudo -E bash deploy.sh
```

The `dscan` launcher auto-loads `WHOISFREAKS_API_KEY` from `/etc/dscan.env` (root) or
`~/.config/dscan.env` (per-user, `chmod 600`). Re-run `deploy.sh` to update; your env file is kept.

## Usage

```bash
python -m dscan example.com
python -m dscan "example[.]com"          # defanged input is accepted
python -m dscan example.com --json       # machine-readable, for piping / jq
python -m dscan example.com --resolver 9.9.9.9
python -m dscan example.com --raw-whois  # also append raw WHOIS (needs system `whois`)
python -m dscan example.com --no-tls --no-http

python -m dscan --list-categories             # show abuse-report categories
python -m dscan darkbazaar.xyz --report drugs # scan + generate an abuse-report email
python -m dscan darkbazaar.xyz --html-file saved.html   # analyse a saved page (cloaked live fetch)
python -m dscan shop.example --report fraud --report-out report.txt \
                --from-name "Driftlock" --from-contact "abuse@drift-lock.co.uk"

# WhoisFreaks (key from env or flag); --wf-history adds historical WHOIS
export WHOISFREAKS_API_KEY=...                # Windows: setx WHOISFREAKS_API_KEY "..."
python -m dscan example.com --wf-history
```

If installed with `pip install -e .`, drop the `python -m` and just run `dscan example.com`.

### Options

| Flag | Purpose |
|---|---|
| `--json` | Emit JSON instead of the formatted report. |
| `--resolver IP` | DNS resolver to use (repeatable). Default `1.1.1.1` + `8.8.8.8`. |
| `--timeout N` | Per-request timeout, seconds (default 8). |
| `--no-http` / `--no-tls` | Skip the HTTP / TLS stages. |
| `--no-content` | Skip the page-content marketplace / shoplist analysis. |
| `--html-file PATH` | Analyse marketplace indicators from a **saved HTML file** instead of fetching live (use when the live page is cloaked / behind an anti-bot wall). |
| `--raw-whois` | Append raw WHOIS text (requires the `whois` binary). |
| `--no-history` | Don't read or write the local scan history. |
| `--history-dir PATH` | Where snapshots live (default `~/.dscan/history`). |
| `--report CATEGORY` | Generate an abuse-report email for the category (see `--list-categories`). |
| `--list-categories` | List the report categories with explanations, and exit. |
| `--report-out PATH` | Also write the generated email body to a file. |
| `--from-name` / `--from-contact` | Signature used in the generated email. |
| `--whoisfreaks-key KEY` | Enable WhoisFreaks live WHOIS (or set `WHOISFREAKS_API_KEY`). |
| `--wf-history` | Also fetch historical WHOIS (uses more API credits). |

## Change tracking

Each run writes a small JSON snapshot to `~/.dscan/history/<domain>/`. The next run diffs against the
most recent one and reports added/removed **A / AAAA / NS / MX** records, and changes to **nameservers,
registrar, ASN, and Cloudflare status**. The first scan just records a baseline.

> The built-in history starts from your first scan. For history *before* that, `dscan` integrates
> **WhoisFreaks historical WHOIS** (registrar / ownership changes over time) — see below. True historical
> *passive DNS* (resolution history) still needs a dedicated provider; the collectors are structured to
> add one later.

## Marketplace / shoplist detection

When the domain serves HTML, dscan fetches the page once and scans the **source** (no JS executed,
nothing clicked) for the hallmarks of a Telegram-vendor marketplace:

- more than one **Telegram vendor link / @handle**,
- **vendor-card** layout, crypto **payment chips** (BTC/LTC/XMR), and drug-category labels
  (stimulants, ketamine, cannabis, …).

If it matches, the report shows a verdict (e.g. *"Likely DRUG-VENDOR marketplace / shoplist"*) and
**lists the vendor handles** — shown defanged as `t[.]me/<handle>` so the output isn't a working
directory — plus best-effort vendor display names. This also feeds the abuse-report evidence block.
Disable with `--no-content`. Detection keys off page markup, so heavily obfuscated sites may not match.

The scan fetches with a real browser User-Agent (many shoplists serve a stripped page or an anti-bot
challenge to non-browser clients) and the panel shows a **Fetched** line — final URL, HTTP status, and
byte count — plus the **page title**, so a "no indicators" result is easy to explain: if the byte count
is tiny or the title is a challenge page, you didn't get the real source. In that case save the page
from your browser (right-click → *Save as*, or copy *view-source*) and re-run with
`--html-file page.html` to analyse the markup you actually see. A coy storefront that omits drug-category
words is still flagged when its **vendor handles or names** give it away.
## Abuse reporting

`--list-categories` shows the categories (drugs, phishing, malware, fraud, counterfeit, csam), each with
an explanation. `--report <category>` scans the domain and then prints a ready-to-send email:

- a **clean body** (subject + report text) with the abuse explanation, the evidence gathered during the
  scan, and **why it breaches Terms of Service / registry & registrar policy** — with **no recipient
  addresses in it**;
- a separate **"Where to send"** list of the abuse contacts found (registrar, TLD registry, network), so
  you choose recipients yourself.

When the domain is **proxied by Cloudflare**, the email automatically notes that the host is obscured and
that the **registrar and TLD registry** can act at the registration level — and those are the contacts it
surfaces. `csam` is special-cased to point you at a hotline (IWF / NCMEC) and law enforcement rather than
the registrar. Use `--from-name` / `--from-contact` for the signature and `--report-out` to save the body.

## WhoisFreaks

Set `WHOISFREAKS_API_KEY` (or pass `--whoisfreaks-key`). With a key, every scan adds a **live WHOIS**
panel (registrar, abuse contact, dates, registrant) that complements RDAP. Add `--wf-history` for a
**historical WHOIS timeline**. Historical calls cost more credits, so they're opt-in. WhoisFreaks field
names vary by plan; the raw response is preserved and shown under `--json` so output can be reconciled
with your account.

## Notes

- `cryptography` is only needed for full certificate parsing; without it the rest still works and TLS
  degrades to version-only.
- Designed to run the same on Windows and Debian. Pairs well with abuse-reporting workflows: defanged
  input is refanged automatically, and `--json` output is easy to attach to a report.
