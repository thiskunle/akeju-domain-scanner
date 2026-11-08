# akeju-domain-scanner

**Created by Adekunle Akeju, founder of GramByte Technologies Inc.**

A security check for a domain you own, with a report a business owner can read. It tells you what is wrong, why it matters, and how to fix it.

## What it checks

| Area | Checks | How |
|---|---|---|
| Email spoofing | SPF, DMARC, DKIM at common names | DNS only |
| HTTPS | Certificate trust and expiry, TLS version, HTTP redirect | One connection |
| Website headers | HSTS, CSP, clickjacking, MIME sniffing, referrer, server version | Home page only |
| Exposed files | `.env`, `.git`, backups, password files | Only with `--i-own-this-domain` |

## Use it

```
pip install .
akeju-scan example.com
akeju-scan example.com --format markdown --output report.md
akeju-scan example.com --i-own-this-domain
```

The exit code is `1` if anything needs fixing now, so it can run in CI.

## Scan only what you own

Without the flag the tool only reads public DNS, the certificate and the home page. `--i-own-this-domain` adds a few requests for well-known sensitive paths, so use it only on domains you own or have written permission to test. Requests identify the tool in their User-Agent. The report names any exposed path and never stores the file's contents.

This is a quick outside-in check, not a full audit. A clean result does not prove a site is secure.

## Roadmap

- [x] 0.1: email, HTTPS, headers, exposed files, text, Markdown and JSON reports
- [ ] 0.2: HTML report with GramByte branding
- [ ] 0.3: compare two scans and show what changed
- [ ] 0.4: scheduled monitoring with alerts

## Test it

```
pip install -e ".[dev]"
pytest
```

## License and credit

AGPL-3.0-or-later, with an attribution requirement. See [NOTICE.md](NOTICE.md). Copyright (c) 2026 Adekunle Akeju.
