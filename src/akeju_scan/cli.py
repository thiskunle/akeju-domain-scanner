# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import pathlib
import re
import sys

from . import ATTRIBUTION, exposure, mail, report, tls, web
from .models import Status

_DOMAIN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def valid_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not _DOMAIN.match(domain) or domain.replace(".", "").isdigit():
        raise argparse.ArgumentTypeError(f"{value!r} is not a domain name. Use a form like example.com.")
    return domain


def scan(domain: str, active: bool) -> list:
    findings = mail.run(domain) + tls.run(domain)
    findings.append(web.check_redirect(domain))
    findings += web.check_headers(f"https://{domain}/")
    if active:
        findings += exposure.run(f"https://{domain}/")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="akeju-scan", description=f"Plain-English security check for a domain you own. {ATTRIBUTION}.")
    parser.add_argument("domain", type=valid_domain)
    parser.add_argument("--format", choices=report.RENDER, default="text")
    parser.add_argument("--output", type=pathlib.Path, help="write the report to this file")
    parser.add_argument("--i-own-this-domain", action="store_true", dest="owned",
                        help="also request well-known sensitive paths; use only on domains you own or may test")
    parser.add_argument("--version", action="version", version=ATTRIBUTION)
    args = parser.parse_args(argv)

    findings = scan(args.domain, args.owned)
    text = report.RENDER[args.format](args.domain, findings, args.owned)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 1 if any(f.status is Status.FAIL for f in findings) else 0
