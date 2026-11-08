# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Email spoofing protection: SPF, DMARC and DKIM."""
import re
from typing import Callable

from .models import CheckFailed, Finding, Status

Lookup = Callable[[str, str], list[str]]
AREA = "Email spoofing"
DKIM_SELECTORS = ("google", "default", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2")
SPF_LOOKUP_TERMS = re.compile(r"(?:^|\s)[+\-~?]?(include:|a\b|mx\b|ptr\b|exists:|redirect=)", re.I)


def dns_lookup(name: str, rdtype: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=8)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        raise CheckFailed(f"DNS lookup for {name} failed") from exc
    if rdtype == "TXT":
        return ["".join(part.decode("utf-8", "replace") for part in r.strings) for r in answers]
    return [r.to_text() for r in answers]


def check_spf(domain: str, lookup: Lookup) -> Finding:
    records = [r for r in lookup(domain, "TXT") if r.lower().startswith("v=spf1")]
    if not records:
        return Finding(AREA, Status.FAIL, "No SPF record",
                       "Nothing tells other mail servers who may send email as your domain, which makes it easier to forge.",
                       "Publish a TXT record listing your mail provider and ending in -all or ~all.")
    if len(records) > 1:
        return Finding(AREA, Status.FAIL, "More than one SPF record",
                       "Having two SPF records makes the check fail, so your protection does not work.",
                       "Merge them into a single TXT record.")
    record = records[0]
    terms = record.lower().split()
    final = next((t for t in terms if t.endswith("all") and t.lstrip("+-~?") == "all"), None)
    if final in ("all", "+all"):
        return Finding(AREA, Status.FAIL, "SPF allows anyone to send",
                       "Your record ends in +all, which approves every server on the internet.",
                       "Change the ending to -all or ~all.")
    if final in (None, "?all"):
        return Finding(AREA, Status.WARN, "SPF does not reject unknown senders",
                       "Your record never says what to do with servers it does not list.",
                       "End the record with -all or ~all.")
    if len(SPF_LOOKUP_TERMS.findall(record)) > 10:
        return Finding(AREA, Status.WARN, "SPF has too many lookups",
                       "SPF stops working after 10 DNS lookups, and this record uses more than that.",
                       "Remove services you no longer use.")
    return Finding(AREA, Status.PASS, f"SPF is set ({final})", "Other mail servers can tell who may send as your domain.")


def check_dmarc(domain: str, lookup: Lookup) -> Finding:
    records = [r for r in lookup(f"_dmarc.{domain}", "TXT") if r.lower().startswith("v=dmarc1")]
    if not records:
        return Finding(AREA, Status.FAIL, "No DMARC record",
                       "Receiving servers have no instruction for handling email that fakes your domain.",
                       'Publish a TXT record at _dmarc, starting with "v=DMARC1; p=none; rua=mailto:you@yourdomain", then tighten it.')
    tags = dict(p.strip().split("=", 1) for p in records[0].split(";") if "=" in p)
    policy = {k.lower(): v.strip().lower() for k, v in tags.items()}.get("p", "")
    if policy == "none":
        return Finding(AREA, Status.WARN, "DMARC only monitors",
                       "Forged email is reported but still delivered, because the policy is p=none.",
                       "After checking your reports, move to p=quarantine and then p=reject.")
    if policy in ("quarantine", "reject"):
        return Finding(AREA, Status.PASS, f"DMARC is enforced (p={policy})", "Forged email is filtered or refused.")
    return Finding(AREA, Status.FAIL, "DMARC policy is invalid", "The record has no usable p= value, so it is ignored.",
                   "Set p=none, p=quarantine or p=reject.")


def check_dkim(domain: str, lookup: Lookup) -> Finding:
    found = [s for s in DKIM_SELECTORS if any("p=" in r.lower() for r in lookup(f"{s}._domainkey.{domain}", "TXT"))]
    if found:
        return Finding(AREA, Status.PASS, f"DKIM key found ({', '.join(found)})", "Your mail can carry a signature proving it was not altered.")
    return Finding(AREA, Status.WARN, "No DKIM key at common names",
                   "DKIM key names cannot be listed from outside, so yours may simply use an uncommon name.",
                   "In your mail provider's admin panel, confirm DKIM signing is turned on.")


def run(domain: str, lookup: Lookup = dns_lookup) -> list[Finding]:
    findings = []
    for check in (check_spf, check_dmarc, check_dkim):
        try:
            findings.append(check(domain, lookup))
        except CheckFailed as exc:
            findings.append(Finding(AREA, Status.UNKNOWN, f"Could not finish {check.__name__.removeprefix('check_').upper()} check", str(exc)))
    return findings
