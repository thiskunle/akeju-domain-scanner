# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Turn findings into a report a business owner can read."""
import json
from dataclasses import asdict

from . import ATTRIBUTION, __author__, __version__
from .models import ORDER, Finding, Status

LABEL = {Status.FAIL: "Fix now", Status.WARN: "Improve", Status.UNKNOWN: "Could not check", Status.PASS: "Good"}
HELP = "Need help fixing these? GramByte Technologies Inc., info@grambyte.ca"


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: ORDER.index(f.status))


def summary(findings: list[Finding]) -> str:
    fails = sum(f.status is Status.FAIL for f in findings)
    warns = sum(f.status is Status.WARN for f in findings)
    if fails:
        return f"{fails} problem(s) to fix now and {warns} to improve."
    if warns:
        return f"No urgent problems, and {warns} thing(s) to improve."
    return "No problems found in the areas checked."


def to_text(domain: str, findings: list[Finding], active: bool) -> str:
    lines = [f"Security report for {domain}", summary(findings), ""]
    for f in _sorted(findings):
        lines.append(f"[{LABEL[f.status]}] {f.area}: {f.title}")
        lines.append(f"    {f.meaning}")
        if f.fix:
            lines.append(f"    Fix: {f.fix}")
    lines += ["", _scope(active), "", HELP, ATTRIBUTION]
    return "\n".join(lines) + "\n"


def to_markdown(domain: str, findings: list[Finding], active: bool) -> str:
    lines = [f"# Security report for {domain}", "", f"**{summary(findings)}**", ""]
    for status in ORDER:
        group = [f for f in findings if f.status is status]
        if group:
            lines += [f"## {LABEL[status]}", ""]
            for f in group:
                lines.append(f"- **{f.area}: {f.title}.** {f.meaning}" + (f" *Fix:* {f.fix}" if f.fix else ""))
            lines.append("")
    lines += [_scope(active), "", HELP, "", f"*{ATTRIBUTION}*"]
    return "\n".join(lines) + "\n"


def to_json(domain: str, findings: list[Finding], active: bool) -> str:
    return json.dumps({
        "domain": domain, "summary": summary(findings), "exposed_file_check": active,
        "findings": [{**asdict(f), "status": f.status.value} for f in _sorted(findings)],
        "generator": {"name": "akeju-domain-scanner", "version": __version__, "author": __author__},
    }, indent=2) + "\n"


def _scope(active: bool) -> str:
    note = "This is a quick outside-in check, not a full security audit."
    return note if active else note + " The exposed-file check was skipped; add --i-own-this-domain to run it."


RENDER = {"text": to_text, "markdown": to_markdown, "json": to_json}
