# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""Exposed-file check. Only runs when the operator confirms they own the domain.

Each path gets one GET request, with a pause between requests. Content is matched to rule out
"soft 404" pages, then discarded: the report names the path and never includes what was in it.
"""
import re
import time
from typing import Callable

from .models import CheckFailed, Finding, Status
from .web import Fetch, fetch

AREA = "Exposed files"
_html = re.compile(rb"^\s*<(!doctype|html)", re.I)


def _not_html(body: bytes) -> bool:
    return bool(body) and not _html.match(body)


SENSITIVE: tuple[tuple[str, str, Callable[[bytes], bool]], ...] = (
    ("/.env", "Environment file, which often holds passwords and API keys", lambda b: bool(re.search(rb"(?m)^[A-Z][A-Z0-9_]*=", b)) and _not_html(b)),
    ("/.git/config", "Git settings, a sign your full source history can be downloaded", lambda b: b"[core]" in b),
    ("/.git/HEAD", "Git metadata, a sign your full source history can be downloaded", lambda b: b.startswith(b"ref: refs/")),
    ("/.htpasswd", "Password file", lambda b: bool(re.search(rb"(?m)^[^:\s]+:\$", b)) and _not_html(b)),
    ("/backup.sql", "Database backup", lambda b: bool(re.search(rb"(?i)(create table|insert into)", b)) and _not_html(b)),
    ("/backup.zip", "Backup archive", lambda b: b.startswith(b"PK\x03\x04")),
    ("/wp-config.php.bak", "WordPress settings backup, which holds the database password", lambda b: b"DB_PASSWORD" in b),
)


def run(base_url: str, get: Fetch = fetch, pause: float = 0.25) -> list[Finding]:
    exposed, incomplete = [], False
    for path, what, matches in SENSITIVE:
        try:
            response = get(base_url.rstrip("/") + path)
        except CheckFailed:
            incomplete = True
            continue
        if response.status == 200 and matches(response.body):
            exposed.append(Finding(AREA, Status.FAIL, f"{path} is publicly readable", what + ".",
                                   "Remove it from the web root or block it, then change any secrets it held."))
        time.sleep(pause)
    if exposed:
        return exposed
    if incomplete:
        return [Finding(AREA, Status.UNKNOWN, "Exposed-file check did not finish", "Some paths could not be reached.")]
    return [Finding(AREA, Status.PASS, "No common sensitive files found", f"{len(SENSITIVE)} well-known paths were checked.")]
