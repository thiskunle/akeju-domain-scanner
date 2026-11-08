# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP fetch helper and website security header checks."""
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable

from . import USER_AGENT
from .models import CheckFailed, Finding, Status

AREA = "Website headers"
MAX_BODY = 64 * 1024


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


Fetch = Callable[[str], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def fetch(url: str, timeout: float = 10) -> Response:
    """One GET request. Redirects are returned, not followed. Only reads the first 64 KB."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with _opener.open(request, timeout=timeout) as r:
            return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_BODY))
    except urllib.error.HTTPError as r:
        return Response(r.code, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_BODY))
    except (urllib.error.URLError, OSError) as exc:
        raise CheckFailed(f"Could not reach {url}") from exc


def follow(url: str, get: Fetch, limit: int = 5) -> Response:
    for _ in range(limit):
        response = get(url)
        location = response.headers.get("location")
        if response.status not in (301, 302, 303, 307, 308) or not location:
            return response
        url = urllib.parse.urljoin(url, location)
        if not url.startswith(("http://", "https://")):
            break
    raise CheckFailed("The site redirected too many times")


REQUIRED = (
    ("strict-transport-security", "HSTS is missing", "Browsers may try an unencrypted connection first.",
     "Send Strict-Transport-Security: max-age=31536000."),
    ("content-security-policy", "No Content-Security-Policy", "If a script is ever injected, the browser has no rules to stop it.",
     "Add a Content-Security-Policy, starting with report-only mode."),
    ("x-content-type-options", "X-Content-Type-Options is missing", "Browsers may guess a file's type and run it as code.",
     "Send X-Content-Type-Options: nosniff."),
    ("referrer-policy", "No Referrer-Policy", "Full page addresses can leak to other sites.",
     "Send Referrer-Policy: strict-origin-when-cross-origin."),
)


def check_headers(base_url: str, get: Fetch = fetch) -> list[Finding]:
    try:
        response = follow(base_url, get)
    except CheckFailed as exc:
        return [Finding(AREA, Status.UNKNOWN, "Could not read the home page", str(exc))]

    h = response.headers
    findings = []
    for name, title, meaning, fix in REQUIRED:
        if name in h:
            findings.append(Finding(AREA, Status.PASS, f"{name} is set", "This browser protection is on."))
        else:
            findings.append(Finding(AREA, Status.WARN, title, meaning, fix))

    if "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", ""):
        findings.append(Finding(AREA, Status.PASS, "Clickjacking protection is set", "Other sites cannot secretly frame your pages."))
    else:
        findings.append(Finding(AREA, Status.WARN, "No clickjacking protection", "Another site could load your pages in a hidden frame.",
                                "Send X-Frame-Options: DENY, or use frame-ancestors in your CSP."))

    server = h.get("server", "")
    if any(c.isdigit() for c in server):
        findings.append(Finding(AREA, Status.WARN, f"Server version is visible ({server})", "This tells attackers exactly which flaws to try.",
                                "Hide the version in your server settings."))
    return findings


def check_redirect(domain: str, get: Fetch = fetch) -> Finding:
    try:
        response = get(f"http://{domain}/")
    except CheckFailed as exc:
        return Finding("HTTPS", Status.UNKNOWN, "Could not test the HTTP redirect", str(exc))
    if response.status in (301, 302, 307, 308) and response.headers.get("location", "").startswith("https://"):
        return Finding("HTTPS", Status.PASS, "HTTP redirects to HTTPS", "Visitors end up on the encrypted site.")
    return Finding("HTTPS", Status.FAIL, "HTTP does not redirect to HTTPS", "Visitors can stay on an unencrypted connection.",
                   "Turn on a permanent redirect to HTTPS.")
