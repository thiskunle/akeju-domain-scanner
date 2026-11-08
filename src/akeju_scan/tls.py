# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTPS certificate and protocol version."""
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .models import Finding, Status

AREA = "HTTPS"


@dataclass(frozen=True)
class TlsInfo:
    version: str
    not_after: datetime


def probe(host: str, port: int = 443, timeout: float = 8) -> TlsInfo:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as conn:
            cert = conn.getpeercert()
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
            return TlsInfo(conn.version() or "unknown", expires)


def run(host: str, connect: Callable[[str], TlsInfo] = probe, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    try:
        info = connect(host)
    except ssl.SSLCertVerificationError as exc:
        return [Finding(AREA, Status.FAIL, "HTTPS certificate is not trusted",
                        f"Browsers will warn visitors: {exc.verify_message}.",
                        "Install a valid certificate that covers this domain and renew it automatically.")]
    except OSError as exc:
        return [Finding(AREA, Status.UNKNOWN, "Could not connect over HTTPS", f"The connection failed: {exc}.")]

    days = (info.not_after - now).days
    findings = []
    if days < 14:
        findings.append(Finding(AREA, Status.FAIL, f"Certificate expires in {days} days",
                                "Visitors will see a security warning once it expires.", "Renew now and check that auto-renewal works."))
    elif days < 30:
        findings.append(Finding(AREA, Status.WARN, f"Certificate expires in {days} days",
                                "Most certificates renew automatically by now.", "Confirm that auto-renewal is working."))
    else:
        findings.append(Finding(AREA, Status.PASS, f"Certificate is valid for {days} more days", "Visitors get a trusted connection."))

    if info.version in ("TLSv1.3", "TLSv1.2"):
        findings.append(Finding(AREA, Status.PASS, f"Modern encryption ({info.version})", "The connection uses a current protocol."))
    else:
        findings.append(Finding(AREA, Status.FAIL, f"Outdated encryption ({info.version})",
                                "This protocol version has known weaknesses.", "Enable TLS 1.2 or 1.3 and turn off older versions."))
    return findings
