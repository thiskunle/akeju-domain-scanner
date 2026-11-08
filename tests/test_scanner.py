# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import json
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from akeju_scan import cli, exposure, mail, report, tls, web
from akeju_scan.models import CheckFailed, Finding, Status
from akeju_scan.web import Response


def dns(records):
    return lambda name, rdtype: records.get((name, rdtype), [])


@pytest.mark.parametrize("record,status", [
    ("v=spf1 include:_spf.google.com ~all", Status.PASS),
    ("v=spf1 -all", Status.PASS),
    ("v=spf1 +all", Status.FAIL),
    ("v=spf1 all", Status.FAIL),
    ("v=spf1 include:x.com ?all", Status.WARN),
    ("v=spf1 include:x.com", Status.WARN),
    ("v=spf1 " + " ".join(f"include:s{i}.com" for i in range(11)) + " ~all", Status.WARN),
])
def test_spf(record, status):
    assert mail.check_spf("a.com", dns({("a.com", "TXT"): [record]})).status is status


def test_spf_missing_and_duplicate():
    assert mail.check_spf("a.com", dns({})).status is Status.FAIL
    twice = dns({("a.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]})
    assert "More than one" in mail.check_spf("a.com", twice).title


@pytest.mark.parametrize("record,status", [
    ("v=DMARC1; p=reject", Status.PASS), ("v=DMARC1; p=quarantine; rua=mailto:a@b.c", Status.PASS),
    ("v=DMARC1; p=none", Status.WARN), ("v=DMARC1; sp=none", Status.FAIL),
])
def test_dmarc(record, status):
    assert mail.check_dmarc("a.com", dns({("_dmarc.a.com", "TXT"): [record]})).status is status


def test_dkim_found_and_unconfirmed():
    assert mail.check_dkim("a.com", dns({("google._domainkey.a.com", "TXT"): ["v=DKIM1; p=abc"]})).status is Status.PASS
    assert mail.check_dkim("a.com", dns({})).status is Status.WARN


def test_dns_failure_is_unknown_not_a_bad_grade():
    def broken(name, rdtype):
        raise CheckFailed("DNS lookup failed")
    assert {f.status for f in mail.run("a.com", broken)} == {Status.UNKNOWN}


NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)


@pytest.mark.parametrize("days,status", [(90, Status.PASS), (20, Status.WARN), (5, Status.FAIL)])
def test_certificate_expiry(days, status):
    info = tls.TlsInfo("TLSv1.3", NOW + timedelta(days=days, hours=1))
    assert tls.run("a.com", lambda h: info, NOW)[0].status is status


def test_old_protocol_fails():
    info = tls.TlsInfo("TLSv1.1", NOW + timedelta(days=90))
    assert tls.run("a.com", lambda h: info, NOW)[1].status is Status.FAIL


def test_untrusted_certificate_fails():
    def bad(host):
        err = ssl.SSLCertVerificationError("bad")
        err.verify_message = "certificate has expired"
        raise err
    assert tls.run("a.com", bad, NOW)[0].status is Status.FAIL


def test_connection_error_is_unknown():
    def down(host):
        raise ConnectionRefusedError("refused")
    assert tls.run("a.com", down, NOW)[0].status is Status.UNKNOWN


def test_headers_missing_are_warned():
    findings = web.check_headers("https://a.com/", lambda u: Response(200, {}, b""))
    assert len(findings) == 5 and all(f.status is Status.WARN for f in findings)


def test_headers_follow_redirect_and_pass():
    good = {"strict-transport-security": "max-age=1", "content-security-policy": "frame-ancestors 'none'",
            "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}
    pages = {"https://a.com/": Response(301, {"location": "/home"}, b""), "https://a.com/home": Response(200, good, b"")}
    assert all(f.status is Status.PASS for f in web.check_headers("https://a.com/", pages.__getitem__))


def test_redirect_loop_is_unknown():
    loop = lambda u: Response(302, {"location": u}, b"")
    assert web.check_headers("https://a.com/", loop)[0].status is Status.UNKNOWN


def test_server_version_is_flagged():
    findings = web.check_headers("https://a.com/", lambda u: Response(200, {"server": "nginx/1.18.0"}, b""))
    assert any("version" in f.title for f in findings)


def test_http_redirect():
    ok = lambda u: Response(301, {"location": "https://a.com/"}, b"")
    no = lambda u: Response(200, {}, b"")
    assert web.check_redirect("a.com", ok).status is Status.PASS
    assert web.check_redirect("a.com", no).status is Status.FAIL


def serve(files):
    return lambda url: files.get(url.removeprefix("https://a.com"), Response(404, {}, b"nope"))


def test_exposed_env_reported_without_contents():
    files = {"/.env": Response(200, {}, b"DB_PASSWORD=hunter2\n")}
    findings = exposure.run("https://a.com/", serve(files), pause=0)
    assert [f.title for f in findings] == ["/.env is publicly readable"]
    assert "hunter2" not in report.to_text("a.com", findings, True)


def test_soft_404_page_is_not_a_finding():
    page = Response(200, {}, b"<!doctype html><title>Not found</title>A=1")
    files = {p: page for p, _, _ in exposure.SENSITIVE}
    assert exposure.run("https://a.com/", serve(files), pause=0)[0].status is Status.PASS


def test_incomplete_exposure_check_is_unknown():
    def down(url):
        raise CheckFailed("down")
    assert exposure.run("https://a.com/", down, pause=0)[0].status is Status.UNKNOWN


@pytest.mark.parametrize("good", ["example.com", "EXAMPLE.com.", "a-b.co.uk"])
def test_valid_domains(good):
    assert cli.valid_domain(good) == good.lower().rstrip(".")


@pytest.mark.parametrize("bad", ["https://a.com", "localhost", "127.0.0.1", "a.com/x", "-a.com", "a b.com", ""])
def test_invalid_domains(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.valid_domain(bad)


def test_exposure_check_needs_confirmation(monkeypatch):
    called = []
    monkeypatch.setattr(cli.mail, "run", lambda d: [])
    monkeypatch.setattr(cli.tls, "run", lambda d: [])
    monkeypatch.setattr(cli.web, "check_redirect", lambda d: Finding("x", Status.PASS, "t", "m"))
    monkeypatch.setattr(cli.web, "check_headers", lambda u: [])
    monkeypatch.setattr(cli.exposure, "run", lambda u: called.append(u) or [])
    assert cli.main(["example.com"]) == 0 and not called
    assert cli.main(["example.com", "--i-own-this-domain"]) == 0 and called


def test_reports_carry_author_attribution():
    f = [Finding("Email spoofing", Status.FAIL, "No SPF record", "m", "fix")]
    assert "Adekunle Akeju" in report.to_text("a.com", f, False)
    assert "Adekunle Akeju" in report.to_markdown("a.com", f, False)
    assert json.loads(report.to_json("a.com", f, False))["generator"]["author"] == "Adekunle Akeju"


def test_failures_set_exit_code(monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda d, a: [Finding("x", Status.FAIL, "t", "m")])
    assert cli.main(["example.com", "--format", "json"]) == 1
