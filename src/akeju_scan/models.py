# Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
# Akeju Domain Scanner, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    FAIL = "fail"
    WARN = "warn"
    UNKNOWN = "unknown"
    PASS = "pass"


ORDER = [Status.FAIL, Status.WARN, Status.UNKNOWN, Status.PASS]


@dataclass(frozen=True)
class Finding:
    area: str
    status: Status
    title: str
    meaning: str
    fix: str = ""


class CheckFailed(Exception):
    """A network lookup could not finish, so the result is unknown rather than bad."""
