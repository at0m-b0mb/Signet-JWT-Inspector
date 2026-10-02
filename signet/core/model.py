"""
The shapes the inspection produces.

A JSON Web Token is three base64url parts — a header, a payload of claims, and a
signature — joined by dots. Signet reads the first two (anyone can; they are not
encrypted) and reports on the third without ever verifying it. These dataclasses
are the nouns that result: the decoded token, each claim read into something a
person can judge, and the findings and grade built on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    GOOD = "good"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ALERT = "alert"

    @property
    def rank(self) -> int:
        return {
            Severity.GOOD: 0, Severity.INFO: 1, Severity.NOTICE: 2,
            Severity.WARNING: 3, Severity.ALERT: 4,
        }[self]


class TokenKind(Enum):
    JWS = "jws"          # signed — the ordinary three-part token
    JWE = "jwe"          # encrypted — five parts, claims not readable
    UNSIGNED = "unsigned"  # alg "none", or an empty signature
    MALFORMED = "malformed"


@dataclass
class TimeClaim:
    """A NumericDate claim (``exp``, ``nbf``, ``iat``) read as a moment."""

    name: str
    raw: Any
    when: Optional[datetime] = None
    valid: bool = True       # did it parse as a number at all?


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    points: int = 0
    category: str = "general"


@dataclass
class Grade:
    letter: str
    score: int
    headline: str
    ceiling_note: str


@dataclass
class Token:
    kind: TokenKind = TokenKind.MALFORMED
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    signature_b64: str = ""
    signature_bytes: int = 0
    parts: int = 0

    alg: str = ""
    typ: str = ""
    kid: str = ""

    times: dict[str, TimeClaim] = field(default_factory=dict)  # exp / nbf / iat

    findings: list[Finding] = field(default_factory=list)
    grade: Optional[Grade] = None
    notes: list[str] = field(default_factory=list)

    # --- derived -----------------------------------------------------------
    @property
    def lifetime_seconds(self) -> Optional[float]:
        iat = self.times.get("iat")
        exp = self.times.get("exp")
        if iat and exp and iat.when and exp.when:
            return (exp.when - iat.when).total_seconds()
        return None

    def expired(self, now: datetime) -> Optional[bool]:
        exp = self.times.get("exp")
        if exp and exp.when:
            return now >= exp.when
        return None

    def not_yet_valid(self, now: datetime) -> Optional[bool]:
        nbf = self.times.get("nbf")
        if nbf and nbf.when:
            return now < nbf.when
        return None
