"""
Reading the claims.

The registered claims — ``exp``, ``nbf``, ``iat`` — are NumericDates, seconds
since the epoch, so this module turns them into real moments and offers the
human phrasing the interface and the CLI both want ("expires in 2 days",
"issued 5 minutes ago"). It also knows which claim names tend to carry things
that should never ride inside a readable token.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .model import TimeClaim, Token

_TIME_CLAIMS = ("exp", "nbf", "iat")

# Registered claims, for labelling the ones a reader will recognise.
REGISTERED = {
    "iss": "Issuer",
    "sub": "Subject",
    "aud": "Audience",
    "exp": "Expires",
    "nbf": "Not before",
    "iat": "Issued at",
    "jti": "JWT ID",
}

# Claim names whose *presence* suggests a secret or personal datum has been put
# somewhere the whole world can read. Matched case-insensitively as substrings.
SENSITIVE_HINTS = (
    "password", "passwd", "secret", "api_key", "apikey", "private_key",
    "privatekey", "access_key", "client_secret", "ssn", "social_security",
    "credit_card", "creditcard", "card_number", "cvv", "pin",
)

# Softer personal-data hints — worth a gentler note, not an alert.
PII_HINTS = ("email", "phone", "mobile", "address", "dob", "birth",
             "full_name", "firstname", "lastname")


def read_time_claims(tok: Token) -> None:
    """Populate ``tok.times`` from the payload's NumericDate claims."""
    for name in _TIME_CLAIMS:
        if name not in tok.payload:
            continue
        raw = tok.payload[name]
        tc = TimeClaim(name=name, raw=raw)
        try:
            tc.when = datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (TypeError, ValueError, OverflowError, OSError):
            tc.valid = False
        tok.times[name] = tc


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def humanize_delta(target: datetime, now: datetime) -> str:
    """"in 2 days" / "5 minutes ago", from *now* to *target*."""
    secs = (target - now).total_seconds()
    future = secs >= 0
    secs = abs(secs)
    if secs < 60:
        span = f"{int(secs)} second{'s' if int(secs) != 1 else ''}"
    elif secs < 3600:
        span = f"{int(secs // 60)} minute{'s' if int(secs // 60) != 1 else ''}"
    elif secs < 86400:
        span = f"{int(secs // 3600)} hour{'s' if int(secs // 3600) != 1 else ''}"
    elif secs < 86400 * 365:
        span = f"{int(secs // 86400)} day{'s' if int(secs // 86400) != 1 else ''}"
    else:
        span = f"{secs / (86400 * 365):.1f} years"
    return f"in {span}" if future else f"{span} ago"


def humanize_duration(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    return f"{seconds / (86400 * 365):.1f} years"


def sensitive_claims(payload: dict) -> list[str]:
    """Claim names that look like a secret has been placed in the open."""
    hits = []
    for key in payload:
        low = str(key).lower()
        if any(h in low for h in SENSITIVE_HINTS):
            hits.append(str(key))
    return hits


def pii_claims(payload: dict) -> list[str]:
    hits = []
    for key in payload:
        low = str(key).lower()
        if any(h in low for h in PII_HINTS):
            hits.append(str(key))
    return hits
