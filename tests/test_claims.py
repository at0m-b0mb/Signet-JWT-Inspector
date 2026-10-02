"""Interpreting claims: times, durations, exposure."""

from datetime import datetime, timezone

from signet.core.claims import (
    humanize_delta,
    humanize_duration,
    pii_claims,
    read_time_claims,
    sensitive_claims,
)
from signet.core.model import Token

NOW = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)


def test_read_time_claims():
    tok = Token(payload={"iat": 1790985600, "exp": 1790985600 + 900})
    read_time_claims(tok)
    assert "iat" in tok.times and tok.times["iat"].when is not None
    assert tok.lifetime_seconds == 900


def test_invalid_time_claim_marked():
    tok = Token(payload={"exp": "not-a-number"})
    read_time_claims(tok)
    assert tok.times["exp"].valid is False
    assert tok.times["exp"].when is None


def test_humanize_delta_future_and_past():
    future = datetime(2026, 10, 2, 14, 0, 0, tzinfo=timezone.utc)
    past = datetime(2026, 10, 2, 10, 0, 0, tzinfo=timezone.utc)
    assert humanize_delta(future, NOW).startswith("in ")
    assert humanize_delta(past, NOW).endswith(" ago")
    assert "2 hours" in humanize_delta(future, NOW)


def test_humanize_duration():
    assert humanize_duration(900) == "15m"
    assert humanize_duration(3600) == "1.0h"
    assert "days" in humanize_duration(86400 * 7)


def test_sensitive_claims_detected():
    hits = sensitive_claims({"sub": "x", "password": "p", "api_key": "k"})
    assert "password" in hits and "api_key" in hits
    assert "sub" not in hits


def test_pii_claims_detected():
    hits = pii_claims({"sub": "x", "email": "a@b.c", "phone": "123"})
    assert set(hits) == {"email", "phone"}


def test_benign_claims_are_clean():
    assert sensitive_claims({"sub": "x", "role": "user", "scope": "read"}) == []
    assert pii_claims({"sub": "x", "role": "user"}) == []
