"""End-to-end: decode plus inspect, and the honesty ceiling."""

import os
from datetime import datetime, timezone

from signet.core.inspect import analyze

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
# five minutes after the samples' issue time, so the good token is still live
NOW = datetime(2026, 10, 2, 12, 5, 0, tzinfo=timezone.utc)


def _sample(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def _titles(tok):
    return {f.title for f in tok.findings}


def test_good_token_grades_top():
    tok = analyze(_sample("good-access-token.jwt"), now=NOW)
    assert tok.grade.letter == "A+"
    assert "does not verify the signature" in tok.grade.ceiling_note


def test_alg_none_is_F():
    tok = analyze(_sample("alg-none.jwt"), now=NOW)
    assert tok.grade.letter == "F"
    assert "Unsigned token (alg \"none\")" in _titles(tok)
    assert "forge" in tok.grade.headline.lower()


def test_secret_in_claims_capped_and_flagged():
    tok = analyze(_sample("secret-in-claims.jwt"), now=NOW)
    assert tok.grade.letter in ("F", "D-", "D")
    assert "A secret is sitting in the open" in _titles(tok)


def test_session_with_pii_is_mid_grade():
    tok = analyze(_sample("session-with-pii.jwt"), now=NOW)
    assert tok.grade.letter[0] in ("C", "D", "B")
    assert "Personal data is readable in the token" in _titles(tok)


def test_currently_valid_vs_expired():
    tok = analyze(_sample("good-access-token.jwt"), now=NOW)
    assert "Currently within its validity window" in _titles(tok)
    later = datetime(2026, 10, 2, 13, 0, 0, tzinfo=timezone.utc)
    tok2 = analyze(_sample("good-access-token.jwt"), now=later)
    assert "Already expired" in _titles(tok2)


def test_never_says_safe():
    for name in ("good-access-token.jwt", "alg-none.jwt",
                 "secret-in-claims.jwt", "session-with-pii.jwt"):
        tok = analyze(_sample(name), now=NOW)
        assert "safe" not in tok.grade.headline.lower()
        assert "not whether it is genuine" in tok.grade.ceiling_note


def test_findings_sorted_most_severe_first():
    tok = analyze(_sample("secret-in-claims.jwt"), now=NOW)
    ranks = [f.severity.rank for f in tok.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_jwe_handled():
    tok = analyze("a.b.c.d.e", now=NOW)
    assert tok.grade is not None
    assert "Encrypted" in tok.grade.headline or "Encrypted token (JWE)" in _titles(tok)


def test_malformed_handled():
    tok = analyze("not a token", now=NOW)
    assert tok.grade.letter == "F"
    assert "Not a token" in tok.grade.headline


def test_no_expiry_flagged():
    tok = analyze(_sample("secret-in-claims.jwt"), now=NOW)
    assert "No expiry (exp)" in _titles(tok)


def test_asymmetric_is_good_signal():
    tok = analyze(_sample("good-access-token.jwt"), now=NOW)
    assert any("Asymmetric signature" in t for t in _titles(tok))
