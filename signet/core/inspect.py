"""
The judgement — findings first, then a letter.

Signet reads a decoded token and reports what its structure and contents expose:
a dangerous algorithm, a missing or distant expiry, a secret sitting in the
open. Two principles, shared with the rest of this catalogue:

* **Honesty ceiling.** Signet never verifies the signature — that needs the key
  — and cannot know how a server validates the token. A high grade means the
  token is well-formed and discloses little, not that it is genuine or will be
  accepted. The ceiling note says so on every result.
* **Exposure is the subject.** A JWT is signed, not encrypted; every claim is
  readable by anyone who holds the token. So the gravest findings are the ones
  that put a secret or a person's data where everyone can see it.
"""

from __future__ import annotations

from datetime import datetime

from .claims import (
    humanize_delta,
    humanize_duration,
    now_utc,
    pii_claims,
    read_time_claims,
    sensitive_claims,
)
from .model import Finding, Grade, Severity, Token, TokenKind

_ASYMMETRIC = {"rs256", "rs384", "rs512", "es256", "es384", "es512",
               "ps256", "ps384", "ps512", "eddsa"}
_SYMMETRIC = {"hs256", "hs384", "hs512"}

_KID_PROBES = ("../", "..\\", "';", '";', " or ", " union ", "select ",
               "/etc/", "\n", "||", "`")

_LETTERS = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]


def _letter_for_score(score: int) -> str:
    bands = [(97, "A+"), (93, "A"), (90, "A-"), (87, "B+"), (83, "B"),
             (80, "B-"), (77, "C+"), (73, "C"), (70, "C-"), (67, "D+"),
             (63, "D"), (60, "D-")]
    for floor, letter in bands:
        if score >= floor:
            return letter
    return "F"


def _cap(letter: str, ceiling: str) -> str:
    return letter if _LETTERS.index(letter) >= _LETTERS.index(ceiling) else ceiling


_CEILING = (
    "Signet decodes a token and reads its claims — a JWT is not encrypted, so "
    "anyone holding it can read every claim. It does not verify the signature "
    "(that needs the key) and cannot know how your server validates the token. "
    "The grade reflects what the token exposes, not whether it is genuine."
)


def inspect(tok: Token, now: datetime | None = None) -> Token:
    """Populate ``tok.findings`` and ``tok.grade``; return the same token."""
    now = now or now_utc()
    read_time_claims(tok)
    findings: list[Finding] = []
    score = 100

    def add(sev, title, detail, pts=0, cat="general"):
        nonlocal score
        findings.append(Finding(sev, title, detail, pts, cat))
        score -= pts

    # --- the tokens Signet cannot grade on exposure -------------------------
    if tok.kind is TokenKind.MALFORMED:
        tok.findings = []
        tok.grade = Grade("F", 0, "Not a token Signet could read", _CEILING)
        return tok

    if tok.kind is TokenKind.JWE:
        add(Severity.GOOD, "Encrypted token (JWE)",
            "This is a JWE: its claims are ciphertext, not readable without the "
            "recipient's key. Good for confidentiality — and the reason Signet "
            "cannot inspect the contents.", 0, "shape")
        tok.findings = findings
        tok.grade = Grade("A", 90, "Encrypted — contents are not exposed", _CEILING)
        return tok

    # --- algorithm ----------------------------------------------------------
    alg = (tok.alg or "").lower()
    if tok.kind is TokenKind.UNSIGNED or alg == "none":
        add(Severity.ALERT, "Unsigned token (alg \"none\")",
            "The header declares no signature algorithm. A server that accepts "
            "this trusts a token anyone can forge by hand — one of the oldest "
            "and most serious JWT flaws.", 70, "alg")
    elif alg in _ASYMMETRIC:
        add(Severity.GOOD, f"Asymmetric signature ({tok.alg})",
            "Signed with a private key and verified with a public one, so a "
            "verifier never holds the secret that could mint tokens.", 0, "alg")
    elif alg in _SYMMETRIC:
        add(Severity.NOTICE, f"Symmetric signature ({tok.alg})",
            "Signed with a shared secret. Every verifier holds a key that can "
            "also create tokens, and HS/RS algorithm confusion is a known "
            "pitfall if the server trusts the header's choice.", 8, "alg")
    else:
        add(Severity.WARNING, "Unrecognised algorithm",
            f"The header's alg is \"{tok.alg or '(absent)'}\", which Signet does "
            f"not recognise. An unexpected algorithm is worth confirming.",
            18, "alg")

    # --- expiry -------------------------------------------------------------
    exp = tok.times.get("exp")
    iat = tok.times.get("iat")
    if exp is None:
        add(Severity.WARNING, "No expiry (exp)",
            "The token sets no expiry, so a copy of it is valid until the key "
            "changes. Short lifetimes limit the damage of a leaked token.",
            22, "exp")
    elif not exp.valid or exp.when is None:
        add(Severity.NOTICE, "Expiry is not a valid date",
            "The exp claim is present but is not a numeric timestamp.", 8, "exp")
    else:
        expired = now >= exp.when
        when = humanize_delta(exp.when, now)
        if expired:
            add(Severity.INFO, "Already expired",
                f"This token expired {when}. A correctly configured server "
                f"would now reject it — a note, not a weakness of the token.",
                0, "exp")
        else:
            add(Severity.INFO, "Currently within its validity window",
                f"The token expires {when}.", 0, "exp")
        life = tok.lifetime_seconds
        if life is not None:
            span = humanize_duration(life)
            if life > 86400 * 30:
                add(Severity.WARNING, "Very long-lived token",
                    f"It is valid for {span} from issue. A leaked long-lived "
                    f"token is useful to an attacker for just as long.",
                    18, "exp")
            elif life > 86400:
                add(Severity.NOTICE, "Long-lived token",
                    f"It is valid for {span}. Many access tokens live minutes, "
                    f"not days.", 8, "exp")
            else:
                add(Severity.GOOD, "Short-lived token",
                    f"Valid for {span} — a small window if it leaks.", 0, "exp")
        elif iat is None:
            add(Severity.INFO, "No issued-at (iat)",
                "Without iat, the token's lifetime cannot be read.", 3, "exp")

    # --- not-before ---------------------------------------------------------
    nbf = tok.times.get("nbf")
    if nbf and nbf.when and now < nbf.when:
        add(Severity.NOTICE, "Not valid yet (nbf)",
            f"The token becomes valid {humanize_delta(nbf.when, now)}; a verifier "
            f"should reject it until then.", 4, "nbf")

    # --- identifying claims -------------------------------------------------
    if "iss" not in tok.payload:
        add(Severity.NOTICE, "No issuer (iss)",
            "Without an issuer, a verifier cannot confirm who minted the token.",
            4, "claims")
    if "aud" not in tok.payload:
        add(Severity.NOTICE, "No audience (aud)",
            "Without an audience, a token meant for one service can be replayed "
            "against another that shares the key.", 4, "claims")

    # --- exposure -----------------------------------------------------------
    secrets = sensitive_claims(tok.payload)
    if secrets:
        shown = ", ".join(secrets[:4])
        add(Severity.ALERT, "A secret is sitting in the open",
            f"The claim(s) {shown} look like a secret. Remember a JWT is only "
            f"base64 — anyone who holds it reads this in full. Secrets do not "
            f"belong in a token.", min(60, 30 * len(secrets)), "exposure")

    pii = pii_claims(tok.payload)
    if pii:
        shown = ", ".join(pii[:5])
        add(Severity.WARNING, "Personal data is readable in the token",
            f"The claim(s) {shown} carry personal data that travels in the clear "
            f"inside the token. Keep tokens to identifiers, not profiles.",
            12, "exposure")

    # --- header hygiene -----------------------------------------------------
    if tok.kid and any(p in tok.kid for p in _KID_PROBES):
        add(Severity.NOTICE, "The kid header looks like an injection probe",
            f"The key id \"{tok.kid}\" contains characters used to escape into a "
            f"path or a query. Worth confirming how the server resolves it.",
            12, "header")
    if tok.typ and tok.typ.lower() not in ("jwt", "at+jwt"):
        add(Severity.INFO, f"Unusual typ header ({tok.typ})",
            "The token type is not the usual JWT; not a problem, just unusual.",
            0, "header")

    # --- resolve the ceiling ------------------------------------------------
    score = max(0, min(100, score))
    letter = _letter_for_score(score)

    unsigned = tok.kind is TokenKind.UNSIGNED or alg == "none"
    asymmetric = alg in _ASYMMETRIC
    has_exp = exp is not None and exp.valid and exp.when is not None
    short = (tok.lifetime_seconds is not None and tok.lifetime_seconds <= 86400)
    clean_exposure = not secrets and not pii
    fully_identified = "iss" in tok.payload and "aud" in tok.payload

    if unsigned:
        letter = "F"
        headline = "Unsigned — anyone can forge this token"
    elif secrets:
        letter = _cap(letter, "D")
        headline = "A secret is exposed inside the token"
    elif asymmetric and has_exp and short and clean_exposure and fully_identified \
            and score >= 97:
        letter = "A+"
        headline = "Well-formed and discloses little"
    else:
        letter = _cap(letter, "A")
        if score >= 90:
            headline = "Solid, with minor notes"
        elif score >= 75:
            headline = "A few things worth tightening"
        elif score >= 60:
            headline = "Several weaknesses to address"
        else:
            headline = "Serious weaknesses in this token"

    tok.findings = sorted(findings, key=lambda f: -f.severity.rank)
    tok.grade = Grade(letter, score, headline, _CEILING)
    return tok


def analyze(raw: str, now: datetime | None = None) -> Token:
    """Decode then inspect — the whole pipeline in one call."""
    from .decode import decode_token

    return inspect(decode_token(raw), now=now)
