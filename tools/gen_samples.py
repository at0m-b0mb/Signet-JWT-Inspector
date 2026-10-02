#!/usr/bin/env python3
"""
Write the synthetic sample tokens in ``samples/``.

Every token here is fabricated — the signatures are random bytes, the subjects
are invented, and nothing authenticates anything. They exist only so the reader
has something to show. Timestamps are anchored to a fixed reference date so the
files are reproducible and the tests can grade them against a known clock.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")

REF = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
IAT = int(REF.timestamp())


def _b64(obj_or_bytes) -> str:
    if isinstance(obj_or_bytes, (dict, list)):
        data = json.dumps(obj_or_bytes, separators=(",", ":")).encode()
    else:
        data = obj_or_bytes
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(header: dict, payload: dict, sig: bytes = b"") -> str:
    return f"{_b64(header)}.{_b64(payload)}." + (_b64(sig) if sig else "")


SAMPLES_SPEC = {
    "good-access-token.jwt": jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "2026-10-key-a"},
        {"iss": "https://auth.example.com", "aud": "api.example.com",
         "sub": "user-10294", "scope": "read:profile",
         "iat": IAT, "nbf": IAT, "exp": IAT + 900},
        sig=bytes(range(32)),
    ),
    "alg-none.jwt": jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "admin", "role": "superuser", "iat": IAT},
        sig=b"",
    ),
    "secret-in-claims.jwt": jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "svc-reporting", "password": "hunter2-not-real",
         "api_key": "sk_test_FAKE0000000000", "note": "demo only"},
        sig=bytes(range(32, 64)),
    ),
    "session-with-pii.jwt": jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"iss": "https://app.example.com", "aud": "app.example.com",
         "sub": "member-5531", "email": "reader@example.com",
         "iat": IAT, "exp": IAT + 86400 * 7},
        sig=bytes(range(48, 80)),
    ),
}


def main() -> int:
    os.makedirs(SAMPLES, exist_ok=True)
    for name, token in SAMPLES_SPEC.items():
        path = os.path.join(SAMPLES, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
        print(f"wrote samples/{name}  ({len(token)} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
