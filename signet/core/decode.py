"""
Taking a token apart.

A JWS is ``header.payload.signature``; a JWE has five parts and its payload is
encrypted. Signet splits on the dots, base64url-decodes the parts it can, and
parses the header and payload as JSON. It is forgiving about the padding that
compact tokens drop, and it never raises on junk — a malformed token comes back
marked malformed, with a note, rather than as an exception.
"""

from __future__ import annotations

import base64
import binascii
import json

from .model import Token, TokenKind


def _b64url_decode(segment: str) -> bytes:
    """Decode base64url, restoring the padding a compact token leaves off."""
    segment = segment.strip()
    pad = (-len(segment)) % 4
    return base64.urlsafe_b64decode(segment + ("=" * pad))


def decode_token(raw: str) -> Token:
    """Split and decode a token into a :class:`Token` (no judgement here)."""
    tok = Token()
    text = (raw or "").strip()

    # tolerate a copied "Authorization: Bearer <jwt>" prefix
    low = text.lower()
    if low.startswith("bearer "):
        text = text[7:].strip()
    elif low.startswith("authorization:"):
        text = text.split(":", 1)[1].strip()
        if text.lower().startswith("bearer "):
            text = text[7:].strip()

    text = "".join(text.split())  # drop any wrapping whitespace/newlines
    if not text:
        tok.notes.append("No token given.")
        return tok

    parts = text.split(".")
    tok.parts = len(parts)

    if len(parts) == 5:
        tok.kind = TokenKind.JWE
        try:
            tok.header = _decode_json(parts[0])
        except Exception:
            tok.notes.append("The JWE header could not be decoded.")
        tok.notes.append(
            "This is a JWE — an encrypted token. Its claims are ciphertext and "
            "cannot be read without the recipient's key.")
        _lift_header(tok)
        return tok

    if len(parts) != 3:
        tok.kind = TokenKind.MALFORMED
        tok.notes.append(
            f"A JWT has three dot-separated parts; this has {len(parts)}.")
        return tok

    header_seg, payload_seg, sig_seg = parts
    try:
        tok.header = _decode_json(header_seg)
    except Exception as exc:
        tok.notes.append(f"The header is not valid base64url JSON ({exc}).")
    try:
        tok.payload = _decode_json(payload_seg)
    except Exception as exc:
        tok.notes.append(f"The payload is not valid base64url JSON ({exc}).")

    tok.signature_b64 = sig_seg
    try:
        tok.signature_bytes = len(_b64url_decode(sig_seg)) if sig_seg else 0
    except (binascii.Error, ValueError):
        tok.signature_bytes = 0

    _lift_header(tok)

    alg = (tok.alg or "").lower()
    if alg == "none" or (not sig_seg):
        tok.kind = TokenKind.UNSIGNED
    else:
        tok.kind = TokenKind.JWS

    if not isinstance(tok.payload, dict):
        tok.notes.append("The payload is not a JSON object.")
        tok.payload = {}
    return tok


def _decode_json(segment: str) -> dict:
    data = _b64url_decode(segment)
    return json.loads(data.decode("utf-8"))


def _lift_header(tok: Token) -> None:
    if isinstance(tok.header, dict):
        tok.alg = str(tok.header.get("alg", "") or "")
        tok.typ = str(tok.header.get("typ", "") or "")
        tok.kid = str(tok.header.get("kid", "") or "")
