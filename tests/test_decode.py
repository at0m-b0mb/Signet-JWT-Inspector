"""Splitting and decoding a token."""

import base64
import json

from signet.core.decode import decode_token
from signet.core.model import TokenKind


def _b64(obj) -> str:
    data = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt(header, payload, sig="sig"):
    s = base64.urlsafe_b64encode(b"\x00\x01\x02").rstrip(b"=").decode() if sig else ""
    return f"{_b64(header)}.{_b64(payload)}.{s}"


def test_basic_decode():
    tok = decode_token(_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}))
    assert tok.kind is TokenKind.JWS
    assert tok.alg == "HS256"
    assert tok.typ == "JWT"
    assert tok.payload["sub"] == "x"
    assert tok.parts == 3


def test_padding_restored():
    # a payload whose base64 length is not a multiple of 4
    tok = decode_token(_jwt({"alg": "HS256"}, {"a": 1, "bb": 22, "ccc": 333}))
    assert tok.payload["ccc"] == 333


def test_alg_none_is_unsigned():
    tok = decode_token(_jwt({"alg": "none"}, {"sub": "admin"}, sig=""))
    assert tok.kind is TokenKind.UNSIGNED
    assert tok.alg == "none"


def test_empty_signature_is_unsigned():
    tok = decode_token(f"{_b64({'alg':'HS256'})}.{_b64({'s':1})}.")
    assert tok.kind is TokenKind.UNSIGNED


def test_jwe_five_parts():
    tok = decode_token("a.b.c.d.e")
    assert tok.kind is TokenKind.JWE
    assert any("JWE" in n for n in tok.notes)


def test_malformed_wrong_part_count():
    tok = decode_token("just.two")
    assert tok.kind is TokenKind.MALFORMED
    assert tok.parts == 2


def test_bearer_prefix_tolerated():
    body = _jwt({"alg": "HS256"}, {"sub": "x"})
    tok = decode_token("Bearer " + body)
    assert tok.kind is TokenKind.JWS
    assert tok.payload["sub"] == "x"


def test_authorization_header_tolerated():
    body = _jwt({"alg": "HS256"}, {"sub": "x"})
    tok = decode_token("Authorization: Bearer " + body)
    assert tok.payload["sub"] == "x"


def test_whitespace_and_newlines_stripped():
    body = _jwt({"alg": "HS256"}, {"sub": "x"})
    a, b, c = body.split(".")
    tok = decode_token(f"{a}.\n  {b} .\n{c}\n")
    assert tok.payload["sub"] == "x"


def test_garbage_does_not_raise():
    tok = decode_token("%%%.$$$.&&&")
    assert tok.kind in (TokenKind.MALFORMED, TokenKind.JWS, TokenKind.UNSIGNED)
    # payload failed to decode -> left an empty dict and a note
    assert tok.payload == {}
    assert tok.notes


def test_empty_input():
    tok = decode_token("")
    assert tok.kind is TokenKind.MALFORMED
    assert tok.notes
