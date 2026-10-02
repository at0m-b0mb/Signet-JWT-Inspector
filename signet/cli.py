"""
Signet on the command line.

The same engine the window uses, with no Qt — so it runs in a pipe or a script.
Point it at a token file, or pipe a token in; add ``--json`` for machine output.

    signet token.jwt
    echo "$JWT" | signet -
    signet token.jwt --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .core.claims import humanize_delta, now_utc, pii_claims, sensitive_claims
from .core.inspect import analyze
from .core.model import Token, TokenKind

_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "good": "\033[32m", "notice": "\033[33m", "warning": "\033[33m",
    "alert": "\033[31m", "info": "\033[90m",
}


def _paint(text, key, color):
    return f"{_C.get(key,'')}{text}{_C['reset']}" if color else text


def _report_text(tok: Token, color: bool, now) -> str:
    g = tok.grade
    out = [
        _paint(f"  {g.letter}  ", "bold", color) + f" {g.headline}  "
        + _paint(f"({g.score}/100)", "dim", color),
        _paint(g.ceiling_note, "dim", color),
        "",
        f"Kind       {tok.kind.value}",
        f"Algorithm  {tok.alg or 'none'}",
    ]
    if tok.kid:
        out.append(f"kid        {tok.kid}")
    out.append("")

    if tok.payload:
        secrets = set(sensitive_claims(tok.payload))
        pii = set(pii_claims(tok.payload))
        out.append("Claims (all readable — a JWT is not encrypted)")
        for key, value in tok.payload.items():
            if key in tok.times and tok.times[key].when:
                w = tok.times[key].when
                shown = f"{w.strftime('%Y-%m-%d %H:%M UTC')} ({humanize_delta(w, now)})"
            elif isinstance(value, (dict, list)):
                shown = json.dumps(value, separators=(",", ":"))
            else:
                shown = str(value)
            flag = "alert" if key in secrets else ("warning" if key in pii else "dim")
            out.append(f"  {key:<10} {_paint(shown, flag, color)}")
        out.append("")

    out.append(f"Findings ({len(tok.findings)})")
    for f in tok.findings:
        tag = _paint(f"[{f.severity.value:^7}]", f.severity.value, color)
        pts = _paint(f" -{f.points}", "dim", color) if f.points else ""
        out.append(f"  {tag} {f.title}{pts}")
        out.append(_paint(f"          {f.detail}", "dim", color))
    for n in tok.notes:
        out.append(_paint(f"  note: {n}", "dim", color))
    return "\n".join(out)


def _report_json(tok: Token) -> str:
    data = {
        "grade": {"letter": tok.grade.letter, "score": tok.grade.score,
                  "headline": tok.grade.headline, "ceiling_note": tok.grade.ceiling_note},
        "kind": tok.kind.value,
        "header": tok.header,
        "payload": tok.payload,
        "algorithm": tok.alg,
        "signature_bytes": tok.signature_bytes,
        "findings": [{"severity": f.severity.value, "title": f.title,
                      "detail": f.detail, "points": f.points, "category": f.category}
                     for f in tok.findings],
        "notes": tok.notes,
    }
    return json.dumps(data, indent=2, default=str)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="signet", description="Decode a JWT and grade what it exposes.")
    ap.add_argument("source", nargs="?", default="-",
                    help="path to a token file, or - for standard input")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-color", action="store_true", help="plain text")
    args = ap.parse_args(argv)

    if args.source == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(args.source, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"signet: cannot read {args.source}: {exc}", file=sys.stderr)
            return 2
    if not raw.strip():
        print("signet: no token given", file=sys.stderr)
        return 2

    now = now_utc()
    tok = analyze(raw, now=now)
    if args.json:
        print(_report_json(tok))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(_report_text(tok, color, now))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
