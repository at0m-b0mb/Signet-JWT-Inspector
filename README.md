<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/banner-dark.png">
  <img src="images/banner.png" alt="Signet — read the seal" width="100%">
</picture>

<br>

**Read the seal.** An offline inspector for JSON Web Tokens that decodes a token,
draws its validity window, shows every claim it exposes, and grades what it finds
— without ever verifying the signature or calling a token safe.

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-7A5D18?style=flat-square)
![PyQt6](https://img.shields.io/badge/UI-PyQt6-7A5D18?style=flat-square)
![Offline](https://img.shields.io/badge/network-never-2C6249?style=flat-square)
![Tests](https://img.shields.io/badge/tests-152%20passing-2C6249?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-847D6E?style=flat-square)

</div>

---

## Why

A JSON Web Token looks like a secret — a long opaque string you paste into an
`Authorization` header — so people treat it like one. It is not. The first two
parts of a JWT are plain base64url: anyone who holds the token can read every
claim inside it, no key required. The third part is a signature that proves the
token was issued by someone with the key — but you cannot check that without the
key, and the token itself tells you nothing about how your server validates it.

Signet makes that concrete. Paste a token and it shows you:

- **The validity window** — `iat`, `nbf` and `exp` drawn on one time axis, with
  the valid span shaded and *now* marked inside it, past it, or before it.
- **Every claim, in full** — because that is exactly what an attacker who
  intercepts the token sees. Secrets and personal data placed in claims are
  highlighted, because they should not be there.
- **The weaknesses** — `alg: none`, a symmetric algorithm, a missing or distant
  expiry, a missing audience, an injection-shaped `kid`.

Then it grades the token A+ to F.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/screens-dark.png">
  <img src="images/screens.png" alt="A token leaking a secret graded F, and a clean access token graded A+" width="100%">
</picture>
<br>
<sub>A token with a secret in its claims (F) beside a clean, short-lived access token (A+).</sub>
</div>

## The honest part

Signet **never verifies the signature** — that needs the key — and it cannot know
how your server validates a token. A high grade means the token is well-formed
and discloses little, not that it is genuine or will be accepted. The word
"safe" appears nowhere in a result, by design.

- **A+ is reserved** for a token that is asymmetrically signed, carries a sane
  short-lived expiry, names an issuer and audience, and exposes nothing it
  shouldn't — and it still carries the caveat above.
- **`alg: none` is always F.** A token a server will accept without a signature
  is one anyone can forge by hand.
- **A secret in the open caps the grade hard.** A password or API key sitting in
  a claim is, by itself, enough to sink a token — because it is readable by
  everyone who holds it.

## Install

```bash
git clone https://github.com/at0m-b0mb/Signet.git
cd Signet
python3 -m pip install -r requirements.txt   # just PyQt6, for the window
```

The engine and the command line need **no dependencies** — only the standard
library. PyQt6 is required solely for the graphical inspector.

## Run

**The window:**

```bash
python3 -m signet          # or:  python3 run.py
```

Paste a token, open a file, or load one of the bundled samples. Switch between
**Light**, **Dark** and **Auto** from the top-right.

**The command line** — same engine, no Qt:

```bash
signet token.jwt                 # a readable report
echo "$JWT" | signet -           # from a pipe
signet token.jwt --json          # machine-readable
python3 -m signet token.jwt      # without installing
```

```
  F   A secret is exposed inside the token  (2/100)
  Signet decodes a token and reads its claims — a JWT is not encrypted…
  not whether it is genuine.

  Claims (all readable — a JWT is not encrypted)
    sub        svc-reporting
    password   hunter2-not-real
    api_key    sk_test_FAKE0000000000

  Findings (5)
    [ alert ] A secret is sitting in the open
    [warning] No expiry (exp)
    …
```

## What it reads

| Signal | What trips it |
|---|---|
| **Algorithm** | `none` (unsigned), a symmetric `HS*` secret, or an unknown alg |
| **Expiry** | no `exp`, or a lifetime measured in days rather than minutes |
| **Not-before** | an `nbf` that has not arrived yet |
| **Identity** | no `iss`, or no `aud` to bind the token to one service |
| **Exposure** | a claim that looks like a secret, or like personal data |
| **Header** | a `kid` that looks like a path- or query-injection probe |
| **Shape** | a JWE (encrypted — not readable), or a malformed token |

## Privacy

Signet never touches the network. It decodes base64 and parses JSON with the
standard library, and that is all — a token you paste in never leaves your
machine. (Which is also the point: neither does the token, until you hand it to
someone. Read it before you do.)

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
```

152 tests cover the decoder (padding, JWE, `alg: none`, malformed input, bearer
prefixes), the claim interpreter, the full grading pipeline against the sample
set, and a WCAG-AA contrast suite over every text/background pairing in both
themes.

## Layout

```
signet/
  core/            the engine — pure standard library, no Qt
    model.py         the dataclasses everything speaks in
    decode.py        split and base64url-decode the token
    claims.py        registered claims, times, exposure hints
    inspect.py       findings and the letter, with the honesty ceiling
  ui/
    theme.py         the design system: one place for every token
    validity.py      the validity window — Signet's signature element
    widgets.py       cards, chips, key/value rows
    main_window.py   the inspector itself
  cli.py           the same engine on the command line
samples/           synthetic tokens: a clean one, alg:none, a leaked secret
tests/             152 tests, including the contrast suite
tools/             sample generation, screenshot capture, repository art
```

## Colophon

Set in **Iowan Old Style** for identity, the system **sans** for anything you
read, and a **mono** for the token and its claims. Warm paper and two golds in
the light theme; true black, with nothing that reads as blue, in the dark. Every
colour is a light/dark pair, held to WCAG AA by a test suite so the theme cannot
quietly regress.

## License

MIT — see [LICENSE](LICENSE). A reader, for authorised, educational and personal
use. Every token in `samples/` is fabricated; none authenticates anything.
