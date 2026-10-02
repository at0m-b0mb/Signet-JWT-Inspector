# Changelog

All notable changes to Signet are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] — 2026-10-02

First release.

### The inspector
- Decodes a compact JWS into its header, claims and signature, restoring the
  base64url padding compact tokens drop, and tolerating a pasted
  `Authorization: Bearer` prefix. Recognises a JWE (encrypted, five parts) and a
  malformed token without raising.
- **Validity window** — `iat`, `nbf` and `exp` drawn on one time axis, the valid
  span shaded, and *now* marked inside, before, or past it. Coincident ticks are
  merged so labels never overprint.
- **Claims** — every claim shown in full, with registered claims labelled and
  NumericDates rendered as readable moments; claims that look like a secret are
  flagged red and personal data amber, because a JWT is readable by anyone who
  holds it.
- **Findings** — `alg: none`, symmetric algorithms, missing or distant expiry,
  a future `nbf`, missing issuer or audience, exposed secrets or personal data,
  and an injection-shaped `kid`.
- **Grade** — A+ to F, with an honesty ceiling: the signature is never verified,
  `alg: none` is always F, a secret in the open caps the grade, and the word
  "safe" never appears.

### Interfaces
- A PyQt6 window in the house style — warm paper and gold, true-black dark mode,
  and an Auto theme that follows the OS.
- A dependency-free command line sharing the same engine, with text and `--json`
  output and standard-input support.

### Engineering
- The engine (`signet.core`) is pure standard library — no third-party
  dependencies, no network.
- 152 tests across the decoder, the claim interpreter, the full grading pipeline
  against the sample set, and a WCAG-AA contrast suite over both themes.
- Deterministic sample generation, off-screen screenshot capture, and a
  repository-art generator whose social card is held inside GitHub's safe border
  by a registered-rectangle check.
