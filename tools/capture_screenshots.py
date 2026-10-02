#!/usr/bin/env python3
"""Render the window off-screen and save PNGs — proof, and the README sheet."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from signet.ui import theme  # noqa: E402
from signet.ui.main_window import MainWindow  # noqa: E402

# Five minutes after the samples' issue time, so the good token reads as live.
FIXED_NOW = datetime(2026, 10, 2, 12, 5, 0, tzinfo=timezone.utc)

SIZE = (1180, 840)
SHOTS = [
    ("secret-in-claims.jwt", theme.LIGHT),
    ("secret-in-claims.jwt", theme.DARK),
    ("good-access-token.jwt", theme.LIGHT),
    ("good-access-token.jwt", theme.DARK),
    ("session-with-pii.jwt", theme.LIGHT),
]


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    out = os.path.join(ROOT, "images")
    os.makedirs(out, exist_ok=True)
    samples = os.path.join(ROOT, "samples")
    for name, mode in SHOTS:
        win = MainWindow(mode=mode)
        win.fixed_now = FIXED_NOW
        win.resize(*SIZE)
        with open(os.path.join(samples, name), encoding="utf-8") as fh:
            win.source.setPlainText(fh.read())
        win._on_analyze()
        win.show()
        app.processEvents()
        app.processEvents()
        path = os.path.join(out, f"shot-{name[:-4]}-{mode}.png")
        win.grab().save(path)
        print(f"wrote {os.path.relpath(path, ROOT)}")
        win.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
