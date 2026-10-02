"""Launching the window — the Qt bootstrap, kept in one place."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import QApplication

    from .ui import theme
    from .ui.main_window import MainWindow

    app = QApplication.instance() or QApplication(argv or sys.argv)
    app.setApplicationName("Signet")
    base = QFont()
    base.setFamilies([theme.SANS.split(",")[0]])
    base.setPixelSize(13)
    app.setFont(base)

    window = MainWindow(mode=theme.AUTO)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
