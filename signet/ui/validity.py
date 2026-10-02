"""
The validity window — Signet's signature.

A token's time claims only mean something in relation to each other and to now,
so this widget draws them on one axis: issued on the left, expiry on the right,
the valid span shaded between them, and a marker for the present moment that
lands inside the band when the token is live, past the right edge when it has
expired, and before the left edge when it is not valid yet. It is painted rather
than listed because the *relationship* — where now falls against the window — is
the thing worth seeing at a glance.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from . import theme
from ..core.model import Token

_PAD_X = 24
_AXIS_Y = 70
_HEIGHT = 128


class ValidityWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._tok: Token | None = None
        self._mode = theme.LIGHT
        self._now = datetime.now(timezone.utc)
        self.setMinimumHeight(_HEIGHT)
        self.setMaximumHeight(_HEIGHT)

    def set_data(self, tok: Token, mode: str, now: datetime) -> None:
        self._tok, self._mode, self._now = tok, mode, now
        self.update()

    def paintEvent(self, event):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        c = lambda n: QColor(theme.color(n, self._mode))  # noqa: E731
        w = self.width()

        events = self._events()
        if not events:
            p.setPen(c("ink_faint"))
            p.setFont(self._font("subtitle"))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "This token carries no time claims (iat / nbf / exp).")
            p.end()
            return

        times = [dt for _, dt in events]
        t0, t1 = min(times), max(times)
        span = (t1 - t0).total_seconds() or 1.0
        pad = span * 0.08
        lo = (t0.timestamp() - pad)
        hi = (t1.timestamp() + pad)

        def x_of(dt):
            frac = (dt.timestamp() - lo) / (hi - lo)
            return _PAD_X + frac * (w - 2 * _PAD_X)

        # the valid band: from the later of iat/nbf to exp
        tok = self._tok
        start = None
        for key in ("nbf", "iat"):
            tc = tok.times.get(key)
            if tc and tc.when:
                start = tc.when if start is None else max(start, tc.when)
        exp = tok.times.get("exp")
        end = exp.when if exp and exp.when else None

        if start and end:
            live = start <= self._now < end
            band = c("sev_good_wash") if live else c("sev_warning_wash")
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(band))
            p.drawRect(QRectF(x_of(start), _AXIS_Y - 10, x_of(end) - x_of(start), 20))

        # baseline
        p.setPen(QPen(c("rule_strong"), 2))
        p.drawLine(_PAD_X, _AXIS_Y, w - _PAD_X, _AXIS_Y)

        # event ticks
        for label, dt in events:
            x = x_of(dt)
            is_now = label == "now"
            col = c("sev_good") if is_now else c("brass")
            p.setPen(QPen(col, 2))
            p.drawLine(int(x), _AXIS_Y - 12, int(x), _AXIS_Y + 12)
            if is_now:
                p.setBrush(QBrush(col))
                p.drawEllipse(int(x) - 4, _AXIS_Y - 4, 8, 8)

            p.setFont(self._font("label"))
            p.setPen(c("ink_faint") if not is_now else col)
            p.drawText(QRectF(x - 50, _AXIS_Y - 34, 100, 14),
                       Qt.AlignmentFlag.AlignCenter, label.upper())
            p.setFont(self._font("mono_small"))
            p.setPen(c("ink_muted"))
            p.drawText(QRectF(x - 60, _AXIS_Y + 16, 120, 14),
                       Qt.AlignmentFlag.AlignCenter, dt.strftime("%Y-%m-%d %H:%M"))
        p.end()

    def _events(self) -> list[tuple[str, datetime]]:
        if not self._tok:
            return []
        raw: list[tuple[str, datetime]] = []
        for key in ("iat", "nbf", "exp"):
            tc = self._tok.times.get(key)
            if tc and tc.when:
                raw.append((key, tc.when))
        # Merge ticks that land on the same instant (iat == nbf is common) so
        # their labels do not overprint each other.
        merged: list[tuple[str, datetime]] = []
        for label, dt in raw:
            if merged and merged[-1][1] == dt:
                merged[-1] = (f"{merged[-1][0]} / {label}", dt)
            else:
                merged.append((label, dt))
        if merged:
            merged.append(("now", self._now))
        return merged

    def _font(self, role: str) -> QFont:
        family, size, weight = theme.TYPE[role]
        f = QFont()
        f.setFamilies([family.split(",")[0].strip().strip('"')])
        f.setPixelSize(size)
        f.setWeight(QFont.Weight.DemiBold if weight >= 600 else QFont.Weight.Normal)
        return f
