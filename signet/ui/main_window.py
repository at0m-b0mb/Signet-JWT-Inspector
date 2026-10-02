"""
The window.

Left: a token, pasted or loaded from a sample. Right: the reading — a grade, the
header's algorithm, the validity window drawn on a time axis, every claim in
full (a JWT hides nothing from whoever holds it), and the findings. The window
keeps the current token and re-renders the right side on a theme change so chips
and the painted axis always match the palette.
"""

from __future__ import annotations

import json
import os

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..core.claims import REGISTERED, humanize_delta, now_utc, pii_claims, sensitive_claims
from ..core.inspect import analyze
from ..core.model import Severity, Token, TokenKind
from . import theme
from .validity import ValidityWindow
from .widgets import Card, Chip, hrule, key_value, label, mini_label

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

_SEV_TOKEN = {
    Severity.GOOD: "sev_good", Severity.INFO: "sev_info",
    Severity.NOTICE: "sev_notice", Severity.WARNING: "sev_warning",
    Severity.ALERT: "sev_alert",
}

_KIND_TOKEN = {
    TokenKind.JWS: "sev_good", TokenKind.JWE: "sev_info",
    TokenKind.UNSIGNED: "sev_alert", TokenKind.MALFORMED: "sev_alert",
}
_KIND_WORD = {
    TokenKind.JWS: "signed (JWS)", TokenKind.JWE: "encrypted (JWE)",
    TokenKind.UNSIGNED: "unsigned", TokenKind.MALFORMED: "malformed",
}


class MainWindow(QWidget):
    def __init__(self, mode: str = theme.AUTO):
        super().__init__()
        self._mode_choice = mode
        self._mode = theme.resolve(mode)
        self._token: Token | None = None
        self._now = now_utc()
        self.fixed_now = None  # set by the screenshot tool for reproducible art

        self.setWindowTitle("Signet")
        self.resize(1140, 760)
        self._build()
        self._apply_theme()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_header())

        from PyQt6.QtWidgets import QSplitter
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_source_pane())
        split.addWidget(self._build_report_pane())
        split.setSizes([440, 700])
        host = QWidget()
        host.setObjectName("PageHost")
        hl = QVBoxLayout(host)
        hl.setContentsMargins(16, 12, 16, 16)
        hl.addWidget(split)
        root.addWidget(host, 1)

    def _build_header(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("Rail")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 12, 20, 12)
        mark = QLabel("SIGNET")
        mark.setObjectName("Wordmark")
        sub = QLabel("read the seal")
        sub.setObjectName("WordmarkSub")
        wm = QVBoxLayout()
        wm.setSpacing(0)
        wm.addWidget(mark)
        wm.addWidget(sub)
        lay.addLayout(wm)
        lay.addStretch(1)
        lay.addWidget(mini_label("THEME"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Auto", "Light", "Dark"])
        self.theme_box.setCurrentText(self._mode_choice.capitalize())
        self.theme_box.setFixedWidth(110)
        self.theme_box.currentTextChanged.connect(self._on_theme_changed)
        lay.addWidget(self.theme_box)
        return bar

    def _build_source_pane(self) -> QWidget:
        pane = QWidget()
        lay = QVBoxLayout(pane)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(theme.SPACE["base"])
        lay.addWidget(label("Paste a token", "PageTitle"))
        lay.addWidget(label(
            "A JSON Web Token: three base64url parts joined by dots. Signet "
            "reads it the way anyone holding it can — it is not encrypted — and "
            "reports what it exposes.", "PageIntro"))
        self.source = QPlainTextEdit()
        self.source.setObjectName("Mono")
        self.source.setPlaceholderText("eyJhbGciOi...  .  eyJzdWIiOi...  .  signature")
        lay.addWidget(self.source, 1)

        row = QHBoxLayout()
        b = QPushButton("Inspect")
        b.setObjectName("Primary")
        b.clicked.connect(self._on_analyze)
        row.addWidget(b)
        ob = QPushButton("Open file…")
        ob.clicked.connect(self._on_open)
        row.addWidget(ob)
        self.sample_btn = QPushButton("Load sample")
        self._build_sample_menu()
        row.addWidget(self.sample_btn)
        cb = QPushButton("Clear")
        cb.setObjectName("Quiet")
        cb.clicked.connect(self._on_clear)
        row.addWidget(cb)
        row.addStretch(1)
        lay.addLayout(row)
        return pane

    def _build_sample_menu(self) -> None:
        menu = QMenu(self)
        try:
            names = sorted(f for f in os.listdir(_SAMPLES_DIR) if f.endswith(".jwt"))
        except OSError:
            names = []
        if not names:
            a = QAction("(no samples found)", self)
            a.setEnabled(False)
            menu.addAction(a)
        for name in names:
            pretty = name[:-4].replace("-", " ").title()
            a = QAction(pretty, self)
            a.triggered.connect(lambda _=False, n=name: self._load_sample(n))
            menu.addAction(a)
        self.sample_btn.setMenu(menu)

    def _build_report_pane(self) -> QWidget:
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self._set_placeholder()
        return self.report_scroll

    # --- behaviour ----------------------------------------------------------
    def _on_theme_changed(self, text: str) -> None:
        self._mode_choice = text.lower()
        self._mode = theme.resolve(self._mode_choice)
        self._apply_theme()
        if self._token is not None:
            self._render(self._token)
        else:
            self._set_placeholder()

    def _apply_theme(self) -> None:
        self.setStyleSheet(theme.stylesheet(self._mode))

    def _on_analyze(self) -> None:
        src = self.source.toPlainText()
        if not src.strip():
            self._set_placeholder("Paste a token, or load a sample, to begin.")
            return
        self._now = self.fixed_now or now_utc()
        self._token = analyze(src, now=self._now)
        self._render(self._token)

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open a token", "", "Tokens (*.jwt *.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not open the file: {exc}")
            return
        self._on_analyze()

    def _load_sample(self, name: str) -> None:
        try:
            with open(os.path.join(_SAMPLES_DIR, name), encoding="utf-8") as fh:
                self.source.setPlainText(fh.read())
        except OSError as exc:
            self._set_placeholder(f"Could not load the sample: {exc}")
            return
        self._on_analyze()

    def _on_clear(self) -> None:
        self.source.clear()
        self._token = None
        self._set_placeholder()

    # --- rendering ----------------------------------------------------------
    def _set_placeholder(self, text: str = "") -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.addStretch(1)
        lay.addWidget(label("Nothing read yet", "Figure"))
        lay.addWidget(label(
            text or "Signet decodes a JSON Web Token and shows what it reveals: "
            "its algorithm, its validity window, every claim it carries, and the "
            "weaknesses worth fixing. It never verifies the signature, and it "
            "never calls a token safe.", "PageIntro"))
        lay.addStretch(2)
        self.report_scroll.setWidget(host)

    def _render(self, tok: Token) -> None:
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(8, 4, 8, 16)
        lay.setSpacing(theme.SPACE["base"])

        lay.addWidget(self._grade_card(tok))
        lay.addWidget(self._header_card(tok))
        if tok.kind in (TokenKind.JWS, TokenKind.UNSIGNED):
            lay.addWidget(self._validity_card(tok))
            lay.addWidget(self._claims_card(tok))
        lay.addWidget(self._findings_card(tok))
        if tok.notes:
            n = Card("Notes", flat=True)
            for note in tok.notes:
                n.add(label(note, muted=True))
            lay.addWidget(n)
        lay.addStretch(1)
        self.report_scroll.setWidget(host)

    def _grade_card(self, tok: Token) -> QWidget:
        g = tok.grade
        card = Card()
        top = QHBoxLayout()
        letter = QLabel(g.letter)
        letter.setStyleSheet(
            f"{theme.font_css('grade')} color: "
            f"{theme.color(theme.grade_token(g.letter), self._mode)};")
        top.addWidget(letter)
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(mini_label(f"TOKEN GRADE  ·  SCORE {g.score}/100"))
        col.addWidget(label(g.headline, "PageTitle"))
        col.addStretch(1)
        top.addLayout(col, 1)
        card.add_layout(top)
        card.add(hrule())
        card.add(label(g.ceiling_note, "Faint"))
        return card

    def _header_card(self, tok: Token) -> QWidget:
        card = Card("The header")
        row = QHBoxLayout()
        row.setSpacing(theme.SPACE["wide"])
        col = QVBoxLayout()
        col.setSpacing(theme.SPACE["tight"])
        col.addWidget(mini_label("KIND"))
        col.addWidget(Chip(_KIND_WORD[tok.kind].split()[0], _KIND_TOKEN[tok.kind], self._mode))
        col.addStretch(1)
        w = QWidget()
        w.setLayout(col)
        row.addWidget(w)
        col2 = QVBoxLayout()
        col2.setSpacing(theme.SPACE["tight"])
        col2.addWidget(mini_label("ALGORITHM"))
        alg_tok = "sev_alert" if (tok.alg.lower() == "none" or not tok.alg) else "sev_info"
        col2.addWidget(Chip(tok.alg or "none", alg_tok, self._mode))
        col2.addStretch(1)
        w2 = QWidget()
        w2.setLayout(col2)
        row.addWidget(w2)
        row.addStretch(1)
        card.add_layout(row)
        if tok.typ:
            card.add(key_value("typ", tok.typ, self._mode))
        if tok.kid:
            card.add(key_value("kid", tok.kid, self._mode, mono=True))
        card.add(key_value("signature", f"{tok.signature_bytes} bytes"
                           if tok.signature_bytes else "none", self._mode))
        return card

    def _validity_card(self, tok: Token) -> QWidget:
        card = Card("The validity window")
        expired = tok.expired(self._now)
        not_yet = tok.not_yet_valid(self._now)
        if expired is None:
            summary = "This token sets no expiry."
        elif expired:
            ex = tok.times["exp"].when
            summary = f"Expired {humanize_delta(ex, self._now)}."
        elif not_yet:
            summary = "Not valid yet."
        else:
            ex = tok.times["exp"].when
            summary = f"Currently valid; expires {humanize_delta(ex, self._now)}."
        card.add(label(summary, "Faint"))
        vw = ValidityWindow()
        vw.set_data(tok, self._mode, self._now)
        card.add(vw)
        return card

    def _claims_card(self, tok: Token) -> QWidget:
        secrets = set(sensitive_claims(tok.payload))
        pii = set(pii_claims(tok.payload))
        card = Card(f"The claims ({len(tok.payload)}) — all readable")
        if not tok.payload:
            card.add(label("The payload carries no claims.", muted=True))
            return card
        for i, (key, value) in enumerate(tok.payload.items()):
            if i:
                card.add(hrule())
            tok_color = None
            if key in secrets:
                tok_color = "sev_alert"
            elif key in pii:
                tok_color = "sev_warning"
            display = self._format_claim(tok, key, value)
            lbl = REGISTERED.get(key, key)
            prefix = f"{lbl}" if lbl == key else f"{lbl}  ({key})"
            card.add(key_value(prefix, display, self._mode,
                               value_token=tok_color, mono=True))
        return card

    def _format_claim(self, tok: Token, key: str, value) -> str:
        if key in tok.times and tok.times[key].when:
            when = tok.times[key].when
            return f"{when.strftime('%Y-%m-%d %H:%M UTC')}  ({humanize_delta(when, self._now)})"
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(", ", ": "))
        return str(value)

    def _findings_card(self, tok: Token) -> QWidget:
        card = Card(f"Findings ({len(tok.findings)})")
        if not tok.findings:
            card.add(label("No findings.", muted=True))
            return card
        for i, f in enumerate(tok.findings):
            if i:
                card.add(hrule())
            row = QHBoxLayout()
            row.setSpacing(theme.SPACE["base"])
            chip = Chip(f.severity.value, _SEV_TOKEN[f.severity], self._mode)
            chip.setFixedWidth(84)
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
            col = QVBoxLayout()
            col.setSpacing(2)
            head = QHBoxLayout()
            head.addWidget(label(f.title, "body"))
            head.addStretch(1)
            if f.points:
                head.addWidget(label(f"−{f.points}", "Faint"))
            col.addLayout(head)
            col.addWidget(label(f.detail, muted=True))
            row.addLayout(col, 1)
            card.add_layout(row)
        return card
