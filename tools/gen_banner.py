#!/usr/bin/env python3
"""
Repository art — social card, README banner, contact sheet.

Same three surfaces and rules as the rest of the catalogue: a 1280x640 social
card held inside GitHub's 80px safe border by a registered-rectangle check, a
2560x800 light/dark banner pair that may bleed, and a contact sheet of real
off-screen captures, one per theme. Signet's signature motif is the validity
window drawn on a time axis, so the card and banner carry the product's own
picture rather than an illustration of it.

Run ``python tools/capture_screenshots.py`` first; the contact sheet needs it.
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "images")

SERIF = "/System/Library/Fonts/Supplemental/Iowan Old Style.ttc"
SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/Menlo.ttc"


def _pal(dark: bool) -> dict:
    if dark:
        return dict(bg="#000000", surface="#131312", ink="#F3F0E9",
                    muted="#A29C91", faint="#6B675F", rule="#2B2B28",
                    rule_strong="#3D3C38", brass="#D9B75C", shine="#F1C84B",
                    green="#67BE94", green_wash="#0D1F16")
    return dict(bg="#F3F1EC", surface="#FFFFFF", ink="#1B1813",
                muted="#575144", faint="#847D6E", rule="#DCD6C9",
                rule_strong="#C4BCAA", brass="#7A5D18", shine="#C39B24",
                green="#2C6249", green_wash="#E9F3ED")


def font(path, size, index=0):
    return ImageFont.truetype(path, size, index=index)


class SafeBox:
    def __init__(self, w, h, safe):
        self.w, self.h, self.safe, self.rects = w, h, safe, []

    def add(self, name, box):
        self.rects.append((name, tuple(int(round(v)) for v in box)))

    def check(self):
        worst = None
        for name, (l, t, r, b) in self.rects:
            m = min(l, t, self.w - r, self.h - b)
            if worst is None or m < worst[0]:
                worst = (m, name, (l, t, r, b))
        if worst:
            m, name, box = worst
            assert m >= self.safe, (
                f"{name} at {box} leaves {m}px; need {self.safe}px.")
            print(f"  safe border ok — tightest: {name} at {m}px")


def _text(draw, xy, s, fnt, fill, ls=0, anchor="la"):
    if ls == 0:
        draw.text(xy, s, font=fnt, fill=fill, anchor=anchor)
        l, t, r, b = draw.textbbox(xy, s, font=fnt, anchor=anchor)
        return r - l
    x, y = xy
    for ch in s:
        draw.text((x, y), ch, font=fnt, fill=fill, anchor="la")
        x += draw.textbbox((0, 0), ch, font=fnt)[2] + ls
    return x - xy[0] - ls


def _round(draw, box, r, fill=None, outline=None, width=1):
    draw.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)


def _draw_validity(draw, box, pal, ss):
    """A horizontal validity window with issued / now / expires, real-ish."""
    x0, y0, x1, y1 = box
    _round(draw, box, 10 * ss, fill=pal["surface"], outline=pal["rule"],
           width=max(1, ss))
    pad = 30 * ss
    _text(draw, (x0 + pad, y0 + 20 * ss), "THE VALIDITY WINDOW",
          font(SANS, 13 * ss), pal["faint"], ls=2 * ss)

    axis_y = int((y0 + y1) / 2) + 12 * ss
    ax0 = x0 + pad + 10 * ss
    ax1 = x1 - pad - 10 * ss
    # three points: issued (left), now (mid-left, inside), expires (right)
    xi = ax0
    xn = ax0 + int((ax1 - ax0) * 0.34)
    xe = ax1

    # valid band
    draw.rectangle([xi, axis_y - 9 * ss, xe, axis_y + 9 * ss],
                   fill=pal["green_wash"])
    draw.line([(ax0, axis_y), (ax1, axis_y)], fill=pal["rule_strong"], width=2 * ss)

    f_lab = font(SANS, 12 * ss)
    f_date = font(MONO, 12 * ss)
    for x, lab, date, col in (
        (xi, "ISSUED", "12:00", pal["brass"]),
        (xn, "NOW", "12:05", pal["green"]),
        (xe, "EXPIRES", "12:15", pal["brass"]),
    ):
        draw.line([(x, axis_y - 12 * ss), (x, axis_y + 12 * ss)], fill=col,
                  width=2 * ss)
        if lab == "NOW":
            draw.ellipse([x - 5 * ss, axis_y - 5 * ss, x + 5 * ss, axis_y + 5 * ss],
                         fill=col)
        _text(draw, (x, axis_y - 34 * ss), lab, f_lab, col, anchor="ma")
        _text(draw, (x, axis_y + 20 * ss), date, f_date, pal["muted"], anchor="ma")


def render_card(path, dark=False):
    W, H, SS, SAFE = 1280, 640, 2, 80
    pal = _pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)
    box = SafeBox(W * SS, H * SS, SAFE * SS)
    lx = 96 * SS

    wmw = _text(d, (lx, 150 * SS), "SIGNET", font(SERIF, 86 * SS), pal["ink"])
    box.add("wordmark", (lx, 150 * SS, lx + wmw, 236 * SS))
    d.line([(lx, 258 * SS), (lx + wmw, 258 * SS)], fill=pal["brass"], width=3 * SS)
    tgw = _text(d, (lx, 278 * SS), "READ THE SEAL", font(SANS, 20 * SS),
                pal["faint"], ls=4 * SS)
    box.add("tagline", (lx, 278 * SS, lx + tgw, 302 * SS))

    fp = font(SERIF, 36 * SS)
    d.text((lx, 330 * SS), "Decode a token.", font=fp, fill=pal["ink"])
    d.text((lx, 374 * SS), "See what it reveals.", font=fp, fill=pal["ink"])
    box.add("pitch", (lx, 330 * SS, lx + 380 * SS, 414 * SS))

    fs = font(SANS, 18 * SS)
    for i, line in enumerate(["A JWT is not encrypted. Signet reads every",
                              "claim, draws its lifetime, and grades it honestly."]):
        d.text((lx, (440 + i * 26) * SS), line, font=fs, fill=pal["muted"])
    box.add("sub", (lx, 440 * SS, lx + 430 * SS, 492 * SS))

    urlw = _text(d, (lx, 516 * SS), "github.com/at0m-b0mb/Signet",
                 font(MONO, 17 * SS), pal["brass"])
    box.add("url", (lx, 516 * SS, lx + urlw, 536 * SS))

    panel = (700 * SS, 220 * SS, (W - 96) * SS, (H - 220) * SS)
    _draw_validity(d, panel, pal, SS)
    box.add("panel", panel)

    box.check()
    im = im.resize((W, H), Image.LANCZOS)
    im.save(path)
    _assert_safe_border(path, SAFE, pal["bg"])
    print(f"wrote {os.path.relpath(path, ROOT)}")


def _assert_safe_border(path, margin, bg_hex):
    im = Image.open(path).convert("RGB")
    W, H = im.size
    px = im.load()
    bg = tuple(int(bg_hex.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))
    near = lambda c: all(abs(c[i] - bg[i]) <= 6 for i in range(3))  # noqa: E731
    pts = [(x, y) for y in range(0, H, 2) for x in range(0, W, 2) if not near(px[x, y])]
    if not pts:
        return
    l = min(p[0] for p in pts); r = max(p[0] for p in pts)
    t = min(p[1] for p in pts); b = max(p[1] for p in pts)
    m = min(l, W - 1 - r, t, H - 1 - b)
    assert m >= margin, f"content reaches {m}px from the edge (need {margin})"
    print(f"  measured margins: L{l} R{W-1-r} T{t} B{H-1-b} — ok")


def render_banner(path, dark=False):
    W, H, SS = 1280, 400, 2
    pal = _pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)
    d.rectangle([(W - 150) * SS, 0, W * SS, H * SS], fill=pal["brass"])
    d.rectangle([(W - 156) * SS, 0, (W - 150) * SS, H * SS], fill=pal["shine"])

    lx = 80 * SS
    _text(d, (lx, 120 * SS), "SIGNET", font(SERIF, 100 * SS), pal["ink"])
    d.line([(lx, 246 * SS), (lx + 330 * SS, 246 * SS)], fill=pal["brass"], width=3 * SS)
    _text(d, (lx, 266 * SS), "READ THE SEAL", font(SANS, 22 * SS), pal["faint"], ls=5 * SS)
    fs = font(SANS, 21 * SS)
    d.text((lx, 306 * SS), "An offline inspector for JSON Web Tokens.",
           font=fs, fill=pal["muted"])
    d.text((lx, 338 * SS), "Decode, read the claims, grade the exposure.",
           font=fs, fill=pal["muted"])

    panel = (770 * SS, 90 * SS, (W - 175) * SS, (H - 90) * SS)
    _draw_validity(d, panel, pal, SS)
    im.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({im.size[0]}x{im.size[1]})")


def render_contact_sheet(path, shots, dark=False):
    pal = _pal(dark)
    loaded = [Image.open(os.path.join(IMG, n)).convert("RGB")
              for n in shots if os.path.exists(os.path.join(IMG, n))]
    if not loaded:
        print(f"  (no screenshots for {os.path.basename(path)})")
        return
    gap, pad, sw = 28, 40, 560
    thumbs = [im.resize((sw, int(im.height * sw / im.width)), Image.LANCZOS)
              for im in loaded]
    W = pad * 2 + sw * len(thumbs) + gap * (len(thumbs) - 1)
    Hh = pad * 2 + max(t.height for t in thumbs)
    sheet = Image.new("RGB", (W, Hh), pal["bg"])
    d = ImageDraw.Draw(sheet)
    x = pad
    for t in thumbs:
        sheet.paste(t, (x, pad))
        d.rectangle([x, pad, x + t.width - 1, pad + t.height - 1],
                    outline=pal["rule"], width=1)
        x += t.width + gap
    sheet.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({W}x{Hh})")


def main():
    os.makedirs(IMG, exist_ok=True)
    print("social card:")
    render_card(os.path.join(IMG, "social-preview.png"))
    print("banner (light + dark):")
    render_banner(os.path.join(IMG, "banner.png"), dark=False)
    render_banner(os.path.join(IMG, "banner-dark.png"), dark=True)
    print("contact sheet (light + dark):")
    render_contact_sheet(os.path.join(IMG, "screens.png"),
                         ["shot-secret-in-claims-light.png",
                          "shot-good-access-token-light.png"])
    render_contact_sheet(os.path.join(IMG, "screens-dark.png"),
                         ["shot-secret-in-claims-dark.png",
                          "shot-good-access-token-dark.png"], dark=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
