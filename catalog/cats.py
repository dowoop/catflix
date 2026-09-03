"""Procedurally drawn cats.

Real cat photographs would mean downloading somebody else's pictures and
publishing them from a contract with my name on the signing key. These are
drawn from a seed instead: no download, no licence question, and a catalogue
that rebuilds identically on a machine with no network.
"""

from __future__ import annotations

import math
import random

from PIL import Image, ImageDraw, ImageFilter

PALETTES = [
    ("#f4a259", "#e07a3e", "#2b1b17", "#ffd9a0"),
    ("#8d99ae", "#5c6b80", "#1d1f24", "#e8eef4"),
    ("#d6a2ad", "#b3707f", "#2a1a20", "#ffe6ec"),
    ("#a3b18a", "#6b8f5a", "#1e2a1a", "#e4f0d6"),
    ("#e5c07b", "#c39b3f", "#2d2412", "#fff3d0"),
    ("#7f95d1", "#4e63a8", "#161c2e", "#dfe6ff"),
    ("#c9ada7", "#9a7b76", "#241c1a", "#f2e9e4"),
    ("#f28482", "#d1524f", "#2b1414", "#ffe0df"),
]


def _ellipse(d, box, fill, outline=None, width=3):
    d.ellipse(box, fill=fill, outline=outline, width=width)


def draw_cat(seed: int, size: int = 768) -> Image.Image:
    """One cat, deterministic in `seed`."""
    rng = random.Random(seed)
    coat, shade, ink, bg = PALETTES[seed % len(PALETTES)]

    img = Image.new("RGB", (size, size), bg)
    d = ImageDraw.Draw(img)
    s = size / 768.0

    # A soft vignette so the portrait reads as a portrait rather than a sticker.
    for i in range(14):
        k = i / 14
        d.ellipse(
            [size * (0.5 - 0.62 * (1 - k)), size * (0.5 - 0.62 * (1 - k)),
             size * (0.5 + 0.62 * (1 - k)), size * (0.5 + 0.62 * (1 - k))],
            outline=shade, width=int(6 * s),
        )
    img = img.filter(ImageFilter.GaussianBlur(radius=18 * s))
    d = ImageDraw.Draw(img)

    cx, cy = size * 0.5, size * 0.56
    hw, hh = size * 0.30, size * 0.27

    # Ears first, so the head overlaps their base.
    ear_lean = rng.uniform(0.6, 1.0)
    for sign in (-1, 1):
        bx = cx + sign * hw * 0.72
        d.polygon(
            [(bx - 62 * s, cy - hh * 0.62), (bx + 62 * s, cy - hh * 0.52),
             (bx + sign * 34 * s, cy - hh * (0.72 + 0.62 * ear_lean))],
            fill=coat, outline=ink,
        )
        d.polygon(
            [(bx - 30 * s, cy - hh * 0.60), (bx + 30 * s, cy - hh * 0.55),
             (bx + sign * 18 * s, cy - hh * (0.66 + 0.44 * ear_lean))],
            fill=PALETTES[(seed + 3) % len(PALETTES)][3],
        )

    _ellipse(d, [cx - hw, cy - hh, cx + hw, cy + hh], coat, ink, int(5 * s))

    # Tabby stripes, or none. A cat with no markings is a legitimate cat.
    if seed % 3 != 0:
        for i in range(rng.randint(3, 6)):
            y = cy - hh * 0.72 + i * hh * 0.20
            w = hw * rng.uniform(0.24, 0.46)
            d.arc([cx - w, y - 30 * s, cx + w, y + 30 * s], 200, 340, fill=shade, width=int(11 * s))

    eye_y = cy - hh * 0.10
    eye_dx = hw * 0.42
    eye_w, eye_h = hw * 0.27, hh * 0.24
    iris = ["#4ec9b0", "#f4d35e", "#7ec8e3", "#a8e063"][seed % 4]
    for sign in (-1, 1):
        ex = cx + sign * eye_dx
        _ellipse(d, [ex - eye_w, eye_y - eye_h, ex + eye_w, eye_y + eye_h], "#fdfdfd", ink, int(4 * s))
        _ellipse(d, [ex - eye_w * 0.72, eye_y - eye_h * 0.86, ex + eye_w * 0.72, eye_y + eye_h * 0.86], iris)
        # Slit pupil, the thing that makes it read as a cat and not a bear.
        d.ellipse([ex - eye_w * 0.17, eye_y - eye_h * 0.84, ex + eye_w * 0.17, eye_y + eye_h * 0.84], fill=ink)
        d.ellipse([ex - eye_w * 0.44, eye_y - eye_h * 0.58, ex - eye_w * 0.14, eye_y - eye_h * 0.22], fill="#ffffff")

    ny = cy + hh * 0.26
    d.polygon([(cx - 26 * s, ny - 12 * s), (cx + 26 * s, ny - 12 * s), (cx, ny + 22 * s)],
              fill="#e8898f", outline=ink)
    d.line([(cx, ny + 20 * s), (cx, ny + 46 * s)], fill=ink, width=int(4 * s))
    for sign in (-1, 1):
        d.arc([cx + (0 if sign < 0 else 0) + sign * 54 * s - 54 * s, ny + 22 * s,
               cx + sign * 54 * s + 54 * s, ny + 78 * s],
              0 if sign > 0 else 180, 180 if sign > 0 else 360, fill=ink, width=int(5 * s))

    for sign in (-1, 1):
        for i in range(3):
            a = math.radians(rng.uniform(-16, 16) + i * 11 - 11)
            x0 = cx + sign * hw * 0.34
            y0 = ny + 12 * s + i * 20 * s
            length = hw * rng.uniform(0.75, 1.05)
            d.line([(x0, y0), (x0 + sign * length * math.cos(a), y0 + length * math.sin(a) * 0.5)],
                   fill=ink, width=int(3 * s))
    return img


def poster_from(full: Image.Image, size: int = 384) -> Image.Image:
    """The free half: recognisable, deliberately not the thing being sold.

    Pixelated and dimmed rather than merely smaller. A poster that is just a
    downscale invites the obvious question of why anyone would pay for the
    upscale, and answering it with "the paid one is bigger" would be a fair
    complaint about the product rather than about the paywall.
    """
    small = full.resize((size, size), Image.LANCZOS)
    pix = small.resize((24, 24), Image.BILINEAR).resize((size, size), Image.NEAREST)
    return Image.blend(pix, Image.new("RGB", (size, size), "#12131a"), 0.28)
