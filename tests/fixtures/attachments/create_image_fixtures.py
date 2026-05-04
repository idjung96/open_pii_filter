# SYNTHETIC DATA - NOT REAL PII
"""Synthetic image fixture generator (Phase 5).

Builds in-memory bytes for every image attachment shape we need:

  - PNG / JPEG with PII text
  - Rotated PNG (90 deg)
  - Pure-landscape PNG (no text)
  - Multi-page TIFF with one PII per page
  - Synthetic ID card / business card mockups

All fixtures are deterministic. PII inside them comes exclusively from
:mod:`tests.fixtures.synthetic_pii_generator` (or hard-coded synthetic
constants used elsewhere in the suite).
"""

from __future__ import annotations

import io
from typing import Final

from PIL import Image, ImageDraw, ImageFont

# Re-export the same synthetic constants used by Phase 4 fixtures so
# our PNG/PDF text matches the suite-wide assertions.
SYNTH_PHONE: Final[str] = "010-0000-1234"
SYNTH_EMAIL: Final[str] = "synth@example.com"
SYNTH_RRN: Final[str] = "900101-1234567"  # checksum-invalid; safe for fixtures
SYNTH_NAME: Final[str] = "홍길동"


def _load_font(size: int = 28) -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    """Load a TrueType font that can render basic ASCII + (best-effort) CJK.

    Falls back to PIL's default bitmap font if no TTF is found. The
    default font won't render Hangul, but the tests assert on ASCII
    runs (RRN digits, phone numbers, email) which always work.
    """
    candidates = [
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _text_image(
    lines: list[str],
    *,
    width: int = 800,
    height: int = 500,
    bg: tuple[int, int, int] = (255, 255, 255),
    fg: tuple[int, int, int] = (0, 0, 0),
    font_size: int = 36,
    fmt: str = "PNG",
) -> bytes:
    """Render ``lines`` onto a blank canvas and return the encoded bytes."""
    img = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(img)
    font = _load_font(font_size)
    y = 30
    for line in lines:
        draw.text((30, y), line, font=font, fill=fg)
        y += int(font_size * 1.6)
    buf = io.BytesIO()
    img.save(buf, format=fmt)
    return buf.getvalue()


def make_id_card_png() -> bytes:
    """Synthetic ID card mockup. RRN + name + a couple of label lines."""
    return _text_image(
        [
            "ID CARD (SYNTHETIC)",
            f"Name: {SYNTH_NAME}",
            f"RRN: {SYNTH_RRN}",
            "SYNTHETIC DATA - NOT REAL PII",
        ],
        width=900,
        height=560,
    )


def make_business_card_png() -> bytes:
    """Synthetic business card mockup. Phone + email + name."""
    return _text_image(
        [
            "Business Card (SYNTHETIC)",
            f"Name: {SYNTH_NAME}",
            f"Phone: {SYNTH_PHONE}",
            f"Email: {SYNTH_EMAIL}",
        ],
        width=900,
        height=560,
    )


def make_rotated_png(rotation_degrees: int = 90) -> bytes:
    """Take the ID card image and rotate it by ``rotation_degrees``."""
    base = Image.open(io.BytesIO(make_id_card_png()))
    rotated = base.rotate(rotation_degrees, expand=True)
    buf = io.BytesIO()
    rotated.save(buf, format="PNG")
    return buf.getvalue()


def make_landscape_png() -> bytes:
    """A pure-landscape PNG with no text content."""
    img = Image.new("RGB", (640, 400), (200, 220, 240))
    draw = ImageDraw.Draw(img)
    # Just some shapes — no glyphs.
    draw.rectangle((40, 40, 600, 360), outline=(50, 100, 150), width=4)
    draw.ellipse((100, 100, 540, 300), fill=(120, 180, 220))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_multipage_tiff() -> bytes:
    """3-page TIFF; one synthetic PII per page (RRN, phone, email)."""
    pages = [
        Image.open(io.BytesIO(_text_image(
            ["Page 1 - SYNTHETIC", f"RRN: {SYNTH_RRN}"],
            width=700, height=300,
        ))),
        Image.open(io.BytesIO(_text_image(
            ["Page 2 - SYNTHETIC", f"Phone: {SYNTH_PHONE}"],
            width=700, height=300,
        ))),
        Image.open(io.BytesIO(_text_image(
            ["Page 3 - SYNTHETIC", f"Email: {SYNTH_EMAIL}"],
            width=700, height=300,
        ))),
    ]
    buf = io.BytesIO()
    pages[0].save(
        buf,
        format="TIFF",
        save_all=True,
        append_images=pages[1:],
    )
    return buf.getvalue()


def make_oversized_png(target_bytes: int) -> bytes:
    """Build a PNG larger than ``target_bytes`` for the size-limit test.

    Uses a noisy random buffer so PNG can't compress it to ~nothing. We
    write a minimal valid PNG header and append junk after — but cleaner
    is to actually construct a noisy bitmap, which is what we do here.
    """
    import os

    # Pick a square big enough that the PNG payload exceeds target_bytes.
    # Empirically PNG with random RGB ≈ width*height*3 bytes (incompressible).
    side = int((target_bytes / 3) ** 0.5) + 200
    raw = os.urandom(side * side * 3)
    img = Image.frombytes("RGB", (side, side), raw)
    buf = io.BytesIO()
    img.save(buf, format="PNG", compress_level=0)
    return buf.getvalue()
