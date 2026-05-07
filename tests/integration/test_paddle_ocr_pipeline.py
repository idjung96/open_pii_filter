# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — PaddleOCR is the default engine.

The suite drives the existing image fixtures (`make_id_card_png`,
`make_business_card_png`) through the dispatcher with `OCR_ENGINE=paddle`
to confirm:

- Paddle returns text + boxes when the engine is reachable
- The synthetic RRN / phone number embedded in the fixture survives
  the round-trip (i.e., the analyser sees PII it can recognise)
- The dispatcher's paddle → vlm fallback fires when paddle raises
  (regression for the auto-recovery path)
- Switching `Settings.ocr_engine="vlm"` skips the paddle code path
  entirely

Tests skip cleanly when `paddleocr` is not importable — useful in CI
images that strip the heavy paddle wheel for footprint reasons.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from app.extractors.ocr import _run_engine
from app.extractors.ocr_paddle import is_paddle_available
from tests.fixtures.attachments.create_image_fixtures import (
    SYNTH_PHONE,
    SYNTH_RRN,
    make_business_card_png,
    make_id_card_png,
)

if TYPE_CHECKING:
    pass


# Auto-skip the entire module when the paddle wheel is unavailable in
# the test runtime — keeps the suite green on CPU-stripped CI images.
pytestmark = pytest.mark.skipif(
    not is_paddle_available(),
    reason="paddleocr is not installed in this environment",
)


def _png_to_pil_image(data: bytes):  # type: ignore[no-untyped-def]
    import io

    from PIL import Image, ImageOps

    raw = Image.open(io.BytesIO(data))
    raw.load()
    return ImageOps.exif_transpose(raw) or raw


def _patch_engine_paddle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the dispatcher to take the paddle branch regardless of `.env`."""
    from app.config import Settings

    base = Settings().model_dump()
    base["ocr_engine"] = "paddle"
    fake = lambda: Settings(**base)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.extractors.ocr as ocr_mod

    monkeypatch.setattr(ocr_mod, "get_settings", fake, raising=False)


def _patch_engine_vlm(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import Settings

    base = Settings().model_dump()
    base["ocr_engine"] = "vlm"
    fake = lambda: Settings(**base)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.extractors.ocr as ocr_mod

    monkeypatch.setattr(ocr_mod, "get_settings", fake, raising=False)


# ── TC-1.7 / TC-1.8: Paddle returns text for the canonical ID-card sample ──
async def test_paddle_runs_on_id_card_sample(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_engine_paddle(monkeypatch)
    image = _png_to_pil_image(make_id_card_png())
    result = await _run_engine(image, filename="id.png")
    # Paddle does not always render Hangul (depends on font availability)
    # but the digit runs we care about (RRN) come through reliably.
    assert SYNTH_RRN in result.text or "900101" in result.text, result.text


async def test_paddle_extracts_phone_from_business_card(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_engine_paddle(monkeypatch)
    image = _png_to_pil_image(make_business_card_png())
    result = await _run_engine(image, filename="biz.png")
    assert SYNTH_PHONE in result.text or "010-0000-1234" in result.text, result.text


# ── TC-D.1: paddle → vlm fallback fires when paddle raises ─────────────────
async def test_paddle_failure_falls_back_to_vlm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When paddle is the chosen engine but raises, the dispatcher must
    silently route the request through to the VLM path."""
    _patch_engine_paddle(monkeypatch)

    async def _boom(_image):  # type: ignore[no-untyped-def]
        raise RuntimeError("simulated paddle crash")

    async def _fake_vlm(image, *, settings):  # type: ignore[no-untyped-def]
        from app.extractors.ocr_vlm import OCRResult

        return OCRResult(
            text="vlm-fallback-output", boxes=[], width=image.width, height=image.height
        )

    import app.extractors.ocr as ocr_mod

    monkeypatch.setattr("app.extractors.ocr_paddle.paddle_ocr", _boom)
    monkeypatch.setattr(ocr_mod, "vlm_ocr", _fake_vlm)

    image = _png_to_pil_image(make_id_card_png())
    result = await _run_engine(image, filename="fallback.png")
    assert result.text == "vlm-fallback-output"


# ── TC-D.2: OCR_ENGINE=vlm bypasses paddle entirely ─────────────────────────
async def test_vlm_setting_skips_paddle(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_engine_vlm(monkeypatch)

    paddle_called = {"n": 0}

    async def _no(_image):  # type: ignore[no-untyped-def]
        paddle_called["n"] += 1
        return

    async def _fake_vlm(image, *, settings):  # type: ignore[no-untyped-def]
        from app.extractors.ocr_vlm import OCRResult

        return OCRResult(text="ok", boxes=[], width=image.width, height=image.height)

    import app.extractors.ocr as ocr_mod

    monkeypatch.setattr("app.extractors.ocr_paddle.paddle_ocr", _no)
    monkeypatch.setattr(ocr_mod, "vlm_ocr", _fake_vlm)

    image = _png_to_pil_image(make_id_card_png())
    result = await _run_engine(image, filename="vlm.png")
    assert result.text == "ok"
    assert paddle_called["n"] == 0
