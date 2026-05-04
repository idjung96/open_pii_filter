# SYNTHETIC DATA - NOT REAL PII
"""Phase 5 OCR + image PII tests (T5.1~T5.8).

VLM-bound tests are gated on a connectivity probe so they skip cleanly
when the internal Qwen-VL endpoint is unreachable from the dev box.
The rest of the suite (size limits, error mapping, masking, fallback
parsing) runs offline.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.config import get_settings
from app.extractors.fetcher import ExtractionError
from app.extractors.ocr import MAX_OCR_IMAGE_BYTES, ocr_image
from app.extractors.ocr_vlm import OCRBox, OCRResult, _parse_response
from tests.fixtures.attachments.create_image_fixtures import (
    SYNTH_PHONE,
    SYNTH_RRN,
    make_business_card_png,
    make_id_card_png,
    make_landscape_png,
    make_multipage_tiff,
    make_oversized_png,
    make_rotated_png,
)

if TYPE_CHECKING:
    pass


def _vlm_reachable() -> bool:
    """Probe the VLM endpoint synchronously with a short timeout."""
    settings = get_settings()
    base = settings.vlm_endpoint.rstrip("/")
    try:
        r = httpx.get(f"{base}/models", timeout=3.0)
        return r.status_code < 500
    except (httpx.HTTPError, httpx.TimeoutException, OSError):
        return False


vlm_required = pytest.mark.skipif(
    not _vlm_reachable(), reason="VLM endpoint unreachable from this box"
)


async def _ocr_or_skip(data: bytes, filename: str, mime_type: str):  # type: ignore[no-untyped-def]
    """Wrapper that ``pytest.skip``s when the VLM SLA times out.

    The integration test suite isn't responsible for VLM latency
    regressions — we have ``test_t5_7_vlm_unavailable_maps_to_svr_5004``
    for that — so a real VLM timeout becomes a soft skip.
    """
    try:
        return await ocr_image(data, filename, mime_type)
    except ExtractionError as e:
        if e.code == "SVR-5004":
            pytest.skip(f"VLM unavailable / slow: {e}")
        raise


# ── T5.1: ID-card PNG → RRN detected ──────────────────────────────────────
@vlm_required
async def test_t5_1_id_card_ocr_detects_rrn() -> None:
    data = make_id_card_png()
    res = await _ocr_or_skip(data, "id.png", "image/png")
    assert res.text, "VLM returned empty text for ID card"
    # ASCII RRN digits should survive any reasonable OCR engine.
    digits = SYNTH_RRN.replace("-", "")
    text_no_punc = res.text.replace("-", "").replace(" ", "")
    assert digits in text_no_punc or SYNTH_RRN in res.text, (
        f"expected RRN substring in OCR result; got: {res.text!r}"
    )


# ── T5.2: Business card PNG → phone + email detected ─────────────────────
@vlm_required
async def test_t5_2_business_card_ocr_detects_phone_email() -> None:
    data = make_business_card_png()
    res = await _ocr_or_skip(data, "card.png", "image/png")
    assert res.text
    # Phone digits should at least appear (with or without hyphens).
    phone_digits = SYNTH_PHONE.replace("-", "")
    text_digits = "".join(ch for ch in res.text if ch.isdigit())
    assert phone_digits in text_digits, (
        f"expected phone {phone_digits} in OCR digits; got {text_digits!r}"
    )
    # Email is more brittle; check for the local-or-domain substring.
    assert "example.com" in res.text or "synth" in res.text, (
        f"expected email fragment in OCR result; got: {res.text!r}"
    )


# ── T5.3: masked image PII recovery — Phase 9D 에서 마스킹 폐기로 삭제 ─────


# ── T5.4: rotated PNG still OCRs ──────────────────────────────────────────
@vlm_required
async def test_t5_4_rotated_image_ocr_works() -> None:
    data = make_rotated_png(90)
    res = await _ocr_or_skip(data, "rot.png", "image/png")
    # OCR should still recover at least the digit run from the RRN.
    digits = SYNTH_RRN.replace("-", "")
    text_digits = "".join(ch for ch in res.text if ch.isdigit())
    assert any(piece in text_digits for piece in (digits, digits[:6])), (
        f"rotated OCR missed RRN: {res.text!r}"
    )


# ── T5.5: pure-landscape PNG → 0 detections, no leak ──────────────────────
@vlm_required
async def test_t5_5_landscape_no_text() -> None:
    data = make_landscape_png()
    res = await _ocr_or_skip(data, "scene.png", "image/png")
    # Allow some hallucinated noise but assert no PII-shaped digit runs.
    digits = "".join(ch for ch in res.text if ch.isdigit())
    # 13-digit RRN-shaped run shouldn't appear out of nowhere.
    long_run = max(
        (len(seg) for seg in __import__("re").findall(r"\d+", digits)),
        default=0,
    )
    assert long_run < 11, f"landscape image hallucinated digit run: {res.text!r}"


# ── T5.6: multi-page TIFF → all pages OCR'd ──────────────────────────────
@vlm_required
async def test_t5_6_multipage_tiff() -> None:
    data = make_multipage_tiff()
    res = await _ocr_or_skip(data, "multi.tiff", "image/tiff")
    # All three pages should contribute to the text.
    digits = "".join(ch for ch in res.text if ch.isdigit())
    rrn_digits = SYNTH_RRN.replace("-", "")
    phone_digits = SYNTH_PHONE.replace("-", "")
    assert rrn_digits[:6] in digits, "page 1 RRN missing"
    assert phone_digits[:7] in digits, "page 2 phone missing"
    assert "example.com" in res.text or "synth" in res.text, "page 3 email missing"


# ── T5.7: VLM 5xx → ExtractionError(SVR-5004) ─────────────────────────────
async def test_t5_7_vlm_unavailable_maps_to_svr_5004() -> None:
    """Mock the VLM endpoint to always 503; ocr_image must surface SVR-5004."""

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="model down")

    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, "__init__", patched_init):
        data = make_business_card_png()
        with pytest.raises(ExtractionError) as exc:
            await ocr_image(data, "card.png", "image/png")
        assert exc.value.code == "SVR-5004"


# ── T5.8: 100+ MB image → REQ-4031 ────────────────────────────────────────
async def test_t5_8_oversized_image_rejected() -> None:
    # Construct a payload deliberately above the threshold.
    target = MAX_OCR_IMAGE_BYTES + 1024 * 1024  # +1 MB headroom
    payload = make_oversized_png(target)
    assert len(payload) > MAX_OCR_IMAGE_BYTES
    with pytest.raises(ExtractionError) as exc:
        await ocr_image(payload, "huge.png", "image/png")
    assert exc.value.code == "REQ-4031"


# ── Unit: VLM JSON parser robustness ──────────────────────────────────────
def test_parse_response_strips_fences() -> None:
    fenced = '```json\n{"text": "hi", "blocks": []}\n```'
    text, boxes = _parse_response(fenced)
    assert text == "hi"
    assert boxes == []


def test_parse_response_handles_garbage() -> None:
    text, boxes = _parse_response("totally not json")
    assert text == ""
    assert boxes == []


def test_parse_response_normalises_box_order() -> None:
    raw = '{"text": "x", "blocks": [{"bbox": [10, 30, 5, 20], "text": "abc"}]}'
    text, boxes = _parse_response(raw)
    assert text == "x"
    assert len(boxes) == 1
    b = boxes[0]
    assert b.x1 <= b.x2
    assert b.y1 <= b.y2
    assert b.text == "abc"


# Phase 9D — image_masking 단위 테스트 삭제 (mask_image 제거됨).


def test_ocrresult_dataclass() -> None:
    r = OCRResult(text="hi", boxes=[OCRBox(0, 0, 10, 10, "hi")], width=100, height=50)
    assert r.text == "hi"
    assert r.boxes[0].text == "hi"
    assert r.width == 100


# ── Engine dispatch sanity checks ─────────────────────────────────────────
def test_paddle_unavailable_falls_back_to_vlm() -> None:
    """Even with ocr_engine="paddle", missing paddleocr falls through to VLM."""
    from app.extractors.ocr_paddle import is_paddle_available

    # In this environment paddle is not installed; sanity-check the helper.
    assert is_paddle_available() is False


async def test_ocr_image_uses_vlm_when_engine_paddle_but_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When paddle is requested but absent, fallback path calls vlm_ocr."""
    from app.extractors import ocr as ocr_mod
    from app.extractors.ocr_vlm import OCRResult as _OCRResult

    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: type(
            "S",
            (),
            {
                "ocr_engine": "paddle",
                "vlm_endpoint": "http://x/v1",
                "vlm_model_id": "x",
                "vlm_api_key": "",
                "ocr_request_timeout_seconds": 1.0,
            },
        )(),
    )

    fake = AsyncMock(return_value=_OCRResult(text="ok", boxes=[], width=10, height=10))
    monkeypatch.setattr(ocr_mod, "vlm_ocr", fake)

    from PIL import Image

    img_bytes_buf = __import__("io").BytesIO()
    Image.new("RGB", (50, 50), (255, 255, 255)).save(img_bytes_buf, format="PNG")
    res = await ocr_mod.ocr_image(img_bytes_buf.getvalue(), "x.png", "image/png")
    assert res.text == "ok"
    assert fake.await_count == 1


async def test_concurrent_ocr_image_requests_dont_share_state() -> None:
    """Smoke check that multiple concurrent calls don't share a global VLM client."""

    # Mock the network so we can fire 5 in parallel.
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"text": "ok", "blocks": []}'}}]},
        )

    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    with patch.object(httpx.AsyncClient, "__init__", patched_init):
        from PIL import Image

        img_buf = __import__("io").BytesIO()
        Image.new("RGB", (50, 50), (255, 255, 255)).save(img_buf, format="PNG")
        data = img_buf.getvalue()
        results = await asyncio.gather(
            *[ocr_image(data, f"img{i}.png", "image/png") for i in range(5)]
        )
    assert all(r.text == "ok" for r in results)
