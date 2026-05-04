# SYNTHETIC DATA - NOT REAL PII
"""Phase 5 scan-PDF auto-OCR routing tests.

Verifies that ``extract_pdf`` returning ``is_scan=True`` causes the
dispatcher to render every PDF page via pypdfium2 and run OCR. Most
assertions here use mocks so the test stays hermetic and fast; the
end-to-end VLM path is exercised by ``test_phase5_ocr.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from app.api.schemas import Attachment
from app.extractors.dispatcher import dispatch_extract
from app.extractors.ocr_vlm import OCRBox, OCRResult

if TYPE_CHECKING:
    pass


def _attachment(*, filename: str = "scan.pdf", mime_type: str = "application/pdf") -> Attachment:
    return Attachment(
        attachment_id="att_001",
        filename=filename,
        size_bytes=10,
        mime_type=mime_type,
        sha256="0" * 64,
        fetch_url="https://files.example.com/scan.pdf",
    )


# ── dispatch_extract on a scan PDF triggers OCR ──────────────────────────
async def test_scan_pdf_routes_through_ocr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When extract_pdf reports is_scan=True the dispatcher must call OCR."""
    from PIL import Image

    fake_pages = [
        Image.new("RGB", (200, 100), (255, 255, 255)),
        Image.new("RGB", (200, 100), (255, 255, 255)),
    ]

    async def fake_extract_pdf(_data: bytes, _filename: str) -> tuple[str, bool]:
        return "", True

    async def fake_render_pages(_data: bytes, _filename: str) -> list:
        return fake_pages

    fake_ocr = AsyncMock(
        return_value=OCRResult(
            text="page1 RRN 900101-1234567\npage2 phone 010-0000-1234",
            boxes=[
                OCRBox(0, 0, 50, 20, "RRN 900101-1234567"),
                OCRBox(0, 100, 50, 120, "phone 010-0000-1234"),
            ],
            width=200,
            height=200,
        )
    )

    monkeypatch.setattr("app.extractors.dispatcher.extract_pdf", fake_extract_pdf)
    monkeypatch.setattr("app.extractors.dispatcher.render_pdf_pages", fake_render_pages)
    monkeypatch.setattr("app.extractors.dispatcher.ocr_pil_pages", fake_ocr)

    text, needs_ocr = await dispatch_extract(b"%PDF-fake", _attachment())
    assert needs_ocr is True
    assert "900101-1234567" in text
    assert "010-0000-1234" in text
    fake_ocr.assert_awaited_once()


# ── dispatch_extract on a text PDF skips OCR ──────────────────────────────
async def test_text_pdf_skips_ocr(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_extract_pdf(_data: bytes, _filename: str) -> tuple[str, bool]:
        return "this is text", False

    fake_render = AsyncMock()
    fake_ocr = AsyncMock()
    monkeypatch.setattr("app.extractors.dispatcher.extract_pdf", fake_extract_pdf)
    monkeypatch.setattr("app.extractors.dispatcher.render_pdf_pages", fake_render)
    monkeypatch.setattr("app.extractors.dispatcher.ocr_pil_pages", fake_ocr)

    text, needs_ocr = await dispatch_extract(b"%PDF-fake", _attachment())
    assert needs_ocr is False
    assert text == "this is text"
    fake_render.assert_not_awaited()
    fake_ocr.assert_not_awaited()


# Phase 9D — masked_url 검증 테스트 삭제 (마스킹 인프라 폐기).
