# SYNTHETIC DATA - NOT REAL PII
"""Phase 5 — 스캔 PDF 자동 OCR 라우팅 회귀 방지.

`extract_pdf` 가 `is_scan=True` 를 반환하면 dispatcher 가 pypdfium2 로 모든
페이지를 렌더한 뒤 OCR 파이프라인 (`ocr_pil_pages`) 으로 보내고, 그 결과
텍스트가 분석기까지 도달하는지 확인한다. 텍스트 레이어가 있는 PDF 는
OCR 을 건너뛰어야 한다는 반대 케이스도 함께 핀(pin).

대부분의 단언은 mock 기반으로 빠르고 결정적이며, 실 VLM 호출까지 포함한
end-to-end 경로는 `test_phase5_ocr.py` 가 담당한다.
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


# ── dispatch_extract: 스캔 PDF → OCR 경로 사용 ──────────────────────────
async def test_scan_pdf_routes_through_ocr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`is_scan=True` 일 때 dispatcher 가 OCR 까지 실행하고 RRN/전화번호를 추출.

    `extract_pdf` 가 `("", True)` (빈 텍스트 + 스캔 플래그) 를 반환하도록
    monkeypatch 한 뒤, 뒤따르는 `render_pdf_pages` + `ocr_pil_pages` 가
    실제로 호출되어 OCR 결과 텍스트 (`900101-1234567`, `010-0000-1234`) 가
    상위 호출자에게 전달되는지 확인.
    """
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


# ── dispatch_extract: 텍스트 레이어 있는 PDF → OCR 우회 ────────────────
async def test_text_pdf_skips_ocr(monkeypatch: pytest.MonkeyPatch) -> None:
    """텍스트 레이어가 있는 PDF 는 OCR 단계가 호출되지 않아야 한다.

    `extract_pdf` 가 텍스트 + `is_scan=False` 를 반환하면 더 비싼 OCR 경로
    (`render_pdf_pages` / `ocr_pil_pages`) 가 절대 호출되면 안 된다. CPU /
    Paddle 모델 로딩 비용 절약을 위해 매우 중요한 분기.
    """

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
