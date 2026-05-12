# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — 신규 첨부 형식 (XLSX/PPTX/Markdown) 의 dispatcher 라우팅.

`dispatch_extract` 가 MIME 별로 올바른 추출기에 위임하고, 그 결과 텍스트
안에 합성 PII (전화번호 / 이메일) 가 보존되어 분석기가 잡아낼 수 있는지를
한 번에 검증한다. 이미지 / 스캔 PDF / OCR 분기는 `test_phase5_*` 가
담당하며 이 모듈은 xlsx / pptx / markdown 만 책임진다.
"""

from __future__ import annotations

import pytest

from app.api.schemas import Attachment
from app.extractors.dispatcher import dispatch_extract
from tests.fixtures.attachments.create_fixtures import (
    SYNTH_EMAIL,
    SYNTH_PHONE,
    SYNTH_TEXT,
    make_markdown_with_pii,
    make_pptx_with_pii,
    make_xlsx_with_pii,
)


def _att(*, mime: str, filename: str, payload: bytes) -> Attachment:
    """테스트 입력용 Attachment 객체 — `fetch_url`/`sha256` 은 더미 값.

    `dispatch_extract` 는 bytes 입력만 보므로 fetch URL/checksum 은
    실제 의미를 갖지 않는다. 스키마 검증 통과를 위해 형식만 맞춰준다.
    """
    return Attachment(
        attachment_id="att_001",
        filename=filename,
        size_bytes=len(payload),
        mime_type=mime,
        sha256="0" * 64,
        fetch_url="https://example.test/x",
    )


@pytest.mark.parametrize(
    ("mime", "filename", "factory", "expected_substrings"),
    [
        (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "synthetic.xlsx",
            make_xlsx_with_pii,
            (SYNTH_TEXT, SYNTH_PHONE),
        ),
        (
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "synthetic.pptx",
            make_pptx_with_pii,
            (SYNTH_TEXT, SYNTH_EMAIL),
        ),
        (
            "text/markdown",
            "synthetic.md",
            make_markdown_with_pii,
            (SYNTH_TEXT, SYNTH_PHONE),
        ),
    ],
)
async def test_dispatch_routes_each_new_format_to_text(
    mime: str,
    filename: str,
    factory,  # type: ignore[no-untyped-def]
    expected_substrings: tuple[str, ...],
) -> None:
    """3개 MIME (XLSX/PPTX/Markdown) 각각에 대해 추출 → 합성 PII 보존 확인.

    각 케이스:
      - 합성 fixture 를 만들어 dispatcher 에 흘리고
      - `needs_ocr=False` 가 반환되며 (텍스트 컨테이너이므로 OCR 미사용)
      - 결과 텍스트에 fixture 가 심어둔 PII 토큰이 그대로 남아 있어야 함

    이 검증이 실패하면 추출기 자체에 회귀가 있거나 dispatcher MIME 매핑
    오류 — 어느 쪽이든 첨부 검사가 무력화되는 큰 사고로 이어진다.
    """
    payload = factory()
    text, needs_ocr = await dispatch_extract(
        payload, _att(mime=mime, filename=filename, payload=payload)
    )
    assert needs_ocr is False
    for needle in expected_substrings:
        assert needle in text, f"{needle!r} not in extracted text for {mime}"
