# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — dispatcher routing for the new attachment formats.

Walks the dispatch matrix end-to-end at the unit level: every
supported MIME yields the synthetic PII strings the analyzer would
key off of. Image / scan-PDF / OCR branches stay covered by the
existing `test_phase5_*` files; this module owns xlsx / pptx /
markdown only.
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
    payload = factory()
    text, needs_ocr = await dispatch_extract(
        payload, _att(mime=mime, filename=filename, payload=payload)
    )
    assert needs_ocr is False
    for needle in expected_substrings:
        assert needle in text, f"{needle!r} not in extracted text for {mime}"
