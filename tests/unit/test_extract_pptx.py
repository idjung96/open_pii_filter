# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `app.extractors.pptx.extract_pptx`.

Verifies:
  - body text from a regular slide shape is harvested
  - speaker notes contribute to the output (institutions often paste
    PII into note frames)
  - encrypted (MS-CFB) presentation surfaces REQ-4051
  - corrupted (non-ZIP) blob surfaces REQ-4042
"""

from __future__ import annotations

import pytest

from app.extractors.fetcher import ExtractionError
from app.extractors.pptx import extract_pptx
from tests.fixtures.attachments.create_fixtures import (
    SYNTH_EMAIL,
    SYNTH_TEXT,
    make_pptx_with_pii,
)


async def test_extract_pptx_returns_text_and_notes() -> None:
    text = await extract_pptx(make_pptx_with_pii(), "synthetic.pptx")
    assert SYNTH_TEXT in text
    # Speaker notes from slide 2 must also be reachable.
    assert SYNTH_EMAIL in text


async def test_extract_pptx_rejects_encrypted_blob() -> None:
    encrypted = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    with pytest.raises(ExtractionError) as excinfo:
        await extract_pptx(encrypted, "secret.pptx")
    assert excinfo.value.code == "REQ-4051"


async def test_extract_pptx_rejects_corrupt_zip() -> None:
    with pytest.raises(ExtractionError) as excinfo:
        await extract_pptx(b"definitely not a zip", "broken.pptx")
    assert excinfo.value.code == "REQ-4042"
