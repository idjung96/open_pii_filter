# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `app.extractors.xlsx.extract_xlsx`.

Verifies:
  - text from every cell of every sheet is concatenated
  - numeric / non-string cell values are stringified (digit runs that
    look like RRNs or business numbers stay analysable)
  - encrypted (MS-CFB) workbook surfaces REQ-4051
  - corrupted (non-ZIP) blob surfaces REQ-4042
"""

from __future__ import annotations

import pytest

from app.extractors.fetcher import ExtractionError
from app.extractors.xlsx import extract_xlsx
from tests.fixtures.attachments.create_fixtures import (
    SYNTH_PHONE,
    SYNTH_TEXT,
    make_xlsx_with_pii,
)


async def test_extract_xlsx_returns_text_from_every_cell() -> None:
    text = await extract_xlsx(make_xlsx_with_pii(), "synthetic.xlsx")
    assert SYNTH_TEXT in text
    assert SYNTH_PHONE in text
    # The numeric cell A2 (1234567890) should also appear stringified —
    # PII patterns expect digit runs, not typed values.
    assert "1234567890" in text


async def test_extract_xlsx_rejects_encrypted_blob() -> None:
    encrypted = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    with pytest.raises(ExtractionError) as excinfo:
        await extract_xlsx(encrypted, "secret.xlsx")
    assert excinfo.value.code == "REQ-4051"


async def test_extract_xlsx_rejects_corrupt_zip() -> None:
    with pytest.raises(ExtractionError) as excinfo:
        await extract_xlsx(b"not a zip at all", "broken.xlsx")
    assert excinfo.value.code == "REQ-4042"
