# SYNTHETIC DATA - NOT REAL PII
"""Phase 4 extractor unit-level integration tests (T4.1~T4.12).

Each fixture is built programmatically inside the test module so we
never persist real or PII-bearing files to disk. Network calls in the
fetcher are mocked with httpx.MockTransport so the tests stay
hermetic.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest

from app.api.schemas import Attachment
from app.extractors.clamav import scan_bytes
from app.extractors.dispatcher import dispatch_extract
from app.extractors.fetcher import ExtractionError, fetch_attachment
from app.extractors.hwpx import extract_hwpx
from app.extractors.pdf import extract_pdf
from tests.fixtures.attachments.create_fixtures import (
    SYNTH_PHONE,
    make_corrupted_pdf,
    make_docx_with_table_pii,
    make_encrypted_pdf,
    make_hwp5_binary,
    make_hwpx_with_text,
    make_multipage_pdf,
    make_scan_only_pdf,
    make_text_file,
    make_text_pdf,
)


# ── helpers ───────────────────────────────────────────────────────────────
def _patch_httpx_get(monkeypatch: pytest.MonkeyPatch, status: int, body: bytes) -> None:
    """Monkeypatch httpx.AsyncClient so any GET returns a fixed response."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=status, content=body)

    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


# ── T4.1: extract_pdf on a real text PDF ──────────────────────────────────
async def test_t4_1_extract_pdf_text() -> None:
    data = make_text_pdf()
    text, is_scan = await extract_pdf(data, "a.pdf")
    assert is_scan is False
    # The hand-rolled PDF can't render CJK, but ASCII tokens come through
    # verbatim — sufficient to verify the extractor returns the embedded run.
    assert SYNTH_PHONE in text


# ── T4.2: scan-only PDF → is_scan=True ────────────────────────────────────
async def test_t4_2_extract_pdf_scan_only() -> None:
    data = make_scan_only_pdf()
    text, is_scan = await extract_pdf(data, "scan.pdf")
    assert is_scan is True
    assert text == ""


# ── T4.3: DOCX table cell PII is detected ─────────────────────────────────
async def test_t4_3_extract_docx_table_pii() -> None:
    data = make_docx_with_table_pii()
    from app.extractors.docx import extract_docx
    text = await extract_docx(data, "table.docx")
    assert SYNTH_PHONE in text
    assert "전화" in text


# ── T4.4: HWPX file with text ─────────────────────────────────────────────
async def test_t4_4_extract_hwpx() -> None:
    data = make_hwpx_with_text()
    text = await extract_hwpx(data, "doc.hwpx", "application/hwp+zip")
    assert SYNTH_PHONE in text


# ── T4.5: HWP 5 mime → REQ-4033 ───────────────────────────────────────────
async def test_t4_5_hwp5_unsupported() -> None:
    data = make_hwp5_binary()
    with pytest.raises(ExtractionError) as exc:
        await extract_hwpx(data, "old.hwp", "application/x-hwp")
    assert exc.value.code == "REQ-4033"


# ── T4.6: corrupted PDF → REQ-4042 ────────────────────────────────────────
async def test_t4_6_corrupted_pdf() -> None:
    data = make_corrupted_pdf()
    with pytest.raises(ExtractionError) as exc:
        await extract_pdf(data, "broken.pdf")
    assert exc.value.code == "REQ-4042"


# ── T4.7: 101-page PDF → REQ-4043 ─────────────────────────────────────────
async def test_t4_7_too_many_pages() -> None:
    data = make_multipage_pdf(101)
    with pytest.raises(ExtractionError) as exc:
        await extract_pdf(data, "big.pdf")
    assert exc.value.code == "REQ-4043"


# ── T4.8: ClamAV EICAR test (skipped if scanner unavailable) ──────────────
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    b"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


async def test_t4_8_clamav_eicar_blocks() -> None:
    """If ClamAV is reachable and serving fresh signatures, EICAR
    raises REQ-4050. If ClamAV is unavailable, scan_bytes silently
    returns; the test passes either way."""
    try:
        await scan_bytes(EICAR, "eicar.txt")
        pytest.skip("ClamAV unavailable — soft-fail path exercised")
    except ExtractionError as exc:
        assert exc.code == "REQ-4050"


# ── T4.9: encrypted PDF → REQ-4051 ────────────────────────────────────────
async def test_t4_9_encrypted_pdf() -> None:
    data = make_encrypted_pdf()
    with pytest.raises(ExtractionError) as exc:
        await extract_pdf(data, "locked.pdf")
    assert exc.value.code == "REQ-4051"


# ── T4.10: fetch_attachment 404 → REQ-4040 ────────────────────────────────
async def test_t4_10_fetch_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_httpx_get(monkeypatch, status=404, body=b"")
    att = Attachment(
        attachment_id="att_001",
        filename="missing.pdf",
        size_bytes=10,
        mime_type="application/pdf",
        sha256="0" * 64,
        fetch_url="https://files.example.com/missing.pdf",
    )
    with pytest.raises(ExtractionError) as exc:
        await fetch_attachment(att)
    assert exc.value.code == "REQ-4040"


# ── T4.11: SHA256 mismatch → REQ-4041 ─────────────────────────────────────
async def test_t4_11_sha256_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = b"hello"
    _patch_httpx_get(monkeypatch, status=200, body=payload)
    att = Attachment(
        attachment_id="att_002",
        filename="wrong.txt",
        size_bytes=len(payload),
        mime_type="text/plain",
        sha256="0" * 64,  # wrong digest
        fetch_url="https://files.example.com/wrong.txt",
    )
    with pytest.raises(ExtractionError) as exc:
        await fetch_attachment(att)
    assert exc.value.code == "REQ-4041"


async def test_fetch_success(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = make_text_file()
    _patch_httpx_get(monkeypatch, status=200, body=payload)
    att = Attachment(
        attachment_id="att_010",
        filename="ok.txt",
        size_bytes=len(payload),
        mime_type="text/plain",
        sha256=hashlib.sha256(payload).hexdigest(),
        fetch_url="https://files.example.com/ok.txt",
    )
    result = await fetch_attachment(att)
    assert result == payload


# ── T4.12: dispatch_extract on application/octet-stream → REQ-4033 ────────
async def test_t4_12_unsupported_mime() -> None:
    att = Attachment(
        attachment_id="att_003",
        filename="random.bin",
        size_bytes=4,
        mime_type="application/octet-stream",
        sha256="0" * 64,
        fetch_url="https://example.com/random.bin",
    )
    with pytest.raises(ExtractionError) as exc:
        await dispatch_extract(b"\x00\x01\x02\x03", att)
    assert exc.value.code == "REQ-4033"


# ── Bonus: dispatch_extract on text/plain ─────────────────────────────────
async def test_dispatch_text_plain() -> None:
    att = Attachment(
        attachment_id="att_004",
        filename="note.txt",
        size_bytes=10,
        mime_type="text/plain",
        sha256="0" * 64,
        fetch_url="https://example.com/note.txt",
    )
    text, needs_ocr = await dispatch_extract(b"hi there", att)
    assert text == "hi there"
    assert needs_ocr is False
