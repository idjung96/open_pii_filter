"""PDF text extraction (Phase 4, T4.1/T4.2/T4.6/T4.7/T4.9).

Strategy:
  1. ``pdfplumber`` is the primary text extractor (best layout fidelity).
  2. ``pypdfium2`` is the fallback when pdfplumber raises or yields no
     text on a non-encrypted, structurally valid PDF.
  3. Empty result on a healthy PDF is treated as a scan-only document
     and reported back via ``is_scan=True`` so the orchestrator can
     route to OCR (Phase 5).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from app.extractors.fetcher import ExtractionError

logger = logging.getLogger(__name__)

MAX_PAGES = 100
MAX_PDF_SIZE = 50 * 1024 * 1024  # 50 MB

# Hints that pdfplumber/pypdfium2 raise when a PDF is password-protected.
_ENCRYPTED_HINTS = ("encrypted", "password", "decrypt")


def _looks_encrypted(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(h in msg for h in _ENCRYPTED_HINTS)


def _has_encrypt_dict(data: bytes) -> bool:
    """Sniff the trailer for ``/Encrypt`` to catch crafted encrypted PDFs.

    Both pdfplumber and pypdfium2 occasionally surface encryption as a
    generic 'unknown filter' or low-level decode error rather than a
    password hint. Inspecting the raw bytes is the most reliable way
    to distinguish password-protected files from genuinely corrupted
    ones.
    """
    # Search the last 4 KB of the file (where the trailer/xref lives).
    tail = data[-4096:] if len(data) > 4096 else data
    return b"/Encrypt" in tail


def _extract_sync(data: bytes, filename: str) -> tuple[str, bool]:
    """Synchronous core run on a worker thread."""
    import io

    import pdfplumber
    import pypdfium2  # type: ignore[import-untyped]

    if len(data) > MAX_PDF_SIZE:
        raise ExtractionError(
            "REQ-4031",
            filename=filename,
            detail=f"size {len(data)} > {MAX_PDF_SIZE}",
        )

    # ── Pre-flight encryption sniff (T4.9) ────────────────────────────
    # pdfplumber / pypdfium2 don't always surface a "password" hint on
    # encrypted PDFs; checking the trailer for /Encrypt is the most
    # reliable cross-parser detector.
    if _has_encrypt_dict(data):
        raise ExtractionError(
            "REQ-4051", filename=filename, detail="password-protected"
        )

    # ── Page-count check via pypdfium2 (cheap; doesn't render) ────────
    try:
        pdf = pypdfium2.PdfDocument(io.BytesIO(data))
    except pypdfium2.PdfiumError as e:
        if _looks_encrypted(e):
            raise ExtractionError(
                "REQ-4051", filename=filename, detail="password-protected"
            ) from e
        raise ExtractionError(
            "REQ-4042", filename=filename, detail=str(e)
        ) from e
    except Exception as e:
        raise ExtractionError(
            "REQ-4042", filename=filename, detail=str(e)
        ) from e

    try:
        page_count = len(pdf)
    finally:
        with contextlib.suppress(Exception):
            pdf.close()

    if page_count > MAX_PAGES:
        raise ExtractionError(
            "REQ-4043",
            filename=filename,
            detail=f"page count {page_count} > {MAX_PAGES}",
        )

    # ── Primary path: pdfplumber ──────────────────────────────────────
    text_chunks: list[str] = []
    try:
        with pdfplumber.open(io.BytesIO(data)) as doc:
            for page in doc.pages:
                t = page.extract_text() or ""
                if t:
                    text_chunks.append(t)
    except Exception as e:
        if _looks_encrypted(e):
            raise ExtractionError(
                "REQ-4051", filename=filename, detail="password-protected"
            ) from e
        # Fall back to pypdfium2 instead of failing outright; some PDFs
        # break pdfplumber's layout heuristics but render fine via
        # pdfium's text API.
        logger.warning(
            "pdfplumber failed for %s (%s); trying pypdfium2", filename, e
        )

    text = "\n".join(text_chunks).strip()
    if text:
        return text, False

    # ── Fallback path: pypdfium2 ──────────────────────────────────────
    try:
        pdf = pypdfium2.PdfDocument(io.BytesIO(data))
        try:
            pages_text: list[str] = []
            for i in range(len(pdf)):
                page = pdf[i]
                tp = page.get_textpage()
                try:
                    pages_text.append(tp.get_text_range() or "")
                finally:
                    tp.close()
                page.close()
            text = "\n".join(pages_text).strip()
        finally:
            pdf.close()
    except Exception as e:
        if _looks_encrypted(e):
            raise ExtractionError(
                "REQ-4051", filename=filename, detail="password-protected"
            ) from e
        raise ExtractionError(
            "REQ-4042", filename=filename, detail=str(e)
        ) from e

    if text:
        return text, False
    # Healthy PDF with no embedded text → scan/image only.
    return "", True


async def extract_pdf(data: bytes, filename: str) -> tuple[str, bool]:
    """Extract text + scan-flag from a PDF byte string.

    Returns:
        (text, is_scan): ``is_scan=True`` when the PDF is structurally
        valid but contains no extractable text — caller should route
        to OCR (Phase 5).
    """
    return await asyncio.to_thread(_extract_sync, data, filename)
