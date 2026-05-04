"""MIME → extractor dispatcher (Phase 4 + Phase 5).

Single fan-out point so the orchestrator never needs to branch on
``mime_type`` itself.

Phase 4 returned ``(text, needs_ocr)`` where ``needs_ocr=True`` only
for scan-only PDFs. Phase 5 collapses that branch by running OCR
inline: scan PDFs and image attachments now produce text + bounding
boxes inside the dispatcher and the orchestrator no longer has to
care which family of files needed OCR.

For image attachments and scan PDFs the orchestrator also wants to
produce a masked image artifact (Phase 5, T5.3). Those callers should
use :func:`extract_image` / :func:`render_pdf_pages` directly so they
get the source PIL frames + per-block boxes alongside the extracted
text.
"""

from __future__ import annotations

import asyncio
import io
import logging
from typing import TYPE_CHECKING

from app.extractors.docx import extract_docx
from app.extractors.fetcher import ExtractionError
from app.extractors.hwpx import HWP5_MIMES, extract_hwpx
from app.extractors.ocr import IMAGE_MIME_TYPES, ocr_image, ocr_pil_pages
from app.extractors.ocr_vlm import OCRBox, OCRResult
from app.extractors.pdf import extract_pdf

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

    from app.api.schemas import Attachment

logger = logging.getLogger(__name__)

PDF_MIMES = frozenset({"application/pdf"})
DOCX_MIMES = frozenset({
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
})
HWPX_MIMES = frozenset({
    "application/hwp+zip",
    "application/x-hwpx",
    "application/haansofthwpx",
})
TEXT_MIMES = frozenset({"text/plain"})


def _render_pdf_pages_sync(data: bytes, filename: str) -> list[PILImage]:
    """Render every page of a scan PDF to a PIL image (300 DPI default)."""
    import pypdfium2  # type: ignore[import-untyped]
    from PIL import Image

    try:
        pdf = pypdfium2.PdfDocument(io.BytesIO(data))
    except Exception as e:
        raise ExtractionError(
            "REQ-4042", filename=filename, detail=f"pdfium open failed: {e}"
        ) from e

    pages: list[PILImage] = []
    try:
        for i in range(len(pdf)):
            page = pdf[i]
            try:
                # 200 DPI is a reasonable trade-off for OCR accuracy vs.
                # memory; pypdfium2 uses 72 DPI as the unit so scale=200/72.
                bitmap = page.render(scale=200 / 72)
                pil = bitmap.to_pil()
                if not isinstance(pil, Image.Image):
                    raise ExtractionError(
                        "REQ-4042",
                        filename=filename,
                        detail="pdfium rendered non-PIL image",
                    )
                pages.append(pil)
            finally:
                page.close()
    finally:
        pdf.close()
    return pages


async def render_pdf_pages(data: bytes, filename: str) -> list[PILImage]:
    """Async wrapper around :func:`_render_pdf_pages_sync`."""
    return await asyncio.to_thread(_render_pdf_pages_sync, data, filename)


async def extract_image(
    data: bytes, attachment: Attachment
) -> tuple[OCRResult, PILImage]:
    """Run OCR on an image attachment and also return the source PIL image.

    The PIL image is needed by the orchestrator to draw masking
    rectangles (Phase 5).
    """
    from PIL import Image, ImageOps

    result = await ocr_image(data, attachment.filename, attachment.mime_type)
    # Re-open to get a fresh, EXIF-rotated PIL handle to mask on.
    raw = Image.open(io.BytesIO(data))
    raw.load()
    image: PILImage = ImageOps.exif_transpose(raw) or raw
    if image.mode not in {"RGB", "L"}:
        image = image.convert("RGB")
    return result, image


async def dispatch_extract(
    data: bytes, attachment: Attachment
) -> tuple[str, bool]:
    """Extract plaintext from ``data`` based on ``attachment.mime_type``.

    Returns:
        (text, needs_ocr): ``needs_ocr`` is informational only — it stays
        True for image attachments and scan PDFs so callers that want
        the *masked artifact* path know to take it. Body text is always
        populated when extraction (incl. OCR) succeeds.

    Raises:
        ExtractionError(REQ-4033): unsupported MIME (incl. HWP 5)
        ExtractionError(REQ-404x/REQ-4051): per-extractor failure modes
        ExtractionError(SVR-5004): OCR engine unavailable
    """
    mime = attachment.mime_type

    if mime in PDF_MIMES:
        text, is_scan = await extract_pdf(data, attachment.filename)
        if not is_scan:
            return text, False
        # Scan-only PDF → render + OCR every page.
        pages = await render_pdf_pages(data, attachment.filename)
        if not pages:
            return "", True
        ocr = await ocr_pil_pages(pages, filename=attachment.filename)
        return ocr.text, True

    if mime in DOCX_MIMES:
        text = await extract_docx(data, attachment.filename)
        return text, False

    if mime in HWPX_MIMES:
        text = await extract_hwpx(data, attachment.filename, mime)
        return text, False

    if mime in HWP5_MIMES:
        # The HWP 5 binary format has no Linux-compatible parser under
        # an acceptable license; surface as unsupported.
        raise ExtractionError(
            "REQ-4033",
            filename=attachment.filename,
            detail=f"mime_type {mime} unsupported (HWP 5)",
        )

    if mime in IMAGE_MIME_TYPES:
        ocr = await ocr_image(data, attachment.filename, mime)
        return ocr.text, True

    if mime in TEXT_MIMES:
        try:
            return data.decode("utf-8"), False
        except UnicodeDecodeError:
            try:
                return data.decode("cp949"), False
            except UnicodeDecodeError as e:
                raise ExtractionError(
                    "REQ-4042",
                    filename=attachment.filename,
                    detail="undecodable text payload",
                ) from e

    raise ExtractionError(
        "REQ-4033",
        filename=attachment.filename,
        detail=f"mime_type {mime} unsupported",
    )


__all__ = [
    "DOCX_MIMES",
    "HWPX_MIMES",
    "IMAGE_MIME_TYPES",
    "PDF_MIMES",
    "TEXT_MIMES",
    "OCRBox",
    "OCRResult",
    "dispatch_extract",
    "extract_image",
    "render_pdf_pages",
]
