"""OCR engine dispatcher (Phase 5).

Single fan-out point so the rest of the codebase doesn't need to know
which engine is active. Inputs:

  - raw image bytes (any of the supported MIME types)
  - filename (for error messages)
  - mime_type (for the multi-frame TIFF branch)

Outputs:

  - :class:`OCRResult` whose ``text`` is the concatenated OCR text and
    whose ``boxes`` are the per-block bounding boxes used downstream
    by :mod:`app.extractors.image_masking`. For multi-frame TIFFs the
    boxes from later frames are y-shifted so the canvas stack reads
    naturally top-to-bottom.

Limits:

  - ``MAX_OCR_IMAGE_BYTES`` — payload size (REQ-4031)
  - ``MAX_OCR_DIMENSION`` — pixel ceiling per side (downscaled in place)

Errors:

  - REQ-4031 — payload too large
  - REQ-4042 — corrupted / undecodable image
  - SVR-5004 — OCR engine unavailable (VLM 5xx, paddle OOM, etc.)
"""

from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING

from PIL import Image, ImageOps, UnidentifiedImageError

from app.config import get_settings
from app.extractors.fetcher import ExtractionError
from app.extractors.ocr_vlm import OCRBox, OCRResult, VLMError, vlm_ocr

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

logger = logging.getLogger(__name__)


MAX_OCR_IMAGE_BYTES = 100 * 1024 * 1024  # 100 MB
MAX_OCR_DIMENSION = 16384

IMAGE_MIME_TYPES = frozenset({
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/bmp",
    "image/webp",
    "image/gif",
})


def _open_image(data: bytes, filename: str) -> PILImage:
    """Open ``data`` as a PIL image, applying EXIF rotation."""
    try:
        img = Image.open(io.BytesIO(data))
        # Force the decoder to actually parse the bitmap so corruption
        # surfaces here (not on first .save() much later).
        img.load()
    except UnidentifiedImageError as e:
        raise ExtractionError(
            "REQ-4042", filename=filename, detail="unidentified image format"
        ) from e
    except Exception as e:
        raise ExtractionError(
            "REQ-4042", filename=filename, detail=f"image decode failed: {e}"
        ) from e
    return img


def _normalise(image: PILImage) -> PILImage:
    """Apply EXIF rotation + downscale-to-MAX_OCR_DIMENSION (preserve aspect)."""
    transposed: PILImage = ImageOps.exif_transpose(image)
    if transposed.width > MAX_OCR_DIMENSION or transposed.height > MAX_OCR_DIMENSION:
        transposed.thumbnail(
            (MAX_OCR_DIMENSION, MAX_OCR_DIMENSION), Image.Resampling.LANCZOS
        )
    # Strip alpha so JPEG-style models don't see RGBA holes.
    if transposed.mode not in {"RGB", "L"}:
        transposed = transposed.convert("RGB")
    return transposed


async def _run_engine(image: PILImage, *, filename: str) -> OCRResult:
    """Dispatch to the configured engine and translate engine errors."""
    settings = get_settings()
    engine = settings.ocr_engine

    if engine == "paddle":
        from app.extractors.ocr_paddle import is_paddle_available, paddle_ocr

        if is_paddle_available():
            try:
                return await paddle_ocr(image)
            except Exception as e:
                logger.warning(
                    "paddle OCR failed for %s (%s); falling back to VLM",
                    filename, e,
                )
        else:
            logger.warning(
                "paddle OCR requested but paddleocr not installed; "
                "falling back to VLM"
            )
        # Fall through to VLM.

    # Default / fallback path: VLM.
    try:
        return await vlm_ocr(image, settings=settings)
    except VLMError as e:
        raise ExtractionError(
            "SVR-5004", filename=filename, detail=f"VLM unavailable: {e}"
        ) from e


def _shift_boxes(boxes: list[OCRBox], dy: int) -> list[OCRBox]:
    """Return ``boxes`` with each y-coordinate shifted by ``dy``."""
    return [OCRBox(b.x1, b.y1 + dy, b.x2, b.y2 + dy, b.text) for b in boxes]


async def ocr_image(data: bytes, filename: str, mime_type: str) -> OCRResult:
    """Run OCR on a single image payload.

    For multi-frame TIFFs each frame is OCR'd in turn and the results
    concatenated; later-frame boxes are y-shifted so a downstream caller
    that builds a vertical strip image can use the same coordinates.
    """
    if len(data) > MAX_OCR_IMAGE_BYTES:
        raise ExtractionError(
            "REQ-4031",
            filename=filename,
            detail=f"image size {len(data)} > {MAX_OCR_IMAGE_BYTES}",
        )

    base = _open_image(data, filename)

    # Multi-frame TIFF / GIF support.
    n_frames = getattr(base, "n_frames", 1)
    if mime_type == "image/tiff" and n_frames > 1:
        all_text: list[str] = []
        all_boxes: list[OCRBox] = []
        running_height = 0
        total_w = 0
        for i in range(n_frames):
            base.seek(i)
            frame = base.copy()
            frame = _normalise(frame)
            res = await _run_engine(frame, filename=filename)
            if res.text:
                all_text.append(res.text)
            all_boxes.extend(_shift_boxes(res.boxes, running_height))
            running_height += frame.height
            total_w = max(total_w, frame.width)
        return OCRResult(
            text="\n".join(all_text),
            boxes=all_boxes,
            width=total_w,
            height=running_height,
        )

    # Single-frame path.
    image = _normalise(base)
    return await _run_engine(image, filename=filename)


async def ocr_pil_pages(images: list[PILImage], *, filename: str) -> OCRResult:
    """OCR a list of pre-rendered PIL pages (used for scan PDFs).

    Each page is OCR'd in turn; boxes are y-shifted so the same canvas
    coordinate system can be used for masked output stacking.
    """
    all_text: list[str] = []
    all_boxes: list[OCRBox] = []
    running_height = 0
    total_w = 0
    for image in images:
        normalised = _normalise(image)
        res = await _run_engine(normalised, filename=filename)
        if res.text:
            all_text.append(res.text)
        all_boxes.extend(_shift_boxes(res.boxes, running_height))
        running_height += normalised.height
        total_w = max(total_w, normalised.width)
    return OCRResult(
        text="\n".join(all_text),
        boxes=all_boxes,
        width=total_w,
        height=running_height,
    )
