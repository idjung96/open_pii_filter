"""PaddleOCR-backed OCR (Phase 5, optional engine).

PaddleOCR ships under the ``[ocr]`` extras and is **not** installed by
default. ``is_paddle_available`` lets the dispatcher decide at runtime
whether to even attempt this engine; if the import fails we surface a
clean error and fall back to the VLM path.

The engine is held as a module-level singleton because PaddleOCR's
model load is expensive (~3-5s, plus weights download on first run).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from app.extractors.ocr_vlm import OCRBox, OCRResult

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

logger = logging.getLogger(__name__)


_paddle_engine: Any = None
_paddle_lock: asyncio.Lock | None = None


def is_paddle_available() -> bool:
    """Return True if ``paddleocr`` is importable in the current env."""
    try:
        import paddleocr  # type: ignore[import-not-found,unused-ignore]  # noqa: F401
    except ImportError:
        return False
    return True


def _build_paddle_engine() -> Any:
    """Construct a PaddleOCR Korean recogniser (CPU mode)."""
    import paddleocr  # type: ignore[import-not-found,unused-ignore]

    return paddleocr.PaddleOCR(use_angle_cls=True, lang="korean", use_gpu=False)


def _ocr_sync(image: PILImage) -> OCRResult:
    """Synchronous PaddleOCR run (executed on a worker thread)."""
    import numpy as np  # type: ignore[import-not-found,unused-ignore]

    global _paddle_engine
    if _paddle_engine is None:
        _paddle_engine = _build_paddle_engine()

    arr = np.asarray(image.convert("RGB"))
    raw = _paddle_engine.ocr(arr, cls=True)

    text_chunks: list[str] = []
    boxes: list[OCRBox] = []
    # PaddleOCR returns: [[ [bbox4], (text, confidence) ], ... ] or nested.
    # Normalise to a flat list of (bbox, text) pairs.
    for row in raw or []:
        if not row:
            continue
        # New paddle: row is a list of detections. Old paddle: row IS a detection.
        items = row if isinstance(row[0], list) and len(row[0]) >= 2 else [row]
        for item in items:
            if not item or len(item) < 2:
                continue
            bbox, payload = item[0], item[1]
            if isinstance(payload, (list, tuple)) and len(payload) >= 1:
                txt = str(payload[0])
            else:
                txt = str(payload)
            try:
                xs = [int(p[0]) for p in bbox]
                ys = [int(p[1]) for p in bbox]
                box = OCRBox(min(xs), min(ys), max(xs), max(ys), txt)
            except (TypeError, IndexError, ValueError):
                continue
            text_chunks.append(txt)
            boxes.append(box)

    return OCRResult(
        text="\n".join(text_chunks),
        boxes=boxes,
        width=image.width,
        height=image.height,
    )


async def paddle_ocr(image: PILImage) -> OCRResult:
    """Run PaddleOCR on ``image`` and return an :class:`OCRResult`.

    Raises ``RuntimeError`` if paddleocr is not installed — caller is
    expected to gate on :func:`is_paddle_available` first.
    """
    if not is_paddle_available():
        raise RuntimeError("paddleocr is not installed (install [ocr] extras)")
    global _paddle_lock
    if _paddle_lock is None:
        _paddle_lock = asyncio.Lock()
    # PaddleOCR's models aren't thread-safe — serialise.
    async with _paddle_lock:
        return await asyncio.to_thread(_ocr_sync, image)
