"""VLM-backed OCR via OpenAI-compatible chat completions (Phase 5).

Posts a base64-encoded image to ``Settings.vlm_endpoint`` and parses
the model's JSON response into a structured :class:`OCRResult`. The
prompt asks for the full extracted text plus per-block bounding boxes
so downstream PII masking knows where to draw rectangles.

The client is intentionally minimal — one async ``httpx.AsyncClient``
per call. Concurrency is bounded by the asyncio worker that spawns us
(see ``app.workers.attachment_processor``), so per-call socket reuse
is unnecessary.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, NamedTuple

import httpx

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

    from app.config import Settings

logger = logging.getLogger(__name__)


_PROMPT = (
    # Qwen3.x reasoning suppression — vLLM honours "/no_think" inline tag
    # even when chat_template_kwargs.enable_thinking is silently ignored.
    "/no_think "
    "You are an OCR system. Extract ALL text from the image, including "
    "any rotated or partially obscured text. Return ONLY a JSON object "
    "with this exact schema: "
    '{"text": "<full extracted text>", "blocks": '
    '[{"bbox": [x1,y1,x2,y2], "text": "<block text>"}]}. '
    "Coordinates are pixel coordinates with origin at top-left. "
    "No prose, no markdown fences. If the image has no readable text, "
    'return {"text": "", "blocks": []}.'
)


class OCRBox(NamedTuple):
    """A single OCR block with pixel-space bounding box + text."""

    x1: int
    y1: int
    x2: int
    y2: int
    text: str


@dataclass
class OCRResult:
    """OCR output for one image."""

    text: str
    boxes: list[OCRBox] = field(default_factory=list)
    width: int = 0
    height: int = 0


class VLMError(RuntimeError):
    """Raised on transport-level VLM failure (network/5xx/timeout)."""


def _encode_png_base64(image: PILImage) -> str:
    """Encode ``image`` as PNG → base64 ASCII for the data: URL."""
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_fences(s: str) -> str:
    """Remove leading/trailing ``` fences a model might emit anyway."""
    return _FENCE_RE.sub("", s).strip()


def _parse_response(content: str) -> tuple[str, list[OCRBox]]:
    """Parse the model's content string into (text, boxes).

    Robust to stray prose / fences. Falls back to empty result on JSON error.
    """
    cleaned = _strip_fences(content)
    try:
        data: dict[str, Any] = json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to locate the first balanced { ... } chunk.
        first = cleaned.find("{")
        last = cleaned.rfind("}")
        if first >= 0 and last > first:
            try:
                data = json.loads(cleaned[first : last + 1])
            except json.JSONDecodeError:
                logger.warning("VLM returned non-JSON content; treating as empty")
                return "", []
        else:
            logger.warning("VLM returned non-JSON content; treating as empty")
            return "", []

    text = str(data.get("text") or "")
    raw_blocks = data.get("blocks") or []
    boxes: list[OCRBox] = []
    if isinstance(raw_blocks, list):
        for blk in raw_blocks:
            if not isinstance(blk, dict):
                continue
            bbox = blk.get("bbox") or []
            block_text = str(blk.get("text") or "")
            if (
                not isinstance(bbox, (list, tuple))
                or len(bbox) != 4
                or not all(isinstance(v, (int, float)) for v in bbox)
            ):
                continue
            x1, y1, x2, y2 = (int(v) for v in bbox)
            # Normalise coordinate order so callers can rely on x1<=x2, y1<=y2.
            xa, xb = sorted((x1, x2))
            ya, yb = sorted((y1, y2))
            boxes.append(OCRBox(xa, ya, xb, yb, block_text))
    return text, boxes


async def vlm_ocr(image: PILImage, *, settings: Settings) -> OCRResult:
    """Run OCR against the configured VLM endpoint.

    Raises:
        VLMError: transport / 5xx / timeout — the caller maps this to
            ``ExtractionError("SVR-5004")``.
    """
    b64 = _encode_png_base64(image)
    payload: dict[str, Any] = {
        "model": settings.vlm_model_id,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": _PROMPT},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{b64}"
                        },
                    },
                ],
            }
        ],
        "temperature": 0.0,
        # Cap output so long generations don't dominate latency. OCR
        # output is bounded by the visible-text count. 4000 leaves
        # headroom for any thinking tokens this Qwen3.5 reasoning model
        # emits when chat_template_kwargs.enable_thinking is ignored.
        "max_tokens": 4000,
        # Qwen3.x reasoning models default to interleaved <think>...</think>
        # output that vLLM surfaces in ``message.reasoning`` instead of
        # ``message.content``. Disable thinking so OCR latency stays
        # predictable and content is populated directly.
        "extra_body": {"chat_template_kwargs": {"enable_thinking": False}},
    }

    headers: dict[str, str] = {"content-type": "application/json"}
    if settings.vlm_api_key:
        headers["authorization"] = f"Bearer {settings.vlm_api_key}"

    url = settings.vlm_endpoint.rstrip("/") + "/chat/completions"
    timeout = httpx.Timeout(settings.ocr_request_timeout_seconds)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException as e:
        raise VLMError(f"VLM timeout after {settings.ocr_request_timeout_seconds}s") from e
    except httpx.HTTPError as e:
        raise VLMError(f"VLM transport error: {type(e).__name__}: {e}") from e

    if resp.status_code >= 500:
        raise VLMError(f"VLM HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code >= 400:
        # 4xx is a client/config bug — surface but still wrap as VLMError so
        # the caller can map to SVR-5004 (op-visible) without leaking details.
        raise VLMError(f"VLM HTTP {resp.status_code}: {resp.text[:200]}")

    try:
        body = resp.json()
        msg = body["choices"][0]["message"]
    except (KeyError, IndexError, ValueError, json.JSONDecodeError) as e:
        raise VLMError(f"VLM malformed response: {e}") from e

    # Some vLLM-served reasoning models leave ``content`` empty and put
    # the actual answer in ``reasoning`` (or a trailing chunk after a
    # </think> tag). Cover both shapes.
    content = msg.get("content") or msg.get("reasoning") or ""
    text, boxes = _parse_response(str(content))
    return OCRResult(text=text, boxes=boxes, width=image.width, height=image.height)
