"""Asyncio attachment-processing orchestrator (Phase 4 → Phase 9D).

Spawned as a background task from the Case-C handler in
``app.api.detect``. For each attachment:

  1. ``fetch_attachment`` (HTTPS GET + SHA-256 verify)
  2. ``scan_bytes``       (ClamAV INSTREAM, soft-fail)
  3. ``dispatch_extract`` (PDF/DOCX/HWPX/text/image → text)
     - For images and scan PDFs we additionally OCR the rendered pages.
  4. PII analysis on the extracted text
  5. Mapping to verdict + response code

Phase 9D — 마스킹 파이프라인 폐기. 검출 시 BLOCK 으로 즉시 거절.
이미지 / 스캔 PDF 마스킹 PNG 저장 / 제공 모두 제거.

Per-attachment ``ExtractionError`` is captured and surfaced as that
attachment's webhook entry; the rest of the job continues. Job-level
exceptions mark the job FAILED and abort the webhook.

Status transitions:
  PENDING (created) → PROCESSING (worker starts) → COMPLETED | FAILED
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from app.api.detect import _analyze_field
from app.api.schemas import (
    Attachment,
    Detection,
    WebhookAttachmentResult,
    WebhookPayload,
)
from app.core.analyzer import build_analyzer
from app.core.codes import Verdict, get_code
from app.db.crud import update_job
from app.extractors.clamav import scan_bytes
from app.extractors.dispatcher import (
    IMAGE_MIME_TYPES,
    PDF_MIMES,
    dispatch_extract,
    extract_image,
    render_pdf_pages,
)
from app.extractors.fetcher import ExtractionError, fetch_attachment
from app.extractors.ocr import ocr_pil_pages
from app.extractors.pdf import extract_pdf
from app.security.metrics_collector import observe_attachment_size, observe_extraction_job
from app.workers.webhook_sender import send_webhook, serialize_payload

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from uuid import UUID

    from presidio_analyzer import AnalyzerEngine
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = logging.getLogger(__name__)


def _decide_attachment_code(
    detections: list[Detection],
) -> tuple[str, Verdict]:
    """Pick the strongest single response code for one attachment.

    Phase 9D — WARN 등급 폐기. BLOCK 또는 PASS 만 가능.
    """
    has_block = False
    for d in detections:
        rc = get_code(d.code)
        if rc.verdict is Verdict.BLOCK:
            has_block = True
            break
    if has_block:
        return "BLOCK-2010", Verdict.BLOCK
    return "OK-0000", Verdict.PASS


def _overall_verdict(
    body_verdict: str, attachment_results: list[WebhookAttachmentResult]
) -> tuple[Verdict, str]:
    """Combine body + attachment outcomes into the overall webhook verdict.

    Phase 9D — Precedence: BLOCK > PASS. ERROR-only attachments don't
    change the body verdict — they're surfaced per-attachment.
    """
    has_block = body_verdict == Verdict.BLOCK.value
    for r in attachment_results:
        if r.verdict is Verdict.BLOCK:
            has_block = True
            break
    if has_block:
        # Re-use the attachment-level BLOCK code if it's the only BLOCK
        # signal so user_message names the offending file.
        for r in attachment_results:
            if r.verdict is Verdict.BLOCK:
                return Verdict.BLOCK, r.code
        return Verdict.BLOCK, "BLOCK-2008"
    return Verdict.PASS, "OK-0000"


# ── Per-attachment pipeline ───────────────────────────────────────────────
async def _process_image(
    attachment: Attachment,
    data: bytes,
    *,
    strictness: str,
    analyzer: AnalyzerEngine,
) -> WebhookAttachmentResult:
    """Image attachment branch — OCR → analyze. No masking output."""
    ocr_result, _source = await extract_image(data, attachment)
    detections = await asyncio.to_thread(
        _analyze_field,
        ocr_result.text,
        field=f"attachment.{attachment.attachment_id}",
        strictness=strictness,
        analyzer=analyzer,
    )

    code, verdict = _decide_attachment_code(detections)
    return WebhookAttachmentResult(
        attachment_id=attachment.attachment_id,
        filename=attachment.filename,
        verdict=verdict,
        code=code,
        detections=detections,
    )


async def _process_scan_pdf(
    attachment: Attachment,
    data: bytes,
    *,
    strictness: str,
    analyzer: AnalyzerEngine,
) -> WebhookAttachmentResult:
    """Scan PDF branch — render pages → OCR → analyze. No masking output."""
    pages = await render_pdf_pages(data, attachment.filename)
    if not pages:
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=Verdict.PASS,
            code="OK-0000",
            detections=[],
        )

    ocr_result = await ocr_pil_pages(pages, filename=attachment.filename)
    detections = await asyncio.to_thread(
        _analyze_field,
        ocr_result.text,
        field=f"attachment.{attachment.attachment_id}",
        strictness=strictness,
        analyzer=analyzer,
    )

    code, verdict = _decide_attachment_code(detections)
    return WebhookAttachmentResult(
        attachment_id=attachment.attachment_id,
        filename=attachment.filename,
        verdict=verdict,
        code=code,
        detections=detections,
    )


async def _process_one_attachment(
    attachment: Attachment,
    *,
    strictness: str,
    analyzer: AnalyzerEngine,
) -> WebhookAttachmentResult:
    """Run the full per-attachment pipeline; never raises."""
    observe_attachment_size(size_bytes=attachment.size_bytes)
    try:
        data = await fetch_attachment(attachment)
        await scan_bytes(data, attachment.filename)

        # Image branch — OCR + analyze.
        if attachment.mime_type in IMAGE_MIME_TYPES:
            return await _process_image(
                attachment,
                data,
                strictness=strictness,
                analyzer=analyzer,
            )

        # PDF branch — sniff text vs. scan first; scan-only takes the
        # OCR path.
        if attachment.mime_type in PDF_MIMES:
            text, is_scan = await extract_pdf(data, attachment.filename)
            if is_scan:
                return await _process_scan_pdf(
                    attachment,
                    data,
                    strictness=strictness,
                    analyzer=analyzer,
                )
            detections = await asyncio.to_thread(
                _analyze_field,
                text,
                field=f"attachment.{attachment.attachment_id}",
                strictness=strictness,
                analyzer=analyzer,
            )
            code, verdict = _decide_attachment_code(detections)
            return WebhookAttachmentResult(
                attachment_id=attachment.attachment_id,
                filename=attachment.filename,
                verdict=verdict,
                code=code,
                detections=detections,
            )

        # Everything else (DOCX/HWPX/text) — text-only path.
        text, _needs_ocr = await dispatch_extract(data, attachment)
        detections = await asyncio.to_thread(
            _analyze_field,
            text,
            field=f"attachment.{attachment.attachment_id}",
            strictness=strictness,
            analyzer=analyzer,
        )
        code, verdict = _decide_attachment_code(detections)
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=verdict,
            code=code,
            detections=detections,
        )

    except ExtractionError as e:
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=Verdict.ERROR,
            code=e.code,
            detections=[],
        )
    except Exception:
        logger.exception("unexpected error processing attachment %s", attachment.filename)
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=Verdict.ERROR,
            code="REQ-4042",
            detections=[],
        )


async def process_attachment_job(
    job_id: str,
    request_id: UUID,
    attachments: list[Attachment],
    callback_url: str | None,
    body_code: str,  # noqa: ARG001 — kept in signature for audit/log parity
    body_verdict: str,
    strictness: str,
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    analyzer_factory: Callable[[], Awaitable[AnalyzerEngine]] | None = None,
    webhook_sender: Callable[..., Awaitable[bool]] | None = None,
) -> None:
    """Run the Case-C async pipeline end-to-end.

    The function is fire-and-forget from the request handler's POV; any
    raised exception is logged + recorded on the job row.
    """
    sender = webhook_sender or send_webhook

    try:
        async with sessionmaker() as session:
            await update_job(session, job_id, status="PROCESSING")
        observe_extraction_job(status="PROCESSING")

        if analyzer_factory is not None:
            analyzer = await analyzer_factory()
        else:
            # Fall back to a fresh in-memory analyzer; the runtime caller
            # passes in the shared one via the factory.
            analyzer = await asyncio.to_thread(build_analyzer)

        # Process attachments sequentially to keep CPU + ClamAV pressure
        # bounded. Concurrency tuning is a Phase 5/6 follow-up.
        attachment_results: list[WebhookAttachmentResult] = []
        for att in attachments:
            result = await _process_one_attachment(
                att,
                strictness=strictness,
                analyzer=analyzer,
            )
            attachment_results.append(result)

            # Mirror the running tally into the DB so /v1/jobs/{id} can
            # report partial progress.
            async with sessionmaker() as session:
                await update_job(
                    session,
                    job_id,
                    attachments_json=json.dumps(
                        [r.model_dump(mode="json") for r in attachment_results],
                        ensure_ascii=False,
                    ),
                )

        verdict, overall_code = _overall_verdict(body_verdict, attachment_results)
        rc = get_code(overall_code)
        # user_message rendering uses {filename} for BLOCK-2010 — pull
        # the first BLOCK attachment's filename so the message resolves.
        first_block = next(
            (r for r in attachment_results if r.verdict is Verdict.BLOCK),
            None,
        )
        try:
            user_message = rc.user_message_template.format(
                filename=first_block.filename if first_block else "",
            )
        except (KeyError, IndexError):
            user_message = rc.user_message_template

        payload = WebhookPayload(
            request_id=request_id,
            job_id=job_id,
            verdict=verdict,
            code=overall_code,
            user_message=user_message,
            attachment_results=attachment_results,
            completed_at=datetime.now(tz=UTC),
        )

        async with sessionmaker() as session:
            await update_job(
                session,
                job_id,
                status="COMPLETED",
                attachments_json=serialize_payload(payload),
                completed_at=datetime.now(tz=UTC),
            )
        observe_extraction_job(status="COMPLETED")

        if callback_url:
            delivered = await sender(callback_url, payload)
            async with sessionmaker() as session:
                await update_job(
                    session,
                    job_id,
                    webhook_attempts=1 if delivered else 5,
                    webhook_delivered_at=datetime.now(tz=UTC) if delivered else None,
                )
            if not delivered:
                logger.warning(
                    "webhook delivery failed permanently for job %s; result "
                    "still queryable via /v1/jobs/%s",
                    job_id,
                    job_id,
                )

    except asyncio.CancelledError:
        # Worker shutdown / restart: leave job in PROCESSING so a future
        # operator (or Phase 5 retry orchestrator) can pick it up. This
        # is what T4.22 exercises.
        logger.warning("attachment job %s cancelled", job_id)
        raise
    except Exception as e:
        logger.exception("attachment job %s failed", job_id)
        observe_extraction_job(status="FAILED")
        try:
            async with sessionmaker() as session:
                await update_job(
                    session,
                    job_id,
                    status="FAILED",
                    error=f"{type(e).__name__}: {e}",
                    completed_at=datetime.now(tz=UTC),
                )
        except Exception:
            logger.exception("failed to mark job %s FAILED", job_id)
