# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/D — callback_url DELETE for blocked posts (T4b.14~T4b.16).

Drives `process_attachment_job` directly with synthetic attachments
and a recorder-style fake `delete_sender` so we can observe whether
the DELETE was scheduled, what payload it carried, and how it
responded to retryable / non-retryable status codes.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.schemas import (
    Attachment,
    Detection,
    WebhookAttachmentResult,
    WebhookPayload,
)
from app.config import get_settings
from app.core.codes import Verdict
from app.db.crud import create_job
from app.db.models import ExtractionJob
from app.workers.attachment_processor import process_attachment_job
from tests.fixtures.attachments.create_fixtures import make_text_file

if TYPE_CHECKING:
    pass


def _att(*, attachment_id: str, filename: str, mime: str, payload: bytes) -> Attachment:
    return Attachment(
        attachment_id=attachment_id,
        filename=filename,
        size_bytes=len(payload),
        mime_type=mime,
        sha256=hashlib.sha256(payload).hexdigest(),
        fetch_url="https://files.example.test/x",
    )


@pytest.fixture
async def temp_job() -> tuple[str, UUID]:
    """Create an ExtractionJob row so update_job() inside the worker
    has something to update; clean up on test exit."""
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    request_id = uuid.uuid4()
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        await create_job(
            s,
            ExtractionJob(
                job_id=job_id,
                request_id=str(request_id),
                callback_url="https://board.example.test/cb",
                status="PENDING",
                body_code="OK-0000",
                body_verdict="PASS",
            ),
        )
        await s.commit()
    yield job_id, request_id
    async with sm() as s:
        await s.execute(
            text("DELETE FROM pii.extraction_jobs WHERE job_id = :j"),
            {"j": job_id},
        )
        await s.commit()


def _stub_block_payload(_url: str, payload: WebhookPayload) -> bool:
    """Stand-in for `send_webhook` — record nothing, claim success."""
    _ = (payload,)
    return True


# ── T4b.14: BLOCK attachment triggers DELETE on callback_url ───────────────
async def test_block_attachment_triggers_delete(
    temp_job: tuple[str, UUID],
) -> None:
    job_id, request_id = temp_job
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)

    delete_calls: list[dict[str, str]] = []

    async def _stub_webhook(_url: str, _payload: WebhookPayload) -> bool:
        return True

    async def _stub_delete(
        url: str,
        *,
        request_id: str,
        job_id: str,
        code: str,
        **_kw: object,
    ) -> bool:
        delete_calls.append({"url": url, "request_id": request_id, "job_id": job_id, "code": code})
        return True

    # We pre-build attachment results so the worker doesn't actually
    # fetch / OCR — we monkeypatch `_process_one_attachment`.
    from app.workers import attachment_processor as ap

    async def _fake_one(attachment: Attachment, **_kw: object) -> WebhookAttachmentResult:
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=Verdict.BLOCK,
            code="BLOCK-2010",
            detections=[
                Detection(
                    field=f"attachment.{attachment.attachment_id}",
                    entity_type="KR_RRN",
                    code="BLOCK-2001",
                    score=0.95,
                    start=0,
                    end=14,
                )
            ],
        )

    original = ap._process_one_attachment
    ap._process_one_attachment = _fake_one  # type: ignore[assignment]
    try:
        await process_attachment_job(
            job_id=job_id,
            request_id=request_id,
            attachments=[
                _att(
                    attachment_id="att_001",
                    filename="leak.txt",
                    mime="text/plain",
                    payload=make_text_file(),
                )
            ],
            callback_url="https://board.example.test/cb",
            body_code="OK-0000",
            body_verdict="PASS",
            strictness="medium",
            sessionmaker=sm,
            webhook_sender=_stub_webhook,
            delete_sender=_stub_delete,
        )
    finally:
        ap._process_one_attachment = original  # type: ignore[assignment]

    assert len(delete_calls) == 1
    call = delete_calls[0]
    assert call["url"] == "https://board.example.test/cb"
    assert call["request_id"] == str(request_id)
    assert call["job_id"] == job_id
    assert call["code"] == "BLOCK-2010"


# ── T4b.15: PASS verdict does NOT call delete_sender ───────────────────────
async def test_pass_verdict_skips_delete(
    temp_job: tuple[str, UUID],
) -> None:
    job_id, request_id = temp_job
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)

    delete_called = asyncio.Event()

    async def _stub_webhook(_url: str, _payload: WebhookPayload) -> bool:
        return True

    async def _stub_delete(*_a: object, **_kw: object) -> bool:
        delete_called.set()
        return True

    from app.workers import attachment_processor as ap

    async def _fake_one(attachment: Attachment, **_kw: object) -> WebhookAttachmentResult:
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=Verdict.PASS,
            code="OK-0000",
            detections=[],
        )

    original = ap._process_one_attachment
    ap._process_one_attachment = _fake_one  # type: ignore[assignment]
    try:
        await process_attachment_job(
            job_id=job_id,
            request_id=request_id,
            attachments=[
                _att(
                    attachment_id="att_002",
                    filename="clean.txt",
                    mime="text/plain",
                    payload=make_text_file(),
                )
            ],
            callback_url="https://board.example.test/cb",
            body_code="OK-0000",
            body_verdict="PASS",
            strictness="medium",
            sessionmaker=sm,
            webhook_sender=_stub_webhook,
            delete_sender=_stub_delete,
        )
    finally:
        ap._process_one_attachment = original  # type: ignore[assignment]

    assert not delete_called.is_set()


# ── T4b.16: audit_only=True skips DELETE even with BLOCK detections ────────
async def test_audit_only_skips_delete(
    temp_job: tuple[str, UUID],
) -> None:
    job_id, request_id = temp_job
    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)

    delete_called = asyncio.Event()

    async def _stub_webhook(_url: str, _payload: WebhookPayload) -> bool:
        return True

    async def _stub_delete(*_a: object, **_kw: object) -> bool:
        delete_called.set()
        return True

    from app.workers import attachment_processor as ap

    async def _fake_one(attachment: Attachment, **_kw: object) -> WebhookAttachmentResult:
        # Per-attachment verdict still records BLOCK (so the audit row
        # captures the detection) but the worker should demote the
        # webhook payload's overall verdict to PASS.
        return WebhookAttachmentResult(
            attachment_id=attachment.attachment_id,
            filename=attachment.filename,
            verdict=Verdict.BLOCK,
            code="BLOCK-2010",
            detections=[
                Detection(
                    field=f"attachment.{attachment.attachment_id}",
                    entity_type="KR_RRN",
                    code="BLOCK-2001",
                    score=0.95,
                    start=0,
                    end=14,
                )
            ],
        )

    original = ap._process_one_attachment
    ap._process_one_attachment = _fake_one  # type: ignore[assignment]
    try:
        await process_attachment_job(
            job_id=job_id,
            request_id=request_id,
            attachments=[
                _att(
                    attachment_id="att_003",
                    filename="trusted.txt",
                    mime="text/plain",
                    payload=make_text_file(),
                )
            ],
            callback_url="https://board.example.test/cb",
            body_code="OK-0000",
            body_verdict="PASS",
            strictness="medium",
            sessionmaker=sm,
            webhook_sender=_stub_webhook,
            delete_sender=_stub_delete,
            audit_only=True,
        )
    finally:
        ap._process_one_attachment = original  # type: ignore[assignment]

    assert not delete_called.is_set()
