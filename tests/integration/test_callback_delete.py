# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/D — callback_url DELETE 회귀 방지 (T4b.14~T4b.16).

첨부 검사 결과가 BLOCK 일 때 워커가 호출자 시스템의 `callback_url` 로
DELETE 요청을 보내 호출자 측에 "이미 게시되어 있다면 폐기하라" 라고
알리는 흐름을 검증한다. 세 시나리오:

  - T4b.14: 첨부가 BLOCK → DELETE 가 정확히 한 번, 올바른 메타 (request_id,
    job_id, code) 와 함께 호출됨
  - T4b.15: PASS verdict 일 때는 DELETE 가 절대 호출되면 안 됨
  - T4b.16: 예외 IP audit_only=True 일 때도 DELETE 가 호출되지 않음
    (per-attachment audit 행은 BLOCK 으로 남지만 사용자 응답은 PASS 강제)

`_process_one_attachment` 를 monkeypatch 해서 실제 fetch/OCR 없이 결과만
주입 — 워커 로직 (DELETE 결정 부분) 만 핀(pin) 한다.
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


# ── T4b.14: BLOCK 첨부 → callback_url DELETE 호출 ────────────────────────
async def test_block_attachment_triggers_delete(
    temp_job: tuple[str, UUID],
) -> None:
    """첨부 검사 결과가 BLOCK 이면 워커가 callback_url 로 DELETE 1회 전송.

    payload 의 4가지 키 (url, request_id, job_id, code) 모두 정확히 채워져야
    호출자가 어느 게시물을 폐기해야 하는지 식별 가능. 회귀 시 BLOCK 사고가
    이미 외부에 노출된 채로 남게 됨.
    """
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


# ── T4b.15: PASS verdict → delete_sender 호출 안 됨 ──────────────────────
async def test_pass_verdict_skips_delete(
    temp_job: tuple[str, UUID],
) -> None:
    """첨부에 PII 가 없어 PASS 일 때는 callback_url DELETE 가 호출되면 안 된다.

    호출자가 정상 게시물을 폐기해 버리는 사고 방지. asyncio.Event 가 set
    되지 않은 채 테스트가 끝나야 한다.
    """
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


# ── T4b.16: audit_only=True → BLOCK 이라도 DELETE 호출 안 됨 ─────────────
async def test_audit_only_skips_delete(
    temp_job: tuple[str, UUID],
) -> None:
    """예외 IP (audit_only) 경로에서는 BLOCK 검출이 있어도 사용자 응답은 PASS,
    callback DELETE 도 호출되지 않아야 한다.

    예외 IP 는 신뢰된 게시자 — audit 행으로 검출 메타데이터는 기록하되
    실제 차단/폐기 동작은 일으키지 않는 것이 정책. 회귀 시 신뢰된 게시자의
    정상 게시물이 폐기되는 사고로 직결.
    """
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
