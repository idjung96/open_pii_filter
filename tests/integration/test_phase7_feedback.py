# SYNTHETIC DATA - NOT REAL PII
"""Phase 7 — POST /v1/feedback (T7.4).

Covers:
  - 202 ACK-3010 + feedback row inserted + audit row recorded
  - reporter_email is hashed (raw select shows hash, not plaintext)
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import select, text

from app.db.crud import list_audit_events
from app.db.models import PiiFeedback
from app.db.session import get_sessionmaker

if TYPE_CHECKING:
    from httpx import AsyncClient


@pytest.fixture
async def clean_feedback_audit() -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_feedback"))
        await s.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
        await s.execute(text("DELETE FROM pii.audit_events"))
        await s.commit()
    yield
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_feedback"))
        await s.commit()


async def test_t7_4_feedback_creates_row_and_audit(
    client: AsyncClient,
    clean_feedback_audit: None,
) -> None:
    request_id = str(uuid.uuid4())
    reporter_email = "alice@example.com"
    payload = {
        "request_id": request_id,
        "original_code": "BLOCK-2001",
        "reason": "오탐: 실제로는 게시판 ID 입니다.",
        "reporter_email": reporter_email,
    }
    resp = await client.post("/v1/feedback", json=payload)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["code"] == "ACK-3010"
    assert "feedback_id" in body and isinstance(body["feedback_id"], int)

    # The DB row exists and reporter_hash is sha256 hex (length 64),
    # NOT the plaintext email.
    sm = get_sessionmaker()
    async with sm() as s:
        row = await s.scalar(
            select(PiiFeedback).where(PiiFeedback.id == body["feedback_id"])
        )
    assert row is not None
    assert row.original_code == "BLOCK-2001"
    assert row.reporter_hash is not None
    assert len(row.reporter_hash) == 64
    assert reporter_email not in (row.reporter_hash or "")
    assert reporter_email not in (row.reason or "")

    # Audit row was recorded.
    for _ in range(50):
        async with sm() as s:
            rows = await list_audit_events(s, limit=20)
        if any(r.path == "/v1/feedback" for r in rows):
            break
        await asyncio.sleep(0.05)
    assert any(r.path == "/v1/feedback" and r.response_code == "ACK-3010" for r in rows)


async def test_t7_4_feedback_anonymous_uses_ip_hash(
    client: AsyncClient,
    clean_feedback_audit: None,
) -> None:
    request_id = str(uuid.uuid4())
    payload = {
        "request_id": request_id,
        "original_code": "WARN-1001",
        "reason": "전화번호인데 OK 처리됨",
    }
    resp = await client.post("/v1/feedback", json=payload)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["code"] == "ACK-3010"

    sm = get_sessionmaker()
    async with sm() as s:
        row = await s.scalar(
            select(PiiFeedback).where(PiiFeedback.id == body["feedback_id"])
        )
    assert row is not None
    # Hash present even when no email supplied (falls back to source IP).
    assert row.reporter_hash is not None
    assert len(row.reporter_hash) == 64


async def test_t7_4_feedback_invalid_email_rejected(
    client: AsyncClient,
    clean_feedback_audit: None,
) -> None:
    payload = {
        "request_id": str(uuid.uuid4()),
        "original_code": "WARN-1001",
        "reason": "x",
        "reporter_email": "not-an-email",
    }
    resp = await client.post("/v1/feedback", json=payload)
    # Pydantic validation → REQ-4003 (default malformed JSON path)
    assert resp.status_code in (400, 422)
