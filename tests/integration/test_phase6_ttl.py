# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — retention TTL for audit events + extraction jobs (T6.3)."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import text

from app.db.crud import (
    cleanup_expired_audit_events,
    cleanup_expired_jobs,
    insert_audit_event,
)
from app.db.models import ExtractionJob

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


async def test_t6_3_audit_cleanup_drops_old_rows(db_session: AsyncSession) -> None:
    # Insert one row + age it past the retention window.
    request_id = str(uuid.uuid4())
    row = await insert_audit_event(
        db_session,
        request_id=request_id,
        api_key_id="ttl-old",
        source_ip="127.0.0.1",
        method="POST",
        path="/v1/detect/post",
        http_status=200,
        response_code="OK-0000",
    )
    inserted_id = row.id

    await db_session.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
    await db_session.execute(
        text(
            "UPDATE pii.audit_events SET occurred_at = now() - interval '400 days' "
            "WHERE id = :id"
        ),
        {"id": inserted_id},
    )
    await db_session.commit()

    # 365-day retention → row should be deleted.
    deleted = await cleanup_expired_audit_events(db_session, retention_days=365)
    assert deleted >= 1


async def test_t6_3_extraction_job_cleanup_30d(db_session: AsyncSession) -> None:
    """ExtractionJob completed_at older than 30 days is GC'd by Phase 4
    cleanup helper. Phase 6 just confirms the TTL contract holds.
    """
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    db_session.add(
        ExtractionJob(
            job_id=job_id,
            request_id=str(uuid.uuid4()),
            callback_url=None,
            status="COMPLETED",
            body_code="OK-0000",
            body_verdict="PASS",
        )
    )
    await db_session.flush()
    # Force completed_at into the distant past.
    await db_session.execute(
        text(
            "UPDATE pii.extraction_jobs SET completed_at = now() - interval '40 days' "
            "WHERE job_id = :j"
        ),
        {"j": job_id},
    )
    await db_session.commit()

    # 30-day retention (in hours = 720) drops the row.
    deleted = await cleanup_expired_jobs(db_session, retention_hours=24 * 30)
    assert deleted >= 1
