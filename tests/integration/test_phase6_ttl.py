# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — audit_events / extraction_jobs 보존 TTL 회귀 방지 (T6.3).

`cleanup_expired_*` 헬퍼가 약속된 보존 기간을 넘긴 row 를 정확히 삭제하는
지 검증한다:

- audit_events 365일 (1년) 보존 → 그 이전 row 는 GC
- extraction_jobs 24시간 보존 → 완료 후 30일 경과 row 는 GC

audit_events 는 append-only 트리거 때문에 일반 DELETE 가 막혀 있으므로
`SET LOCAL app.bypass_audit_lock = 'on'` 로 GC 권한을 일시 부여하는
패턴이 살아 있는지도 함께 확인한다.
"""

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
    """400일 전 audit_event row 가 365일 retention GC 로 삭제되는지.

    append-only 트리거를 우회하기 위해 `SET LOCAL app.bypass_audit_lock`
    를 키고 `occurred_at` 을 강제로 옛 날짜로 밀어둔 뒤 GC 헬퍼를 실행해
    실제로 deleted ≥ 1 인지 확인. 트리거 / GC 둘 다 동시에 검증된다.
    """
    # 한 row 추가 + retention 윈도우 밖으로 시간 끌어내리기.
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
            "UPDATE pii.audit_events SET occurred_at = now() - interval '400 days' WHERE id = :id"
        ),
        {"id": inserted_id},
    )
    await db_session.commit()

    # 365-day retention → row should be deleted.
    deleted = await cleanup_expired_audit_events(db_session, retention_days=365)
    assert deleted >= 1


async def test_t6_3_extraction_job_cleanup_30d(db_session: AsyncSession) -> None:
    """COMPLETED 후 40일 경과 ExtractionJob 이 30일 (720h) TTL GC 로 삭제.

    Phase 4 의 `cleanup_expired_jobs` 헬퍼가 retention 시간을 초과한 row 를
    실제 DELETE 하는지 확인 — webhook 결과가 영구 보존되지 않고 24시간/
    30일 단위로 자동 정리되어 PII 메타데이터가 무한 누적되지 않도록 보호.
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
