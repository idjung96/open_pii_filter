"""Deny-list + policy + feedback CRUD (Phase 2 + Phase 7).

Phase 9E — pii_patterns / pii_pattern_history 테이블이 폐기되어 패턴 CRUD
함수와 검증 헬퍼가 모두 제거됐다. deny_list 는 별도 메커니즘으로 보존.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    AuditEvent,
    ExtractionJob,
    PiiDenyList,
    PiiFeedback,
    PiiPolicy,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Phase 7 — policy mode/action constants ────────────────────────────────
POLICY_MODES: frozenset[str] = frozenset({"enabled", "shadow", "disabled"})
POLICY_ACTIONS: frozenset[str] = frozenset({"BLOCK", "WARN", "MASK", "LOG_ONLY", "PASS"})


class PolicyValidationError(ValueError):
    """Raised when a policy fails validation (e.g. invalid action / band)."""


# ── Validation ────────────────────────────────────────────────────────────
def validate_score(score: float) -> None:
    if not (0.0 <= score <= 1.0):
        raise PolicyValidationError(f"score must be in [0,1]; got {score}")


def validate_mode(value: str) -> None:
    if value not in POLICY_MODES:
        raise PolicyValidationError(f"mode must be one of {sorted(POLICY_MODES)}; got {value}")


def validate_action(value: str) -> None:
    if value not in POLICY_ACTIONS:
        raise PolicyValidationError(f"action must be one of {sorted(POLICY_ACTIONS)}; got {value}")


# ── Deny-list CRUD ────────────────────────────────────────────────────────
async def add_deny_entry(
    session: AsyncSession,
    *,
    entity_type: str,
    value: str,
    score: float = 0.95,
    note: str | None = None,
    created_by: str = "system",
) -> PiiDenyList:
    validate_score(score)
    entry = PiiDenyList(
        entity_type=entity_type,
        value=value,
        score=score,
        note=note,
        created_by=created_by,
    )
    session.add(entry)
    try:
        await session.flush()
    except IntegrityError as e:
        raise PolicyValidationError(f"duplicate deny entry: ({entity_type}, {value})") from e
    return entry


async def list_deny_entries(
    session: AsyncSession, *, entity_type: str | None = None
) -> list[PiiDenyList]:
    stmt = select(PiiDenyList)
    if entity_type is not None:
        stmt = stmt.where(PiiDenyList.entity_type == entity_type)
    rows = await session.scalars(stmt)
    return list(rows)


# ── ExtractionJob CRUD (Phase 4) ──────────────────────────────────────────
async def create_job(session: AsyncSession, job: ExtractionJob) -> None:
    """Insert a new extraction job row and commit immediately.

    Phase 4 — Case C creates the row synchronously so the HTTP 202
    response carries a real ``job_id`` callers can poll. Commit happens
    here so the asyncio worker (which uses its own session) can see it.
    """
    session.add(job)
    await session.commit()


async def get_job(session: AsyncSession, job_id: str) -> ExtractionJob | None:
    return await session.get(ExtractionJob, job_id)


async def update_job(session: AsyncSession, job_id: str, **fields: Any) -> None:
    """Apply a partial update to an extraction job row.

    Unknown columns are silently dropped so callers can pass kwargs that
    map 1:1 to ``ExtractionJob`` columns without dynamic introspection.
    """
    if not fields:
        return
    valid = {c.key for c in ExtractionJob.__table__.columns}
    payload = {k: v for k, v in fields.items() if k in valid}
    if not payload:
        return
    await session.execute(
        update(ExtractionJob).where(ExtractionJob.job_id == job_id).values(**payload)
    )
    await session.commit()


async def get_job_by_request_id(session: AsyncSession, request_id: str) -> ExtractionJob | None:
    stmt = (
        select(ExtractionJob)
        .where(ExtractionJob.request_id == request_id)
        .order_by(ExtractionJob.created_at.desc())
        .limit(1)
    )
    result: ExtractionJob | None = await session.scalar(stmt)
    return result


async def cleanup_expired_jobs(session: AsyncSession, *, retention_hours: int = 24) -> int:
    """Delete completed/failed jobs whose ``completed_at`` is older than
    ``retention_hours``. Returns the number of rows removed.
    """
    cutoff = datetime.now(tz=UTC) - timedelta(hours=retention_hours)
    stmt = delete(ExtractionJob).where(
        ExtractionJob.completed_at.is_not(None),
        ExtractionJob.completed_at < cutoff,
    )
    res = await session.execute(stmt)
    await session.commit()
    return getattr(res, "rowcount", 0) or 0


# ── AuditEvent CRUD (Phase 6) ─────────────────────────────────────────────
async def insert_audit_event(
    session: AsyncSession,
    *,
    request_id: str,
    api_key_id: str | None,
    source_ip: str,
    method: str,
    path: str,
    http_status: int | None,
    response_code: str | None,
    detected_entity_count: int = 0,
    detected_entity_types: str | None = None,
    processing_ms: int | None = None,
    body_hash: str | None = None,
    shadow_hit_types: str | None = None,
    request_body_text: str | None = None,
    response_body_text: str | None = None,
    request_headers_text: str | None = None,
) -> AuditEvent:
    """Append-only insert into ``pii.audit_events``.

    Commits immediately so the row survives even if a downstream worker
    crashes. The Postgres BEFORE UPDATE/DELETE triggers (see
    ``phase-6a`` migration) prevent any later mutation by the app role.
    """
    row = AuditEvent(
        request_id=request_id,
        api_key_id=api_key_id,
        source_ip=source_ip,
        method=method,
        path=path,
        http_status=http_status,
        response_code=response_code,
        detected_entity_count=detected_entity_count,
        detected_entity_types=detected_entity_types,
        processing_ms=processing_ms,
        body_hash=body_hash,
        shadow_hit_types=shadow_hit_types,
        request_body_text=request_body_text,
        response_body_text=response_body_text,
        request_headers_text=request_headers_text,
    )
    session.add(row)
    await session.commit()
    return row


async def cleanup_expired_audit_events(session: AsyncSession, *, retention_days: int) -> int:
    """Delete audit rows older than ``retention_days``.

    The append-only trigger refuses DELETE unless the session has set
    ``app.bypass_audit_lock = 'on'`` first (Phase 6 design). We do that
    inside the same transaction so the lock is automatically reset by
    commit/rollback.
    """
    cutoff = datetime.now(tz=UTC) - timedelta(days=retention_days)
    await session.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
    res = await session.execute(delete(AuditEvent).where(AuditEvent.occurred_at < cutoff))
    await session.commit()
    return getattr(res, "rowcount", 0) or 0


async def list_audit_events(
    session: AsyncSession,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    request_id: str | None = None,
    api_key_id: str | None = None,
    response_code: str | None = None,
    cursor_occurred_at: datetime | None = None,
    cursor_id: int | None = None,
    limit: int = 100,
) -> list[AuditEvent]:
    """List audit rows ordered by (occurred_at DESC, id DESC).

    Pagination uses keyset (``cursor_*``) so we never re-scan rows the
    caller has already seen. Pass ``cursor_occurred_at`` and
    ``cursor_id`` from the previous page's last row.
    """
    stmt = select(AuditEvent)
    if since is not None:
        stmt = stmt.where(AuditEvent.occurred_at >= since)
    if until is not None:
        stmt = stmt.where(AuditEvent.occurred_at <= until)
    if request_id is not None:
        stmt = stmt.where(AuditEvent.request_id == request_id)
    if api_key_id is not None:
        stmt = stmt.where(AuditEvent.api_key_id == api_key_id)
    if response_code is not None:
        stmt = stmt.where(AuditEvent.response_code == response_code)
    if cursor_occurred_at is not None and cursor_id is not None:
        # Strict tuple comparison for keyset pagination.
        stmt = stmt.where(
            (AuditEvent.occurred_at < cursor_occurred_at)
            | ((AuditEvent.occurred_at == cursor_occurred_at) & (AuditEvent.id < cursor_id))
        )
    stmt = stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(
        min(max(limit, 1), 500)
    )
    rows = await session.scalars(stmt)
    return list(rows)


# ── PiiPolicy CRUD (Phase 7) ──────────────────────────────────────────────
async def list_active_policies(
    session: AsyncSession,
    *,
    modes: Sequence[str] = ("enabled",),
) -> list[PiiPolicy]:
    """Return policy rows in the requested modes ordered by specificity.

    Specificity ordering: narrower score band first, then higher score_min.
    The policy engine consumes this order directly.
    """
    stmt = (
        select(PiiPolicy)
        .where(PiiPolicy.mode.in_(list(modes)))
        .order_by(
            (PiiPolicy.score_max - PiiPolicy.score_min).asc(),
            PiiPolicy.score_min.desc(),
            PiiPolicy.id.asc(),
        )
    )
    rows = await session.scalars(stmt)
    return list(rows)


async def add_policy(
    session: AsyncSession,
    *,
    entity_type: str,
    score_min: float,
    score_max: float,
    action: str,
    user_message_template: str | None = None,
    mode: str = "enabled",
    created_by: str = "system",
) -> PiiPolicy:
    """Insert a single policy row. Validates action / mode / score band."""
    validate_action(action)
    validate_mode(mode)
    if not (0.0 <= score_min <= score_max <= 1.0):
        raise PolicyValidationError(f"score band invalid: [{score_min}, {score_max}]")

    row = PiiPolicy(
        entity_type=entity_type,
        score_min=score_min,
        score_max=score_max,
        action=action,
        user_message_template=user_message_template,
        mode=mode,
        created_by=created_by,
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError as e:
        raise PolicyValidationError(
            f"duplicate policy: ({entity_type}, [{score_min},{score_max}], {mode})"
        ) from e
    await session.commit()
    return row


async def update_policy_mode(session: AsyncSession, policy_id: int, mode: str) -> None:
    """Flip a policy's mode (enabled/shadow/disabled). No-op if missing."""
    validate_mode(mode)
    await session.execute(
        update(PiiPolicy)
        .where(PiiPolicy.id == policy_id)
        .values(mode=mode, version=PiiPolicy.version + 1)
    )
    await session.commit()


async def get_policy(session: AsyncSession, policy_id: int) -> PiiPolicy | None:
    return await session.get(PiiPolicy, policy_id)


# ── PiiFeedback CRUD (Phase 7) ────────────────────────────────────────────
async def insert_feedback(
    session: AsyncSession,
    *,
    request_id: str,
    original_code: str,
    reason: str,
    reporter_hash: str | None,
) -> PiiFeedback:
    """Append a false-positive report. ``reporter_hash`` is SHA-256 of
    (project salt + email-or-IP) — never plaintext email.
    """
    row = PiiFeedback(
        request_id=request_id,
        original_code=original_code,
        reason=reason,
        reporter_hash=reporter_hash,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def list_feedback(
    session: AsyncSession,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    original_code: str | None = None,
    cursor_created_at: datetime | None = None,
    cursor_id: int | None = None,
    limit: int = 100,
) -> list[PiiFeedback]:
    """List feedback newest-first with keyset pagination."""
    stmt = select(PiiFeedback)
    if since is not None:
        stmt = stmt.where(PiiFeedback.created_at >= since)
    if until is not None:
        stmt = stmt.where(PiiFeedback.created_at <= until)
    if original_code is not None:
        stmt = stmt.where(PiiFeedback.original_code == original_code)
    if cursor_created_at is not None and cursor_id is not None:
        stmt = stmt.where(
            (PiiFeedback.created_at < cursor_created_at)
            | ((PiiFeedback.created_at == cursor_created_at) & (PiiFeedback.id < cursor_id))
        )
    stmt = stmt.order_by(PiiFeedback.created_at.desc(), PiiFeedback.id.desc()).limit(
        min(max(limit, 1), 500)
    )
    rows = await session.scalars(stmt)
    return list(rows)


async def count_feedback_by_code(
    session: AsyncSession,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, int]:
    """Aggregate feedback counts grouped by ``original_code``."""
    stmt = select(PiiFeedback.original_code, func.count(PiiFeedback.id)).group_by(
        PiiFeedback.original_code
    )
    if since is not None:
        stmt = stmt.where(PiiFeedback.created_at >= since)
    if until is not None:
        stmt = stmt.where(PiiFeedback.created_at <= until)
    rows = await session.execute(stmt)
    return {code: int(n) for code, n in rows.all()}
