"""GET /v1/admin/stats/* — operator analytics endpoints (Phase 7).

Re-uses the same admin gate as ``app.api.admin_audit.require_admin``
(IP allowlist + API-key ``is_admin``). All endpoints aggregate over
``audit_events`` and ``pii_feedback`` only — there is no PII plaintext
in either source.

Endpoints
---------
- ``GET /v1/admin/stats/detections`` — hourly counts grouped by entity_type
- ``GET /v1/admin/stats/verdicts``   — block / warn / pass ratio
- ``GET /v1/admin/stats/feedback``   — recent feedback rows + per-code totals
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.admin_audit import require_admin
from app.core.codes import Verdict, get_code
from app.db.crud import count_feedback_by_code, list_feedback
from app.db.models import AuditEvent
from app.db.session import get_sessionmaker
from app.security.hmac_auth import AuthedCaller

router = APIRouter(prefix="/v1/admin/stats", tags=["admin-stats"])


# ── Response models ───────────────────────────────────────────────────────
class HourlyEntityCount(BaseModel):
    hour: datetime
    entity_type: str
    count: int


class DetectionsStatsResponse(BaseModel):
    since: datetime
    until: datetime
    buckets: list[HourlyEntityCount] = Field(default_factory=list)
    # Phase 7B — when ?include_shadow=true, populate parallel buckets for
    # entity_types observed only in the shadow analyzer (verdict-neutral).
    shadow_buckets: list[HourlyEntityCount] = Field(default_factory=list)


class VerdictsStatsResponse(BaseModel):
    since: datetime
    until: datetime
    total: int
    block: int
    warn: int
    pass_: int = Field(alias="pass")
    error: int
    block_ratio: float
    warn_ratio: float
    pass_ratio: float

    model_config = {"populate_by_name": True}


class FeedbackRow(BaseModel):
    id: int
    request_id: str
    original_code: str
    reason: str
    created_at: datetime


class FeedbackStatsResponse(BaseModel):
    since: datetime
    until: datetime
    total: int
    by_code: dict[str, int] = Field(default_factory=dict)
    rows: list[FeedbackRow] = Field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────
def _floor_hour(t: datetime) -> datetime:
    return t.replace(minute=0, second=0, microsecond=0)


def _split_types(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [s for s in (chunk.strip() for chunk in raw.split(",")) if s]


# ── Endpoints ─────────────────────────────────────────────────────────────
@router.get("/detections", response_model=DetectionsStatsResponse)
async def stats_detections(
    since: datetime | None = Query(default=None),  # noqa: B008
    until: datetime | None = Query(default=None),  # noqa: B008
    include_shadow: bool = Query(default=False),
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> DetectionsStatsResponse:
    """Hourly counts of each ``entity_type`` over the window.

    Phase 7B — pass ``include_shadow=true`` to also return buckets for
    entity_types that fired only in the shadow analyzer (audit-only).
    """
    if since is None:
        since = datetime.now(tz=UTC) - timedelta(hours=24)
    if until is None:
        until = datetime.now(tz=UTC)

    sm = get_sessionmaker()
    counter: Counter[tuple[datetime, str]] = Counter()
    shadow_counter: Counter[tuple[datetime, str]] = Counter()

    async with sm() as session:
        stmt = (
            select(
                AuditEvent.occurred_at,
                AuditEvent.detected_entity_types,
                AuditEvent.shadow_hit_types,
            )
            .where(AuditEvent.occurred_at >= since)
            .where(AuditEvent.occurred_at <= until)
        )
        result = await session.execute(stmt)
        for occurred_at, types_csv, shadow_csv in result.all():
            hour = _floor_hour(occurred_at)
            for t in _split_types(types_csv):
                counter[(hour, t)] += 1
            if include_shadow:
                for t in _split_types(shadow_csv):
                    shadow_counter[(hour, t)] += 1

    buckets = [
        HourlyEntityCount(hour=h, entity_type=t, count=n)
        for (h, t), n in sorted(counter.items())
    ]
    shadow_buckets = [
        HourlyEntityCount(hour=h, entity_type=t, count=n)
        for (h, t), n in sorted(shadow_counter.items())
    ]
    return DetectionsStatsResponse(
        since=since, until=until,
        buckets=buckets, shadow_buckets=shadow_buckets,
    )


@router.get("/verdicts", response_model=VerdictsStatsResponse)
async def stats_verdicts(
    since: datetime | None = Query(default=None),  # noqa: B008
    until: datetime | None = Query(default=None),  # noqa: B008
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> VerdictsStatsResponse:
    """BLOCK / WARN / PASS / ERROR breakdown over the window."""
    if since is None:
        since = datetime.now(tz=UTC) - timedelta(hours=24)
    if until is None:
        until = datetime.now(tz=UTC)

    counts = {"BLOCK": 0, "WARN": 0, "PASS": 0, "ERROR": 0, "PROCESSING": 0}
    sm = get_sessionmaker()
    async with sm() as session:
        stmt = (
            select(AuditEvent.response_code)
            .where(AuditEvent.occurred_at >= since)
            .where(AuditEvent.occurred_at <= until)
        )
        result = await session.execute(stmt)
        for (response_code,) in result.all():
            if not response_code:
                continue
            try:
                rc = get_code(response_code)
            except KeyError:
                continue
            verdict = rc.verdict.value
            if verdict == Verdict.BLOCK.value:
                counts["BLOCK"] += 1
            elif verdict == Verdict.WARN.value:
                counts["WARN"] += 1
            elif verdict == Verdict.PASS.value:
                counts["PASS"] += 1
            elif verdict == Verdict.ERROR.value:
                counts["ERROR"] += 1
            else:
                counts["PROCESSING"] += 1

    total = counts["BLOCK"] + counts["WARN"] + counts["PASS"] + counts["ERROR"]
    denom = float(total) if total else 1.0
    return VerdictsStatsResponse(
        since=since,
        until=until,
        total=total,
        block=counts["BLOCK"],
        warn=counts["WARN"],
        **{"pass": counts["PASS"]},
        error=counts["ERROR"],
        block_ratio=round(counts["BLOCK"] / denom, 4),
        warn_ratio=round(counts["WARN"] / denom, 4),
        pass_ratio=round(counts["PASS"] / denom, 4),
    )


@router.get("/feedback", response_model=FeedbackStatsResponse)
async def stats_feedback(
    since: datetime | None = Query(default=None),  # noqa: B008
    until: datetime | None = Query(default=None),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=500),
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> FeedbackStatsResponse:
    """Recent feedback rows + counts grouped by ``original_code``."""
    if since is None:
        since = datetime.now(tz=UTC) - timedelta(days=7)
    if until is None:
        until = datetime.now(tz=UTC)

    sm = get_sessionmaker()
    async with sm() as session:
        rows = await list_feedback(session, since=since, until=until, limit=limit)
        by_code = await count_feedback_by_code(session, since=since, until=until)

    out_rows = [
        FeedbackRow(
            id=r.id,
            request_id=r.request_id,
            original_code=r.original_code,
            reason=r.reason,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return FeedbackStatsResponse(
        since=since,
        until=until,
        total=sum(by_code.values()),
        by_code=by_code,
        rows=out_rows,
    )
