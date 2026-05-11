"""`GET /v1/jobs/{job_id}` — Case C 비동기 작업 상태 조회 (Phase 4, T4.17/T4.21).

Case C 의 첨부 검사 워커가 만든 `ExtractionJob` 의 현재 상태와 (완료된 경우)
첨부별 검사 결과를 돌려준다. 호출자가 webhook 을 놓쳤거나, 운영자가 사후
감사를 할 때 사용한다.

보존 정책:
  - COMPLETED 후 24시간 동안 행이 살아 있으므로 webhook 미수신 시 폴링으로
    결과 복구 가능
  - 24시간 후 `cleanup_expired_jobs` 가 행을 삭제 → 이 엔드포인트는 404

인증:
  - `/v1/detect/post` 와 동일한 `require_auth` (HMAC 4종 헤더) 사용 — 호출자
    측 인증 코드 재사용
"""

from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.schemas import WebhookAttachmentResult
from app.db.crud import get_job
from app.db.session import get_sessionmaker
from app.security.auth import require_auth
from app.security.hmac_auth import AuthedCaller

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["jobs"])


class JobStatusResponse(BaseModel):
    """`GET /v1/jobs/{job_id}` 응답 스키마.

    `status` 는 DB 컬럼 그대로 노출 — `PENDING` → `PROCESSING` →
    `COMPLETED` / `FAILED` 전이. COMPLETED 이전에는 `attachment_results`
    는 빈 배열일 수 있다.
    """

    job_id: str = Field(
        description="`ExtractionJob.job_id` — 워커가 발급한 UUID 단축형 (예: `job_a1b2c3d4e5f6`)"
    )
    request_id: str = Field(description="원본 `POST /v1/detect/post` 의 `request_id`")
    status: str = Field(description="상태값: `PENDING` / `PROCESSING` / `COMPLETED` / `FAILED`")
    body_code: str | None = Field(default=None, description="본문 검사 결과 코드 (예: `OK-0000`)")
    body_verdict: str | None = Field(default=None, description="본문 verdict — `PASS` / `BLOCK`")
    attachment_results: list[WebhookAttachmentResult] = Field(
        default_factory=list,
        description="첨부별 검사 결과 (COMPLETED 일 때만 채워짐). 각 항목은 webhook payload 의 `attachment_results[]` 와 동일 스키마",
    )
    error: str | None = Field(
        default=None, description="`FAILED` 상태일 때만 채워지는 운영자용 에러 메시지"
    )
    completed_at: datetime | None = Field(
        default=None, description="COMPLETED/FAILED 전이 시각 (UTC)"
    )
    webhook_delivered_at: datetime | None = Field(
        default=None, description="webhook 2xx 응답을 받은 시각 (없으면 미배달)"
    )


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Case C 비동기 작업 상태 조회",
    description="""
Case C (`POST /v1/detect/post` 응답이 `ACK-3001`) 에서 발급된 `job_id` 의
현재 상태와 (COMPLETED 인 경우) 첨부별 검사 결과를 돌려준다.

**보존 기간** — COMPLETED 후 24시간. 그 이후 호출은 404.

**폴링 권장 주기** — 30초. webhook 이 도착하면 폴링 중단.
""".strip(),
    responses={
        200: {"description": "현재 상태 + (COMPLETED 인 경우) `attachment_results` 포함"},
        401: {"description": "`REQ-4010~4013` — HMAC 인증 실패"},
        403: {"description": "`REQ-4014/4015` — 키 폐기 또는 IP allowlist 외 접근"},
        404: {"description": "job_id 가 없거나 24h retention 으로 GC 됨"},
    },
)
async def get_job_status(
    job_id: str,
    caller: AuthedCaller = Depends(require_auth),  # noqa: B008,ARG001
) -> JobStatusResponse:
    """현재 상태 + (COMPLETED 시) 첨부별 검사 결과 반환.

    24시간 retention vacuum 이 행을 삭제하면 404 — 호출자는 webhook 을 못 받았다면
    24시간 안에 폴링으로 가져가야 한다.
    """
    sm = get_sessionmaker()
    async with sm() as session:
        job = await get_job(session, job_id)

    if job is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})

    attachment_results: list[WebhookAttachmentResult] = []
    if job.attachments_json:
        try:
            raw = json.loads(job.attachments_json)
        except json.JSONDecodeError:
            logger.exception("corrupt attachments_json for job %s", job_id)
            raw = []
        for entry in raw:
            try:
                attachment_results.append(WebhookAttachmentResult.model_validate(entry))
            except Exception:
                logger.warning("skipping malformed attachment entry in job %s", job_id)

    return JobStatusResponse(
        job_id=job.job_id,
        request_id=job.request_id,
        status=job.status,
        body_code=job.body_code,
        body_verdict=job.body_verdict,
        attachment_results=attachment_results,
        error=job.error,
        completed_at=job.completed_at,
        webhook_delivered_at=job.webhook_delivered_at,
    )
