"""GET /v1/jobs/{job_id} — async job status (Phase 4, T4.17/T4.21).

Returns the live status of an extraction job created by Case C. Once a
job has been COMPLETED its row sticks around for 24 hours so callers
who missed the webhook can still pull the result. Past that retention
window ``cleanup_expired_jobs`` removes the row and this endpoint
surfaces 404.

Auth: re-uses the same ``require_auth`` dependency as ``/v1/detect/post``
so callers reach the API exactly the way they reach the detect path.
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
    """Response shape for ``GET /v1/jobs/{job_id}``."""

    job_id: str
    request_id: str
    status: str
    body_code: str | None = None
    body_verdict: str | None = None
    attachment_results: list[WebhookAttachmentResult] = Field(default_factory=list)
    error: str | None = None
    completed_at: datetime | None = None
    webhook_delivered_at: datetime | None = None


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
    caller: AuthedCaller = Depends(require_auth),  # noqa: B008,ARG001
) -> JobStatusResponse:
    """Return current status + (when COMPLETED) attachment results.

    Returns 404 if the job is not found, including the case where it
    has been pruned by the 24-hour retention vacuum (T4.21).
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
