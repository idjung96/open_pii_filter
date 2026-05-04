"""POST /v1/feedback — accept false-positive / false-negative reports.

Phase 7 (Q4). The endpoint is externally exposed (HMAC + API key, same
contract as ``/v1/detect/post``). The body is small and audit-only;
detections themselves are still re-evaluated server-side, this just
gives operators a queue to review.

Privacy invariant
-----------------
The reporter's email — when supplied — is hashed with the project-wide
salt before storage. The plaintext email never touches the DB.
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from app.api.responses import build_response
from app.config import get_settings
from app.core.codes import get_code
from app.db.crud import insert_feedback
from app.db.session import get_sessionmaker
from app.security.audit_middleware import AuditPayload
from app.security.auth import require_auth
from app.security.hmac_auth import AuthedCaller
from app.security.metrics_collector import observe_feedback

if TYPE_CHECKING:
    pass

router = APIRouter(prefix="/v1", tags=["feedback"])


_EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class FeedbackRequest(BaseModel):
    request_id: UUID
    original_code: str = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=1, max_length=2000)
    reporter_email: str | None = Field(default=None, max_length=320)

    @field_validator("reporter_email")
    @classmethod
    def _check_email(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not _EMAIL_RX.match(v):
            raise ValueError("invalid email format")
        return v


class FeedbackResponse(BaseModel):
    request_id: UUID
    code: str
    feedback_id: int
    user_message: str
    processed_at: datetime
    processing_ms: int


def _hash_reporter(email_or_ip: str) -> str:
    """SHA-256(salt + email-or-ip). Salt comes from
    ``Settings.pii_encryption_key`` (already a high-entropy secret) so
    operators don't have to manage another env var.
    """
    salt = get_settings().pii_encryption_key or "fallback-salt"
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    h.update(b":")
    h.update(email_or_ip.encode("utf-8"))
    return h.hexdigest()


@router.post("/feedback")
async def submit_feedback(
    payload: FeedbackRequest,
    request: Request,
    caller: AuthedCaller = Depends(require_auth),  # noqa: B008
) -> JSONResponse:
    """Accept a feedback row. Always returns ``ACK-3010`` (HTTP 202)."""
    started = time.perf_counter()
    request.state.caller = caller

    # Compute reporter hash. Prefer the supplied email; fall back to
    # the source IP so we can still de-duplicate spammers.
    reporter_source = (
        str(payload.reporter_email)
        if payload.reporter_email is not None
        else caller.client_ip
    )
    reporter_hash = _hash_reporter(reporter_source)

    sm = get_sessionmaker()
    async with sm() as session:
        row = await insert_feedback(
            session,
            request_id=str(payload.request_id),
            original_code=payload.original_code,
            reason=payload.reason,
            reporter_hash=reporter_hash,
        )
    # Phase 8 — Prometheus counter (T8.4).
    observe_feedback()

    code = "ACK-3010"
    rc = get_code(code)
    resp_envelope = build_response(
        request_id=payload.request_id,
        code=code,
        processing_ms=int((time.perf_counter() - started) * 1000),
    )

    body = {
        "request_id": str(payload.request_id),
        "code": code,
        "feedback_id": row.id,
        "user_message": resp_envelope.user_message,
        "processed_at": datetime.now(tz=UTC).isoformat(),
        "processing_ms": resp_envelope.processing_ms,
    }

    # Phase 6 audit hook — record the feedback submission.
    request.state.audit_payload = AuditPayload(
        response_code=code,
        detected_entity_count=0,
        detected_entity_types=None,
    )

    return JSONResponse(status_code=rc.http_status, content=body)
