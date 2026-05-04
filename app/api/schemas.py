"""Pydantic models for request/response payloads (§2.2 and §2.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.codes import Verdict

Strictness = Literal["low", "medium", "high"]


# ── Request ─────────────────────────────────────────────────────────────────
class Author(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    user_id: str | None = Field(default=None, max_length=100)
    ip: str = Field(..., min_length=1, max_length=45)  # IPv4 or IPv6
    is_anonymous: bool = False


# Body length limits — enforced manually in the endpoint so we can map
# violations to REQ-4030 (HTTP 413) instead of pydantic's default 422.
MAX_TITLE_LEN = 500
MAX_BODY_LEN = 50_000


class Post(BaseModel):
    board_id: str = Field(..., max_length=64)
    title: str
    body: str


class Attachment(BaseModel):
    attachment_id: str = Field(..., max_length=64)
    filename: str = Field(..., max_length=255)
    size_bytes: int = Field(..., ge=0)
    mime_type: str = Field(..., max_length=100)
    sha256: str = Field(..., min_length=64, max_length=64)
    fetch_url: str = Field(..., max_length=2048)


class Options(BaseModel):
    strictness: Strictness = "medium"


class DetectPostRequest(BaseModel):
    """POST /v1/detect/post request (§2.2)."""

    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    author: Author
    post: Post
    attachments: list[Attachment] | None = None
    callback_url: str | None = Field(default=None, max_length=2048)
    options: Options = Field(default_factory=Options)

    @field_validator("attachments", mode="before")
    @classmethod
    def _normalize_attachments(cls, v: object) -> object:
        """Treat null and [] identically (§2.8 edge cases)."""
        if v is None:
            return None
        return v

    @property
    def has_attachments(self) -> bool:
        return bool(self.attachments)


# ── Response ────────────────────────────────────────────────────────────────
class Detection(BaseModel):
    """A single PII entity hit reported back to the caller (§2.3)."""

    field: str  # e.g., "post.body", "post.title", "attachment.att_001"
    entity_type: str
    code: str
    score: float = Field(ge=0.0, le=1.0)
    start: int | None = None
    end: int | None = None
    masked_preview: str | None = None


class JobInfo(BaseModel):
    """Async job pointer returned in Case C (§2.3, HTTP 202)."""

    job_id: str
    status_url: str
    estimated_completion_seconds: int
    attachment_count: int


class BodyResult(BaseModel):
    """Body verdict summary embedded in Case C response."""

    verdict: Verdict
    code: str
    detections: list[Detection] = Field(default_factory=list)


class DetectPostResponse(BaseModel):
    """Unified response envelope for /v1/detect/post (§2.3)."""

    request_id: UUID
    verdict: Verdict
    code: str
    system_message: str
    user_message: str
    developer_message: str | None = None

    detections: list[Detection] = Field(default_factory=list)

    # Case C only
    body_result: BodyResult | None = None
    job: JobInfo | None = None

    processed_at: datetime
    processing_ms: int


class WebhookAttachmentResult(BaseModel):
    attachment_id: str
    filename: str
    verdict: Verdict
    code: str
    detections: list[Detection] = Field(default_factory=list)


class WebhookPayload(BaseModel):
    """Payload posted to callback_url when attachment processing completes."""

    request_id: UUID
    job_id: str
    verdict: Verdict
    code: str
    user_message: str
    attachment_results: list[WebhookAttachmentResult] = Field(default_factory=list)
    completed_at: datetime
