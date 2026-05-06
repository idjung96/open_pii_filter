"""SQLAlchemy models for Phase 2 (deny-list) + Phase 7 (policy engine +
false-positive feedback).

Tables (under the `pii` schema, see Settings.db_schema):
  - pii_deny_list         : exact-match deny entries (employee names, etc.)
  - pii_policies          : DB-driven (entity_type, score band) overrides
  - pii_feedback          : false-positive reports (no plaintext email)

Phase 9E — pii_patterns / pii_pattern_history 테이블이 삭제됐다.
사용자 등록 정규식 패턴은 운영 부담 대비 효용이 낮아 폐기되고 분석
엔진은 코드에 정의된 인식기만 사용한다.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import get_settings

_SCHEMA = get_settings().db_schema


class Base(DeclarativeBase):
    """Project-wide declarative base. Each table sets its own schema."""


class PiiDenyList(Base):
    """Exact-match deny list (employee names, sensitive identifiers, etc.)."""

    __tablename__ = "pii_deny_list"
    __table_args__ = (
        UniqueConstraint("entity_type", "value", name="uq_pii_deny_list_entity_value"),
        CheckConstraint("score >= 0 AND score <= 1", name="ck_pii_deny_list_score"),
        {"schema": _SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.95)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ApiKey(Base):
    """Issued API key (Phase 3 — auth & rate limiting).

    The plaintext ``secret`` is the symmetric key used for HMAC. Storing
    plaintext keeps the client SDK simple (standard HMAC-SHA256 of the
    canonical string). The column is a candidate for pgcrypto AES
    column-level encryption in Phase 6.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        CheckConstraint(
            "rate_per_minute > 0 AND rate_per_hour > 0",
            name="ck_api_keys_rate_positive",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    secret: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # NULL = no per-key IP restriction (global allowlist still applies if set).
    ip_allowlist: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    rate_per_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    rate_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Phase 6 — gate for /v1/admin/* endpoints. Default false; set via the
    # CLI ``apikey issue --admin`` flag.
    is_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_by: Mapped[str] = mapped_column(String(64), nullable=False, default="cli")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExtractionJob(Base):
    """Phase 4 — async attachment-processing job (Case C).

    One row per /v1/detect/post call that has attachments. Updated by the
    extraction worker as it progresses through fetch → scan → extract →
    analyze. Retained for 24 hours after completion (T4.21) so callers
    can poll /v1/jobs/{id} even if the webhook delivery fails.
    """

    __tablename__ = "extraction_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','PROCESSING','COMPLETED','FAILED')",
            name="ck_extraction_jobs_status",
        ),
        {"schema": _SCHEMA},
    )

    job_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    callback_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING", index=True)
    body_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    body_verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # JSON-encoded list[WebhookAttachmentResult-shaped dict]; populated
    # incrementally as each attachment completes.
    attachments_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Webhook delivery audit: number of POST attempts so far.
    webhook_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    webhook_delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ApiKeyNonce(Base):
    """Replay-defense store: every (key_id, nonce) pair is single-use within
    the timestamp window. Cleaned by a periodic vacuum routine that drops
    rows with `used_at < now() - 10 minutes`.
    """

    __tablename__ = "api_key_nonces"
    __table_args__ = ({"schema": _SCHEMA},)

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )


class AuditEvent(Base):
    """Append-only audit trail of every authenticated request (Phase 6).

    Postgres BEFORE UPDATE/DELETE triggers (see migration ``phase-6a``)
    raise an exception unless the session has set
    ``app.bypass_audit_lock = 'on'`` — only the retention cleanup worker
    does that. Application code may only INSERT.

    No PII plaintext is ever stored here. Detected entity types are kept
    as a comma-separated list (``KR_RRN,EMAIL_ADDRESS``) and the body is
    represented by its SHA-256 hash for forensic correlation only.
    """

    __tablename__ = "audit_events"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    api_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String(256), nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detected_entity_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Comma-separated entity_type list (NOT plaintext) — e.g. "KR_RRN,EMAIL_ADDRESS"
    detected_entity_types: Mapped[str | None] = mapped_column(Text, nullable=True)
    processing_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # SHA-256 hex of the request body for joining without storing content.
    body_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Phase 7 — comma-separated entity_types that fired only in shadow
    # mode (NOT counted toward verdict). Useful for trial-rolling new
    # patterns without affecting callers.
    shadow_hit_types: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Phase 9B — optional full request/response capture (audit detail).
    # Only populated when ``audit_detail_enabled`` is True in system_settings.
    request_body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_headers_text: Mapped[str | None] = mapped_column(Text, nullable=True)


class PiiPolicy(Base):
    """Phase 7 — DB-driven policy override for (entity_type, score band).

    Resolution order at request time:
      1. Find ``mode='enabled'`` rows where ``entity_type`` matches and
         ``score_min <= score <= score_max``. Most-specific (narrowest band)
         wins; ties break on highest ``score_min``.
      2. If no DB row matches, fall back to ``app.core.policies`` mapping.

    Shadow rows (``mode='shadow'``) are evaluated for audit/log purposes
    only; they never alter the caller-visible verdict.

    Actions
    -------
    BLOCK     — verdict=BLOCK; surfaces a BLOCK-level user_message
    WARN      — verdict=WARN; surfaces a WARN-level user_message
    MASK      — verdict=PASS, but the masked text is enforced for output;
                user_message indicates auto-redaction (WARN-1010)
    LOG_ONLY  — entity dropped from caller-visible response, but the type
                is recorded in audit_events
    PASS      — entity dropped from response (no audit type either)
    """

    __tablename__ = "pii_policies"
    __table_args__ = (
        UniqueConstraint(
            "entity_type",
            "score_min",
            "score_max",
            "mode",
            name="uq_pii_policies_entity_band_mode",
        ),
        CheckConstraint(
            "action IN ('BLOCK','WARN','MASK','LOG_ONLY','PASS')",
            name="ck_pii_policies_action",
        ),
        CheckConstraint(
            "mode IN ('enabled','shadow','disabled')",
            name="ck_pii_policies_mode",
        ),
        CheckConstraint(
            "score_min >= 0 AND score_max <= 1 AND score_min <= score_max",
            name="ck_pii_policies_score_band",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    score_min: Mapped[float] = mapped_column(Float, nullable=False)
    score_max: Mapped[float] = mapped_column(Float, nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    user_message_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="enabled", server_default=text("'enabled'")
    )
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    created_by: Mapped[str] = mapped_column(
        String(64), nullable=False, default="system", server_default=text("'system'")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class PiiFeedback(Base):
    """Phase 7 — append-only false-positive / false-negative report.

    Submitted via POST /v1/feedback. The reporter's email (when supplied)
    is hashed with the project-wide salt before storage; raw email never
    hits the DB. The row links to ``request_id`` so operators can join
    against ``audit_events`` for forensic context (no PII plaintext).
    """

    __tablename__ = "pii_feedback"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    original_code: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 hex of (project salt + email-or-IP). NEVER plaintext email.
    reporter_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ExceptionIp(Base):
    """Phase 9A — IP exception list for ``post.author.ip``.

    When the post author's IP matches any CIDR in this table the body
    PII analysis is skipped and an OK-0000 PASS verdict is returned
    immediately. Used for trusted internal authors who must be allowed
    to publish posts containing PII (e.g. HR or admin accounts).
    """

    __tablename__ = "exception_ips"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cidr: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    label: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=text("''")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class ApiIpCaller(Base):
    """Phase 9A — IP-based alternative to HMAC authentication.

    When a request arrives WITHOUT any HMAC headers
    (``X-API-Key``/``X-Timestamp``/``X-Nonce``/``X-Signature``) and the
    client IP matches a CIDR in this table, the request is authenticated
    as ``ip:<cidr>`` and the per-row rate limits apply. Any HMAC header
    present forces the regular HMAC code path.
    """

    __tablename__ = "api_ip_callers"
    __table_args__ = (
        CheckConstraint(
            "rate_per_minute > 0 AND rate_per_hour > 0",
            name="ck_api_ip_callers_rate_positive",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cidr: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    rate_per_minute: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default=text("60")
    )
    rate_per_hour: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1000, server_default=text("1000")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AlerterState(Base):
    """Phase 7 — single-row state for a named alerter (e.g. 'feedback').

    Used by the hourly feedback alerter to avoid re-sending the same
    alert after a process restart inside the alert window.
    """

    __tablename__ = "alerter_state"
    __table_args__ = ({"schema": _SCHEMA},)

    key: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    last_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AttachmentBlocklist(Base):
    """Phase 4b — runtime-managed deny list for attachment formats.

    A row blocks an attachment when its `extension` matches the trailing
    suffix of the filename (case-insensitive, dot stripped) OR its
    `mime_type` matches the request's declared MIME. At least one of the
    two must be set per row (DB CHECK constraint).

    Operators add/remove rows via `POST/DELETE /v1/admin/attachment-blocklist`;
    the per-process cache (`app.core.blocklist_cache`) is reloaded on
    every mutation. The seed migration ships archive (zip/rar/7z/...) and
    legacy-OLE Office (hwp/hwpx/doc/xls/ppt) entries.

    Exception-IP authors bypass the blocklist entirely (Phase 9A trust
    semantics) — the gate lives in `app/api/detect.py`.
    """

    __tablename__ = "attachment_blocklist"
    __table_args__ = (
        CheckConstraint(
            "extension IS NOT NULL OR mime_type IS NOT NULL",
            name="ck_attachment_blocklist_match_required",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    extension: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    mime_type: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=text("''")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
