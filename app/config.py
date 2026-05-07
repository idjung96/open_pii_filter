"""Environment-driven application settings.

All configuration is loaded from environment variables or a local `.env` file.
Never hardcode credentials. See `.env.example` for the full variable list.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # App
    app_env: str = "development"
    log_level: str = "INFO"

    # PostgreSQL (required)
    database_url: str
    database_url_sync: str
    db_schema: str = "pii"

    # Redis
    redis_url: str = "redis://127.0.0.1:6379/0"

    # ClamAV (TCP)
    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310

    # Phase 3 — auth & rate limiting
    # Comma-separated CIDRs for the global IP allowlist; empty = no restriction.
    ip_allowlist: str = ""
    # Hard cap on HTTP request body (bytes); enforced by BodySizeLimitMiddleware.
    max_request_body_bytes: int = 1 * 1024 * 1024
    # Per-IP fallback for unauthenticated traffic (requests/min).
    ip_rate_per_minute: int = 10
    # Q5: only honour X-Forwarded-For when behind a trusted reverse proxy.
    # Set to true in production deployments fronted by Nginx (deploy/nginx.conf).
    trust_forwarded_for: bool = False

    # Phase 4 — async attachment processing
    # HMAC signing secret for outbound webhook callbacks. Empty disables
    # signing (callbacks are POSTed without an X-Signature header). The
    # canonical-string format matches `app.security.hmac_auth`.
    webhook_signing_secret: str = ""
    # Per-attempt timeout for HTTP fetch + webhook POST (seconds).
    attachment_fetch_timeout_seconds: float = 30.0
    webhook_post_timeout_seconds: float = 15.0

    # Phase 5 / 4b — OCR
    # Engine selector. "paddle" (default) uses PaddleOCR (CPU, in-process,
    # ships with the runtime). "vlm" routes to OpenAI-compatible chat
    # completions against the internal Qwen-VL endpoint — kept as an opt-in
    # for low-quality scans where Paddle accuracy regresses; the dispatcher
    # falls back to VLM automatically when Paddle errors.
    ocr_engine: Literal["vlm", "paddle"] = "paddle"
    vlm_endpoint: str = "http://vlm-host:18000/v1"
    vlm_model_id: str = "Qwen/Qwen3.5-27B-GPTQ-Int4"
    vlm_api_key: str = ""
    ocr_request_timeout_seconds: float = 120.0
    # Phase 9D — masked_image_dir / masked_image_retention_hours /
    # public_base_url 설정은 마스킹 인프라 폐기와 함께 제거되었다.

    # ── Phase 6 — privacy & audit ────────────────────────────────────────
    # Hex-encoded 32-byte AES-256 master key. Required when calling
    # ``app.security.encryption.encrypt_str`` / ``decrypt_str``. An empty
    # value disables the singleton lazily — the helpers raise
    # EncryptionError on first use rather than at import time so dev
    # environments without crypto configured can still boot the app.
    pii_encryption_key: str = ""
    # Logical version byte stored alongside the ciphertext for rotation.
    pii_encryption_key_id: int = 1
    # JSON-encoded mapping {"<key_id>": "<hex>"} of retired master keys
    # that should still decrypt. Used during rotation grace periods.
    # Example: PII_ENCRYPTION_OLD_KEYS='{"1":"<hex>","2":"<hex>"}'
    pii_encryption_old_keys: str = ""

    # Detection-result retention in days (Phase 6, Q2).
    detection_retention_days: int = 30
    # Audit-log retention in days. Default 1 year per ISMS-P guidance.
    audit_log_retention_days: int = 365

    # ── Phase 6 — admin / audit query endpoint ───────────────────────────
    # CIDR allowlist for /v1/admin/*. Empty → router not mounted at all
    # (returns 404). Non-empty → requests must originate from these CIDRs
    # AND present an API key whose ``is_admin`` column is true.
    admin_ip_allowlist: str = ""

    # ── Phase 7 — feedback alerter (operator-decision A) ─────────────────
    # SMTP configuration for the hourly feedback alerter. ``smtp_host``
    # and ``alert_email_to`` empty → alerter logs WARNING and idles.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_from: str = ""
    alert_email_to: str = ""  # CSV of recipients
    feedback_alert_threshold: int = 10  # rows/hour
    # Polling cadence for the alerter loop. Tests override to a few
    # milliseconds via monkeypatch.
    feedback_alert_interval_seconds: int = 3600

    # ── Phase 7 — privacy notice template variables (operator-decision D)
    # Substituted into ``docs/privacy_notice.md`` placeholders when the
    # public ``GET /v1/legal/privacy-notice`` endpoint is hit. Empty
    # values leave the placeholder verbatim so the operator notices.
    company_name: str = ""
    company_contact_email: str = ""
    company_contact_phone: str = ""
    data_protection_officer_name: str = ""
    data_protection_officer_email: str = ""

    # ── Phase 9A — admin dashboard (Jinja2 + Bootstrap) ──────────────────
    # CIDR allowlist for the /admin dashboard. Defaults to "0.0.0.0/0"
    # which permits any IP — operators tighten this in production via
    # the env var. Empty value disables the dashboard entirely.
    admin_dashboard_ip_allowlist: str = "0.0.0.0/0"
    # Login form credentials. Override BOTH in production.
    admin_dashboard_username: str = "admin"
    admin_dashboard_password: str = "changeme"  # noqa: S105 — dev default; override in env


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings instance.

    `lru_cache` ensures a single Settings object across the process so that
    `.env` is read only once at startup.
    """
    return Settings()
