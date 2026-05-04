"""Response builder: turn (code, context) into a DetectPostResponse envelope.

Keeps all user-facing template rendering in one place so §2.5 rules
(user_message must not leak position/score/entity-type/masked value) can
be enforced with a single static check.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.api.schemas import BodyResult, Detection, DetectPostResponse, JobInfo
from app.core.codes import CODES, ResponseCode, Verdict, get_code


def _render(template: str | None, **vars: object) -> str | None:
    """Safely format a code template. Unknown placeholders are left intact."""
    if template is None:
        return None
    try:
        return template.format(**vars)
    except (KeyError, IndexError):
        return template


def build_response(
    *,
    request_id: UUID,
    code: str,
    detections: list[Detection] | None = None,
    processing_ms: int,
    template_vars: dict[str, object] | None = None,
    body_result: BodyResult | None = None,
    job: JobInfo | None = None,
) -> DetectPostResponse:
    """Build the unified response envelope for /v1/detect/post."""
    rc: ResponseCode = get_code(code)
    tv = template_vars or {}

    user_message = _render(rc.user_message_template, **tv) or ""
    # developer_message is only surfaced for ERROR category (§2.5).
    developer_message: str | None = None
    if rc.verdict is Verdict.ERROR:
        developer_message = _render(rc.developer_message_template, **tv)

    return DetectPostResponse(
        request_id=request_id,
        verdict=rc.verdict,
        code=rc.code,
        system_message=rc.system_message,
        user_message=user_message,
        developer_message=developer_message,
        detections=detections or [],
        body_result=body_result,
        job=job,
        processed_at=datetime.now(tz=UTC),
        processing_ms=processing_ms,
    )


# ── User-message safety check ──────────────────────────────────────────────
# §2.5 forbids the following from ever appearing in `user_message`:
#   - exact position ("position", "offset", digit-heavy spans)
#   - confidence score (numeric 0.x values, "score", "confidence")
#   - algorithm name (presidio, spacy, gliner, ner, regex)
#   - internal entity codes (KR_RRN, EMAIL_ADDRESS, CREDIT_CARD, etc.)
#   - masked PII preview (asterisks mixed with digits, etc.)
_FORBIDDEN_IN_USER_MESSAGE: tuple[str, ...] = (
    "score", "confidence", "presidio", "spacy", "gliner", "regex",
    "KR_RRN", "KR_PHONE", "KR_PASSPORT", "KR_DRIVERLICENSE",
    "KR_BUSINESS_NUM", "KR_BANK_ACCOUNT", "EMAIL_ADDRESS",
    "CREDIT_CARD", "PERSON", "LOCATION", "INTERNAL_NAME",
)


def user_message_safety_violations(template: str) -> list[str]:
    """Return any forbidden substrings found in a user_message template.

    Used by T1.16 and CI to enforce §2.5 across the whole catalog.
    """
    lowered = template.lower()
    hits: list[str] = []
    for banned in _FORBIDDEN_IN_USER_MESSAGE:
        if banned.lower() in lowered:
            hits.append(banned)
    return hits


def audit_all_user_messages() -> dict[str, list[str]]:
    """Scan every code's user_message_template; return { code: [violations] }."""
    return {
        code: v
        for code, rc in CODES.items()
        if (v := user_message_safety_violations(rc.user_message_template))
    }
