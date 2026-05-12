"""응답 envelope 빌더 — `(code, context)` → `DetectPostResponse` 변환.

모든 사용자 메시지 템플릿 렌더링을 한 곳에 모아두는 이유는 §2.5 보안 규칙
(`user_message` 에 위치 / score / entity 코드 / 마스킹된 PII 가 절대 등장
하지 않아야 함) 을 단일 정적 검사로 강제하기 위해서다.

빌더 동작:
  - `code` 로 `ResponseCode` 카탈로그 조회
  - `template_vars` 로 `user_message_template` / `developer_message_template`
    의 placeholder (예: `{filename}`) 치환
  - BLOCK 응답 + detections 가 있으면 한국어 entity 라벨 접미사
    `(검출된 항목: 주민등록번호, 전화번호)` 자동 부착
  - `developer_message` 는 ERROR (`REQ-/SVR-`) 카테고리에만 채움 (§2.5)
  - 응답 envelope 생성 후 `audit_all_user_messages()` 가 모든 템플릿이
    §2.5 금지어 (`KR_RRN`, `score`, `presidio` 등) 를 노출하지 않는지 정적
    검사 (테스트가 호출)
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.api.schemas import BodyResult, Detection, DetectPostResponse, JobInfo
from app.core.codes import CODES, ResponseCode, Verdict, get_code
from app.core.entity_labels import detected_summary_kr


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
    # Phase 4b/C — when the verdict is BLOCK we append the Korean labels
    # of the detected PII kinds so the operator can act on it ("…
    # 검출된 항목: 주민등록번호, 전화번호"). Codes (KR_RRN etc.) never
    # surface — only the human-readable labels — so the §2.5 forbidden
    # filter further down the file still catches accidental leaks.
    if rc.verdict is Verdict.BLOCK and detections:
        summary = detected_summary_kr(detections)
        if summary:
            user_message = f"{user_message} (검출된 항목: {summary})".strip()
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
    "score",
    "confidence",
    "presidio",
    "spacy",
    "gliner",
    "regex",
    "KR_RRN",
    "KR_PHONE",
    "KR_PASSPORT",
    "KR_DRIVERLICENSE",
    "KR_BUSINESS_NUM",
    "KR_BANK_ACCOUNT",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "PERSON",
    "LOCATION",
    "INTERNAL_NAME",
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
