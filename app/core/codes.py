"""응답 코드 카탈로그 (§2.4).

이 모듈은 API 가 외부로 노출하는 모든 응답 코드의 단일 진실 원천이다.
응답 envelope 의 `code` 필드는 항상 여기 정의된 식별자 중 하나로 떨어지며,
클라이언트는 `code` 만 보고 분기 가능하도록 설계되었다.

코드 정책 — **불변 식별자**:
  - 한 번 발급된 코드의 의미는 **절대 재정의하지 않는다** (예: BLOCK-2001 이
    오늘 RRN 이라면 영원히 RRN. 카탈로그 정리하면서 의미를 옮기지 말 것)
  - 새 코드는 다음 빈 번호에 추가하면 되고 호환성 영향 없음
  - 폐기된 코드도 카탈로그에 남겨둔다 (역사적 audit 행과의 호환)

카테고리 → HTTP 매핑:
  - `OK-xxxx`    → PASS / HTTP 200 (게시 허용)
  - `WARN-xxxx`  → WARN / HTTP 200 — Phase 9D 폐기. 신규 발생하지 않음
  - `BLOCK-xxxx` → BLOCK / HTTP 200 (게시 차단, user_message 안내)
  - `ACK-xxxx`   → PROCESSING / HTTP 202 (Case C 비동기 시작)
  - `REQ-xxxx`   → ERROR / HTTP 4xx (호출자 측 잘못)
  - `SVR-xxxx`   → ERROR / HTTP 5xx (서버 측 잘못, `retryable=True` 가능)

각 `ResponseCode` 는 다음을 포함:
  - `http_status` — FastAPI 가 응답에 사용할 HTTP 코드
  - `system_message` — 운영자/로그용 영문 메시지 (PII 미포함)
  - `user_message_template` — 사용자 안내 한국어 (placeholder 치환 가능)
  - `developer_message_template` — ERROR 카테고리만 채움 (§2.5 — PASS/BLOCK 에는 미노출)
  - `retryable` — SVR-5xxx 가 클라이언트 측 backoff 재시도 안전한지 표시
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Verdict(StrEnum):
    PASS = "PASS"  # noqa: S105 — not a secret; verdict label
    WARN = "WARN"
    BLOCK = "BLOCK"
    PROCESSING = "PROCESSING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ResponseCode:
    code: str
    http_status: int
    verdict: Verdict
    system_message: str
    user_message_template: str
    developer_message_template: str | None = None
    retryable: bool = False


# ── PASS ────────────────────────────────────────────────────────────────────
_PASS: dict[str, ResponseCode] = {
    "OK-0000": ResponseCode(
        code="OK-0000",
        http_status=200,
        verdict=Verdict.PASS,
        system_message="No PII detected",
        user_message_template="게시 가능합니다.",
    ),
    "OK-0001": ResponseCode(
        code="OK-0001",
        http_status=200,
        verdict=Verdict.PASS,
        system_message="Weak signals only, policy allows",
        user_message_template="게시 가능합니다.",
    ),
}

# ── WARN ────────────────────────────────────────────────────────────────────
# DEPRECATED since Phase 9D — WARN 등급은 더 이상 신규 발생하지 않는다.
# 모든 임계값 이상 탐지는 BLOCK 으로 흡수되며 사용자가 직접 PII 를 제거 후
# 재등록한다. 아래 코드들은 기존 ``audit_events.response_code`` 컬럼에
# 저장된 과거 행과의 호환을 위해 보존된다 (조회/렌더링 경로는 유지).
_WARN: dict[str, ResponseCode] = {
    "WARN-1001": ResponseCode(
        code="WARN-1001",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="KR phone-like pattern detected in body",
        user_message_template=(
            "본문에 전화번호로 보이는 정보가 포함되어 있습니다. "
            "공개되어도 괜찮은 정보인지 확인 후 게시해주세요."
        ),
    ),
    "WARN-1002": ResponseCode(
        code="WARN-1002",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="Email address detected in body",
        user_message_template=(
            "본문에 이메일 주소가 포함되어 있습니다. 공개되어도 괜찮은 정보인지 확인해주세요."
        ),
    ),
    "WARN-1003": ResponseCode(
        code="WARN-1003",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="Address-like pattern detected in body",
        user_message_template="본문에 주소로 보이는 정보가 포함되어 있습니다.",
    ),
    "WARN-1004": ResponseCode(
        code="WARN-1004",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="Multiple person names detected in body",
        user_message_template=("본문에 사람 이름으로 보이는 표현이 여러 건 포함되어 있습니다."),
    ),
    "WARN-1005": ResponseCode(
        code="WARN-1005",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="Body person name differs from author",
        user_message_template=(
            "본문에 작성자 본인이 아닌 다른 사람의 이름이 포함된 것 같습니다. "
            "동의 없는 타인 정보 노출에 유의해주세요."
        ),
    ),
    "WARN-1099": ResponseCode(
        code="WARN-1099",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="Other weak PII signal",
        user_message_template=(
            "본문에 개인정보로 의심되는 표현이 포함되어 있습니다. 확인 후 게시해주세요."
        ),
    ),
    # Phase 7 — auto-redaction (action=MASK).
    "WARN-1010": ResponseCode(
        code="WARN-1010",
        http_status=200,
        verdict=Verdict.WARN,
        system_message="Sensitive content auto-redacted",
        user_message_template=(
            "본문 일부가 자동으로 가려졌습니다. 가려진 내용은 그대로 게시됩니다."
        ),
    ),
}

# ── BLOCK ───────────────────────────────────────────────────────────────────
_BLOCK: dict[str, ResponseCode] = {
    "BLOCK-2001": ResponseCode(
        code="BLOCK-2001",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Korean RRN detected in body",
        user_message_template=(
            "본문에 주민등록번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다. "
            "해당 정보를 삭제하거나 가린 후 다시 시도해주세요."
        ),
    ),
    "BLOCK-2002": ResponseCode(
        code="BLOCK-2002",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Korean driver license detected in body",
        user_message_template=(
            "본문에 운전면허번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다."
        ),
    ),
    "BLOCK-2003": ResponseCode(
        code="BLOCK-2003",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Korean passport detected in body",
        user_message_template=("본문에 여권번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다."),
    ),
    "BLOCK-2004": ResponseCode(
        code="BLOCK-2004",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Foreign registration number detected in body",
        user_message_template=(
            "본문에 외국인등록번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다."
        ),
    ),
    "BLOCK-2005": ResponseCode(
        code="BLOCK-2005",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Credit card detected in body",
        user_message_template=(
            "본문에 신용카드번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다."
        ),
    ),
    "BLOCK-2006": ResponseCode(
        code="BLOCK-2006",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Bank account (strong) detected in body",
        user_message_template=(
            "본문에 계좌번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다. "
            "금융 정보 노출은 보이스피싱 등에 악용될 수 있습니다."
        ),
    ),
    "BLOCK-2007": ResponseCode(
        code="BLOCK-2007",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Internal name (deny list) detected in body",
        user_message_template=(
            "본문에 기관 임직원 정보가 포함되어 있어 게시할 수 없습니다. "
            "직원 정보 공개가 필요한 경우 담당 부서로 문의해주세요."
        ),
    ),
    "BLOCK-2008": ResponseCode(
        code="BLOCK-2008",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Multiple PII types detected simultaneously",
        user_message_template=(
            "본문에 여러 종류의 개인정보가 함께 포함되어 있어 게시할 수 없습니다. "
            "해당 정보를 모두 제거한 후 다시 시도해주세요."
        ),
    ),
    "BLOCK-2010": ResponseCode(
        code="BLOCK-2010",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="PII detected in attachment",
        user_message_template=(
            "첨부파일 '{filename}'에 개인정보가 포함되어 있어 게시할 수 없습니다. "
            "첨부파일을 가리거나 제거한 후 다시 시도해주세요."
        ),
    ),
    "BLOCK-2011": ResponseCode(
        code="BLOCK-2011",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="PII detected via OCR in image",
        user_message_template=(
            "첨부 이미지 '{filename}'에서 개인정보가 포함된 텍스트가 발견되어 게시할 수 없습니다."
        ),
    ),
    "BLOCK-2012": ResponseCode(
        code="BLOCK-2012",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Image looks like an ID card",
        user_message_template=(
            "첨부 이미지 '{filename}'이 신분증 사진으로 의심됩니다. "
            "신분증 이미지는 게시할 수 없습니다."
        ),
    ),
    "BLOCK-2099": ResponseCode(
        code="BLOCK-2099",
        http_status=200,
        verdict=Verdict.BLOCK,
        system_message="Other strong PII signal",
        user_message_template=(
            "본문에 개인정보로 판단되는 정보가 포함되어 있어 게시할 수 없습니다."
        ),
    ),
}

# ── ACK (PROCESSING) ────────────────────────────────────────────────────────
_ACK: dict[str, ResponseCode] = {
    "ACK-3001": ResponseCode(
        code="ACK-3001",
        http_status=202,
        verdict=Verdict.PROCESSING,
        system_message="Body passed, attachments queued",
        user_message_template=(
            "본문은 이상이 없습니다. 첨부파일 검사가 진행 중입니다 (예상 {eta_seconds}초 이내)."
        ),
    ),
    "ACK-3002": ResponseCode(
        code="ACK-3002",
        http_status=202,
        verdict=Verdict.PROCESSING,
        system_message="Attachment queue backlog causing delay",
        user_message_template=(
            "첨부파일 검사가 진행 중입니다. 현재 처리량이 많아 평소보다 시간이 더 걸릴 수 있습니다."
        ),
    ),
    # Phase 7 — POST /v1/feedback acknowledgement.
    "ACK-3010": ResponseCode(
        code="ACK-3010",
        http_status=202,
        verdict=Verdict.PROCESSING,
        system_message="Feedback received",
        user_message_template=("의견이 접수되었습니다. 검토 후 정책에 반영하겠습니다."),
    ),
}

# ── REQ (client errors, HTTP 4xx) ───────────────────────────────────────────
_REQ: dict[str, ResponseCode] = {
    "REQ-4001": ResponseCode(
        code="REQ-4001",
        http_status=400,
        verdict=Verdict.ERROR,
        system_message="Required field missing",
        user_message_template="요청 정보가 부족합니다.",
        developer_message_template="누락 필드: {fields}",
    ),
    "REQ-4002": ResponseCode(
        code="REQ-4002",
        http_status=400,
        verdict=Verdict.ERROR,
        system_message="Invalid author field format",
        user_message_template="작성자 정보 형식이 올바르지 않습니다.",
        developer_message_template="author.{field} 검증 실패",
    ),
    "REQ-4003": ResponseCode(
        code="REQ-4003",
        http_status=400,
        verdict=Verdict.ERROR,
        system_message="Malformed JSON",
        user_message_template="요청 형식이 올바르지 않습니다.",
        developer_message_template="JSON parse error: {detail}",
    ),
    "REQ-4004": ResponseCode(
        code="REQ-4004",
        http_status=400,
        verdict=Verdict.ERROR,
        system_message="Invalid request_id format",
        user_message_template="요청 식별자 형식이 올바르지 않습니다.",
        developer_message_template="UUID v4 형식 필요",
    ),
    "REQ-4005": ResponseCode(
        code="REQ-4005",
        http_status=400,
        verdict=Verdict.ERROR,
        system_message="Duplicate request_id (idempotency)",
        user_message_template="이미 처리된 요청입니다.",
        developer_message_template="중복 검출 (idempotency)",
    ),
    "REQ-4010": ResponseCode(
        code="REQ-4010",
        http_status=401,
        verdict=Verdict.ERROR,
        system_message="HMAC signature mismatch",
        user_message_template="요청 인증에 실패했습니다.",
        developer_message_template=(
            "X-Signature 헤더가 서버 계산값과 일치하지 않습니다. "
            "body 직렬화 방식(JSON canonical form)과 timestamp 포함 여부를 확인하세요."
        ),
    ),
    "REQ-4011": ResponseCode(
        code="REQ-4011",
        http_status=401,
        verdict=Verdict.ERROR,
        system_message="API key missing or invalid",
        user_message_template="요청 인증에 실패했습니다.",
        developer_message_template="X-API-Key 헤더 누락 또는 무효",
    ),
    "REQ-4012": ResponseCode(
        code="REQ-4012",
        http_status=401,
        verdict=Verdict.ERROR,
        system_message="Timestamp out of window",
        user_message_template="요청 시각이 유효 범위를 벗어났습니다.",
        developer_message_template="timestamp 윈도우 ±5분 초과",
    ),
    "REQ-4013": ResponseCode(
        code="REQ-4013",
        http_status=401,
        verdict=Verdict.ERROR,
        system_message="Replay suspected",
        user_message_template="중복 요청이 감지되었습니다.",
        developer_message_template="동일 (timestamp, nonce) 재전송",
    ),
    "REQ-4014": ResponseCode(
        code="REQ-4014",
        http_status=403,
        verdict=Verdict.ERROR,
        system_message="API key revoked",
        user_message_template="요청 권한이 없습니다.",
        developer_message_template="API Key가 비활성 상태",
    ),
    "REQ-4015": ResponseCode(
        code="REQ-4015",
        http_status=403,
        verdict=Verdict.ERROR,
        system_message="IP not in allowlist",
        user_message_template="요청 권한이 없습니다.",
        developer_message_template="IP {ip}는 허용 목록에 없음",
    ),
    "REQ-4020": ResponseCode(
        code="REQ-4020",
        http_status=429,
        verdict=Verdict.ERROR,
        system_message="Rate limit exceeded",
        user_message_template="요청이 너무 많습니다. 잠시 후 다시 시도해주세요.",
        developer_message_template="rate limit exceeded for this caller",
    ),
    "REQ-4030": ResponseCode(
        code="REQ-4030",
        http_status=413,
        verdict=Verdict.ERROR,
        system_message="Body too long",
        user_message_template="본문이 너무 깁니다. 길이를 줄여 주세요.",
        developer_message_template="post body exceeds maximum length",
    ),
    "REQ-4031": ResponseCode(
        code="REQ-4031",
        http_status=413,
        verdict=Verdict.ERROR,
        system_message="Attachment too large",
        user_message_template="첨부파일 '{filename}'의 크기가 너무 큽니다.",
        developer_message_template="attachment size exceeds maximum",
    ),
    "REQ-4032": ResponseCode(
        code="REQ-4032",
        http_status=400,
        verdict=Verdict.ERROR,
        system_message="Too many attachments",
        user_message_template="첨부파일 개수가 너무 많습니다.",
        developer_message_template="too many attachments in request",
    ),
    "REQ-4033": ResponseCode(
        code="REQ-4033",
        http_status=415,
        verdict=Verdict.ERROR,
        system_message="Unsupported attachment type",
        user_message_template="첨부파일 '{filename}'의 형식은 검사가 지원되지 않습니다.",
        developer_message_template="mime_type {mime_type} 미지원",
    ),
    "REQ-4034": ResponseCode(
        code="REQ-4034",
        http_status=403,
        verdict=Verdict.ERROR,
        system_message="HWP/HWPX restricted to allowlisted authors",
        user_message_template=(
            "한글(.hwp/.hwpx) 파일 '{filename}' 은(는) 등록된 작성자만 첨부할 수 있습니다."
        ),
        developer_message_template=(
            "hwp attachment from non-exception ip — author={author_ip}, mime={mime_type}. "
            "Linux runtime cannot parse hwp/hwpx (pyhwpx is Windows-only); only "
            "exception-ip authors who skip PII analysis may attach these formats."
        ),
    ),
    # Phase 4b — REQ-4034 is no longer emitted by new code paths; the
    # generic blocklist (REQ-4035) supersedes it. Kept in the catalog for
    # historical audit row compatibility.
    "REQ-4035": ResponseCode(
        code="REQ-4035",
        http_status=415,
        verdict=Verdict.ERROR,
        system_message="Attachment format is on the deny list",
        user_message_template=("첨부파일 '{filename}' 의 형식({reason})은 등록할 수 없습니다."),
        developer_message_template=(
            "attachment format blocked — filename={filename}, mime={mime_type}, "
            "match={match_kind}, reason={reason}"
        ),
    ),
    "REQ-4040": ResponseCode(
        code="REQ-4040",
        http_status=422,
        verdict=Verdict.ERROR,
        system_message="Attachment fetch failed",
        user_message_template="첨부파일 '{filename}'을 가져올 수 없습니다.",
        developer_message_template="fetch_url HTTP {status}",
    ),
    "REQ-4041": ResponseCode(
        code="REQ-4041",
        http_status=422,
        verdict=Verdict.ERROR,
        system_message="Attachment SHA256 mismatch",
        user_message_template="첨부파일 '{filename}'의 무결성 검증에 실패했습니다.",
        developer_message_template="sha256 mismatch",
    ),
    "REQ-4042": ResponseCode(
        code="REQ-4042",
        http_status=422,
        verdict=Verdict.ERROR,
        system_message="Attachment corrupted",
        user_message_template="첨부파일 '{filename}'이 손상되어 검사할 수 없습니다.",
        developer_message_template="파서 예외: {detail}",
    ),
    "REQ-4043": ResponseCode(
        code="REQ-4043",
        http_status=422,
        verdict=Verdict.ERROR,
        system_message="PDF page count exceeded",
        user_message_template=(
            "첨부파일 '{filename}'의 페이지 수가 너무 많습니다. (최대 {limit}페이지)"
        ),
        developer_message_template="page count {n} > {limit}",
    ),
    "REQ-4050": ResponseCode(
        code="REQ-4050",
        http_status=422,
        verdict=Verdict.ERROR,
        system_message="Malware detected",
        user_message_template=(
            "첨부파일 '{filename}'에서 보안 위협이 발견되어 검사를 중단했습니다."
        ),
        developer_message_template="ClamAV: {signature}",
    ),
    "REQ-4051": ResponseCode(
        code="REQ-4051",
        http_status=422,
        verdict=Verdict.ERROR,
        system_message="Encrypted/password-protected file",
        user_message_template="암호가 걸린 첨부파일 '{filename}'은 검사할 수 없습니다.",
        developer_message_template="암호 보호 PDF/문서",
    ),
}

# ── SVR (server errors, HTTP 5xx) ───────────────────────────────────────────
_SVR: dict[str, ResponseCode] = {
    "SVR-5001": ResponseCode(
        code="SVR-5001",
        http_status=500,
        verdict=Verdict.ERROR,
        system_message="Internal analyzer error",
        user_message_template="검사 중 일시적 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
        retryable=True,
    ),
    "SVR-5002": ResponseCode(
        code="SVR-5002",
        http_status=503,
        verdict=Verdict.ERROR,
        system_message="Analyzer not ready",
        user_message_template="검사 서비스가 준비 중입니다. 잠시 후 다시 시도해주세요.",
        retryable=True,
    ),
    "SVR-5003": ResponseCode(
        code="SVR-5003",
        http_status=503,
        verdict=Verdict.ERROR,
        system_message="Database unavailable",
        user_message_template="검사 서비스 일시 장애. 잠시 후 다시 시도해주세요.",
        retryable=True,
    ),
    "SVR-5004": ResponseCode(
        code="SVR-5004",
        http_status=503,
        verdict=Verdict.ERROR,
        system_message="OCR worker down",
        user_message_template=(
            "이미지 검사가 일시 불가합니다. 텍스트만 게시하거나 잠시 후 다시 시도해주세요."
        ),
        retryable=True,
    ),
    "SVR-5005": ResponseCode(
        code="SVR-5005",
        http_status=503,
        verdict=Verdict.ERROR,
        system_message="Queue saturated",
        user_message_template="현재 처리량이 한계에 도달했습니다. 잠시 후 다시 시도해주세요.",
        retryable=True,
    ),
    "SVR-5006": ResponseCode(
        code="SVR-5006",
        http_status=504,
        verdict=Verdict.ERROR,
        system_message="Processing timeout",
        user_message_template=(
            "검사 시간이 초과되었습니다. 첨부파일 크기를 줄이거나 잠시 후 다시 시도해주세요."
        ),
        retryable=True,
    ),
    "SVR-5099": ResponseCode(
        code="SVR-5099",
        http_status=500,
        verdict=Verdict.ERROR,
        system_message="Uncategorized internal error",
        user_message_template=(
            "일시적 오류가 발생했습니다. 문제가 지속되면 관리자에게 문의해주세요."
        ),
    ),
}

# ── Master registry ─────────────────────────────────────────────────────────
CODES: dict[str, ResponseCode] = {**_PASS, **_WARN, **_BLOCK, **_ACK, **_REQ, **_SVR}


def get_code(code: str) -> ResponseCode:
    """Look up a response code, raising KeyError for unknown codes."""
    if code not in CODES:
        raise KeyError(f"Unknown response code: {code}")
    return CODES[code]


# Fallback codes for unclassified detections
FALLBACK_BLOCK = "BLOCK-2099"
FALLBACK_WARN = "WARN-1099"
FALLBACK_PASS = "OK-0000"  # noqa: S105 — not a secret; verdict code
