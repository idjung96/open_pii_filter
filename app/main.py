"""FastAPI 애플리케이션 진입점.

이 모듈은 다음을 책임진다:

- `FastAPI` 인스턴스 생성 + Swagger/OpenAPI 메타데이터 (`title`, `description`,
  `version`, `tags`, contact, license) 구성
- 미들웨어 체인 등록 — `BodySizeLimitMiddleware` (1 MiB 한도) → `AuditMiddleware`
  (append-only 감사 로그) → require_auth dependency (라우터별)
- 백그라운드 워커 (`lifespan`) — nonce vacuum / job cleanup / audit GC /
  feedback alerter 4개. `APP_ENV=test` 일 때는 비활성.
- 라우터 마운트 — 외부 API (`/v1/detect`, `/v1/jobs`, `/v1/feedback`,
  `/v1/legal`) + 헬스 + 운영자 (`/admin/*`, `/v1/admin/*`)
- 전역 예외 핸들러 — `RequestValidationError` 를 REQ-4xxx 응답 envelope 로
  변환, `EnvelopeHTTPException` 을 flat envelope 로 변환 (`{"detail": ...}`
  래핑 없음)

운영 환경에서는 `uvicorn app.main:app --host 0.0.0.0 --port 9000` 으로 실행.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.detect import router as detect_router
from app.api.health import router as health_router
from app.api.jobs import router as jobs_router
from app.api.metrics import router as metrics_router
from app.api.responses import build_response
from app.config import get_settings
from app.core.codes import get_code

logger = logging.getLogger(__name__)


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Start the nonce vacuum, Phase 4 job cleanup (Q4), Phase 6 audit cleanup,
    and Phase 7 feedback alerter. Also installs the PII log scrubber.

    Phase 9D — masked-artifact cleanup loop 제거 (마스킹 인프라 폐기).
    Phase 9E — pattern_listener 제거 (pii_patterns 테이블 폐기).
    """
    from app.core.api_ip_caller_cache import reload_api_ip_callers
    from app.core.blocklist_cache import reload_blocklist
    from app.core.exception_ip_cache import reload_exception_ips
    from app.db.session import get_sessionmaker
    from app.security.log_filter import install_pii_log_filter
    from app.workers.audit_cleanup import audit_cleanup_loop
    from app.workers.feedback_alerter import feedback_alerter_loop
    from app.workers.job_cleanup import job_cleanup_loop
    from app.workers.nonce_vacuum import nonce_vacuum_loop

    # Install before any worker starts so even their startup logs are
    # scrubbed (the filter is idempotent — safe across reloads).
    install_pii_log_filter()

    # Phase 9A — preload exception-IP and API-IP-caller caches. Failures
    # are swallowed by the helpers themselves so the API still boots
    # when the database is unavailable.
    try:
        async with get_sessionmaker()() as bootstrap_session:
            await reload_exception_ips(bootstrap_session)
            await reload_api_ip_callers(bootstrap_session)
            # Phase 4b — load attachment-format deny list before the
            # detect endpoint sees its first request.
            await reload_blocklist(bootstrap_session)
    except Exception as e:
        logger.warning("phase 9A cache preload failed: %s", e)

    tasks: list[asyncio.Task[None]] = []
    if get_settings().app_env != "test":
        tasks.append(asyncio.create_task(nonce_vacuum_loop(), name="pii-nonce-vacuum"))
        tasks.append(asyncio.create_task(job_cleanup_loop(), name="pii-job-cleanup"))
        tasks.append(asyncio.create_task(audit_cleanup_loop(), name="pii-audit-cleanup"))
        tasks.append(asyncio.create_task(feedback_alerter_loop(), name="pii-feedback-alerter"))
        logger.info("started %d background tasks", len(tasks))

    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t


# ── OpenAPI 메타데이터 ────────────────────────────────────────────────────
# Swagger UI (`/docs`) / ReDoc (`/redoc`) 가 자동 생성하는 페이지를 풍부화
# 한다. 외부 클라이언트 개발자가 Swagger 만 보고도 호출이 가능하도록
# description 에 핵심 흐름·인증 헤더·응답 코드 요약을 마크다운으로 적는다.
_API_DESCRIPTION = """
공공기관/기업 게시판에 글이 게시되기 전 본문·첨부파일에서 **개인정보(PII)**
를 식별하고 차단하는 self-hosted REST API.

## 핵심 흐름

| 사례 | 조건 | HTTP | 응답 시점 |
|------|------|------|----------|
| **Case A** | 본문에 BLOCK 급 PII | 200 | 즉시 — 첨부 검사 생략 |
| **Case B** | 본문 PASS, 첨부 없음 | 200 | 즉시 |
| **Case C** | 본문 PASS, 첨부 있음 | 202 | 즉시 (`ACK-3001`) + 워커가 webhook 으로 회신 |

## 인증 (모든 `/v1/*` 엔드포인트 공통)

요청마다 다음 4개 헤더가 필요합니다 (`X-Api-Key` / `X-Timestamp` / `X-Nonce` /
`X-Signature`). canonical 형식:

```
{timestamp}\\n{nonce}\\n{METHOD}\\n{path}\\n{sha256_hex(body)}
```

상세 — [`docs/api_integration.md`](https://github.com/idjung96/open_pii_filter/blob/main/docs/api_integration.md).

## 탐지 엔진

Microsoft Presidio + spaCy `ko_core_news_lg` + 커스텀 한국어 인식기
(주민등록번호 / 운전면허 / 여권 / 사업자번호 / 전화 / 이메일 / 카드 / 계좌).
첨부 OCR 은 **PaddleOCR PP-OCRv5 (CPU)** 기본, 사내 vLLM 폴백 (옵트인).

## 보안

- HMAC-SHA256 + ±5분 timestamp + nonce 재사용 차단 (10분)
- IP allowlist (외부 `:443` / 관리자 `:8443` 신뢰영역 분리)
- append-only `audit_events` (BEFORE UPDATE/DELETE 트리거, 1년 보존)
- 평문 PII 는 로그·메트릭·트레이스·DB 어디에도 저장되지 않습니다.
""".strip()

_OPENAPI_TAGS: list[dict[str, str]] = [
    {
        "name": "detect",
        "description": "PII 검사 — 본문/제목/첨부에서 개인정보 식별 후 PASS/BLOCK 판정.",
    },
    {
        "name": "jobs",
        "description": "Case C 비동기 작업 상태 조회 / 폐기 — 완료 후 24h 보존.",
    },
    {
        "name": "feedback",
        "description": "사용자 오탐/미탐 제보 — 운영자 모니터링과 정책 튜닝에 사용.",
    },
    {
        "name": "legal",
        "description": "공개 개인정보처리방침 (운영자 결정 D, 인증 불요).",
    },
    {
        "name": "health",
        "description": "쿠버네티스 liveness/readiness probe — 인증 불요.",
    },
    {
        "name": "admin",
        "description": "운영자 전용 — Prometheus 메트릭·감사 조회·통계·deny-list 관리. "
        "`admin_ip_allowlist` 가 비어 있으면 라우터가 마운트되지 않아 외부에는 404.",
    },
    {
        "name": "dashboard",
        "description": "Jinja2 운영자 대시보드 (`/admin/*`) — 세션 쿠키 + IP allowlist 기반. "
        "HMAC `/v1/admin/*` 와는 독립 게이트.",
    },
]

app = FastAPI(
    title="Open PII Filter",
    version="0.1.0",
    description=_API_DESCRIPTION,
    summary="한국어 게시판용 PII 사전 차단 REST API",
    contact={
        "name": "Open PII Filter 운영팀",
        "url": "https://github.com/idjung96/open_pii_filter",
    },
    license_info={
        "name": "GPL-3.0-or-later",
        "url": "https://www.gnu.org/licenses/gpl-3.0.html",
    },
    openapi_tags=_OPENAPI_TAGS,
    swagger_ui_parameters={
        # 1) Swagger UI 에서 endpoint 를 alpha 순으로 정렬 — 카탈로그형
        #    문서 가독성 우선 (HTTP 메서드 그룹핑보다 이름 정렬이 외부
        #    개발자에게 더 직관적이라는 운영자 결정).
        "operationsSorter": "alpha",
        "tagsSorter": "alpha",
        # 2) 첨부 검사용 multipart 시도 시 try-it-out 사용 가능.
        "tryItOutEnabled": True,
        # 3) 응답 페이로드의 한글이 깨지지 않도록 monospace 가독성 강화.
        "syntaxHighlight": {"theme": "obsidian"},
    },
    lifespan=lifespan,
)

# Phase 3 — body size cap (T3.9). Registered before the router so the
# 413 response is emitted before any auth or analyzer cost.
from app.security.audit_middleware import AuditMiddleware  # noqa: E402
from app.security.auth import EnvelopeHTTPException  # noqa: E402
from app.security.body_size import BodySizeLimitMiddleware  # noqa: E402

app.add_middleware(
    BodySizeLimitMiddleware,
    max_bytes=get_settings().max_request_body_bytes,
)

# Phase 6 — append-only request audit. Registered AFTER BodySizeLimit so
# rejected oversize bodies are NOT recorded (no benefit, just noise).
app.add_middleware(AuditMiddleware)


@app.exception_handler(EnvelopeHTTPException)
async def _envelope_handler(_request: Request, exc: EnvelopeHTTPException) -> JSONResponse:
    """Q3 — return the envelope at top level (no `{"detail": ...}` wrap)."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail,
        headers=exc.headers or None,
    )


app.include_router(detect_router)
app.include_router(jobs_router)

# Phase 8 — health probes (k8s-style, no auth) and Prometheus exposition.
# /healthz lives below as a separate inline route for back-compat with
# tests that import it from app.main; the new /readyz + /v1/readyz come
# from the dedicated router.
app.include_router(health_router)
# Metrics router is mounted unconditionally; the require_admin gate
# rejects every request when admin_ip_allowlist is empty (defence in
# depth — the surface returns 403, not 404, when an operator forgets to
# configure the allowlist; admin gate is enforced via a noisy denial
# rather than silent unmapped routes).
app.include_router(metrics_router)

# 개발 환경 전용: /metrics (no auth). APP_ENV=development 일 때만 마운트.
from app.api.metrics import get_dev_router as _get_dev_metrics_router  # noqa: E402

_dev_metrics = _get_dev_metrics_router()
if _dev_metrics is not None:
    app.include_router(_dev_metrics)

# Phase 7 — public privacy notice (operator-decision D); no auth.
from app.api.feedback import router as feedback_router  # noqa: E402
from app.api.legal import router as legal_router  # noqa: E402

app.include_router(legal_router)
app.include_router(feedback_router)

# Phase 9A — Jinja2 admin dashboard at /admin. The router enforces its
# own IP allowlist + session cookies; unrelated to the HMAC-protected
# /v1/admin/* endpoints.
from app.api.dashboard import (  # noqa: E402
    DashboardAuthError,
    dashboard_auth_exception_handler,
)
from app.api.dashboard import router as dashboard_router  # noqa: E402

app.include_router(dashboard_router)
app.add_exception_handler(DashboardAuthError, dashboard_auth_exception_handler)

# Phase 6 — admin audit-query router only mounts when the operator has
# explicitly configured an admin IP allowlist. Empty allowlist =
# external surface returns 404, hiding the endpoint from scanners.
# Phase 7 — admin stats router uses the same gate.
if get_settings().admin_ip_allowlist.strip():
    from app.api.admin_audit import router as admin_audit_router
    from app.api.admin_blocklist import router as admin_blocklist_router
    from app.api.admin_stats import router as admin_stats_router

    app.include_router(admin_audit_router)
    app.include_router(admin_stats_router)
    # Phase 4b — runtime CRUD for the attachment deny list.
    app.include_router(admin_blocklist_router)


@app.get(
    "/healthz",
    tags=["health"],
    summary="Liveness probe",
    description="프로세스가 살아있는지만 확인 — 의존 시스템 (DB/Redis/ClamAV) 상태는 보지 않음. "
    "쿠버네티스/LB liveness 용. 인증 불요.",
)
async def healthz() -> dict[str, str]:
    """Liveness probe — 서비스 프로세스 가동 여부만 확인.

    LB/오케스트레이터가 빈번하게 polling 하므로 페이로드를 최소로 유지하고
    어떤 의존성도 만지지 않는다 (의존성 상태는 `/readyz` 가 담당).
    """
    return {"status": "ok"}


@app.get(
    "/v1/healthz",
    tags=["health"],
    summary="Liveness probe (v1)",
    description="`/healthz` 와 동일하지만 응답에 `env` (예: `dev`/`stage`/`prod`) 라벨 포함. "
    "운영자가 LB 로그만 보고도 어느 환경의 호출인지 식별 가능.",
)
async def v1_healthz() -> dict[str, str]:
    """버전드 liveness probe — 응답에 `env` 라벨을 포함해 환경 식별 가능."""
    settings = get_settings()
    return {"status": "ok", "env": settings.app_env}


# ── 요청 검증 실패 → REQ-4xxx envelope 변환 ──────────────────────────────
# pydantic 의 기본 422 응답 (`{"detail": [...]}`) 대신 운영 친화적인 REQ-4xxx
# 코드와 한국어 user_message 가 들어간 envelope 로 바꿔준다. 클라이언트는
# 응답 `code` 만 보고 어느 필드가 어떻게 깨졌는지 즉시 식별 가능.
def _classify_validation(
    errors: list[dict[str, Any]],
) -> tuple[str, dict[str, object]]:
    """pydantic 검증 실패 정보로부터 가장 구체적인 REQ-4xxx 코드를 고른다.

    매핑 우선순위 (위에서 아래로):
      - UUID 형식 위반 → `REQ-4004`
      - JSON 파싱 실패 → `REQ-4003`
      - 필수 필드 누락 → `REQ-4001` (어느 필드인지 `fields=...` 로 안내)
      - `author.*` 필드 형식 오류 → `REQ-4002`
      - 그 외 → `REQ-4003` 일반 검증 오류
    """
    error_types = {str(e.get("type", "")) for e in errors}
    locs = [list(e.get("loc", ())) for e in errors]

    if any("uuid" in t for t in error_types):
        return "REQ-4004", {}
    if any("json" in t for t in error_types):
        return "REQ-4003", {"detail": str(errors[0].get("msg", "invalid JSON"))}

    missing = [
        ".".join(str(p) for p in loc[1:] if p != "body")
        for loc, e in zip(locs, errors, strict=False)
        if "missing" in str(e.get("type", ""))
    ]
    if missing:
        return "REQ-4001", {"fields": ", ".join(missing)}

    # Author-specific shape errors
    if any(len(loc) >= 2 and loc[1] == "author" for loc in locs):
        bad = next((loc for loc in locs if len(loc) >= 3 and loc[1] == "author"), None)
        field = bad[2] if bad is not None and len(bad) >= 3 else "?"
        return "REQ-4002", {"field": str(field)}

    return "REQ-4003", {"detail": str(errors[0].get("msg", "validation error"))}


@app.exception_handler(RequestValidationError)
async def _validation_handler(
    request: Request,  # noqa: ARG001 — FastAPI signature
    exc: RequestValidationError,
) -> JSONResponse:
    code, vars_ = _classify_validation(list(exc.errors()))
    rc = get_code(code)

    request_id = _safe_request_id(exc)
    resp = build_response(
        request_id=request_id,
        code=code,
        processing_ms=0,
        template_vars=vars_,
    )
    payload = resp.model_dump(mode="json")
    payload["processed_at"] = datetime.now(tz=UTC).isoformat()
    return JSONResponse(status_code=rc.http_status, content=payload)


def _safe_request_id(exc: RequestValidationError) -> UUID:
    """Best-effort extraction of request_id from the offending payload."""
    body = exc.body if isinstance(exc.body, dict) else None
    if body is not None:
        raw = body.get("request_id")
        if isinstance(raw, str):
            try:
                return UUID(raw)
            except ValueError:
                return uuid4()
    return uuid4()
