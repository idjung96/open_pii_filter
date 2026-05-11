"""Phase 3 통합 인증 dependency — `require_auth`.

모든 `/v1/*` 엔드포인트가 사용하는 단일 인증 게이트. 4단계 검증을 한 모듈
에서 결정적 순서로 수행해 실패 시 일관된 응답 코드를 보장한다:

  1. **HMAC 서명 검증** (T3.1~T3.5)
     - `X-Api-Key` / `X-Timestamp` / `X-Nonce` / `X-Signature` 4종 헤더
     - canonical: `{ts}\\n{nonce}\\n{METHOD}\\n{path}\\n{sha256(body)}`
     - 타임스탬프 ±5분 윈도우, nonce 10분 재사용 차단
     - 실패 → REQ-4010 ~ REQ-4013 (HTTP 401)
  2. **키 폐기 확인** (T3.6) — DB 의 `revoked_at` 컬럼 점검, REQ-4014 (403)
  3. **IP allowlist** (T3.8) — 키 단위 + 전역 allowlist AND, REQ-4015 (403)
  4. **Rate limit** (T3.7) — GCRA 토큰 버킷 (Redis), REQ-4020 (429 + Retry-After)

이 dependency 한 군데에서만 보안 게이트가 적용되므로 신규 엔드포인트를
추가할 때 `Depends(require_auth)` 만 선언하면 4종 검증이 자동 적용된다 —
엔드포인트별 누락 / 순서 오류 / 응답 코드 불일치 회귀를 원천 방지.

실패 응답은 모두 `EnvelopeHTTPException` 으로 던져 main.py 의 핸들러가
flat envelope (`{"code": ..., "user_message": ...}`) 로 변환한다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Header, HTTPException, Request

from app.api.responses import build_response
from app.config import get_settings
from app.core.codes import get_code
from app.db.session import get_session
from app.security.hmac_auth import (
    AuthedCaller,
    HmacAuthError,
    verify_request,
)
from app.security.ip_allowlist import IpNotAllowedError
from app.security.ip_allowlist import enforce as enforce_ip
from app.security.metrics_collector import observe_rate_limit_rejection
from app.security.rate_limit import get_limiter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession


def _global_ip_allowlist() -> list[str]:
    """Settings.ip_allowlist (comma-separated CIDRs) → list."""
    raw = getattr(get_settings(), "ip_allowlist", "") or ""
    return [c.strip() for c in raw.split(",") if c.strip()]


class EnvelopeHTTPException(HTTPException):
    """Carries the response envelope as the body — flattened in Q3.

    A FastAPI exception_handler returns ``detail`` directly as the JSON
    body rather than wrapping it in ``{"detail": ...}``.
    """


def _envelope(
    code: str,
    *,
    status: int = 0,  # noqa: ARG001 — kept for callsite compatibility
    headers: dict[str, str] | None = None,
    **vars: object,
) -> EnvelopeHTTPException:
    from uuid import UUID

    rc = get_code(code)
    resp = build_response(
        request_id=UUID("00000000-0000-0000-0000-000000000000"),
        code=code,
        processing_ms=0,
        template_vars=vars or None,
    )
    detail = resp.model_dump(mode="json")
    return EnvelopeHTTPException(status_code=rc.http_status, detail=detail, headers=headers)


async def _ip_failure_burst(request: Request) -> None:
    """Q2 — per-IP brute-force defence.

    Consumes one token from the per-IP fallback bucket on every auth
    failure. When the IP exceeds its configured budget the next failure
    surfaces as REQ-4020 (429 + Retry-After) instead of the original
    401/403, choking off scripted scanning without affecting legitimate
    callers (their first request succeeds and bypasses this path).
    """
    from app.security.hmac_auth import _client_ip

    settings = get_settings()
    ip = _client_ip(request)
    outcome = await get_limiter().check_ip(ip=ip, per_minute=settings.ip_rate_per_minute)
    if not outcome.allowed:
        observe_rate_limit_rejection(scope="ip")
        raise _envelope(
            "REQ-4020",
            status=429,
            headers={"Retry-After": str(outcome.retry_after)},
        )


async def require_auth(
    request: Request,
    x_api_key: str | None = Header(default=None),
    x_timestamp: str | None = Header(default=None),
    x_nonce: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
) -> AuthedCaller:
    """Single dependency composing HMAC + IP + rate-limit checks."""
    # Phase 9A — when ALL HMAC headers are absent, fall back to the
    # IP-based allowlist (``pii.api_ip_callers``). Any HMAC header
    # present forces the regular HMAC code path so a partial header set
    # still yields REQ-4011 instead of silently bypassing signature
    # verification.
    from app.core.api_ip_caller_cache import find_caller_by_ip
    from app.security.hmac_auth import _client_ip

    no_hmac_headers = (
        x_api_key is None and x_timestamp is None and x_nonce is None and x_signature is None
    )
    if no_hmac_headers:
        client_ip = _client_ip(request)
        entry = find_caller_by_ip(client_ip)
        if entry is not None:
            caller = AuthedCaller(
                key_id=f"ip:{entry.cidr}",
                name=entry.name,
                rate_per_minute=entry.rate_per_minute,
                rate_per_hour=entry.rate_per_hour,
                ip_allowlist=None,
                client_ip=client_ip,
                is_admin=False,
            )
            # Skip the HMAC nonce/key lookup but keep the global IP
            # allowlist + per-caller rate limit checks below.
            return await _post_auth_checks(caller)

    # 1. HMAC + key lookup + nonce claim (own DB session because nonce
    #    insertion needs to be committed independently of the endpoint).
    async for session in get_session():
        try:
            caller = await verify_request(
                request,
                session,
                x_api_key=x_api_key,
                x_timestamp=x_timestamp,
                x_nonce=x_nonce,
                x_signature=x_signature,
            )
        except HmacAuthError as e:
            # Q2: failed auth charges the per-IP fallback bucket; if the
            # caller has burned through it, surface 429 instead of 401/403
            # so brute-force scanners get throttled.
            await _ip_failure_burst(request)
            rc = get_code(e.code)
            raise _envelope(e.code, status=rc.http_status) from e
        break  # one-shot use of the async generator

    return await _post_auth_checks(caller)


async def _post_auth_checks(caller: AuthedCaller) -> AuthedCaller:
    """Apply IP-allowlist + rate-limit checks shared by HMAC and
    IP-caller paths."""
    # 2. IP allowlist (per-key + global).
    try:
        enforce_ip(
            caller.client_ip,
            key_allowlist=caller.ip_allowlist,
            global_allowlist=_global_ip_allowlist() or None,
        )
    except IpNotAllowedError as e:
        raise _envelope("REQ-4015", status=403, ip=e.ip) from e

    # 3. Rate limit (per API key).
    outcome = await get_limiter().check_caller(
        key_id=caller.key_id,
        per_minute=caller.rate_per_minute,
        per_hour=caller.rate_per_hour,
    )
    if not outcome.allowed:
        observe_rate_limit_rejection(scope="caller")
        raise _envelope(
            "REQ-4020",
            status=429,
            headers={"Retry-After": str(outcome.retry_after)},
        )

    return caller


async def session_dep() -> AsyncIterator[AsyncSession]:
    """Re-export for endpoint consumption."""
    async for s in get_session():
        yield s
