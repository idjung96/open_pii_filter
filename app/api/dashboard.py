"""Phase 9A — Jinja2-rendered admin dashboard.

The dashboard runs at ``/admin`` and exposes a small set of pages for
operators to manage PII configuration without the API:

  * ``/admin/login``         — credential form (in-memory session cookies)
  * ``/admin/``              — system-status home (Prometheus summary)
  * ``/admin/exception-ips`` — manage ``pii.exception_ips`` rows
  * ``/admin/api-callers``   — manage ``pii.api_ip_callers`` rows
  * ``/admin/recognizers``   — read-only view of registered PII recognizers

Trust-zone separation
---------------------
Every request — login OR authenticated page — is gated by
``Settings.admin_dashboard_ip_allowlist``. An IP that is not in the
allowlist receives an HTML 403 before any auth/render cost.

The session store is process-local: a single ``dict[str, dict]`` keyed
by an opaque session id (cookies named ``admin_session``). Each entry
records the issuing IP and an expiration timestamp; cookies are
``HttpOnly`` and ``SameSite=Lax``. The 4-hour TTL matches the spec.

Phase 9E — pii_patterns 인프라 폐기. 사용자 등록 패턴 관리 라우트와 폼이
제거됐다. 인식기 페이지는 read-only 단일 화면으로 단순화됐다.
"""

from __future__ import annotations

import ipaddress
import logging
import secrets
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select

from app.config import get_settings
from app.core.api_ip_caller_cache import reload_api_ip_callers
from app.core.exception_ip_cache import reload_exception_ips
from app.db.models import ApiIpCaller, AuditEvent, ExceptionIp
from app.db.session import get_sessionmaker
from app.security.hmac_auth import _client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["dashboard"])

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# KST(GMT+9) 변환 필터 — DB의 timezone-aware UTC datetime을 KST 문자열로 렌더링.
_KST = timezone(timedelta(hours=9))


def _kst_filter(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_KST).strftime(fmt)


templates.env.filters["kst"] = _kst_filter


def _pretty_json_filter(value: object) -> str:
    """JSON 문자열이면 한글이 보이게 (``ensure_ascii=False``) 다시 직렬화한다.

    audit_detail 페이지에서 ``request_body_text`` / ``response_body_text`` 가
    ``\\uXXXX`` 형태로 escape 돼 가독성이 떨어지는 문제 해결용.
    JSON 으로 파싱되지 않으면 원본 문자열 그대로 반환한다.
    """
    import json as _json

    if not isinstance(value, str) or not value:
        return value if isinstance(value, str) else ""
    stripped = value.lstrip()
    if not stripped or stripped[0] not in "{[":
        return value
    try:
        parsed = _json.loads(value)
    except Exception:
        return value
    return _json.dumps(parsed, ensure_ascii=False, indent=2)


templates.env.filters["prettyjson"] = _pretty_json_filter

# In-memory session store: {session_id: {"ip": str, "expires": datetime}}.
_sessions: dict[str, dict[str, Any]] = {}


def _active_credentials() -> tuple[str, str]:
    """관리자 username/password — system_settings override 우선, 없으면 env."""
    from app.core import system_settings as _ss

    settings = get_settings()
    user = settings.admin_dashboard_username
    pw_override = _ss.get("admin_dashboard_password_override")
    pw = (
        pw_override
        if isinstance(pw_override, str) and pw_override
        else settings.admin_dashboard_password
    )
    return user, pw


SESSION_COOKIE_NAME = "admin_session"
SESSION_TTL = timedelta(hours=4)


# ── IP allowlist gate ─────────────────────────────────────────────────────
def _dashboard_allowlist() -> list[str]:
    raw = (get_settings().admin_dashboard_ip_allowlist or "").strip()
    return [c.strip() for c in raw.split(",") if c.strip()]


def _ip_allowed(ip: str) -> bool:
    cidrs = _dashboard_allowlist()
    if not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False


def _forbidden(message: str = "Forbidden") -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><body><h1>403 Forbidden</h1><p>{message}</p></body></html>",
        status_code=403,
    )


# ── Session helpers ───────────────────────────────────────────────────────
def _create_session(ip: str) -> str:
    """Generate an opaque session id and stash the (ip, expiry) tuple."""
    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = {
        "ip": ip,
        "expires": datetime.now(tz=UTC) + SESSION_TTL,
    }
    return session_id


def _purge_expired() -> None:
    now = datetime.now(tz=UTC)
    stale = [
        sid for sid, meta in _sessions.items() if meta.get("expires") and meta["expires"] < now
    ]
    for sid in stale:
        _sessions.pop(sid, None)


def _valid_session(session_id: str | None, ip: str) -> bool:
    if not session_id:
        return False
    _purge_expired()
    meta = _sessions.get(session_id)
    if not meta:
        return False
    if meta.get("ip") != ip:
        return False
    expires = meta.get("expires")
    return isinstance(expires, datetime) and expires >= datetime.now(tz=UTC)


async def get_dashboard_session(request: Request) -> str:
    """FastAPI dependency: enforce IP allowlist + session cookie validity.

    Returns the session id on success; raises an HTML 403/redirect via
    ``DashboardAuthError`` (handled by the exception handler below).
    """
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        raise DashboardAuthError(_forbidden(f"IP {ip} not allowed."))
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not _valid_session(session_id, ip):
        raise DashboardAuthError(RedirectResponse(url="/admin/login", status_code=303))
    assert session_id is not None
    return session_id


class DashboardAuthError(Exception):
    """Carries a pre-built HTTP response (HTML 403 or redirect)."""

    def __init__(self, response: Response) -> None:
        super().__init__("dashboard auth failed")
        self.response = response


# ── Login pages ───────────────────────────────────────────────────────────
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    """Render the credential form (or 403 when the IP is not allowed)."""
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        return _forbidden(f"IP {ip} not allowed.")
    return templates.TemplateResponse(
        request,
        "admin/login.html",
        {"error": None},
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> Response:
    """Verify credentials, issue session cookie, redirect to the home page."""
    ip = _client_ip(request)
    if not _ip_allowed(ip):
        return _forbidden(f"IP {ip} not allowed.")
    expected_user, expected_pass = _active_credentials()
    if not (
        secrets.compare_digest(username, expected_user)
        and secrets.compare_digest(password, expected_pass)
    ):
        return templates.TemplateResponse(
            request,
            "admin/login.html",
            {"error": "사용자명 또는 비밀번호가 올바르지 않습니다."},
            status_code=401,
        )
    session_id = _create_session(ip)
    resp = RedirectResponse(url="/admin/", status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
    )
    return resp


@router.get("/logout")
async def logout(request: Request) -> Response:
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if sid:
        _sessions.pop(sid, None)
    resp = RedirectResponse(url="/admin/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


# ── Dashboard home ────────────────────────────────────────────────────────
def _metrics_summary() -> list[tuple[str, str]]:
    """Best-effort scrape of selected counter values from the default registry.

    The full Prometheus exposition is too noisy for an HTML page; we
    surface a curated subset (request totals + detection counts) here
    and let operators visit ``/v1/admin/metrics`` for the full payload.
    """
    try:
        from prometheus_client import REGISTRY
    except Exception:
        return []
    interesting = (
        "pii_http_requests_total",
        "pii_detections_total",
        "pii_rate_limit_rejections_total",
    )
    out: list[tuple[str, str]] = []
    for metric in REGISTRY.collect():
        if metric.name not in interesting:
            continue
        for sample in metric.samples:
            label_str = ",".join(f"{k}={v}" for k, v in sorted(sample.labels.items()))
            display = sample.name
            if label_str:
                display = f"{sample.name}{{{label_str}}}"
            out.append((display, str(int(sample.value))))
    return out


@router.get("/", response_class=HTMLResponse)
async def dashboard_home(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    settings = get_settings()
    sm = get_sessionmaker()
    exception_ip_count = 0
    api_caller_count = 0
    try:
        from sqlalchemy import func as sa_func

        async with sm() as session:
            exception_ip_count = (
                await session.scalar(select(sa_func.count()).select_from(ExceptionIp))
            ) or 0
            api_caller_count = (
                await session.scalar(select(sa_func.count()).select_from(ApiIpCaller))
            ) or 0
    except Exception as e:
        logger.warning("dashboard_home counts unavailable: %s", e)

    return templates.TemplateResponse(
        request,
        "admin/dashboard.html",
        {
            "env": settings.app_env,
            "exception_ip_count": exception_ip_count,
            "api_caller_count": api_caller_count,
            "metrics_summary": _metrics_summary(),
            "flash": None,
        },
    )


# ── IP allowlist (통합 페이지: 작성자 예외 + 서비스 IP) ───────────────────
@router.get("/ip-allowlist", response_class=HTMLResponse)
async def ip_allowlist_page(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """예외 IP + 서비스 IP 통합 관리 페이지 (Phase 9G)."""
    sm = get_sessionmaker()
    exception_rows: list[ExceptionIp] = []
    caller_rows: list[ApiIpCaller] = []
    try:
        async with sm() as session:
            r1 = await session.execute(select(ExceptionIp).order_by(ExceptionIp.id.desc()))
            exception_rows = list(r1.scalars().all())
            r2 = await session.execute(select(ApiIpCaller).order_by(ApiIpCaller.id.desc()))
            caller_rows = list(r2.scalars().all())
    except Exception as e:
        logger.warning("ip_allowlist_page query failed: %s", e)
    return templates.TemplateResponse(
        request,
        "admin/ip_allowlist.html",
        {"exception_rows": exception_rows, "caller_rows": caller_rows},
    )


# ── Exception IPs (POST 호환 + GET redirect) ──────────────────────────────
@router.get("/exception-ips")
async def exception_ips_list(
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """예전 URL → 통합 페이지로 redirect (작성자 예외 IP 탭)."""
    return RedirectResponse(url="/admin/ip-allowlist#tab-exception", status_code=303)


@router.post("/exception-ips")
async def exception_ips_create(
    request: Request,
    cidr: str = Form(...),
    label: str = Form(""),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    cidr = cidr.strip()
    label = label.strip()
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return templates.TemplateResponse(
            request,
            "admin/exception_ips.html",
            {
                "rows": await _list_exception_ips(),
                "flash": f"잘못된 CIDR: {cidr}",
                "flash_type": "danger",
            },
            status_code=400,
        )
    sm = get_sessionmaker()
    try:
        async with sm() as session:
            session.add(ExceptionIp(cidr=cidr, label=label, enabled=True))
            await session.commit()
        async with sm() as session:
            await reload_exception_ips(session)
    except Exception as e:
        logger.warning("exception_ips_create failed: %s", e)
    return RedirectResponse(url="/admin/ip-allowlist#tab-exception", status_code=303)


@router.post("/exception-ips/{row_id}/delete")
async def exception_ips_delete(
    row_id: int,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    sm = get_sessionmaker()
    try:
        async with sm() as session:
            await session.execute(delete(ExceptionIp).where(ExceptionIp.id == row_id))
            await session.commit()
        async with sm() as session:
            await reload_exception_ips(session)
    except Exception as e:
        logger.warning("exception_ips_delete failed: %s", e)
    return RedirectResponse(url="/admin/ip-allowlist#tab-exception", status_code=303)


async def _list_exception_ips() -> list[ExceptionIp]:
    sm = get_sessionmaker()
    try:
        async with sm() as session:
            result = await session.execute(select(ExceptionIp).order_by(ExceptionIp.id.desc()))
            return list(result.scalars().all())
    except Exception:
        return []


# ── 서비스 IP (API IP callers) — POST 호환 + GET redirect ─────────────────
@router.get("/api-callers")
async def api_callers_list(
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """예전 URL → 통합 페이지로 redirect (서비스 IP 탭)."""
    return RedirectResponse(url="/admin/ip-allowlist#tab-service", status_code=303)


@router.post("/api-callers")
async def api_callers_create(
    cidr: str = Form(...),
    name: str = Form(...),
    rate_per_minute: int = Form(60),
    rate_per_hour: int = Form(1000),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    cidr = cidr.strip()
    name = name.strip()
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return RedirectResponse(url="/admin/ip-allowlist#tab-service", status_code=303)
    if rate_per_minute <= 0 or rate_per_hour <= 0:
        return RedirectResponse(url="/admin/ip-allowlist#tab-service", status_code=303)
    sm = get_sessionmaker()
    try:
        async with sm() as session:
            session.add(
                ApiIpCaller(
                    cidr=cidr,
                    name=name,
                    rate_per_minute=rate_per_minute,
                    rate_per_hour=rate_per_hour,
                    enabled=True,
                )
            )
            await session.commit()
        async with sm() as session:
            await reload_api_ip_callers(session)
    except Exception as e:
        logger.warning("api_callers_create failed: %s", e)
    return RedirectResponse(url="/admin/ip-allowlist#tab-service", status_code=303)


@router.post("/api-callers/{row_id}/delete")
async def api_callers_delete(
    row_id: int,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    sm = get_sessionmaker()
    try:
        async with sm() as session:
            await session.execute(delete(ApiIpCaller).where(ApiIpCaller.id == row_id))
            await session.commit()
        async with sm() as session:
            await reload_api_ip_callers(session)
    except Exception as e:
        logger.warning("api_callers_delete failed: %s", e)
    return RedirectResponse(url="/admin/ip-allowlist#tab-service", status_code=303)


# ── Patterns (Phase 9F: rename + per-recognizer on/off) ───────────────────
@router.get("/patterns", response_class=HTMLResponse)
async def patterns_list(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """분석 엔진에 등록된 모든 PII 패턴 (인식기) 목록 + 개별 on/off.

    Phase 9F — 메뉴명 "인식기" → "패턴" 으로 변경. system_settings.json
    의 ``disabled_recognizers`` 리스트에 포함된 인식기 클래스명은 분석
    엔진에서 자동 제외된다. 토글 시 캐시를 reset 하여 즉시 반영.

    표시 대상:
      - 활성: 분석 엔진 registry 에 실제 등록된 인식기
      - 비활성: 코드는 존재하나 disabled_recognizers 로 제외된 인식기
    """
    from app.core.analyzer import inspect_all_candidates

    all_known = inspect_all_candidates()
    disabled_count = sum(1 for r in all_known if not r.get("enabled"))

    grouped: dict[str, list[dict[str, Any]]] = {
        "custom_kr": [],
        "presidio_builtin": [],
        "db_deny_list": [],
    }
    for r in all_known:
        grouped.setdefault(str(r["source"]), []).append(r)

    return templates.TemplateResponse(
        request,
        "admin/patterns.html",
        {"grouped": grouped, "disabled_count": disabled_count},
    )


@router.post("/patterns/toggle")
async def patterns_toggle(
    class_name: str = Form(...),
    action: str = Form(...),  # "enable" | "disable"
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """개별 인식기 on/off — system_settings.json 의 disabled_recognizers 갱신."""
    from app.core import system_settings as _ss
    from app.core.analyzer import reset_analyzer_cache

    raw = _ss.get("disabled_recognizers")
    current: list[str] = list(raw) if isinstance(raw, list) else []

    if action == "disable" and class_name not in current:
        current.append(class_name)
    elif action == "enable":
        current = [c for c in current if c != class_name]

    _ss.set_value("disabled_recognizers", current)
    reset_analyzer_cache()  # 다음 분석 호출 시 새 registry 로 재빌드
    return RedirectResponse(url="/admin/patterns", status_code=303)


# Phase 9I — patterns / context 런타임 편집 ────────────────────────────────
@router.get("/patterns/edit", response_class=HTMLResponse)
async def patterns_edit_form(
    request: Request,
    class_name: str = Query(..., alias="class"),
    error: str | None = Query(default=None),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """선택한 인식기의 patterns / context 편집 폼을 렌더링."""
    from app.core.analyzer import inspect_all_candidates

    target = next(
        (r for r in inspect_all_candidates() if r.get("class") == class_name),
        None,
    )
    if target is None:
        return RedirectResponse(url="/admin/patterns", status_code=303)
    if target.get("source") == "db_deny_list":
        return RedirectResponse(url="/admin/patterns", status_code=303)

    return templates.TemplateResponse(
        request,
        "admin/pattern_edit.html",
        {"r": target, "error": error},
    )


@router.post("/patterns/edit")
async def patterns_edit_save(
    _request: Request,
    class_name: str = Form(...),
    pattern_name: list[str] = Form(default=[]),  # noqa: B008
    pattern_regex: list[str] = Form(default=[]),  # noqa: B008
    pattern_score: list[str] = Form(default=[]),  # noqa: B008
    context: str = Form(default=""),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """폼 입력으로 patterns / context 오버라이드 저장 + 캐시 reset."""
    from urllib.parse import quote

    from app.core.analyzer import reset_analyzer_cache
    from app.core.recognizer_overrides import set_override

    rows = max(len(pattern_name), len(pattern_regex), len(pattern_score))
    patterns: list[dict[str, Any]] = []
    for i in range(rows):
        name = (pattern_name[i] if i < len(pattern_name) else "").strip()
        regex = pattern_regex[i] if i < len(pattern_regex) else ""
        score_raw = (pattern_score[i] if i < len(pattern_score) else "").strip()
        if not name and not regex:
            continue
        try:
            score = float(score_raw) if score_raw else 0.5
        except ValueError:
            score = 0.5
        patterns.append({"name": name, "regex": regex, "score": score})

    context_words = [line.strip() for line in context.splitlines() if line.strip()]

    try:
        set_override(class_name, patterns=patterns, context=context_words)
    except ValueError as e:
        url = f"/admin/patterns/edit?class={quote(class_name)}&error={quote(str(e))}"
        return RedirectResponse(url=url, status_code=303)

    reset_analyzer_cache()
    return RedirectResponse(url="/admin/patterns", status_code=303)


@router.post("/patterns/reset")
async def patterns_reset(
    class_name: str = Form(...),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """해당 인식기의 모든 오버라이드 제거 → 코드 기본값으로 복원."""
    from app.core.analyzer import reset_analyzer_cache
    from app.core.recognizer_overrides import reset_recognizer

    reset_recognizer(class_name)
    reset_analyzer_cache()
    return RedirectResponse(url="/admin/patterns", status_code=303)


# Phase 9F — back-compat redirect: 이전 URL `/admin/recognizers` 를 새 URL 로.
@router.get("/recognizers")
async def recognizers_redirect(
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    return RedirectResponse(url="/admin/patterns", status_code=303)


# ── API 사용 이력 / PII 탐지 이력 ─────────────────────────────────────────

_AUDIT_PAGE_SIZE = 100


def _is_blocked_response(http_status: int | None, response_code: str | None) -> bool:
    """차단으로 분류할 응답 판정.

    - HTTP 4xx/5xx 전체
    - response_code 가 BLOCK-/REQ-/SVR- 로 시작
    """
    if http_status is not None and http_status >= 400:
        return True
    return bool(
        response_code
        and (
            response_code.startswith("BLOCK-")
            or response_code.startswith("REQ-")
            or response_code.startswith("SVR-")
        )
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit_list(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """전체 API 사용 이력 (최근 N건)."""
    sm = get_sessionmaker()
    rows: list[AuditEvent] = []
    try:
        async with sm() as session:
            result = await session.execute(
                select(AuditEvent).order_by(AuditEvent.occurred_at.desc()).limit(_AUDIT_PAGE_SIZE)
            )
            rows = list(result.scalars().all())
    except Exception as e:
        logger.warning("audit_list query failed: %s", e)
    return templates.TemplateResponse(
        request,
        "admin/audit.html",
        {"rows": rows, "page_size": _AUDIT_PAGE_SIZE},
    )


@router.get("/pii-audit", response_class=HTMLResponse)
async def pii_audit_list(
    request: Request,
    tab: str = Query(default="all"),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """PII 탐지 API (``POST /v1/detect/post``) 호출만 모은 audit 뷰.

    Phase 9K — 일반 audit 페이지는 dashboard GUI 호출, 헬스체크, 인증
    실패 등 모든 호출을 섞어 노이즈가 크다. 운영자가 개인정보 탐지 결과만
    별도로 추적할 수 있도록 path 를 좁히고 PASS/BLOCK 탭을 제공한다.

    탭 분류 (``response_code`` prefix 기반):
      * ``all``   — 모든 호출 (REQ-/SVR- 등 입력 거절도 포함)
      * ``pass``  — ``OK-`` (PII 미탐지 통과)
      * ``block`` — ``BLOCK-`` (PII 탐지 → 차단)
    """
    sm = get_sessionmaker()
    rows: list[AuditEvent] = []
    counts = {"all": 0, "pass": 0, "block": 0}
    try:
        async with sm() as session:
            base = select(AuditEvent).where(AuditEvent.path == "/v1/detect/post")
            from sqlalchemy import func as sa_func

            count_stmt = (
                select(
                    sa_func.count().label("c_all"),
                    sa_func.count().filter(AuditEvent.response_code.like("OK-%")).label("c_pass"),
                    sa_func.count()
                    .filter(AuditEvent.response_code.like("BLOCK-%"))
                    .label("c_block"),
                )
                .select_from(AuditEvent)
                .where(AuditEvent.path == "/v1/detect/post")
            )
            cnt_row = (await session.execute(count_stmt)).first()
            if cnt_row is not None:
                counts = {
                    "all": int(cnt_row.c_all),
                    "pass": int(cnt_row.c_pass),
                    "block": int(cnt_row.c_block),
                }

            stmt = base.order_by(AuditEvent.occurred_at.desc()).limit(_AUDIT_PAGE_SIZE)
            if tab == "pass":
                stmt = (
                    base.where(AuditEvent.response_code.like("OK-%"))
                    .order_by(AuditEvent.occurred_at.desc())
                    .limit(_AUDIT_PAGE_SIZE)
                )
            elif tab == "block":
                stmt = (
                    base.where(AuditEvent.response_code.like("BLOCK-%"))
                    .order_by(AuditEvent.occurred_at.desc())
                    .limit(_AUDIT_PAGE_SIZE)
                )
            result = await session.execute(stmt)
            rows = list(result.scalars().all())
    except Exception as e:
        logger.warning("pii_audit_list query failed: %s", e)

    if tab not in ("all", "pass", "block"):
        tab = "all"

    return templates.TemplateResponse(
        request,
        "admin/pii_audit.html",
        {
            "rows": rows,
            "page_size": _AUDIT_PAGE_SIZE,
            "tab": tab,
            "counts": counts,
        },
    )


# Phase 9K — 기존 ``/admin/blocked`` (HTTP 4xx/5xx 모음) 페이지는 제거됐다.
# PII 검출 차단 (HTTP 200 + BLOCK-) 은 ``/admin/pii-audit?tab=block`` 에서,
# HTTP 레벨 거절 (인증 실패 / 입력 오류 등) 은 ``/admin/audit`` 에서 확인.
@router.get("/blocked")
async def blocked_redirect(
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    return RedirectResponse(url="/admin/pii-audit?tab=block", status_code=303)


# ── 오픈소스 라이브러리 목록 ──────────────────────────────────────────────

_DEPENDENCIES: list[dict[str, str]] = [
    # 웹/런타임
    {
        "name": "FastAPI",
        "version": ">=0.115",
        "category": "Web Framework",
        "license": "MIT",
        "purpose": "REST API 프레임워크",
    },
    {
        "name": "Uvicorn",
        "version": ">=0.32",
        "category": "Web Framework",
        "license": "BSD-3-Clause",
        "purpose": "ASGI 서버",
    },
    {
        "name": "Pydantic",
        "version": ">=2.9",
        "category": "Web Framework",
        "license": "MIT",
        "purpose": "데이터 검증/직렬화",
    },
    {
        "name": "pydantic-settings",
        "version": ">=2.6",
        "category": "Web Framework",
        "license": "MIT",
        "purpose": "환경 변수 기반 설정",
    },
    {
        "name": "Jinja2",
        "version": "transitive",
        "category": "Web Framework",
        "license": "BSD-3-Clause",
        "purpose": "관리자 대시보드 템플릿 렌더링",
    },
    # 데이터베이스
    {
        "name": "SQLAlchemy",
        "version": ">=2.0",
        "category": "Database",
        "license": "MIT",
        "purpose": "ORM (asyncio 지원)",
    },
    {
        "name": "asyncpg",
        "version": ">=0.29",
        "category": "Database",
        "license": "Apache-2.0",
        "purpose": "PostgreSQL 비동기 드라이버",
    },
    {
        "name": "psycopg2-binary",
        "version": ">=2.9",
        "category": "Database",
        "license": "LGPL-3.0",
        "purpose": "PostgreSQL 동기 드라이버 (Alembic용)",
    },
    {
        "name": "Alembic",
        "version": ">=1.13",
        "category": "Database",
        "license": "MIT",
        "purpose": "DB 마이그레이션",
    },
    {
        "name": "redis-py",
        "version": ">=5.0",
        "category": "Database",
        "license": "MIT",
        "purpose": "Redis 클라이언트 (rate limit, nonce)",
    },
    # PII 분석 엔진
    {
        "name": "Microsoft Presidio (analyzer)",
        "version": "2.2.362",
        "category": "PII Engine",
        "license": "MIT",
        "purpose": "PII 분석 프레임워크 — 정규식 인식기 등록/실행, decision_process 노출",
    },
    {
        "name": "spaCy",
        "version": "3.8.14",
        "category": "PII Engine",
        "license": "MIT",
        "purpose": "한국어 NLP 토크나이저 (Phase 9E 이후 NER 미사용)",
    },
    {
        "name": "ko_core_news_lg",
        "version": "3.8.0",
        "category": "PII Engine",
        "license": "MIT",
        "purpose": "한국어 spaCy 모델 (토크나이저로만 사용)",
    },
    # 파일 추출
    {
        "name": "pypdfium2",
        "version": ">=4.30",
        "category": "File Extraction",
        "license": "Apache-2.0/BSD-3-Clause",
        "purpose": "PDF 텍스트/이미지 추출",
    },
    {
        "name": "pdfplumber",
        "version": ">=0.11",
        "category": "File Extraction",
        "license": "MIT",
        "purpose": "PDF 표/레이아웃 분석",
    },
    {
        "name": "python-docx",
        "version": ">=1.1",
        "category": "File Extraction",
        "license": "MIT",
        "purpose": "DOCX 텍스트 추출",
    },
    {
        "name": "lxml",
        "version": ">=5.0",
        "category": "File Extraction",
        "license": "BSD-3-Clause",
        "purpose": "XML/HWPX 파싱",
    },
    # OCR/이미지
    {
        "name": "PaddleOCR (선택)",
        "version": ">=2.8",
        "category": "OCR",
        "license": "Apache-2.0",
        "purpose": "한국어 OCR (paddle 엔진 사용 시)",
    },
    {
        "name": "PaddlePaddle (선택)",
        "version": ">=2.6",
        "category": "OCR",
        "license": "Apache-2.0",
        "purpose": "PaddleOCR 런타임",
    },
    {
        "name": "Pillow",
        "version": "transitive",
        "category": "OCR",
        "license": "MIT-CMU",
        "purpose": "OCR 입력 이미지 로딩/전처리",
    },
    # 보안/통신
    {
        "name": "httpx",
        "version": ">=0.27",
        "category": "Security/Network",
        "license": "BSD-3-Clause",
        "purpose": "비동기 HTTP 클라이언트 (첨부 fetch, 웹훅)",
    },
    {
        "name": "clamd",
        "version": ">=1.0.2",
        "category": "Security/Network",
        "license": "LGPL-3.0",
        "purpose": "ClamAV 악성코드 스캐너 클라이언트",
    },
    {
        "name": "prometheus-client",
        "version": ">=0.20",
        "category": "Observability",
        "license": "Apache-2.0",
        "purpose": "Prometheus 메트릭 노출",
    },
    # CLI
    {
        "name": "Typer",
        "version": ">=0.12",
        "category": "CLI",
        "license": "MIT",
        "purpose": "API 키 관리 CLI",
    },
    # 외부 시스템
    {
        "name": "PostgreSQL",
        "version": "16",
        "category": "External System",
        "license": "PostgreSQL License",
        "purpose": "주 데이터베이스 (pgcrypto AES 암호화)",
    },
    {
        "name": "Redis",
        "version": "7",
        "category": "External System",
        "license": "RSALv2/SSPL",
        "purpose": "rate limit + nonce 캐시",
    },
    {
        "name": "ClamAV",
        "version": "1.3",
        "category": "External System",
        "license": "GPL-2.0",
        "purpose": "첨부 파일 악성코드 스캔",
    },
    {
        "name": "vLLM (Qwen3.5-27B-VL)",
        "version": "external",
        "category": "External System",
        "license": "Apache-2.0",
        "purpose": "VLM OCR 엔드포인트",
    },
    # 개발 도구
    {
        "name": "Ruff",
        "version": ">=0.7",
        "category": "Dev Tooling",
        "license": "MIT",
        "purpose": "린터/포매터",
    },
    {
        "name": "mypy",
        "version": ">=1.13",
        "category": "Dev Tooling",
        "license": "MIT",
        "purpose": "타입 체커 (strict)",
    },
    {
        "name": "bandit",
        "version": ">=1.8",
        "category": "Dev Tooling",
        "license": "Apache-2.0",
        "purpose": "보안 정적 분석",
    },
    {
        "name": "pip-audit",
        "version": ">=2.7",
        "category": "Dev Tooling",
        "license": "Apache-2.0",
        "purpose": "의존성 취약점 스캔",
    },
    {
        "name": "pytest",
        "version": ">=8.3",
        "category": "Dev Tooling",
        "license": "MIT",
        "purpose": "테스트 러너",
    },
    {
        "name": "pytest-asyncio",
        "version": ">=0.24",
        "category": "Dev Tooling",
        "license": "Apache-2.0",
        "purpose": "asyncio 테스트 지원",
    },
    {
        "name": "Locust",
        "version": ">=2.30",
        "category": "Dev Tooling",
        "license": "MIT",
        "purpose": "부하 테스트",
    },
    {
        "name": "pre-commit",
        "version": ">=4.0",
        "category": "Dev Tooling",
        "license": "MIT",
        "purpose": "pre-commit 훅 관리",
    },
    # 컨테이너/배포
    {
        "name": "Docker / Docker Compose",
        "version": "external",
        "category": "Deployment",
        "license": "Apache-2.0",
        "purpose": "컨테이너 빌드/오케스트레이션",
    },
    {
        "name": "Nginx",
        "version": "external",
        "category": "Deployment",
        "license": "BSD-2-Clause",
        "purpose": "리버스 프록시 (외부 :443 / 관리자 :8443)",
    },
]


@router.get("/dependencies", response_class=HTMLResponse)
async def dependencies_list(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """사용 중인 오픈소스 라이브러리 / 외부 시스템 목록."""
    # 카테고리별 그룹핑 (입력 순서 보존)
    grouped: dict[str, list[dict[str, str]]] = {}
    for dep in _DEPENDENCIES:
        grouped.setdefault(dep["category"], []).append(dep)
    return templates.TemplateResponse(
        request,
        "admin/dependencies.html",
        {"grouped": grouped, "total": len(_DEPENDENCIES)},
    )


# ── PII 검사 테스트 페이지 ────────────────────────────────────────────────


@router.get("/test", response_class=HTMLResponse)
async def test_form(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """게시글 본문 + 첨부파일을 업로드해 PII 분석을 즉석 테스트."""
    return templates.TemplateResponse(
        request,
        "admin/test.html",
        {"result": None, "form": {}},
    )


def _verdict_for_code(code: str) -> str:
    if code.startswith("BLOCK-"):
        return "BLOCK"
    if code.startswith("WARN-"):
        return "WARN"
    return "PASS"


def _collect_explanations(
    analyzer: Any,
    text: str,
) -> dict[tuple[int, int, str], dict[str, Any]]:
    """분석을 한 번 더 호출해 decision_process 를 수집한다.

    Presidio의 ``return_decision_process=True`` 는 각 ``RecognizerResult`` 에
    ``analysis_explanation`` 을 채워 — 어떤 인식기/패턴이 어떤 점수로 매칭됐는지,
    context word 가 점수를 얼마나 끌어올렸는지 등을 노출한다.
    오버헤드는 ~0% (벤치 측정).
    """
    if not text:
        return {}
    out: dict[tuple[int, int, str], dict[str, Any]] = {}
    try:
        raw = analyzer.analyze(text=text, language="ko", return_decision_process=True)
    except Exception:
        return out
    for r in raw:
        expl = getattr(r, "analysis_explanation", None)
        if expl is None:
            continue
        key = (r.start, r.end, r.entity_type)
        out[key] = {
            "recognizer": getattr(expl, "recognizer", None),
            "pattern_name": getattr(expl, "pattern_name", None),
            "pattern": getattr(expl, "pattern", None),
            "original_score": getattr(expl, "original_score", None),
            "score": getattr(expl, "score", None),
            "score_context_improvement": getattr(expl, "score_context_improvement", None),
            "supportive_context_word": getattr(expl, "supportive_context_word", None),
            "validation_result": getattr(expl, "validation_result", None),
            "textual_explanation": getattr(expl, "textual_explanation", None),
        }
    return out


async def _ensure_dashboard_test_key() -> tuple[str, str]:
    """검사 테스트 전용 API key 확보. 없거나 비활성화돼 있으면 자동 발급.

    system_settings.json 에 ``dashboard_test_api_key_id`` /
    ``dashboard_test_api_secret`` 으로 저장한다 (secret 은 발급 직후가 아니면
    DB 에서 복구 불가능하므로). DB 의 ApiKey 행이 disabled/revoked 면 새 키를
    발급한다.

    Phase 9J — 검사 테스트가 일반 API 호출 흐름을 그대로 사용하도록 도입.
    """
    from app.core import system_settings as _ss
    from app.security.api_key import find_active_key, issue_api_key

    key_id = _ss.get("dashboard_test_api_key_id")
    secret = _ss.get("dashboard_test_api_secret")

    sm = get_sessionmaker()
    async with sm() as session:
        if isinstance(key_id, str) and isinstance(secret, str):
            row = await find_active_key(session, key_id)
            if row is not None and row.enabled and row.revoked_at is None:
                return key_id, secret

        new_row, new_secret = await issue_api_key(
            session,
            name="__dashboard_test__",
            ip_allowlist=None,
            rate_per_minute=600,
            rate_per_hour=10000,
            created_by="admin-dashboard",
        )
        await session.commit()
        _ss.set_value("dashboard_test_api_key_id", new_row.key_id)
        _ss.set_value("dashboard_test_api_secret", new_secret)
        return new_row.key_id, new_secret


@router.post("/test", response_class=HTMLResponse)
async def test_submit(
    request: Request,
    title: str = Form(""),
    body: str = Form(""),
    strictness: str = Form("medium"),
    author_ip: str = Form("203.0.113.5"),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """검사 테스트 — 일반 API ``/v1/detect/post`` 흐름을 그대로 재사용한다.

    Phase 9J — 이전 구현은 분석 엔진을 직접 호출하여 audit/idempotency/응답
    정책 미들웨어를 모두 우회했다. 그 결과 검사 테스트가 사용 이력/차단
    내역에 남지 않았다. 본 핸들러는 httpx ``ASGITransport`` 로 같은 프로세스의
    FastAPI 앱을 호출하여 운영 호출과 동일한 흐름 (HMAC 검증, 응답 정책,
    audit middleware) 을 거치도록 한다. 첨부는 ``fetch_url`` 메타 기반이라
    검사 테스트로 시뮬레이션이 어려워 입력에서 제외한다.
    """
    import json as _json
    import time as _time
    import uuid as _uuid

    import httpx

    from app.main import app as _fastapi_app
    from app.security.hmac_auth import compute_signature

    started = _time.perf_counter()

    error: str | None = None
    envelope: dict[str, Any] = {}
    http_status = 0

    try:
        key_id, secret = await _ensure_dashboard_test_key()
    except Exception as e:
        error = f"검사 테스트용 API 키 준비 실패: {e}"
        logger.warning("dashboard test key bootstrap failed: %s", e)
        elapsed_ms = int((_time.perf_counter() - started) * 1000)
        return templates.TemplateResponse(
            request,
            "admin/test.html",
            {
                "result": {
                    "envelope": {},
                    "http_status": 0,
                    "error": error,
                    "elapsed_ms": elapsed_ms,
                    "strictness": strictness,
                    "author_ip": author_ip,
                },
                "form": {
                    "title": title,
                    "body": body,
                    "strictness": strictness,
                    "author_ip": author_ip,
                },
            },
        )

    payload = {
        "request_id": str(_uuid.uuid4()),
        "author": {
            "name": "dashboard-test",
            "ip": (author_ip or "").strip() or "203.0.113.5",
        },
        "post": {
            "board_id": "dashboard-test",
            "title": title or "",
            "body": body or "",
        },
        "options": {"strictness": strictness},
    }
    body_bytes = _json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    timestamp = str(int(_time.time()))
    nonce = _uuid.uuid4().hex + _uuid.uuid4().hex  # 64 hex chars
    signature = compute_signature(
        secret=secret,
        timestamp=timestamp,
        nonce=nonce,
        method="POST",
        path="/v1/detect/post",
        body=body_bytes,
    )
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": key_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }

    try:
        transport = httpx.ASGITransport(app=_fastapi_app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://dashboard-test"
        ) as client:
            r = await client.post(
                "/v1/detect/post",
                content=body_bytes,
                headers=headers,
                timeout=60.0,
            )
            http_status = r.status_code
            try:
                envelope = r.json()
            except Exception:
                envelope = {"raw": r.text}
    except Exception as e:
        error = f"API 호출 실패: {e}"
        logger.warning("test_submit api call failed: %s", e)

    elapsed_ms = int((_time.perf_counter() - started) * 1000)

    # 응답 envelope 에서 화면용 view-model 추출
    detections: list[dict[str, Any]] = []
    for d in envelope.get("detections", []) or []:
        if not isinstance(d, dict):
            continue
        detections.append(
            {
                "field": d.get("field"),
                "entity_type": d.get("entity_type"),
                "code": d.get("code"),
                "score": d.get("score"),
                "start": d.get("start"),
                "end": d.get("end"),
                "verdict": _verdict_for_code(str(d.get("code") or "")),
            }
        )

    result = {
        "envelope": envelope,
        "http_status": http_status,
        "verdict": envelope.get("verdict"),
        "code": envelope.get("code"),
        "user_message": envelope.get("user_message"),
        "developer_message": envelope.get("developer_message"),
        "system_message": envelope.get("system_message"),
        "request_id": envelope.get("request_id"),
        "processing_ms": envelope.get("processing_ms"),
        "processed_at": envelope.get("processed_at"),
        "detections": detections,
        "error": error,
        "elapsed_ms": elapsed_ms,
        "strictness": strictness,
        "author_ip": author_ip,
    }
    form = {"title": title, "body": body, "strictness": strictness, "author_ip": author_ip}
    return templates.TemplateResponse(
        request,
        "admin/test.html",
        {"result": result, "form": form},
    )


# ── Audit 상세 보기 ────────────────────────────────────────────────────────


def _extract_detections(response_body_text: str | None) -> list[dict[str, Any]]:
    """audit_event.response_body_text 에서 detections 항목을 추출.

    /v1/detect/post 응답 envelope 의 ``detections`` (Case A/B) 와
    ``body_result.detections`` (Case C) 를 모두 합쳐 반환한다. JSON 으로
    파싱되지 않거나 detections 필드가 없으면 빈 리스트.
    """
    import json as _json

    if not response_body_text:
        return []
    try:
        env = _json.loads(response_body_text)
    except Exception:
        return []
    if not isinstance(env, dict):
        return []
    out: list[dict[str, Any]] = []
    for d in env.get("detections", []) or []:
        if isinstance(d, dict):
            out.append(d)
    body_result = env.get("body_result")
    if isinstance(body_result, dict):
        for d in body_result.get("detections", []) or []:
            if isinstance(d, dict):
                out.append(d)
    return out


@router.get("/audit/{event_id}", response_class=HTMLResponse)
async def audit_detail(
    request: Request,
    event_id: int,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """단일 audit_event 상세 페이지."""
    sm = get_sessionmaker()
    row: AuditEvent | None = None
    try:
        async with sm() as session:
            result = await session.execute(select(AuditEvent).where(AuditEvent.id == event_id))
            row = result.scalar_one_or_none()
    except Exception as e:
        logger.warning("audit_detail query failed: %s", e)
    if row is None:
        return templates.TemplateResponse(
            request,
            "admin/audit_detail.html",
            {"row": None, "not_found": True, "detections": []},
            status_code=404,
        )
    return templates.TemplateResponse(
        request,
        "admin/audit_detail.html",
        {
            "row": row,
            "not_found": False,
            "detections": _extract_detections(row.response_body_text),
        },
    )


# ── 시스템 설정 ────────────────────────────────────────────────────────────


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """시스템 설정 페이지."""
    from app.core import system_settings as ss

    return templates.TemplateResponse(
        request,
        "admin/settings.html",
        {"settings": ss.get_settings_dict()},
    )


@router.post("/settings/password")
async def settings_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """관리자 비번 변경 — 현재 비번 검증 후 system_settings.json 에 저장."""
    from app.core import system_settings as _ss

    error: str | None = None
    success = False

    _, current_active = _active_credentials()
    if not secrets.compare_digest(current_password, current_active):
        error = "현재 비밀번호가 올바르지 않습니다."
    elif new_password != confirm_password:
        error = "새 비밀번호와 확인이 일치하지 않습니다."
    elif len(new_password) < 4:
        error = "새 비밀번호는 4자 이상이어야 합니다."
    elif new_password == current_password:
        error = "새 비밀번호가 현재 비밀번호와 동일합니다."
    else:
        _ss.set_value("admin_dashboard_password_override", new_password)
        success = True

    return templates.TemplateResponse(
        request,
        "admin/settings.html",
        {
            "settings": _ss.get_settings_dict(),
            "password_error": error,
            "password_success": success,
        },
    )


@router.post("/settings/audit-detail")
async def settings_audit_detail(
    _request: Request,
    enabled: str = Form(""),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """audit_detail_enabled 토글 처리."""
    from app.core import system_settings as ss

    ss.set_value("audit_detail_enabled", enabled == "on")
    return RedirectResponse(url="/admin/settings", status_code=303)


@router.post("/settings/attachment-scan")
async def settings_attachment_scan(
    _request: Request,
    enabled: str = Form(""),
    _session_id: str = Depends(get_dashboard_session),
) -> Response:
    """Phase 4b/F — `attachment_scan_enabled` 토글 처리.

    OFF 로 두면 detect 핸들러가 첨부 처리 단계 (Case C) 자체를 건너뛰고
    본문 결과만 즉시 반환합니다. 외부 의존(ClamAV / VLM / 추출기) 이
    장애 중일 때 트래픽을 즉시 줄이는 운영자용 kill switch 입니다.
    """
    from app.core import system_settings as ss

    ss.set_value("attachment_scan_enabled", enabled == "on")
    return RedirectResponse(url="/admin/settings", status_code=303)


# ── Exception handler installed at app level ──────────────────────────────
async def dashboard_auth_exception_handler(_request: Request, exc: Exception) -> Response:
    """Map ``DashboardAuthError`` into the carried response.

    Signature uses ``Exception`` so it matches Starlette's
    ``add_exception_handler`` type — we narrow at runtime.
    """
    if isinstance(exc, DashboardAuthError):
        return exc.response
    raise exc  # propagate unknown exceptions
