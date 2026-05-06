"""POST /v1/detect/post — body PII detection (Case A/B only).

Phase 1 scope:
  - Case A: body BLOCK → HTTP 200 + verdict=BLOCK + skip attachment work
  - Case B: body PASS/WARN, no attachments → HTTP 200 + verdict
  - Case C (attachments queued, HTTP 202): NotImplemented — Phase 4 work
  - Idempotency: in-memory cache (24 h TTL), see app/security/idempotency

Auth (HMAC + API key + IP allowlist) is also Phase 3+.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.api.responses import build_response
from app.api.schemas import (
    MAX_BODY_LEN,
    MAX_TITLE_LEN,
    BodyResult,
    Detection,
    DetectPostRequest,
    DetectPostResponse,
    JobInfo,
)
from app.core.analyzer import build_analyzer
from app.core.analyzer_cache import get_analyzer_cache
from app.core.codes import Verdict, get_code
from app.core.exception_ip_cache import is_exception_ip
from app.core.policies import map_detection_to_code, score_to_band
from app.core.policy_engine import (
    ResolvedPolicy,
    get_policy_cache,
    resolve_action,
)
from app.db.crud import create_job
from app.db.models import ExtractionJob
from app.db.session import get_sessionmaker
from app.security.auth import require_auth
from app.security.hmac_auth import AuthedCaller
from app.security.idempotency import IdempotencyCache, ReserveOutcome, get_cache
from app.security.metrics_collector import observe_detect_request, observe_detection

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult

    from app.db.models import PiiPolicy

router = APIRouter(prefix="/v1", tags=["detect"])

# Hard limit for body PII analysis (sync path). Above this we return SVR-5006.
BODY_TIMEOUT_SECONDS = 5.0

# Phase 4 — Case C constraints (T4.13~T4.16).
# Phase 4b — 한 첨부의 최대 크기를 50 MiB → 20 MiB 로 축소.
MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_MB = 20
MAX_ATTACHMENT_BYTES = MAX_ATTACHMENT_MB * 1024 * 1024
# HWP / HWPX 형식 — Linux 런타임에서 파싱 불가. Phase 4b 부터는 일반 IP 의
# HWP/HWPX 첨부를 `attachment_blocklist` (REQ-4035) 가 일괄 거부하므로
# REQ-4034 는 더 이상 새 요청에서 발생하지 않는다. 상수는 historical
# 참조용으로 보존.
HWP_MIME_TYPES = frozenset(
    {
        "application/hwp+zip",
        "application/x-hwpx",
        "application/haansofthwpx",
        "application/x-hwp",
        "application/haansofthwp",
    }
)

SUPPORTED_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        # Phase 4b — xlsx / pptx replace the legacy OLE doc/xls/ppt path
        # (those live on the deny list).
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        # Phase 4b — HWP/HWPX 는 deny list 가 일괄 거부 (REQ-4035) 하므로
        # SUPPORTED_MIME_TYPES 에는 더 이상 포함되지 않는다. 예외 IP 작성자도
        # 추출 자체는 시도하지만, 그 경로는 별도 우회 분기로 처리된다.
        "text/plain",
        "text/markdown",
        # Phase 5 — image OCR
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/bmp",
        "image/webp",
        "image/gif",
    }
)
# Webhook ETA shown to the caller when Case C succeeds (T4.13).
CASE_C_DEFAULT_ETA_SECONDS = 30
# Score floor — below this we never surface a detection (matches medium-band PASS).
MIN_REPORTABLE_SCORE = 0.50
# Per-span detections returned to the caller (Q2 — top-3 candidates).
MAX_DETECTIONS_PER_SPAN = 3


# ── Verdict resolution ────────────────────────────────────────────────────
def _decide_body_code(detections: list[Detection]) -> str:
    """Pick the strongest single response code from a set of detections.

    Phase 9D — WARN 등급 폐기. 결과는 BLOCK 또는 PASS 만 가능.

    Rules:
      - If 2+ distinct entity_types reach BLOCK band → BLOCK-2008
      - Else if any BLOCK band → that single code
      - Else                   → OK-0000
    """
    block_codes: list[tuple[str, str]] = []  # (entity_type, code)
    for d in detections:
        rc = get_code(d.code)
        if rc.verdict is Verdict.BLOCK:
            block_codes.append((d.entity_type, d.code))

    if block_codes:
        distinct = {et for et, _ in block_codes}
        if len(distinct) >= 2:
            return "BLOCK-2008"
        return block_codes[0][1]
    return "OK-0000"


# ── Detection adapters ────────────────────────────────────────────────────
def _to_detection(r: RecognizerResult, *, field: str, strictness: str) -> Detection:
    code = map_detection_to_code(
        entity_type=r.entity_type,
        score=r.score,
        field=field,
        strictness=strictness,  # type: ignore[arg-type]
    )
    return Detection(
        field=field,
        entity_type=r.entity_type,
        code=code,
        score=r.score,
        start=r.start,
        end=r.end,
    )


def _band_to_action(band: str) -> str:
    """Map a policies.py band into a policy_engine action label.

    Phase 9D — WARN 등급 폐기. 'block' → 'BLOCK', 그 외 → 'PASS'.
    Used as the ``code_default_action`` argument to ``resolve_action``.
    """
    if band == "block":
        return "BLOCK"
    return "PASS"


def _topk_per_span(
    raw: list[RecognizerResult], *, k: int = MAX_DETECTIONS_PER_SPAN
) -> list[RecognizerResult]:
    """Q2 — for each exact (start, end) span, keep the top-k highest-scored hits."""
    by_span: dict[tuple[int, int], list[RecognizerResult]] = {}
    for r in raw:
        by_span.setdefault((r.start, r.end), []).append(r)
    out: list[RecognizerResult] = []
    for hits in by_span.values():
        hits.sort(key=lambda h: h.score, reverse=True)
        out.extend(hits[:k])
    return out


def _analyze_field(
    text: str,
    *,
    field: str,
    strictness: str,
    analyzer: AnalyzerEngine | None = None,
    policies: list[PiiPolicy] | None = None,
) -> list[Detection]:
    """Backward-compatible analyzer wrapper.

    Returns only the visible (caller-surfaced) detections — used by
    ``app.workers.attachment_processor``. The body endpoint uses
    :func:`_analyze_field_full` to additionally obtain LOG_ONLY types.
    """
    visible, _log_only = _analyze_field_full(
        text,
        field=field,
        strictness=strictness,
        analyzer=analyzer,
        policies=policies,
    )
    return visible


def _analyze_field_full(
    text: str,
    *,
    field: str,
    strictness: str,
    analyzer: AnalyzerEngine | None = None,
    policies: list[PiiPolicy] | None = None,
) -> tuple[list[Detection], set[str]]:
    """Run the analyzer and apply Phase 7 policy resolution.

    Phase 9D — 마스킹 결과 응답이 폐기되어 ``mask_spans`` 반환을 제거했다.
    검출 시 BLOCK 으로 즉시 거절하므로 마스킹할 필요가 없다.

    Returns a tuple of:
      - ``visible``         : detections returned to the caller
                              (BLOCK only; LOG_ONLY/PASS dropped).
      - ``log_only_types``  : entity_types resolved to LOG_ONLY — surfaced
                              into ``audit_events.detected_entity_types``
                              so operators can see what got swallowed.
    """
    if not text:
        return [], set()
    engine = analyzer if analyzer is not None else build_analyzer()
    raw = engine.analyze(text=text, language="ko")
    raw = _topk_per_span(raw)  # Q2

    pol_rows = policies or []

    visible: list[Detection] = []
    log_only_types: set[str] = set()

    for r in raw:
        if r.score < MIN_REPORTABLE_SCORE:
            continue
        default_code = map_detection_to_code(
            entity_type=r.entity_type,
            score=r.score,
            field=field,
            strictness=strictness,  # type: ignore[arg-type]
        )
        default_band = score_to_band(
            r.score,
            strictness,  # type: ignore[arg-type]
        )
        default_action = _band_to_action(default_band)

        resolved: ResolvedPolicy = resolve_action(
            entity_type=r.entity_type,
            score=r.score,
            code_default_action=default_action,  # type: ignore[arg-type]
            code_default_code=default_code,
            code_default_user_message=None,
            policies=pol_rows,
        )

        if resolved.action == "PASS":
            continue

        if resolved.action == "LOG_ONLY":
            log_only_types.add(r.entity_type)
            continue

        # Phase 9D — MASK action 도 BLOCK 과 동일하게 검출만 surface 한다
        # (마스킹 결과는 더 이상 응답에 포함되지 않음). WARN action 은
        # 정책상 사용되지 않지만 historical row 호환을 위해 surface 한다.
        det = Detection(
            field=field,
            entity_type=r.entity_type,
            code=resolved.code,
            score=r.score,
            start=r.start,
            end=r.end,
        )
        visible.append(det)

    return visible, log_only_types


async def _resolve_analyzer() -> AnalyzerEngine:
    """Return the live analyzer.

    Tries to load DB-backed analyzer (hot-reloadable) and falls back to
    the in-memory hardcoded one if the DB is unreachable. Falling back
    keeps the API responsive when Postgres is briefly unavailable; once
    DB is back the next request will rebuild via the cache.
    """
    try:
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            return await get_analyzer_cache().get(session)
    except Exception:
        return build_analyzer()


async def _resolve_runtime() -> tuple[
    AnalyzerEngine,
    AnalyzerEngine | None,
    list[PiiPolicy],
]:
    """Return ``(production_analyzer, shadow_analyzer_or_None, policies)``.

    Falls back to the hardcoded analyzer + empty policy list on any DB
    failure, mirroring ``_resolve_analyzer``'s availability semantics.
    """
    try:
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            production = await get_analyzer_cache().get(session)
            shadow = await get_analyzer_cache().get_shadow(session)
            policies = await get_policy_cache().get(session)
        return production, shadow, list(policies)
    except Exception:
        return build_analyzer(), None, []


# ── Endpoint ──────────────────────────────────────────────────────────────
def _error(
    req: DetectPostRequest,
    code: str,
    *,
    started: float,
    request: Request | None = None,
    **vars: object,
) -> JSONResponse:
    rc = get_code(code)
    resp = build_response(
        request_id=req.request_id,
        code=code,
        processing_ms=int((time.perf_counter() - started) * 1000),
        template_vars=vars or None,
    )
    if request is not None:
        _stash_audit(request, code=code, detections=[])
    observe_detect_request(verdict=str(rc.verdict))
    return JSONResponse(status_code=rc.http_status, content=resp.model_dump(mode="json"))


def _envelope(
    resp: DetectPostResponse,
    *,
    request: Request | None = None,
    detections: list[Detection] | None = None,
    log_only_types: set[str] | None = None,
    shadow_hit_types: set[str] | None = None,
) -> JSONResponse:
    rc = get_code(resp.code)
    if request is not None:
        _stash_audit(
            request,
            code=resp.code,
            detections=detections or [],
            log_only_types=log_only_types,
            shadow_hit_types=shadow_hit_types,
        )
    observe_detect_request(verdict=str(rc.verdict))
    return JSONResponse(status_code=rc.http_status, content=resp.model_dump(mode="json"))


def _ok_pass(
    req: DetectPostRequest,
    *,
    started: float,
    request: Request | None = None,
    cache: IdempotencyCache | None = None,
) -> JSONResponse:
    """Phase 9A — emit OK-0000 PASS without running the analyzer.

    Used when the post author's IP is on the exception list. We still
    cache the response against the request_id and stash audit metadata
    so operators see "exception_ip" rows in the log.
    """
    response = build_response(
        request_id=req.request_id,
        code="OK-0000",
        processing_ms=int((time.perf_counter() - started) * 1000),
        detections=[],
    )
    if cache is not None:
        cache.complete(req.request_id, response)
    return _envelope(response, request=request, detections=[])


def _stash_audit(
    request: Request,
    *,
    code: str,
    detections: list[Detection],
    log_only_types: set[str] | None = None,
    shadow_hit_types: set[str] | None = None,
) -> None:
    """Attach Phase 6/7 audit metadata to ``request.state``.

    The middleware reads this after the response is built. We store
    aggregate counts only — never plaintext PII.

    Phase 7 — ``log_only_types`` are LOG_ONLY-policy entities not
    surfaced to the caller; they're appended to ``detected_entity_types``
    so audit reflects the true population. ``shadow_hit_types`` are
    detections that fired only in the shadow analyzer (verdict-neutral)
    and go into the dedicated ``shadow_hit_types`` column.
    """
    from app.security.audit_middleware import AuditPayload

    visible_types = {d.entity_type for d in detections} if detections else set()
    all_types = sorted(visible_types | (log_only_types or set()))
    shadow_only = sorted(shadow_hit_types or set())
    request.state.audit_payload = AuditPayload(
        response_code=code,
        detected_entity_count=len(detections) + len(log_only_types or set()),
        detected_entity_types=",".join(all_types) if all_types else None,
        shadow_hit_types=",".join(shadow_only) if shadow_only else None,
    )

    # Phase 8 — Prometheus counter, once per (entity_type, verdict) tuple
    # observed in the response. We deduplicate on type+verdict so a body
    # with five RRN hits still contributes one tick under the BLOCK
    # verdict label (the count column on the histogram is not a unique
    # detection count — for that, Prometheus operators read the counter
    # together with detected_entity_count from the audit log).
    seen: set[tuple[str, str]] = set()
    for det in detections or []:
        try:
            verdict = get_code(det.code).verdict.value
        except KeyError:
            verdict = "PASS"
        key = (det.entity_type, verdict)
        if key in seen:
            continue
        seen.add(key)
        observe_detection(entity_type=det.entity_type, verdict=verdict)
    # Log-only (verdict-neutral) detections still count for ops visibility.
    for et in log_only_types or set():
        key = (et, "LOG_ONLY")
        if key in seen:
            continue
        seen.add(key)
        observe_detection(entity_type=et, verdict="LOG_ONLY")


@router.post("/detect/post")
async def detect_post(
    req: DetectPostRequest,
    request: Request,
    caller: AuthedCaller = Depends(require_auth),  # noqa: B008
) -> JSONResponse:
    """Detect PII in `post.title` + `post.body`.

    Phase 1: body-only sync path. Attachment routing (Case C) is rejected
    until Phase 4 is wired up.
    """
    started = time.perf_counter()
    cache: IdempotencyCache = get_cache()

    # Phase 6 — expose caller to AuditMiddleware so api_key_id ends up on
    # the audit row.
    request.state.caller = caller

    # ── §2.6 Idempotency check ─────────────────────────────────────────
    outcome, cached = cache.reserve(req.request_id)
    if outcome is ReserveOutcome.IN_PROGRESS:
        return _error(req, "REQ-4005", started=started, request=request)
    if outcome is ReserveOutcome.COMPLETED and cached is not None:
        return _envelope(cached, request=request, detections=cached.detections)

    # ── Phase 9A — exception IP short-circuit ─────────────────────────
    # When the post author's IP is on the exception list we skip the
    # body PII analysis and emit OK-0000 immediately. The shadow / log
    # passes are also skipped because there is no caller-visible
    # verdict to compare against.
    if is_exception_ip(req.author.ip or ""):
        return _ok_pass(req, started=started, request=request, cache=cache)

    try:
        # ── §2.8 length limits → REQ-4030 (HTTP 413) ──────────────────
        if len(req.post.title) > MAX_TITLE_LEN:
            return _error(
                req,
                "REQ-4030",
                started=started,
                request=request,
                limit=MAX_TITLE_LEN,
                n=len(req.post.title),
            )
        if len(req.post.body) > MAX_BODY_LEN:
            return _error(
                req,
                "REQ-4030",
                started=started,
                request=request,
                limit=MAX_BODY_LEN,
                n=len(req.post.body),
            )

        # ── Pre-flight Case-C validation (T4.13~T4.16) ────────────────
        # Validating before body analysis lets us reject obviously
        # malformed Case-C requests without spending CPU on PII analysis.
        if req.has_attachments:
            if not req.callback_url:
                return _error(
                    req,
                    "REQ-4001",
                    started=started,
                    request=request,
                    fields="callback_url",
                )
            assert req.attachments is not None
            n_att = len(req.attachments)
            if n_att > MAX_ATTACHMENTS:
                return _error(
                    req,
                    "REQ-4032",
                    started=started,
                    request=request,
                    limit=MAX_ATTACHMENTS,
                    n=n_att,
                )
            from app.core.blocklist_cache import is_blocked as _is_blocked_format

            author_ip_for_blocklist = req.author.ip or ""
            blocklist_bypass = is_exception_ip(author_ip_for_blocklist)
            for att in req.attachments:
                if att.size_bytes > MAX_ATTACHMENT_BYTES:
                    return _error(
                        req,
                        "REQ-4031",
                        started=started,
                        request=request,
                        filename=att.filename,
                        limit=MAX_ATTACHMENT_MB,
                    )
                # Phase 4b — runtime-managed deny list (REQ-4035) covers
                # archives, OLE legacy Office and HWP/HWPX. Exception-IP
                # authors bypass the gate; Phase C downstream will route
                # their analysis result to PASS regardless of detections.
                if not blocklist_bypass:
                    blocked, match_kind = _is_blocked_format(
                        filename=att.filename, mime_type=att.mime_type
                    )
                    if blocked:
                        return _error(
                            req,
                            "REQ-4035",
                            started=started,
                            request=request,
                            filename=att.filename,
                            mime_type=att.mime_type,
                            match_kind=match_kind or "",
                            reason="format on deny list",
                        )
                if att.mime_type not in SUPPORTED_MIME_TYPES:
                    return _error(
                        req,
                        "REQ-4033",
                        started=started,
                        request=request,
                        filename=att.filename,
                        mime_type=att.mime_type,
                    )

        # ── Body analysis with hard timeout (T1.28) ───────────────────
        try:
            async with asyncio.timeout(BODY_TIMEOUT_SECONDS):
                analyzer, shadow_analyzer, policies = await _resolve_runtime()
                title_dets, title_log = await asyncio.to_thread(
                    _analyze_field_full,
                    req.post.title,
                    field="post.title",
                    strictness=req.options.strictness,
                    analyzer=analyzer,
                    policies=policies,
                )
                body_dets, body_log = await asyncio.to_thread(
                    _analyze_field_full,
                    req.post.body,
                    field="post.body",
                    strictness=req.options.strictness,
                    analyzer=analyzer,
                    policies=policies,
                )
        except TimeoutError:
            return _error(req, "SVR-5006", started=started, request=request)

        all_dets = title_dets + body_dets
        log_only_types = title_log | body_log
        body_code = _decide_body_code(all_dets)

        # Phase 9D — WARN 등급 / 마스킹 결과 폐기. 검출 시 BLOCK 또는 PASS만.

        # ── Phase 7: shadow analyzer — fire-and-forget audit-only pass ──
        shadow_types = await _run_shadow(
            req=req,
            shadow_analyzer=shadow_analyzer,
            production_types={d.entity_type for d in all_dets} | log_only_types,
        )

        # ── Case A: body BLOCK → skip attachments ─────────────────────
        rc = get_code(body_code)
        if rc.verdict is Verdict.BLOCK:
            response = build_response(
                request_id=req.request_id,
                code=body_code,
                processing_ms=int((time.perf_counter() - started) * 1000),
                detections=all_dets,
            )
            cache.complete(req.request_id, response)
            return _envelope(
                response,
                request=request,
                detections=all_dets,
                log_only_types=log_only_types,
                shadow_hit_types=shadow_types,
            )

        # ── Case B: body PASS, no attachments → immediate ─────────────
        # Phase 4b — system-wide kill switch: when an operator flips
        # `attachment_scan_enabled` to False the gateway behaves as if
        # the request had no attachments. The body verdict still ships;
        # the caller's responsibility to retry later if needed.
        from app.core import system_settings as _ss

        attachment_scan_enabled = bool(_ss.get("attachment_scan_enabled"))
        if not req.has_attachments or not attachment_scan_enabled:
            response = build_response(
                request_id=req.request_id,
                code=body_code,
                processing_ms=int((time.perf_counter() - started) * 1000),
                detections=all_dets,
            )
            cache.complete(req.request_id, response)
            return _envelope(
                response,
                request=request,
                detections=all_dets,
                log_only_types=log_only_types,
                shadow_hit_types=shadow_types,
            )

        # ── Case C: body PASS + attachments → async (T4.13~T4.16) ─────
        return await _enqueue_attachment_job(
            req,
            body_code=body_code,
            body_dets=all_dets,
            started=started,
            cache=cache,
            request=request,
            log_only_types=log_only_types,
            shadow_hit_types=shadow_types,
        )

    except Exception:
        cache.release(req.request_id)
        raise


async def _run_shadow(
    *,
    req: DetectPostRequest,
    shadow_analyzer: AnalyzerEngine | None,
    production_types: set[str],
) -> set[str]:
    """Run the shadow analyzer and return entity_types that fired only
    in shadow (i.e. weren't already produced by the production analyzer).

    Designed to be called *after* the production verdict is built so its
    cost doesn't push the response past the body timeout. The shadow
    pass uses the already-resolved analyzer and only walks the shadow
    rows' new recognizers.
    """
    if shadow_analyzer is None:
        return set()
    try:
        title_hits = await asyncio.to_thread(shadow_analyzer.analyze, req.post.title, language="ko")
        body_hits = await asyncio.to_thread(shadow_analyzer.analyze, req.post.body, language="ko")
    except Exception:
        return set()
    shadow_types: set[str] = set()
    for r in [*title_hits, *body_hits]:
        if r.score < MIN_REPORTABLE_SCORE:
            continue
        if r.entity_type not in production_types:
            shadow_types.add(r.entity_type)
    return shadow_types


async def _enqueue_attachment_job(
    req: DetectPostRequest,
    *,
    body_code: str,
    body_dets: list[Detection],
    started: float,
    cache: IdempotencyCache,
    request: Request | None = None,
    log_only_types: set[str] | None = None,
    shadow_hit_types: set[str] | None = None,
) -> JSONResponse:
    """Create an extraction job + spawn the asyncio worker.

    Returns the HTTP 202 ACK-3001 envelope to the caller while the
    worker fans out fetch/scan/extract/analyze for each attachment.
    Idempotency for replays is preserved by caching the 202 envelope
    against the original request_id (T4.23).
    """
    from app.workers.attachment_processor import process_attachment_job

    assert req.attachments is not None
    job_id = f"job_{uuid.uuid4().hex[:12]}"

    body_rc = get_code(body_code)
    sm = get_sessionmaker()

    job = ExtractionJob(
        job_id=job_id,
        request_id=str(req.request_id),
        callback_url=req.callback_url,
        status="PENDING",
        body_code=body_code,
        body_verdict=body_rc.verdict.value,
    )
    async with sm() as session:
        await create_job(session, job)

    # Fire-and-forget background worker. The runtime keeps a reference
    # via asyncio's task list so the loop won't GC it.
    asyncio.create_task(  # noqa: RUF006 — fire-and-forget by design
        process_attachment_job(
            job_id=job_id,
            request_id=req.request_id,
            attachments=list(req.attachments),
            callback_url=req.callback_url,
            body_code=body_code,
            body_verdict=body_rc.verdict.value,
            strictness=req.options.strictness,
            sessionmaker=sm,
            analyzer_factory=_resolve_analyzer,
        ),
        name=f"pii-job-{job_id}",
    )

    body_result = BodyResult(verdict=body_rc.verdict, code=body_code, detections=body_dets)
    job_info = JobInfo(
        job_id=job_id,
        status_url=f"/v1/jobs/{job_id}",
        estimated_completion_seconds=CASE_C_DEFAULT_ETA_SECONDS,
        attachment_count=len(req.attachments),
    )
    response = build_response(
        request_id=req.request_id,
        code="ACK-3001",
        processing_ms=int((time.perf_counter() - started) * 1000),
        detections=body_dets,
        body_result=body_result,
        job=job_info,
        template_vars={"eta_seconds": CASE_C_DEFAULT_ETA_SECONDS},
    )
    cache.complete(req.request_id, response)
    return _envelope(
        response,
        request=request,
        detections=body_dets,
        log_only_types=log_only_types,
        shadow_hit_types=shadow_hit_types,
    )
