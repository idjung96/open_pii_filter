"""Prometheus metrics primitives shared across the API surface (Phase 8).

A single module owns every Counter / Histogram instance so middleware,
endpoint handlers, and asyncio workers can bump the same series without
needing to coordinate label sets ad-hoc. Histogram buckets follow the
Phase 8 SLA: body p50 <200 ms, body p95 <1 s, attachments p95 <30 s.

Design notes
------------
* No per-request DB I/O. ``prometheus_client`` keeps everything in
  process-local memory; the ``/v1/admin/metrics`` endpoint walks the
  default registry on demand.
* Path labels must be cardinality-bounded — the audit middleware passes
  the route template (``/v1/detect/post``) rather than the resolved URL
  so we never explode the label space with job_id values.
* All ``observe`` / ``inc`` calls are wrapped in ``contextlib.suppress``
  so a bad label value never breaks request flow.
"""

from __future__ import annotations

import contextlib

from prometheus_client import Counter, Histogram

# ── HTTP layer ────────────────────────────────────────────────────────────
HTTP_REQUESTS_TOTAL: Counter = Counter(
    "http_requests_total",
    "Total HTTP requests handled by the API",
    labelnames=("method", "path", "response_code"),
)

# Buckets sized for the spec SLA: 50 ms / 100 ms / 200 ms (p50) / 500 ms
# / 1 s (body p95) / 2 s (alerter threshold) / 5 s (timeout floor).
HTTP_REQUEST_DURATION_SECONDS: Histogram = Histogram(
    "http_request_duration_seconds",
    "Wall-clock duration of HTTP requests, in seconds",
    labelnames=("method", "path"),
    buckets=(0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0),
)

# ── PII detection layer ───────────────────────────────────────────────────
PII_DETECTIONS_TOTAL: Counter = Counter(
    "pii_detections_total",
    "Number of PII detections produced by the analyzer, by type+verdict",
    labelnames=("entity_type", "verdict"),
)

# ── Async attachment workers ──────────────────────────────────────────────
EXTRACTION_JOBS_TOTAL: Counter = Counter(
    "extraction_jobs_total",
    "Async attachment extraction jobs by terminal status",
    labelnames=("status",),
)

# ── Feedback / rate-limit signals ─────────────────────────────────────────
FEEDBACK_TOTAL: Counter = Counter(
    "feedback_total",
    "Phase 7 feedback rows received",
)

RATE_LIMIT_REJECTIONS_TOTAL: Counter = Counter(
    "rate_limit_rejections_total",
    "Requests rejected by the token-bucket rate limiter",
    labelnames=("scope",),  # 'caller' or 'ip'
)

# ── Detect endpoint outcome counters ──────────────────────────────────────
# `verdict` is the response code's terminal verdict — one of
# {"PASS", "BLOCK", "PROCESSING", "ERROR"}. Sum across verdicts for the
# total POST /v1/detect/post call count; filter to verdict="BLOCK" for the
# blocked-call count. WARN is intentionally absent (deprecated since
# Phase 9D — codes were absorbed into BLOCK or PASS).
PII_DETECT_REQUESTS_TOTAL: Counter = Counter(
    "pii_detect_requests_total",
    "Calls to POST /v1/detect/post grouped by terminal verdict",
    labelnames=("verdict",),
)

# ── OCR latency ────────────────────────────────────────────────────────────
# Buckets cover the spec SLA window for OCR: paddle ~0.5-3 s on CPU, VLM
# 1-10 s typical, with a 30 s ceiling reflecting the attachment job's
# overall budget. `engine` carries which backend actually ran ("vlm" or
# "paddle"); fallback paths label themselves with the engine that handled
# the request, not the original choice.
OCR_DURATION_SECONDS: Histogram = Histogram(
    "ocr_duration_seconds",
    "Wall-clock duration of a single OCR run, in seconds",
    labelnames=("engine",),
    buckets=(0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0),
)

# ── Attachment size distribution ──────────────────────────────────────────
# Buckets span 4 KiB → 50 MiB, covering everything from tiny stamps to the
# Phase-4 hard limit (`MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024`). Observed
# once per attachment as it enters the per-attachment processor — so the
# series reflects what callers actually upload, not what gets stored.
ATTACHMENT_SIZE_BYTES: Histogram = Histogram(
    "attachment_size_bytes",
    "Distribution of attachment sizes accepted into the async pipeline",
    buckets=(
        4 * 1024,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        1 * 1024 * 1024,
        4 * 1024 * 1024,
        16 * 1024 * 1024,
        50 * 1024 * 1024,
    ),
)


def observe_http(
    *,
    method: str,
    path: str,
    response_code: str,
    duration_seconds: float,
) -> None:
    """Record one HTTP request's outcome.

    Suppresses any exception so a metrics failure never propagates into
    the request flow. The middleware calls this from a ``finally`` block.
    """
    with contextlib.suppress(Exception):
        HTTP_REQUESTS_TOTAL.labels(method=method, path=path, response_code=response_code).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, path=path).observe(duration_seconds)


def observe_detection(*, entity_type: str, verdict: str) -> None:
    """Bump the PII-detections counter for one (type, verdict) pair."""
    with contextlib.suppress(Exception):
        PII_DETECTIONS_TOTAL.labels(entity_type=entity_type, verdict=verdict).inc()


def observe_extraction_job(*, status: str) -> None:
    """Bump the extraction-jobs counter for a terminal status."""
    with contextlib.suppress(Exception):
        EXTRACTION_JOBS_TOTAL.labels(status=status).inc()


def observe_feedback() -> None:
    """Bump the feedback counter (Phase 7 ``POST /v1/feedback``)."""
    with contextlib.suppress(Exception):
        FEEDBACK_TOTAL.inc()


def observe_rate_limit_rejection(*, scope: str) -> None:
    """Bump the rate-limit rejection counter for a given scope."""
    with contextlib.suppress(Exception):
        RATE_LIMIT_REJECTIONS_TOTAL.labels(scope=scope).inc()


def observe_detect_request(*, verdict: str) -> None:
    """Tally one POST /v1/detect/post call by its terminal verdict.

    Called from the detect endpoint's response funnels (`_error` for
    error-class outcomes, `_envelope` for body-evaluated outcomes) so a
    single call increments the counter exactly once.
    """
    with contextlib.suppress(Exception):
        PII_DETECT_REQUESTS_TOTAL.labels(verdict=verdict).inc()


def observe_ocr_duration(*, engine: str, seconds: float) -> None:
    """Record one OCR engine call's wall-clock duration."""
    with contextlib.suppress(Exception):
        OCR_DURATION_SECONDS.labels(engine=engine).observe(seconds)


def observe_attachment_size(*, size_bytes: int) -> None:
    """Record the size, in bytes, of a single attachment entering the pipeline."""
    with contextlib.suppress(Exception):
        ATTACHMENT_SIZE_BYTES.observe(size_bytes)
