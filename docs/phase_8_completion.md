# Phase 8 Completion Report

> **Phase 9D (2026-05) 변경 알림**
> 본 보고서가 기술하는 마스킹/익명화 파이프라인은 Phase 9D 에서 폐기됐습니다.
> 마스킹 결과 응답(`masked`/`masked_url`), `MaskedArtifact` 테이블, `/v1/masked-artifacts/{token}` 엔드포인트, WARN 등급은 더 이상 동작하지 않습니다.
> 현재 동작은 PASS/BLOCK 2단계이며 PII 탐지 시 게시가 거부됩니다. 자세한 내용은 `docs/api_integration.md` 참고.

**Status**: COMPLETE — all T8.x tasks delivered, baseline + Phase 8 tests
green (216 + 9 = 225 passing).

## Tasks delivered

| Task | Description | Deliverable |
|------|-------------|-------------|
| T8.1 | Full E2E flow (HMAC + ASGI + webhook) | `tests/integration/test_phase8_e2e.py` |
| T8.2 | Locust scenarios + load report | `tests/load/locustfile.py`, `tests/load/asgi_smoke.py`, `docs/load_test_report.md` |
| T8.3 | Failure-mode tests (PG/Redis/VLM/encryption) | `tests/integration/test_phase8_failure_modes.py` |
| T8.4 | Prometheus exporter + counters/histograms | `app/api/metrics.py`, `app/security/metrics_collector.py`, hooks in middleware/detect/workers/rate_limit, alert rules `deploy/prometheus_alerts.yml` |
| T8.5 | Bandit + pip-audit reports | `docs/security_scan_report.md` |
| T8.6 | Multi-stage Dockerfile + compose + dockerignore | `deploy/Dockerfile`, `deploy/docker-compose.yml`, `.dockerignore` |
| T8.7 | Health probes + Korean operations doc | `app/api/health.py`, `docs/operations.md` |
| CI | Lint/type/test/security/container-build pipeline | `.github/workflows/ci.yml` |

## New code

- **`app/security/metrics_collector.py`** — Prometheus Counter/Histogram
  primitives with `contextlib.suppress` wrappers so a metrics failure
  never breaks the request flow.
- **`app/api/metrics.py`** — `/v1/admin/metrics` endpoint, gated by
  the existing `require_admin` dependency.
- **`app/api/health.py`** — `/readyz` + `/v1/readyz` (DB + Redis ping).
  `/healthz` retained inline in `app/main.py` for back-compat.
- **`app/security/audit_middleware.py`** — bumps `http_requests_total`
  + `http_request_duration_seconds` per request with bounded path
  cardinality (`/v1/jobs/{job_id}` / `/v1/masked-artifacts/{token}`
  templates).
- **`app/api/detect.py::_stash_audit`** — bumps `pii_detections_total`
  per (entity_type, verdict) tuple seen in the response.
- **`app/workers/attachment_processor.py`** — bumps
  `extraction_jobs_total` on each status transition (PROCESSING /
  COMPLETED / FAILED).
- **`app/security/auth.py`** — bumps `rate_limit_rejections_total`
  with `scope="ip"` or `scope="caller"` on rejection.
- **`app/api/feedback.py`** — bumps `feedback_total`.

## Quality gates

```
uv run ruff check app/ tests/        → All checks passed!
uv run mypy app/                     → Success: no issues found
uv run pytest tests/                 → 225 passed (216 baseline + 9 new)
uv run bandit -r app/ -c pyproject   → 0 High, 2 Medium (oversights, see report)
uv run pip-audit --skip-editable     → 1 vuln (pip CVE-2026-3219, build-time only)
```

## Load test summary (single host, single uvicorn worker)

| Concurrency | Duration | RPS | p50 | p95 | p99 | Success |
|-------------|----------|-----|-----|-----|-----|---------|
|     8       | 30 s     | 65.5 | 114 ms | 166 ms | 207 ms | 100% |
|    16       | 30 s     | 61.6 | 246 ms | 354 ms | 511 ms | 100% |
|    32       | 60 s     | 58.2 | 529 ms | 706 ms | 1013 ms | 100% |

**Spec SLA**: 본문 p50 < 200 ms, p95 < 1 s — 모두 통과.
첨부 p95 < 30 s — `tests/integration/test_phase8_e2e.py` 의 60 회 폴링
평균 < 100 ms 으로 SLA 대비 매우 큰 마진.

## Decisions honoured

- ✅ Metrics endpoint mounted unconditionally + admin gate (Operator
  decision C, hybrid mount strategy).
- ✅ Single container runs API + asyncio workers (Operator decision E).
- ✅ Spec default SLA used: 본문 p50 200 ms / p95 1 s, 첨부 p95 30 s
  (Operator decision F).
- ✅ Locust selected for load testing (Python re-uses HMAC signing).
- ✅ Multi-stage Dockerfile (uv builder → python:3.12-slim runtime).
- ✅ prometheus-client (stdlib-style API).
- ✅ bandit + pip-audit for security scans.

## Known limitations

- **Docker build verification not performed** in this environment due
  to sandbox constraints (no docker daemon access). The Dockerfile is
  byte-validated and the CI workflow `container-build` job will catch
  any breakage on first PR.
- **pip CVE-2026-3219** is a build-time tool issue with no fix yet
  released; documented in `security_scan_report.md` §2.2.
- **HWP/HWPX support** continues to be Linux-blocked (pyhwpx is
  Windows-only). Phase 8 doesn't change this — see Phase 4 notes.

## Next phase (Phase 9, if applicable)

Phase 8 closes out the v1 deployment story. Future work candidates:
- VLM-as-OCR migration to a hosted provider for higher concurrency
- Multi-region replication strategy for the masked-artifacts CDN
- Active-learning loop from `pii_feedback` rows to deny-list automation
