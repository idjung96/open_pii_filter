# Phase 4 Completion Report

> **Phase 9D (2026-05) 변경 알림**
> 본 보고서가 기술하는 마스킹/익명화 파이프라인은 Phase 9D 에서 폐기됐습니다.
> 마스킹 결과 응답(`masked`/`masked_url`), `MaskedArtifact` 테이블, `/v1/masked-artifacts/{token}` 엔드포인트, WARN 등급은 더 이상 동작하지 않습니다.
> 현재 동작은 PASS/BLOCK 2단계이며 PII 탐지 시 게시가 거부됩니다. 자세한 내용은 `docs/api_integration.md` 참고.

**Phase**: 4 — Attachment text extraction + Case C async flow
**Date**: 2026-04-25
**Status**: COMPLETE

## Scope

Implements end-to-end async attachment processing for `POST /v1/detect/post`:

- Body PASS/WARN with attachments → HTTP 202 + ACK-3001 + background worker fans out fetch → scan → extract → analyze
- Webhook delivery (HMAC-signed) with exponential backoff
- `GET /v1/jobs/{job_id}` for polling job status (24-hour retention)

## Test Cases (T4.1 ~ T4.23)

All 23 test cases pass.

| ID    | Description                                             | Status |
|-------|---------------------------------------------------------|--------|
| T4.1  | extract_pdf on text PDF — text returned, is_scan=False  | PASS   |
| T4.2  | extract_pdf on scan-only PDF — is_scan=True             | PASS   |
| T4.3  | DOCX with PII in table cells — text extracted          | PASS   |
| T4.4  | HWPX text extraction                                    | PASS   |
| T4.5  | HWP 5 binary mime → REQ-4033                            | PASS   |
| T4.6  | Corrupted PDF → REQ-4042                                | PASS   |
| T4.7  | 101-page PDF → REQ-4043 (limit 100)                     | PASS   |
| T4.8  | EICAR test file → REQ-4050 (or skip when ClamAV down)  | PASS   |
| T4.9  | Encrypted PDF → REQ-4051                                | PASS   |
| T4.10 | fetch_attachment 404 → REQ-4040                         | PASS   |
| T4.11 | fetch_attachment SHA256 mismatch → REQ-4041             | PASS   |
| T4.12 | dispatch_extract on octet-stream → REQ-4033             | PASS   |
| T4.13 | POST with PDF attachment → 202 + ACK-3001 + job_id      | PASS   |
| T4.14 | body BLOCK + attachment → 200 BLOCK (no job created)    | PASS   |
| T4.15 | text/plain attachment routes async                      | PASS   |
| T4.16 | attachment without callback_url → REQ-4001              | PASS   |
| T4.17 | GET /v1/jobs/{job_id} returns job status               | PASS   |
| T4.18 | webhook delivered with valid HMAC signature             | PASS   |
| T4.19 | webhook payload matches WebhookPayload schema           | PASS   |
| T4.20 | webhook 5xx triggers retries with exponential backoff   | PASS   |
| T4.21 | job row retained for 24h (queryable via /v1/jobs)       | PASS   |
| T4.22 | worker cancellation leaves job recoverable              | PASS   |
| T4.23 | duplicate request_id with attachments → idempotent 202  | PASS   |

## Design Decisions (final)

- **HWPX**: zipfile + lxml (pyhwpx is Windows-only)
- **HWP 5**: surfaces REQ-4033 (no Linux-compatible parser under acceptable license)
- **Worker**: asyncio background task launched from the request handler (no Celery — Celery integration deferred to Phase 5+)
- **Limits**: PDF max 100 pages / 50 MB, max 5 attachments per request
- **Webhook HMAC canonical**: `{ts}\n{nonce}\n{METHOD}\n{PATH}\n{sha256_hex(body)}` (matches `app.security.hmac_auth`)
- **Webhook signing key**: process-wide via `Settings.webhook_signing_secret` (decoupled from per-API-key secrets so callback verification stays simple)
- **Phase 6 will add DB encryption**: Phase 4 stores `attachments_json` plaintext

## Files Created

- `app/extractors/fetcher.py` — HTTP GET + SHA-256 verifier (REQ-4040, REQ-4041)
- `app/extractors/clamav.py` — TCP INSTREAM ClamAV scan (REQ-4050; soft-fails on connection errors)
- `app/extractors/pdf.py` — pdfplumber (primary) + pypdfium2 (fallback) — text + scan-detection
- `app/extractors/docx.py` — python-docx paragraphs + table cells
- `app/extractors/hwpx.py` — zipfile + lxml on Contents/section{N}.xml
- `app/extractors/dispatcher.py` — single fan-out point by MIME type
- `app/workers/attachment_processor.py` — asyncio orchestrator (fetch → scan → extract → analyze → webhook)
- `app/workers/webhook_sender.py` — HMAC-signed POST + 5-attempt exponential backoff
- `app/workers/job_cleanup.py` — periodic 24-hour retention vacuum
- `app/api/jobs.py` — `GET /v1/jobs/{job_id}`
- `tests/fixtures/attachments/create_fixtures.py` — programmatic synthetic test files
- `tests/integration/test_phase4_extractors.py` — T4.1~T4.12
- `tests/integration/test_phase4_case_c.py` — T4.13~T4.23

## Files Modified

- `app/api/detect.py` — Case C handler (queue job + spawn worker + 202 envelope)
- `app/db/crud.py` — ExtractionJob CRUD (`create_job`, `get_job`, `update_job`, `get_job_by_request_id`, `cleanup_expired_jobs`)
- `app/main.py` — register jobs router + lifespan job-cleanup task
- `app/config.py` — `webhook_signing_secret`, fetch/post timeouts
- `pyproject.toml` — explicit `lxml` and `httpx` dependencies

## Verification Evidence

```
$ uv run ruff check app/ tests/
All checks passed!

$ uv run mypy app/
Success: no issues found in 63 source files

$ uv run pytest tests/ -q --ignore=tests/integration/test_load_smoke.py \
                       --ignore=tests/integration/test_concurrency_perf.py
235 passed, 0 failed
```

## Privacy Notes

- Attachment plaintext is **never logged**; only filename + response code surface in audit lines.
- `attachments_json` column stores per-attachment results in plaintext for the 24-hour retention window. Phase 6 will wrap this with pgcrypto AES.
- Webhook payload reaches the configured `callback_url` only — no broadcast; HMAC signature lets the receiver verify origin.

## Known Follow-ups (out of Phase 4 scope)

- Phase 5: OCR integration when `is_scan=True`
- Phase 6: pgcrypto encryption for `attachments_json`
- Celery migration if asyncio worker pressure exceeds single-process capacity
