# Phase 6 Completion Report — Privacy Compliance + Audit Log + Column Encryption

> **Phase 9D (2026-05) 변경 알림**
> 본 보고서가 기술하는 마스킹/익명화 파이프라인은 Phase 9D 에서 폐기됐습니다.
> 마스킹 결과 응답(`masked`/`masked_url`), `MaskedArtifact` 테이블, `/v1/masked-artifacts/{token}` 엔드포인트, WARN 등급은 더 이상 동작하지 않습니다.
> 현재 동작은 PASS/BLOCK 2단계이며 PII 탐지 시 게시가 거부됩니다. 자세한 내용은 `docs/api_integration.md` 참고.

## Scope

Phase 6 closes the privacy / compliance loop:

- 컬럼 단위 AES-256-GCM 암호화 헬퍼 (`app/security/encryption.py`)
- 로그 PII 자동 스크럽 필터 (`app/security/log_filter.py`)
- 부재 외부 키 로테이션 그레이스 기간 (`pii_encryption_old_keys`)
- append-only 감사로그 테이블 + Postgres 트리거 (`pii.audit_events`)
- 1년 TTL GC 워커 (`app/workers/audit_cleanup.py`)
- 외부/내부 신뢰 영역 분리 + 사내망 전용 admin 조회 API (`/v1/admin/audit-events`)
- ISMS-P 대비 산출물 (`docs/privacy_notice.md`, `docs/data_flow.md`)

## Tasks Implemented

| Task | Description | Status | Test |
|------|-------------|--------|------|
| T6.1 | 모든 로그 출력에서 평문 PII 자동 스크럽 | Done | `tests/integration/test_phase6_logs_no_pii.py` (11 tests, success/validation/exception paths) |
| T6.2 | AES-256-GCM 컬럼 암호화 round-trip + 변조/키 mismatch 거부 | Done | `tests/unit/test_encryption.py` (10 tests) |
| T6.3 | audit_events / extraction_jobs TTL 기반 자동 파기 | Done | `tests/integration/test_phase6_ttl.py` |
| T6.4 | 모든 인증 요청에 대한 audit row 자동 기록 | Done | `tests/integration/test_phase6_audit.py::test_t6_4_detect_request_records_audit_row` |
| T6.5 | audit_events UPDATE/DELETE는 append-only 트리거로 차단 | Done | `tests/integration/test_phase6_audit.py::test_t6_5_audit_log_is_append_only` |
| T6.5b | cleanup 워커는 `app.bypass_audit_lock` 세션 변수로 DELETE 가능 | Done | `tests/integration/test_phase6_audit.py::test_t6_5b_cleanup_can_delete` |
| T6.6 | 응답 envelope에 평문 PII가 절대 포함되지 않음 | Done | `tests/integration/test_phase6_response_no_plaintext.py` (3 tests) |
| T6.4-extra | 사내망 전용 admin 조회 API + is_admin/IP 게이트 + 페이지네이션 | Done | `tests/integration/test_phase6_audit.py::test_admin_endpoint_*` (5 tests) |

전체 Phase 6 신규 테스트: **27 passed**, 회귀 포함 **197 passed** (Phase 5 OCR 테스트 제외).

## Architecture Decisions

### Q1 — 애플리케이션 레이어 AES-256-GCM (pgcrypto 미사용)

키와 암호문이 동일 DB에 공존하면 DBA가 양쪽을 모두 읽을 수 있어 컴플라이언스 측면에서 의미가 약해집니다. 따라서 본 Phase는 **pgcrypto를 사용하지 않고** 애플리케이션에서 직접 AES-256-GCM을 적용합니다.

- 라이브러리: `cryptography>=42` (pyca/cryptography). 이미 `uv.lock`에 포함됨.
- envelope 포맷: `b"v" + key_id(1B) + nonce(12B) + ciphertext + tag(16B)` → base64 → varchar/text 컬럼.
- 키 저장: `Settings.pii_encryption_key` (32-byte hex 환경변수). DB에 저장하지 않음.

### Q2 — TTL GC = lifespan 백그라운드 태스크

기존 `nonce_vacuum`, `job_cleanup`, `artifact_cleanup` 패턴과 동일하게 `app/workers/audit_cleanup.py`에 1시간 주기 asyncio 루프를 추가했습니다. Celery beat / cron 의존을 추가하지 않습니다.

- 검출 결과 보존: 30일 (`Settings.detection_retention_days`)
- 감사로그 보존: 365일 (`Settings.audit_log_retention_days`)

### Q3 — append-only는 Postgres 트리거로 강제

```sql
CREATE OR REPLACE FUNCTION pii.reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    IF coalesce(current_setting('app.bypass_audit_lock', true), '') = 'on' THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    RAISE EXCEPTION 'audit_events is append-only ...';
END;
$$ LANGUAGE plpgsql;
```

cleanup 워커는 동일 트랜잭션 내에서 `SET LOCAL app.bypass_audit_lock = 'on'`을 실행해 트리거를 우회합니다. SUPERUSER가 필요 없으므로 운영 DB 사용자 권한을 확장하지 않아도 됩니다.

### Q4 — 외부 신뢰 영역 vs 내부 신뢰 영역 (운영 클라리피케이션 반영)

- `Settings.admin_ip_allowlist`가 비어 있으면 `app.main`이 admin 라우터를 **마운트하지 않음** → 외부 스캐너에는 404. (테스트: `test_admin_endpoint_not_mounted_when_allowlist_empty`)
- 비어 있지 않으면 `/v1/admin/audit-events` 공개. 단, 모든 요청은 다음을 모두 통과해야 함:
  1. `require_auth` (HMAC + IP allowlist + rate limit)
  2. `caller.is_admin == True`
  3. 요청 IP가 `Settings.admin_ip_allowlist` CIDR 매칭
- 실패 시 모두 `REQ-4015` (HTTP 403) 동일 응답으로 변별 불가.

`api_keys.is_admin` 컬럼을 동일 마이그레이션에서 추가했고 CLI에 `--admin` 플래그를 노출했습니다.

```sh
python -m app.cli apikey issue --admin --name "ops-team" --ip-allowlist 10.0.0.0/8
```

---

## 검증 (Existing model PII safety) — (a)~(d)

운영 모델에 평문 PII가 저장되는 경로가 없음을 다음과 같이 확인합니다.

### (a) `ExtractionJob.attachments_json`

`app/workers/attachment_processor.py:462-463`에서 `json.dumps([r.model_dump(mode="json") for r in attachment_results])`로 직렬화됩니다. `WebhookAttachmentResult` 스키마 (`app/api/schemas.py:131-141`)는 다음 필드만 노출합니다:

```python
class WebhookAttachmentResult(BaseModel):
    attachment_id: str
    filename: str
    verdict: Verdict
    code: str
    detections: list[Detection] = Field(default_factory=list)
    masked_url: str | None = None
```

`Detection` 스키마 (`app/api/schemas.py:76-86`)는 `field, entity_type, code, score, start, end, masked_preview`만 갖고 있고 **원문 텍스트(`text`) 필드가 존재하지 않습니다**. `masked_preview`는 마스킹된 표시용 문자열로, 검출된 원문 PII 자체를 다시 담지 않습니다 (`tests/integration/test_phase6_response_no_plaintext.py::test_response_has_no_plaintext_pii`에서 RRN/전화/이메일이 envelope 어디에도 등장하지 않음을 검증).

샘플 row 형태(필드 구조만 표시):
```json
{
  "attachment_id": "att_001",
  "filename": "report.pdf",
  "verdict": "WARN",
  "code": "WARN-1001",
  "detections": [
    {"field": "attachment.att_001", "entity_type": "KR_PHONE", "code": "WARN-1001", "score": 0.85, "start": 12, "end": 25}
  ],
  "masked_url": "/v1/masked-artifacts/<token>"
}
```

→ 평문 PII 미저장. **추가 암호화 불필요.**

### (b) `IdempotencyCache`

`app/security/idempotency.py`의 in-memory 캐시는 `_Entry.response: DetectPostResponse | None`을 저장합니다. `DetectPostResponse` (`app/api/schemas.py:110-128`)의 `detections` 필드 역시 위 (a)와 동일한 `Detection` 스키마이므로 **평문 PII가 캐시에 들어가지 않습니다.** TTL 24시간 후 자동 evict.

### (c) `developer_message` 템플릿

`app/api/responses.py:42-46`에서 `developer_message`는 `verdict is Verdict.ERROR`인 경우에만 렌더링됩니다. 모든 템플릿은 `app/core/codes.py`에 코드로 박혀 있는 고정 문자열이며, placeholder는 `{fields}`, `{field}`, `{detail}`, `{ip}`, `{mime_type}`, `{filename}`, `{status}` 등 **운영 메타데이터**에 한정됩니다. 사용자 본문(post.body / post.title)에서 가져온 텍스트는 어떠한 placeholder에도 매핑되지 않습니다.

검증: `app/core/codes.py`의 모든 `developer_message_template` 값이 정적 문자열임을 grep으로 확인 (`tests/integration/test_phase6_response_no_plaintext.py::test_user_message_safe_substrings`에서 user_message 안전성도 확인).

### (d) `masked_url`은 토큰 URL

`MaskedArtifact.token`은 `secrets.token_urlsafe(32)`로 생성된 추측 불가능한 토큰이고, `/v1/masked-artifacts/{token}`은 **마스킹된** 산출물(평문 PII가 검정 사각형으로 가려진 이미지)을 서비스합니다. 24시간 후 disk + DB row 모두 GC. `app/api/masked_artifacts.py`의 응답 본문에 평문 PII는 포함되지 않습니다 (이미 Phase 5에서 검증됨).

→ **(a)~(d) 모두 평문 PII 미저장. 컬럼 암호화 즉시 적용 대상 없음.** `app.security.encryption`은 향후 신규 컬럼 추가 시 즉시 적용 가능하도록 선제 도입했습니다.

---

## Files Modified / Created

### Created

- `app/security/encryption.py` — AES-256-GCM 봉투 암호화
- `app/security/log_filter.py` — 로그 PII 자동 스크럽
- `app/security/audit.py` — middleware → DB 헬퍼
- `app/security/audit_middleware.py` — 요청별 audit row 기록
- `app/api/admin_audit.py` — `/v1/admin/audit-events` 라우터
- `app/workers/audit_cleanup.py` — 365일 TTL GC 루프
- `app/db/migrations/versions/8e1f5d2a9c30_phase_6a_audit_events.py` — `pii.audit_events` + `api_keys.is_admin` + append-only 트리거
- `tests/unit/test_encryption.py`
- `tests/integration/test_phase6_logs_no_pii.py`
- `tests/integration/test_phase6_audit.py`
- `tests/integration/test_phase6_ttl.py`
- `tests/integration/test_phase6_response_no_plaintext.py`
- `docs/privacy_notice.md`
- `docs/data_flow.md`

### Modified

- `app/db/models.py` — `AuditEvent` 모델 추가, `ApiKey.is_admin` 컬럼 추가
- `app/db/crud.py` — `insert_audit_event`, `cleanup_expired_audit_events`, `list_audit_events`
- `app/security/api_key.py` — `issue_api_key(is_admin=...)` 인자 추가
- `app/security/hmac_auth.py` — `AuthedCaller.is_admin` 필드 추가
- `app/cli/apikey.py` — `apikey issue --admin` 플래그
- `app/config.py` — Phase 6 settings (`pii_encryption_key`, `*_retention_days`, `admin_ip_allowlist` 등)
- `app/main.py` — log filter install, AuditMiddleware, audit_cleanup 워커, 조건부 admin 라우터 마운트
- `app/api/detect.py` — `request.state.audit_payload` 채우기

---

## Operations

### 1. Encryption Key Storage

- **저장 위치**: 환경변수 `PII_ENCRYPTION_KEY`만 사용. `.env` 커밋 금지.
- **운영 권장**: 사내 KMS / sealed-secrets / HashiCorp Vault 등 시크릿 매니저로 주입.
- **백업**: 키를 분실하면 암호문 복호화가 불가능합니다. 운영팀 두 명 이상이 별도 보관.

### 2. Key Rotation

분기별 또는 키 노출 의심 시:

1. 새 32B hex 키 생성 → `PII_ENCRYPTION_KEY` 갱신
2. `PII_ENCRYPTION_KEY_ID` 1 증가
3. 이전 키를 `PII_ENCRYPTION_OLD_KEYS='{"1":"<old_hex>"}'` 형태로 환경변수 추가 (그레이스 기간)
4. 재시작 → 신규 암호화는 새 키로, 기존 암호문은 envelope의 `key_id` 바이트 매칭으로 자동 fallback
5. 그레이스 기간 종료(예: 90일) 후 `PII_ENCRYPTION_OLD_KEYS`에서 해당 키 제거

→ 코드 레벨에서는 `app.security.encryption._cipher_for(kid)`가 처리. 테스트: `tests/unit/test_encryption.py::test_old_keys_decrypt_after_rotation`.

### 3. Admin API 운영

- `python -m app.cli apikey issue --admin --name "ops-team" --ip-allowlist 10.0.0.0/8` 으로 admin 키 발급
- 발급된 secret은 즉시 사내 시크릿 매니저에 저장 (재발급 불가)
- `Settings.admin_ip_allowlist`는 사내망 CIDR로 제한 (예: `10.0.0.0/8,192.168.0.0/16`)
- nginx 레이어에서도 `/v1/admin/*` location을 별도 listen으로 분리 권장 (`docs/data_flow.md` § 1)

### 4. Audit Log 조회

```bash
curl -H "X-API-Key: ..." -H "X-Timestamp: ..." -H "X-Nonce: ..." -H "X-Signature: ..." \
  'https://admin.example.internal:8443/v1/admin/audit-events?since=2026-04-01T00:00:00Z&limit=100'
```

응답에는 평문 PII가 절대 포함되지 않습니다. body의 SHA-256 hash로만 정합성을 검증할 수 있습니다.

---

## Quality Gates

```text
$ uv run ruff check app/ tests/ --fix
All checks passed!

$ uv run mypy app/
Success: no issues found in 77 source files

$ uv run pytest tests/ --ignore=tests/integration/test_load_smoke.py \
    --ignore=tests/integration/test_concurrency_perf.py \
    --ignore=tests/integration/test_phase5_ocr.py \
    --ignore=tests/integration/test_phase5_masked_url.py \
    --ignore=tests/integration/test_phase5_scan_pdf.py
197 passed, 2 warnings in 19.49s
```

Phase 5 OCR 테스트는 외부 vLLM 엔드포인트에 의존하므로 회귀 루프에서 제외됩니다. 별도 nightly job에서 실행.
