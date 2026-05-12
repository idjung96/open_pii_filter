# 데이터 흐름도 (Data Flow)

> Phase 6 산출물 — ISMS-P 심사·내부감사 대비. 본 문서는 PII 탐지·마스킹 API의 입력→처리→저장→파기 전 단계 데이터 흐름을 기록합니다.

---

## 1. 신뢰 영역 분리 (Trust Zones)

본 API는 **외부 신뢰 영역**과 **내부 신뢰 영역**을 명확히 분리합니다. 운영 시 두 영역은 서로 다른 listen 포트 또는 nginx location 블록으로 격리해야 합니다.

| 영역 | 노출 위치 | 엔드포인트 | 인증 |
|------|----------|-----------|------|
| **외부 신뢰 영역 (Public)** | 인터넷 / 게시판 서비스 | `POST /v1/detect/post`<br>`GET /v1/jobs/{id}`<br>`GET /healthz`, `GET /v1/healthz` | HMAC API 키 (`is_admin = false`) |
| **내부 신뢰 영역 (Admin)** | 사내망 / VPN | `GET /v1/admin/audit-events` | HMAC API 키 (`is_admin = true`) + `Settings.admin_ip_allowlist` IP 매칭 |

`Settings.admin_ip_allowlist`가 비어 있으면 `app.main`이 admin 라우터를 **마운트하지 않으며**, 외부 스캐너에는 404로만 응답합니다(노출 표면 최소화).

### 권장 nginx 구성 예시 (`deploy/nginx.conf`)

```nginx
# 외부 신뢰 영역 — 일반 트래픽
server {
    listen 443 ssl;
    server_name api.example.com;

    # 운영 본문에서 admin 경로는 명시적으로 차단.
    location /v1/admin/ {
        return 404;
    }
    location / {
        proxy_pass http://pii_api_upstream;
    }
}

# 내부 신뢰 영역 — 사내망 전용 listen
server {
    listen 8443 ssl;
    server_name admin.example.internal;

    # 사내 IP만 허용.
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;

    location /v1/admin/ {
        proxy_pass http://pii_api_upstream;
    }
}
```

> 두 listen이 동일한 FastAPI 프로세스를 가리키더라도 **네트워크 레이어에서 1차 차단**이 이뤄지므로, 애플리케이션 레이어의 `is_admin` + IP 화이트리스트 검사는 2차 방어선으로 작동합니다.

---

## 2. 요청 처리 흐름 (Case A / B / C)

```
┌──────────┐       ┌─────────────────────┐
│  client  │──HTTPS│  Nginx (TLS, ACL)   │
└──────────┘       └─────────┬───────────┘
                             ▼
                  ┌──────────────────────────┐
                  │ BodySizeLimitMiddleware   │  REQ-4030 if > 1 MB
                  └──────────┬────────────────┘
                             ▼
                  ┌──────────────────────────┐
                  │ AuditMiddleware (Phase 6) │  body hash, timer start
                  └──────────┬────────────────┘
                             ▼
              ┌───────────────────────────────────┐
              │ require_auth (HMAC + IP + RL)     │  REQ-4010~4015 / 4020
              └──────────────┬────────────────────┘
                             ▼
                  ┌──────────────────────────┐
                  │  detect_post handler      │
                  └──────────┬────────────────┘
                             ▼
                  ┌──────────────────────────┐
                  │ Presidio + spaCy + DB     │
                  │   patterns + deny list    │
                  └──────────┬────────────────┘
                             ▼
                ┌──────────────────────────────┐
                │ verdict: PASS / BLOCK         │
                └──┬───────────┬───────────────┘
                   │           │
                BLOCK        PASS
                   │           │
        ┌──────────▼─┐    ┌────▼────────────┐
        │ Case A     │    │ has_attachments? │
        │ HTTP 200   │    └─┬───────────┬────┘
        │ (skip atts)│      │           │
        └────────────┘     no          yes
                            │           │
                  ┌─────────▼┐    ┌─────▼─────────────┐
                  │ Case B   │    │ Case C — async    │
                  │ HTTP 200 │    │ HTTP 202 ACK-3001 │
                  └──────────┘    │ + Celery / asyncio │
                                  └─────────┬──────────┘
                                            ▼
                              ┌─────────────────────────┐
                              │ webhook → callback_url   │
                              │ HMAC-signed payload      │
                              └─────────────────────────┘
```

---

## 3. 데이터 수집 지점 및 저장 위치

| 단계 | 데이터 | 저장 위치 | 보존 기간 | 암호화 |
|------|--------|----------|----------|-------|
| 요청 수신 | 본문 (`post.body`, `attachments`) | **저장하지 않음** (메모리에서 처리) | — | — |
| 인증 | `(key_id, nonce)` | `pii.api_key_nonces` | 10분 | TLS in transit |
| 감사로그 | `request_id`, `api_key_id`, `source_ip`, `path`, `body_hash` (SHA-256) | `pii.audit_events` | 1년 | TLS in transit; 민감컬럼은 hash만 저장 |
| 비동기 작업 | `job_id`, attachments 메타데이터 (start/end) | `pii.extraction_jobs` | 24시간(완료 후) | TLS |
| API 키 | `secret` | `pii.api_keys.secret` | 폐기 시까지 | 향후 `app.security.encryption` 적용 가능 |

---

## 4. 암호화 적용 지점

```
┌────────────┐  AES-256-GCM   ┌──────────────────────┐
│  plaintext │──────────────► │ b"v" + key_id +      │
│  PII text  │                │ nonce(12B) + ct + tag │
└────────────┘                │ (base64 encoded)      │
                              └──────────────────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ DB column / disk │
                                └──────────────────┘
```

- 모듈: `app.security.encryption`
- 키: `Settings.pii_encryption_key` (32B hex, 환경변수)
- 키 ID: `Settings.pii_encryption_key_id` (envelope의 1바이트로 저장 → 키 로테이션 대응)
- 구버전 키: `Settings.pii_encryption_old_keys` JSON 매핑(`{"1":"<hex>"}`)으로 그레이스 기간 보장

> **현재 Phase 6 시점**에서 암호화 헬퍼는 운영 코드에서 직접 사용되지 않으나(현재 DB 스키마에 PII 평문이 저장되는 컬럼이 없음을 확인 — `phase_6_completion.md` § 검증 참조), 향후 PII 평문 저장이 필요한 시점에 즉시 적용할 수 있도록 모듈을 선제 도입했습니다.

---

## 5. 감사로그 흐름

```
HTTP request
    │
    ▼
AuditMiddleware
    │  ① body 수신 → SHA-256 hash 계산
    │  ② request_id 추출 (best-effort)
    │  ③ caller 식별 (request.state.caller, 핸들러가 stash)
    │
    └── (응답 후) record_request() ──► insert_audit_event()
                                                │
                                                ▼
                                ┌──────────────────────────┐
                                │ pii.audit_events 테이블   │
                                │  - 평문 PII 절대 저장 X  │
                                │  - body_hash, code, types │
                                │  - BEFORE UPDATE/DELETE   │
                                │    트리거 → append-only   │
                                └──────────┬───────────────┘
                                           │
                                           ▼
                              ┌────────────────────────────┐
                              │ audit_cleanup_loop (1h)     │
                              │  SET LOCAL                  │
                              │  app.bypass_audit_lock=on   │
                              │  → 365일 이전 row DELETE    │
                              └────────────────────────────┘
```

조회는 `/v1/admin/audit-events`(내부 신뢰 영역)에서만 가능합니다. 응답에는 절대 평문 PII가 포함되지 않으며, 검출 메타데이터(start/end, entity_type, score)와 body의 SHA-256 해시만 노출합니다.

---

## 6. 외부 통신 (Outbound)

| 대상 | 용도 | 데이터 | 인증 |
|------|------|--------|------|
| `attachments[*].fetch_url` | 첨부파일 fetch | HTTP GET | TLS, 호출자 통제 |
| `callback_url` | webhook 콜백 | 탐지 결과 메타데이터 (PII 평문 X) | HMAC-SHA256 (`Settings.webhook_signing_secret`), canonical = `{ts}\n{nonce}\n{POST}\n{path}\n{body_sha256}` |
| ClamAV (`Settings.clamav_host:port`) | 악성코드 스캔 | 첨부 바이너리 (사내) | 사내 TCP |
| (선택) VLM endpoint (`Settings.vlm_endpoint`) | OCR — `OCR_ENGINE=vlm` 일 때만 호출 | 이미지 바이너리 (사내) | 사내 vLLM, API 키 옵션 |

기본 OCR 엔진은 **PaddleOCR PP-OCRv5 (CPU)** 로 in-process 동작합니다 — 외부 송출
경로 없음 (`app/extractors/ocr_paddle.py`). VLM 은 `OCR_ENGINE=vlm` 으로 전환하거나
Paddle 예외 시 자동 폴백할 때만 `Settings.vlm_endpoint` 로 호출되며, 사내 vLLM 외
외부 클라우드(OpenAI / Anthropic / Google 등)에 PII가 송출되는 경로는 존재하지 않습니다.

---

## 7. 파기 절차

| 단계 | 트리거 | 조치 |
|------|-------|------|
| 자동 만료 | `audit_cleanup_loop` (1h) | 1년 경과 audit_events DELETE |
| 자동 만료 | `job_cleanup_loop` (1h) | 24시간 경과 extraction_jobs DELETE |
| 수동 폐기 | `python -m app.cli apikey revoke <key_id>` | API 키 영구 폐기 |
| 비상 정지 | docker compose down + DB drop schema pii | 전체 데이터 즉시 삭제 |

파기 결과는 audit_events에 별도 기록되지 않습니다(GC 작업의 노이즈 방지). 수동 폐기 행위는 호출 시 별도 운영 로그에 기록됩니다.
