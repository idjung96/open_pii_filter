# PII Detection & Masking API

기관 대표홈페이지 게시판용 개인정보 탐지·마스킹 REST API.  
본문 및 첨부파일(PDF/DOCX/XLSX/PPTX/텍스트/이미지)의 PII를 검사하고, 이미지는 마스킹 버전을 제공합니다.

---

## 빠른 시작

### Docker Compose (권장)

```bash
cp .env.example .env          # 환경 변수 설정 (최소: PII_ENCRYPTION_KEY, WEBHOOK_SIGNING_SECRET)
cd deploy && docker compose up --build -d
docker compose exec api alembic upgrade head
curl http://localhost:8000/readyz   # {"status":"ok","db":"ok","redis":"ok"}
```

> 상세 설치 절차 → [`docs/installation.md`](docs/installation.md)

### 로컬 개발 (uv)

```bash
# 필요: Python 3.12+, uv, PostgreSQL 16, Redis 7, ClamAV 1.3
cp .env.example .env
uv sync
python -m spacy download ko_core_news_lg
alembic upgrade head
uvicorn app.main:app --reload   # http://127.0.0.1:8000
```

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **텍스트 PII 탐지** | 주민등록번호, 운전면허, 여권, 전화번호, 이메일, 계좌번호 등 |
| **첨부파일 분석** | PDF, DOCX, XLSX, PPTX, 텍스트(.txt/.md), 이미지 (비동기 처리 + 웹훅) |
| **이미지 OCR** | vLLM Qwen3.5-27B-GPTQ-Int4 (기본) / PaddleOCR (에어갭 대안) |
| **HMAC 인증** | API 키 + HMAC-SHA256 서명 + ±5분 타임스탬프 창 |
| **감사 로그** | append-only (DB 트리거), 1년 보존 |
| **AES-256-GCM** | 키 로테이션 지원, 버전 envelope |
| **신뢰 영역 분리** | 외부(:443) / 관리자(:8443) nginx 격리 |
| **Prometheus 메트릭** | `GET /v1/admin/metrics` |

---

## API 개요

단일 엔드포인트 `POST /v1/detect/post`에서 모든 경우를 처리합니다.

```
본문 BLOCK          → HTTP 200  (Case A, 즉시 반환)
본문 PASS           → HTTP 200  (Case B, 첨부 없을 때)
첨부파일 포함       → HTTP 202  (Case C, 비동기 + 웹훅)
```

> 연동 방법 상세 → [`docs/api_integration.md`](docs/api_integration.md)

---

## 요청 처리 흐름

`POST /v1/detect/post` 호출 시 다음 순서로 처리됩니다.

### 1. 미들웨어 체인 (모든 요청 공통)

| # | 단계 | 위치 | 거절 시 응답 |
|---|------|------|--------------|
| 1 | Nginx 라우팅 (외부:443 / 관리자:8443 분리) | `deploy/nginx.conf` | — |
| 2 | 요청 본문 크기 제한 (1 MiB) | `BodySizeLimitMiddleware` | `REQ-4030` (413) |
| 3 | 감사 로그 기록 시작 (요청 본문 SHA-256) | `AuditMiddleware` | — (logging only) |

### 2. 인증 / 인가 (`require_auth` dependency)

| # | 단계 | 위치 | 거절 시 응답 |
|---|------|------|--------------|
| 4 | HMAC 헤더 부재 시: `api_ip_callers` 캐시로 IP 기반 인증 fallback | `app/security/auth.py` | — |
| 5 | HMAC 헤더 검증 (`X-Api-Key`/`X-Timestamp`/`X-Nonce`/`X-Signature`) | `verify_request()` | `REQ-4010~4014` |
| 6 | timestamp ±5분 / nonce 중복 검사 | `hmac_auth.py` | `REQ-4012/4013` |
| 7 | API 키 active 확인 + IP allowlist (per-key + global) | `enforce_ip()` | `REQ-4015` (403) |
| 8 | Rate limit (per-caller minute/hour) | `RateLimiter` | `REQ-4020` (429) |

### 3. 핸들러 진입 (`detect_post`)

| # | 단계 | 거절/분기 시 응답 |
|---|------|-------------------|
| 9 | 멱등성 체크 (`request_id` 24h 캐시 — 중복 → 캐시 응답 반환) | `REQ-4005` (in-progress) |
| 10 | 요청 스키마 검증 (pydantic) | `REQ-4001~4004` |
| 11 | 본문 길이 검증 (`title` ≤ 500, `body` ≤ 50,000) | `REQ-4030` |
| 12 | 첨부 사전 검증 (`callback_url` 필수 / 개수 ≤ 5 / 크기 ≤ **20 MiB** / 지원 MIME) | `REQ-4031~4033` |
| 13 | **첨부 deny list (DB)** — 압축·HWP/HWPX·legacy OLE Office 등을 확장자/MIME 으로 거절. 예외 IP 작성자는 우회. | `REQ-4035` (415) |
| — | `attachment_scan_enabled` 전역 토글이 OFF 면 첨부 처리 자체를 skip 하고 본문 결과만 즉시 반환 (Case B 처럼) | — |

### 4. 본문 PII 분석

| # | 단계 | 동작 |
|---|------|------|
| 14 | 작성자 IP 가 `exception_ips` 매칭 | 분석은 진행하되 응답은 PASS 강제 (audit-only) |
| 15 | Presidio AnalyzerEngine 호출 (커스텀 KR 7개 + 내장 6개) | `RecognizerResult[]` |
| 16 | NER overlap 정리 + top-3 per span 필터 | `_filter_ner_overlap`, `_topk_per_span` |
| 17 | strictness 임계값 (low 0.65 / medium 0.78 / high 0.88) → PASS / BLOCK | `score_to_band()` |
| 18 | DB 정책 override (`pii_policies`) — 패턴별 강등/승급 | `policy_engine.py` |
| 19 | 최종 verdict 산출 (BLOCK 1건이라도 → 전체 BLOCK) | `_decide_body_code()` |

### 5. 응답 분기

```
본문 BLOCK              → Case A: HTTP 200 + verdict=BLOCK + 첨부 처리 skip
본문 PASS, 첨부 없음    → Case B: HTTP 200 + verdict=PASS
본문 PASS, 첨부 있음    → Case C: HTTP 202 + ACK-3001 + job_id
                                    └── 백그라운드 워커 spawn (fire-and-forget)
```

### 6. 백그라운드 워커 (Case C 만, `attachment_processor.py`)

각 첨부파일을 순차 처리:

```
fetch_url 다운로드 (httpx, 30s timeout)
        ↓
SHA-256 무결성 검증 (요청 본문의 sha256 과 비교)
        ↓
ClamAV 악성코드 스캔 (clamd TCP)
        ↓
MIME별 추출기 분기 (extractors/dispatcher.py)
  ├─ PDF        → pypdfium2 + pdfplumber, 스캔이면 vLLM OCR
  ├─ DOCX       → python-docx
  ├─ XLSX       → openpyxl (모든 시트의 셀 텍스트)
  ├─ PPTX       → python-pptx (슬라이드 + 발표자 노트)
  ├─ 텍스트     → text/plain 또는 text/markdown 디코드
  ├─ HWP/HWPX   → 예외 IP 우회 분기에서만 도달 (일반 IP 는 단계 13 에서 차단)
  └─ Image      → vLLM Qwen3.5-27B-GPTQ-Int4 OCR
        ↓
추출 텍스트 → 본문과 동일한 AnalyzerEngine 으로 PII 분석
        ↓
per-attachment verdict 결정 (BLOCK 1건이라도 → 전체 BLOCK)
        ↓
extraction_jobs 테이블 status=completed 갱신
```

### 7. 웹훅 콜백 (Case C 결과 전달)

| # | 단계 | 동작 |
|---|------|------|
| 20 | `callback_url` 로 HMAC 서명된 POST | `webhook_signing_secret` |
| 21 | 5xx / timeout 시 지수 백오프 재시도 | 5회 (1s/4s/16s/64s/256s) |
| 22 | DB 에 결과 저장 (24h TTL) — `GET /v1/jobs/{job_id}` 로 조회 가능 | `extraction_jobs` |

### 8. 응답 후 감사 처리

| # | 단계 | 위치 |
|---|------|------|
| 23 | `AuditMiddleware` 가 응답 status / response_code / 탐지 entity_type 등을 `audit_events` 에 fire-and-forget INSERT | `audit_middleware.py` |
| 24 | (system_settings.audit_detail_enabled=true 이면) 요청/응답 본문 16 KiB + 헤더(민감 헤더 마스킹) 함께 저장 | 운영 시 OFF 권장 |
| 25 | Prometheus 카운터/히스토그램 갱신 | `metrics_collector.py` |

---

## 첨부파일 정책 (Phase 4b)

### 한도

- 첨부 1건당 최대 **20 MiB** (`MAX_ATTACHMENT_BYTES`)
- 한 요청당 최대 **5개**

### 차단 (deny list — DB 기반, 운영 중 변경 가능)

`pii.attachment_blocklist` 테이블이 거절 대상을 보관합니다. 마이그레이션이
다음 기본 항목을 시드합니다 — 운영자는 admin API 로 가감 가능합니다.

| 분류 | 항목 |
|------|------|
| 압축 | `zip, rar, 7z, tar, gz, bz2, xz, tgz, tbz, txz, lz, lz4, zst, cab, arj, iso, lzma, z, ace, sit, dmg, alz, egg` |
| HWP/HWPX | 모든 한글 파일 (Linux 런타임에서 안전한 추출 어려움) |
| Legacy OLE Office | `doc, xls, ppt` — MIT/BSD 라이선스 추출기 부재 (xlsx/pptx 만 지원) |

거절은 `REQ-4035 ATTACHMENT_BLOCKED_FORMAT` (HTTP 415) 으로 응답합니다.
`exception_ips` 에 등록된 작성자는 deny list 를 우회합니다.

### 운영 인터페이스

```
GET    /v1/admin/attachment-blocklist          # 현재 deny list 조회
POST   /v1/admin/attachment-blocklist          # 항목 추가 — body: {extension, mime_type, reason}
DELETE /v1/admin/attachment-blocklist/{row_id} # 항목 제거
```

3개 엔드포인트 모두 `require_admin` (HMAC + is_admin + admin_ip_allowlist)
3중 게이트로 보호되며, 매 변경마다 in-process 캐시가 즉시 갱신됩니다.

### 예외 IP audit-only

`pii.exception_ips` 에 등록된 작성자의 게시글은 본문/첨부 모두 분석을
**진행하되 응답은 항상 PASS** 로 강제합니다. 감사 행에는 실제 검출된
entity_type 가 그대로 기록되어 운영자 가시성을 유지하며, deny list
(HWP/HWPX/압축 등) 도 우회합니다.

### 첨부 BLOCK 시 게시글 자동 삭제

첨부 처리 결과가 BLOCK (BLOCK-2010 / BLOCK-2011 / BLOCK-2012 / BLOCK-2008
등) 인 경우, pii_filter 가 같은 `callback_url` 로 **HMAC-서명된 DELETE**
요청을 추가로 보냅니다. 게시판 시스템은 이 요청을 받아 해당 게시글을
삭제해야 합니다.

- **트리거**: 비동기 첨부 처리(Case C) 의 최종 verdict 가 BLOCK 일 때만.
- **본문 BLOCK (Case A)**: 동기 응답으로 verdict=BLOCK 이 즉시 반환되며,
  서비스가 그 응답을 보고 자체적으로 게시글을 삭제하므로 DELETE 호출은
  보내지 않습니다.
- **예외 IP audit-only**: 결과가 PASS 로 강제 전환되므로 DELETE 호출
  없음.
- **HMAC**: 기존 webhook POST 와 동일한 `webhook_signing_secret` + 동일한
  canonical string (`X-Timestamp`/`X-Nonce`/`X-Signature`).
- **본문 (request body)**: `{request_id, job_id, code, reason}` JSON.
- **재시도**: 5회 (1s/4s/16s/64s/256s, 5xx + timeout). 모든 시도와 응답이
  `request_id`/`job_id` correlation 과 함께 INFO+ 로 로깅되어 외부 서비스
  실패 추적이 쉽습니다.

### 검출 PII 안내

본문/첨부 결과가 BLOCK 인 경우 응답의 `user_message` 끝에 한국어 라벨
요약이 붙습니다 (예: `… 게시할 수 없습니다. (검출된 항목: 주민등록번호,
전화번호)`). entity_type 코드(KR_RRN 등) 는 절대 노출되지 않으며,
`app/api/responses.py` 의 `user_message_safety_violations` 가 매 응답
빌드 시점에 §2.5 금지 토큰을 다시 차단합니다.

### 전역 kill switch

`system_settings.attachment_scan_enabled` (관리자 대시보드에서 토글)
를 OFF 로 두면 첨부가 있어도 다운로드/추출/분석 모두 skip 하고 본문 결과만
즉시 반환합니다. ClamAV 같은 외부 의존이 장애 중일 때 운영 부담을 즉시
줄이는 용도입니다.

---

## 문서 목록

| 문서 | 대상 | 내용 |
|------|------|------|
| [`docs/installation.md`](docs/installation.md) | 관리자 | Docker/수동 설치, 환경 변수, DB 초기화, API 키 발급 |
| [`docs/system_architecture.md`](docs/system_architecture.md) | 관리자/개발자 | 전체 구성도, 요청 흐름, 컴포넌트 역할 |
| [`docs/api_integration.md`](docs/api_integration.md) | 외부 개발자 | HMAC 서명, 요청/응답 스키마, 에러 코드, 언어별 예시 |
| [`docs/operations.md`](docs/operations.md) | 관리자 | 배포, 장애 대응 런북, 키 로테이션, 모니터링 |
| [`docs/data_flow.md`](docs/data_flow.md) | 감사/관리자 | ISMS-P 데이터 흐름, 암호화, 파기 절차 |
| [`docs/privacy_notice.md`](docs/privacy_notice.md) | 법무 | 개인정보처리방침 템플릿 |

---

## 개발 명령

```bash
uv sync                          # 의존성 설치
ruff check .                     # 린트
mypy app/                        # 타입 검사 (strict)
bandit -r app/                   # 보안 스캔
pytest tests/                    # 전체 테스트
pytest tests/unit/               # 단위 테스트
pytest tests/integration/        # 통합 테스트
uvicorn app.main:app --reload    # 개발 서버
alembic upgrade head             # DB 마이그레이션
python -m app.cli apikey issue --name "test"    # API 키 발급
```

---

## 프로젝트 구조

```
app/
├── api/           # FastAPI 라우터 (detect, jobs, feedback, health, metrics, dashboard, legal, responses, schemas, admin_audit, admin_stats)
├── core/          # PII 엔진 (analyzer, recognizers, codes, policies, policy_engine, system_settings, *_cache)
├── extractors/    # 파일 추출 (pdf, docx, hwpx, ocr, ocr_vlm, ocr_paddle, dispatcher, fetcher, clamav)
├── workers/       # 백그라운드 워커 (attachment_processor, webhook_sender, job_cleanup, audit_cleanup, feedback_alerter, nonce_vacuum)
├── db/            # ORM 모델, CRUD, Alembic 마이그레이션
├── security/      # HMAC, rate limit, 암호화, 감사 미들웨어, 메트릭
├── cli/           # `python -m app.cli` (apikey 관리)
└── config.py      # pydantic-settings 기반 환경 변수
tests/
├── unit/          # 단위 테스트 (analyzer, codes, policies, encryption, …)
├── integration/   # Phase 1~8 통합 테스트 (HMAC, rate limit, OCR, 감사로그, 메트릭 등)
├── fixtures/      # 합성 PII 데이터 생성기 (실제 PII 사용 금지)
└── load/          # Locust 부하 테스트 + ASGI smoke
deploy/
├── Dockerfile     # multi-stage, non-root appuser
├── docker-compose.yml
├── nginx.conf
└── prometheus_alerts.yml
docs/              # 설치·운영·연동·아키텍처 문서
```

---

## 기술 스택

- **Runtime**: Python 3.12, FastAPI, uvicorn
- **DB**: PostgreSQL 16 + asyncpg + SQLAlchemy 2.x + Alembic
- **Cache**: Redis 7 (GCRA rate limiting, nonce dedup, idempotency)
- **PII 엔진**: Microsoft Presidio (analyzer) + spaCy `ko_core_news_lg` (토크나이저)
- **OCR**: vLLM Qwen3.5-27B-GPTQ-Int4 (기본, OpenAI-호환 chat completions) / PaddleOCR (대안)
- **이미지**: Pillow (이미지 처리), pypdfium2 (스캔 PDF 렌더링)
- **보안**: HMAC-SHA256, AES-256-GCM, ClamAV, append-only 감사로그
- **관측성**: prometheus-client, structlog, PIIScrubFilter

---

## 개발 Phase 완료 현황

| Phase | 내용 | 태그 |
|-------|------|------|
| 0 | FastAPI 스캐폴딩 + CI | `phase-0-complete` |
| 1 | KR Presidio 인식기 + `/v1/detect/post` + 멱등성 | `phase-1-complete` |
| 2 | SQLAlchemy + Alembic + deny_list + 정책 인프라 (Phase 9E 에서 패턴 인프라 폐기) | `phase-2-complete` |
| 3 | HMAC 인증 + Redis rate limit + IP allowlist + Nginx | `phase-3-complete` |
| 4 | 첨부파일 추출 + Case C 비동기 + 웹훅 | `phase-4-complete` |
| 5 | VLM OCR (이미지/스캔 PDF 텍스트 추출) | `phase-5-complete` |
| 6 | AES-256-GCM + append-only 감사로그 + 신뢰 영역 분리 | `phase-6-complete` |
| 7 | DB 정책 엔진 + 섀도 모드 + 피드백 + SMTP 알림 | `phase-7-complete` |
| 8 | Prometheus + 헬스체크 + Docker + 부하 테스트 + 운영 문서 | `phase-8-complete` |

---

## 개발 방식 (Pair Programming with Claude Code)

본 프로젝트는 [**Claude Code**](https://claude.com/claude-code) (Anthropic 의 공식 CLI) 와의 **페어 프로그래밍**으로 개발되고 있습니다.

- 사람(설계·검토·의사결정) ↔ Claude Code(코드 작성·테스트·문서화) 가 한 쌍으로 작업합니다.
- 모든 코드 변경은 사람의 리뷰·승인을 거쳐 커밋되며, AI 가 작성한 변경에는 커밋 메시지에 `Co-Authored-By: Claude …` 트레일러를 남겨 추적 가능성을 확보합니다.
- 요구사항 정의·아키텍처 결정·민감한 보안/개인정보 영역(키 관리, 감사로그 정책 등)은 사람이 최종 결정합니다.

---

## 라이선스

본 프로젝트는 **GNU General Public License v3.0 or later (GPL-3.0-or-later)** 로 배포됩니다.
전체 본문은 저장소 루트의 `LICENSE` 파일을 참고하세요.

### 별도 라이선스 자산

| 자산 | 라이선스 | 비고 |
|------|----------|------|
| `ko_core_news_lg` (spaCy 한국어 모델) | CC BY-SA 4.0 | 저장소에 포함되지 않음. 런타임에 `python -m spacy download ko_core_news_lg` 로 별도 설치. CC BY-SA 4.0 → GPL v3 단방향 호환. |

### 주요 의존성 라이선스 요약

| 라이선스 | 패키지 |
|----------|--------|
| MIT | fastapi, pydantic, sqlalchemy, alembic, redis-py, presidio-analyzer, spaCy, pdfplumber, python-docx, typer, locust, pytest, ruff, mypy |
| BSD-2/3-Clause | uvicorn, jinja2, lxml, httpx, starlette, nginx |
| Apache-2.0 | asyncpg, prometheus-client, bandit, pip-audit, pytest-asyncio, pypdfium2, paddleocr/paddlepaddle (선택) |
| MIT-CMU | pillow |
| LGPL with exceptions | psycopg2-binary, clamd (동적 링크 — GPL v3 호환) |
| PostgreSQL License | PostgreSQL (BSD 유사) |

### 의존성 정책

외부 노출 API 의 강한 copyleft 전파 위험을 피하기 위해 **AGPL / SSPL 라이선스 라이브러리 직접 의존은 금지**합니다. 대표 차단 항목: PyMuPDF (AGPL-3.0), pyhwp (AGPL-3.0). MongoDB / Redis 서버 자체가 SSPL 인 점은 외부 데몬으로 사용하는 한 무관합니다.
