# PII Detection & Masking API — 시스템 구조 및 흐름

> 대상: 시스템 관리자 / 개발팀  
> 최종 수정: 2026-04-26

---

## 목차

1. [전체 시스템 구성도](#1-전체-시스템-구성도)
2. [컴포넌트 역할](#2-컴포넌트-역할)
3. [요청 처리 흐름 (Case A / B / C)](#3-요청-처리-흐름)
4. [첨부파일 비동기 처리 흐름 (Case C)](#4-첨부파일-비동기-처리-흐름)
5. [OCR 흐름](#5-ocr-흐름)
6. [인증 및 보안 레이어](#6-인증-및-보안-레이어)
7. [DB 스키마 구조](#7-db-스키마-구조)
8. [백그라운드 워커](#8-백그라운드-워커)
9. [신뢰 영역 분리 (Trust Zone)](#9-신뢰-영역-분리)
10. [데이터 생명주기](#10-데이터-생명주기)
11. [메트릭 및 알림 흐름](#11-메트릭-및-알림-흐름)

---

## 1. 전체 시스템 구성도

```
┌─────────────────────────────────────────────────────────────────────┐
│                         외부 신뢰 영역                               │
│                                                                     │
│   게시판 서비스                       웹훅 수신 서버                  │
│   (bulletin board)                   (callback_url)                │
│        │                                    ▲                      │
│        │ HTTPS + HMAC                       │ HMAC-signed POST     │
└────────┼────────────────────────────────────┼─────────────────────┘
         │                                    │
         ▼                                    │
┌─────────────────────────────────────────────────────────────────────┐
│                        Nginx (TLS 종단)                              │
│  ┌──────────────────────┐    ┌──────────────────────────────────┐  │
│  │  :443 (외부)          │    │  :8443 (내부망 전용)              │  │
│  │  /v1/admin/* → 404   │    │  /v1/admin/* → API               │  │
│  └──────────┬───────────┘    └────────────────┬─────────────────┘  │
└─────────────┼──────────────────────────────────┼───────────────────┘
              │                                  │
              ▼                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      FastAPI 애플리케이션 (port 8000)                │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     미들웨어 스택                             │   │
│  │  BodySizeLimitMiddleware → AuditMiddleware → require_auth    │   │
│  └─────────────────────────────┬───────────────────────────────┘   │
│                                │                                   │
│  ┌─────────────────────────────▼───────────────────────────────┐   │
│  │                      라우터                                   │   │
│  │  POST /v1/detect/post     GET /v1/jobs/{id}                  │   │
│  │  GET /healthz             GET /readyz                        │   │
│  │  ── 내부망 전용 ──────────────────────────────────────────   │   │
│  │  GET /v1/admin/audit-events                                  │   │
│  │  GET /v1/admin/stats/*    GET /v1/admin/metrics              │   │
│  │  POST /v1/feedback        GET /v1/legal/privacy-notice       │   │
│  └─────────────────────────────────────────────────────────────┘   │
└──────────┬───────────────────┬─────────────────┬───────────────────┘
           │                   │                 │
           ▼                   ▼                 ▼
┌──────────────┐   ┌────────────────┐   ┌───────────────────┐
│ PostgreSQL 16│   │   Redis 7      │   │   vLLM (Qwen3.5)  │
│  pii 스키마  │   │ rate limit     │   │   OCR 엔진         │
│  AES-256-GCM │   │ nonce dedup    │   │  (GPU 서버)        │
└──────────────┘   └────────────────┘   └───────────────────┘
           │
           ▼
┌──────────────┐   ┌────────────────┐
│   ClamAV     │
│  악성코드 스캔│
└──────────────┘
```

---

## 2. 컴포넌트 역할

| 컴포넌트 | 역할 |
|----------|------|
| **FastAPI** | REST API 서버. 요청 파싱, 인증, PII 분석, 응답 생성 |
| **Presidio Analyzer** | NER 기반 PII 탐지 엔진 (스코어 0.0~1.0) |
| **spaCy ko_core_news_lg** | 한국어 개체명 인식 (Presidio 내 NlpEngine) |
| **GLiNER (urchade/gliner_multi_pii-v1)** | 다국어 PII 엔티티 인식 보조 |
| **커스텀 KR 인식기** | 주민등록번호, 운전면허번호, 사업자번호, 여권번호 등 정규식 + 체크섬 |
| **PostgreSQL 16** | API 키, 감사로그, 패턴, 정책, 작업 상태, 피드백 저장 |
| **Redis 7** | GCRA 토큰 버킷 rate limiting, nonce 중복 방지 캐시 |
| **ClamAV** | 첨부파일 악성코드 스캔 (TCP INSTREAM, 소프트 실패 허용) |
| **PaddleOCR PP-OCRv5 (한국어, CPU)** | 이미지 OCR 기본 엔진 — 자체 호스팅, in-process. 외부 송출 없음 |
| **vLLM (Qwen3.5-VL)** | OCR 폴백 / 옵트인 — `OCR_ENGINE=vlm` 또는 Paddle 예외 시 자동 호출 (사내 vLLM) |
| **백그라운드 워커** | asyncio fire-and-forget: 첨부처리·감사로그GC·알림 |
| **Nginx** | TLS 종단, 신뢰 영역 분리 (외부:443 / 내부:8443) |

---

## 3. 요청 처리 흐름

모든 요청은 단일 엔드포인트 `POST /v1/detect/post`에서 처리됩니다.

```
POST /v1/detect/post
         │
         ▼
┌─────────────────────────┐
│ BodySizeLimitMiddleware  │──► > 1 MB → REQ-4030 즉시 반환
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│   AuditMiddleware        │  body SHA-256 해시, 타이머 시작
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│   require_auth()         │
│  ┌──────────────────┐   │
│  │ X-Api-Key 헤더   │   │──► 없음/불일치 → REQ-4010
│  │ X-Timestamp 헤더 │   │──► ±5분 초과 → REQ-4011
│  │ X-Signature 헤더 │   │──► HMAC 불일치 → REQ-4012
│  │ IP 화이트리스트  │   │──► 차단 IP → REQ-4015
│  │ Rate Limit (GCRA)│   │──► 초과 → REQ-4020
│  └──────────────────┘   │
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│   중복 요청 검사          │──► request_id 캐시 히트 → 원본 응답 반환
│   (Redis, 24시간)        │──► 진행 중 중복 → REQ-4005
└──────────┬──────────────┘
           ▼
┌─────────────────────────┐
│   본문 PII 분석           │
│   Presidio + spaCy       │
│   + DB 패턴 + deny-list  │
│   (섀도 모드 병렬 실행)   │
└──────────┬──────────────┘
           ▼
┌──────────────────────────────────────────────────┐
│              Verdict 결정 (Phase 9D)              │
│  (entity_type, score_band) → 정책 테이블 조회     │
│  PASS / BLOCK (WARN 등급 폐기)                    │
└──────────┬────────────────────┬──────────────────┘
           │                    │
         BLOCK                PASS
           │                    │
           ▼                    ▼
  ┌──────────────┐    ┌─────────────────┐
  │   Case A     │    │ 첨부파일 있음?   │
  │   HTTP 200   │    └──┬──────────┬───┘
  │ (첨부 스킵)  │       NO        YES
  └──────────────┘       │          │
                         ▼          ▼
                 ┌──────────┐  ┌──────────────────┐
                 │  Case B  │  │     Case C        │
                 │ HTTP 200 │  │ HTTP 202 ACK-3001 │
                 └──────────┘  │ asyncio background │
                               └──────────────────┘
```

### 응답 코드 요약

| 코드 범주 | 예시 | 의미 |
|-----------|------|------|
| `OK-0000` | 정상 처리, PII 없음 | Case B PASS |
| `BLOCK-2001~2099` | PII 확정 차단 | Case A |
| `ACK-3001` | 비동기 접수 완료 | Case C |
| `REQ-4010~4031` | 인증/요청 오류 | 클라이언트 수정 필요 |
| `SVR-5000~5004` | 서버/엔진 오류 | 운영팀 확인 필요 |

> Phase 9D 변경: WARN 등급은 신규 발생하지 않습니다. 기존 `WARN-*`
> 응답 코드 상수는 과거 audit 행과의 호환을 위해 보존됩니다.

---

## 4. 첨부파일 비동기 처리 흐름

Case C: 첨부파일이 있을 때 `HTTP 202`를 즉시 반환하고, 백그라운드에서 처리합니다.

```
HTTP 202 반환 (ACK-3001)
         │
         ▼ (asyncio fire-and-forget)
┌─────────────────────────────────────────────┐
│           attachment_processor               │
│                                             │
│  FOR each attachment:                       │
│    ┌─────────────────────────────────────┐  │
│    │ 1. fetch_url 에서 바이너리 다운로드  │  │
│    │    (timeout: 30s)                   │  │
│    └──────────────┬──────────────────────┘  │
│                   ▼                         │
│    ┌─────────────────────────────────────┐  │
│    │ 2. ClamAV INSTREAM 악성코드 스캔     │  │──► INFECTED → BLOCK-2050
│    └──────────────┬──────────────────────┘  │
│                   ▼                         │
│    ┌─────────────────────────────────────┐  │
│    │ 3. MIME 타입 판별 → 추출기 선택      │  │
│    │                                     │  │
│    │  PDF (텍스트) → pdfplumber           │  │
│    │  PDF (스캔)   → pypdfium2 → OCR     │  │
│    │  DOCX/XLSX/PPTX → python-docx /     │  │
│    │                   openpyxl / pptx    │  │
│    │  TXT/MD       → UTF-8 / CP949       │  │
│    │  이미지        → OCR 디스패처        │  │
│    │  HWP/HWPX/ZIP → deny-list 거절      │  │
│    │                  (REQ-4035)          │  │
│    └──────────────┬──────────────────────┘  │
│                   ▼                         │
│    ┌─────────────────────────────────────┐  │
│    │ 4. PII 분석 (추출된 텍스트 대상)      │  │
│    └──────────────┬──────────────────────┘  │
│                   ▼                         │
│    결과 집계 → WebhookAttachmentResult      │
│    (PII 검출 시 verdict=BLOCK 만 기록)      │
└──────────────────┬──────────────────────────┘
                   ▼
         ┌─────────────────┐
         │  callback_url   │
         │  HMAC-signed    │  ← 최대 5회 재시도
         │  POST 전송       │    (1s / 4s / 16s / 64s / 256s)
         └─────────────────┘

결과는 GET /v1/jobs/{job_id} 로도 24시간 조회 가능
```

### 지원 첨부파일 형식

| MIME 타입 | 처리 방식 |
|-----------|----------|
| `application/pdf` (텍스트 레이어) | pdfplumber 텍스트 추출 |
| `application/pdf` (스캔본) | pypdfium2 페이지 렌더 → PaddleOCR |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.document` (DOCX) | python-docx |
| `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` (XLSX) | openpyxl |
| `application/vnd.openxmlformats-officedocument.presentationml.presentation` (PPTX) | python-pptx |
| `text/plain`, `text/markdown` | UTF-8 → CP949 폴백 디코드 |
| `image/png`, `image/jpeg`, `image/tiff`, `image/bmp`, `image/webp`, `image/gif` | PaddleOCR (CPU 기본) → 실패 시 vLLM 폴백 |
| HWP / HWPX / ZIP / 레거시 OLE (`.doc`/`.xls`/`.ppt`) | `attachment_blocklist` 가 일괄 거절 (`REQ-4035`) |

> Phase 9D 변경: 마스킹된 PDF/이미지 산출물은 더 이상 생성되지 않습니다.
> 첨부파일에서 PII 가 검출되면 즉시 BLOCK 으로 거절되며, 사용자가 직접
> PII 를 제거 후 재등록해야 합니다.

---

## 5. OCR 흐름

```
이미지 바이너리 (또는 스캔 PDF 페이지)
         │
         ▼
┌─────────────────────────────────────────┐
│           OCR 디스패처 (ocr.py)          │
│                                         │
│  OCR_ENGINE=paddle (기본)               │
│    └── paddle_ocr() ──► PaddleOCR       │
│                          PP-OCRv5 (한국어, CPU) │
│                          (text + bbox 배열)    │
│                                         │
│  Paddle 예외 / OCR_ENGINE=vlm 시 폴백   │
│    └── vlm_ocr() ──► vLLM Qwen3.5-VL    │
│                      /no_think prefix    │
│                      JSON 응답 파싱      │
└────────────────┬────────────────────────┘
                 │
                 ▼ OCRResult {text, boxes[], width, height}
┌────────────────────────────────────────┐
│         PII 분석 (추출 텍스트 대상)      │
│         Presidio + KR 인식기            │
└────────────────┬───────────────────────┘
                 │
                 ▼
   검출 시 verdict=BLOCK 으로 즉시 거절
   (Phase 9D — 마스킹 산출물 생성 안 함)
```

---

## 6. 인증 및 보안 레이어

```
요청 수신
    │
    ▼
① IP 허용 목록 확인 (IP_ALLOWLIST)
    │ 차단 → REQ-4015
    ▼
② API 키 헤더 확인 (X-Api-Key)
    │ 없음 / 비활성 키 → REQ-4010
    ▼
③ 타임스탬프 유효성 검사 (X-Timestamp, ±5분)
    │ 범위 초과 → REQ-4011
    ▼
④ HMAC-SHA256 서명 검증
    │ sign(secret, timestamp + "\n" + body)
    │ 불일치 → REQ-4012
    ▼
⑤ Nonce 중복 검사 (Redis, 10분 TTL)
    │ 재전송 감지 → REQ-4013
    ▼
⑥ Rate Limiting (GCRA, Redis Lua)
    │ 분당 요청 초과 → REQ-4020
    ▼
⑦ 관리자 엔드포인트: is_admin 확인
    │ + ADMIN_IP_ALLOWLIST CIDR 매핑
    │ 미충족 → 403
    ▼
   핸들러 진입
```

### 서명 생성 방법 (클라이언트)

```python
import hashlib, hmac, datetime

def sign_request(secret: str, timestamp: str, body_bytes: bytes) -> str:
    message = timestamp.encode() + b"\n" + body_bytes
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
signature = sign_request(MY_SECRET, timestamp, body_bytes)
```

---

## 7. DB 스키마 구조

```
pii 스키마
│
├── api_keys              API 키 (key_id, secret, is_admin, is_active)
├── api_key_nonces        Nonce 중복 방지 (10분 TTL)
│
├── pii_patterns          PII 탐지 패턴 (정규식 + 항목)
│     mode: production | shadow | disabled
│
├── pii_policies          (entity_type, strictness, score_band) → action
│     LISTEN/NOTIFY로 앱 핫 리로드
│
├── extraction_jobs       Case C 작업 상태
│     status: pending | processing | completed | failed
│     expires_at: 24시간 후 GC
│
├── audit_events          감사로그 (append-only)
│     BEFORE UPDATE/DELETE 트리거 → 수정/삭제 차단
│     bypass: SET LOCAL app.bypass_audit_lock = 'on'
│     retention: 1년
│
├── pii_feedback          사용자 피드백 (오탐/미탐)
│     reporter_email: SHA-256+salt 해시로만 저장
│
└── alerter_state         알림 발송 중복 방지 상태
```

### 주요 인덱스

| 테이블 | 인덱스 컬럼 | 용도 |
|--------|-----------|------|
| `extraction_jobs` | `status`, `expires_at` | 만료 GC 쿼리 |
| `audit_events` | `created_at`, `api_key_id` | 감사로그 페이지네이션 |
| `pii_feedback` | `created_at`, `attachment_job_id` | 알림 집계 |

---

## 8. 백그라운드 워커

애플리케이션 시작 시(`app.main` lifespan) asyncio 태스크로 등록됩니다.

| 워커 | 주기 | 역할 |
|------|------|------|
| `attachment_processor` | On-demand (Case C) | 첨부파일 fetch → 분석 → OCR → 웹훅 |
| `job_cleanup_loop` | 1시간 | 만료된 extraction_jobs 삭제 |
| `audit_cleanup_loop` | 1시간 | 1년 경과 audit_events 삭제 |
| `feedback_alerter_loop` | 1시간 | 피드백 임계 초과 시 SMTP 알림 발송 |
| `policy_reload_loop` | LISTEN/NOTIFY | DB 정책 변경 즉시 반영 |

---

## 9. 신뢰 영역 분리

```
인터넷
  │
  ▼
[Nginx :443]  ←── 게시판 서비스 / 외부 클라이언트
  │
  │  허용: /v1/detect/post, /v1/jobs/*
  │        /healthz, /readyz, /v1/feedback, /v1/legal/*
  │
  │  차단: /v1/admin/* → 404 (라우터 미마운트 또는 nginx location 블록)
  │
  ▼
[FastAPI :8000]
  │
  ▼
[Nginx :8443]  ←── 사내망 / VPN (allow 10.0.0.0/8)
  │
  │  허용: /v1/admin/audit-events
  │        /v1/admin/stats/*
  │        /v1/admin/metrics
  │
  ▼
[FastAPI :8000]  (동일 프로세스, is_admin + IP CIDR 2차 검사)
```

`ADMIN_IP_ALLOWLIST`가 비어 있으면 FastAPI가 admin 라우터를 **마운트하지 않음** — 외부 스캐너가 경로를 발견할 수 없습니다.

---

## 10. 데이터 생명주기

```
데이터 종류          생성                  보존       파기 트리거
─────────────────────────────────────────────────────────────────
요청 본문           메모리에서만 처리       없음       처리 완료 즉시
nonce              Redis                  10분       TTL 자동 만료
extraction_jobs    Case C 접수 시         24시간     job_cleanup_loop
audit_events       요청 완료 시           1년        audit_cleanup_loop
pii_feedback       피드백 제출 시         무기한     수동 삭제
api_keys           발급 시               폐기 시까지  python -m app.cli apikey revoke
```

**PII 평문은 어떤 저장소에도 기록되지 않습니다.**  
- 감사로그: body SHA-256 해시만 저장  
- 웹훅 페이로드: 탐지 메타데이터 (entity_type, start/end offset)만 포함  
- 피드백: reporter_email은 SHA-256+salt 단방향 해시  

---

## 11. 메트릭 및 알림 흐름

```
FastAPI 요청 처리
       │
       ▼
AuditMiddleware
  http_requests_total{method, path, status} ++ (Counter)
  http_request_duration_seconds{...}  .observe() (Histogram)
       │
       ▼
detect_post 핸들러 (_envelope / _error 응답 funnel)
  pii_detect_requests_total{verdict} ++ (Counter)
      └─ 호출 수 = sum(...), 차단 수 = verdict="BLOCK" 필터
  pii_detections_total{entity_type, verdict} ++ (Counter)
       │
       ▼
attachment_processor (_process_one_attachment 진입)
  attachment_size_bytes .observe()  (첨부 1건당 크기 분포)
  extraction_jobs_total{status} ++  (PROCESSING/COMPLETED/FAILED)
       │
       ▼
OCR 엔진 _run_engine (vlm / paddle 분기)
  ocr_duration_seconds{engine} .observe()
       │
       ▼ (스크레이핑)
Prometheus ──GET /v1/admin/metrics──► 메트릭 수집 서버
       │
       ▼
Grafana 대시보드
       │
       ▼ (임계 초과)
prometheus_alerts.yml
  ErrorRateHigh    (5xx 비율 > 5%, 5분 지속)
  LatencyHigh      (p95 응답 > 2s, 10분 지속)
  JobBacklog       (대기 작업 > 100건)
  ApiDown          (5분간 응답 없음)


PiiFeedback 알림 (별도 경로)
       │
pii_feedback 테이블
       │
feedback_alerter_loop (1시간)
  임계값 초과 → SMTP → 운영팀 이메일
  alerter_state 로 중복 발송 방지
```

### Prometheus 스크레이핑 설정 예시

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pii_api
    scrape_interval: 15s
    static_configs:
      - targets: ['pii-api.example.internal:8000']
    metrics_path: /v1/admin/metrics
    params: {}
    # 관리자 API 키를 Authorization 헤더로 전달하는 경우
    # bearer_token: <admin_api_key>
```
