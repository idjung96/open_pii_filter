# PII Detection API — 연동 가이드

> 대상: 외부 클라이언트 개발자 (게시판 서비스 등)  
> 최종 수정: 2026-05-07 — 본 가이드는 현재 코드 (`app/api/schemas.py`, `app/security/hmac_auth.py`, `app/workers/webhook_sender.py`) 와 1:1 동기화되었습니다. 이전 판본(2026-04-28)에는 `author` 위치, webhook canonical 서명, MIME 목록, JobInfo 필드 등에 오류가 있었으니 갱신 후 사용하세요.

---

## 목차

1. [개요](#1-개요)
2. [키 발급 및 등록](#2-키-발급-및-등록)
3. [인증 (HMAC-SHA256)](#3-인증-hmac-sha256)
4. [API 엔드포인트 레퍼런스](#4-api-엔드포인트-레퍼런스)
5. [요청/응답 상세](#5-요청응답-상세)
6. [웹훅 수신 설정](#6-웹훅-수신-설정)
7. [에러 코드 전체 목록](#7-에러-코드-전체-목록)
8. [클라이언트 구현 예시](#8-클라이언트-구현-예시)
8-A. [탐지 엔진 — OCR / 인식기 커버리지](#8-a-탐지-엔진--ocr--인식기-커버리지)
9. [재시도 및 에러 처리 전략](#9-재시도-및-에러-처리-전략)
10. [피드백 제출](#10-피드백-제출)

---

## 1. 개요

`POST /v1/detect/post` 단일 엔드포인트로 게시글 본문과 첨부파일의 개인정보(PII)를 검사합니다.

### 처리 모드

| 모드 | 조건 | HTTP 상태 | 응답 시점 |
|------|------|-----------|----------|
| **Case A** | 본문에 BLOCK급 PII 탐지 | `200` | 즉시 |
| **Case B** | 본문 PASS, 첨부파일 없음 | `200` | 즉시 |
| **Case C** | 본문 PASS, 첨부파일 있음 | `202` | 즉시 (첨부 비동기 처리) |

Case C에서는 `202` 응답 후 첨부파일 검사 결과를 `callback_url`로 웹훅 전송합니다.

### Base URL

```
https://pii-api.example.com   (운영)
http://localhost:9000          (개발 — uvicorn 0.0.0.0:9000 기본)
```

`첨부파일 검사 토글` (`/admin/settings`): 운영자가 임시로 첨부 검사 자체를 끌
수 있습니다. OFF 일 때 본문만 검사하고 첨부는 무조건 PASS 로 처리합니다 (HWP/HWPX
deny-list 차단도 동일하게 우회되니 운영 정책에 맞춰 켜고 끄세요).

---

## 2. 키 발급 및 등록

### 2-1. 키 구성 요소

| 구성요소 | 형식 | 설명 |
|----------|------|------|
| `key_id` | `k_` + 32자 hex | 요청 헤더에 포함하는 공개 식별자 |
| `secret` | 64자 hex | HMAC 서명에 사용하는 비밀 키. **발급 시 1회만 출력** |

### 2-2. 방법 A — CLI 발급 (DB 운영 중)

PostgreSQL이 실행 중일 때 CLI로 키를 발급하고 DB에 직접 저장합니다.

```bash
# 기본 발급
python -m app.cli apikey issue --name "homepage"

# IP 제한 포함
python -m app.cli apikey issue \
  --name "homepage" \
  --ip-allowlist "203.0.113.0/24,198.51.100.5/32"

# 출력 예시 (secret을 즉시 복사할 것)
# API key issued — capture the secret NOW; it is not recoverable:
#   key_id : k_f020fb0c1de8380aa706cd02bbeaf091
#   secret : eb770200b4a171d92637d84de380f836434...
#   rate   : 60/min, 1000/hour
```

키 목록 / 비활성화 / 폐기:

```bash
python -m app.cli apikey list
python -m app.cli apikey disable k_f020fb0c1de8380aa706cd02bbeaf091
python -m app.cli apikey revoke  k_f020fb0c1de8380aa706cd02bbeaf091
```

### 2-3. 방법 B — JSON 스크립트 발급 (DB 미운영 시)

DB 없이 개발/스테이징 환경에서 키를 발급하고 `keys/api_keys.json`에 저장합니다.

```bash
# 발급
python scripts/manage_keys.py issue --name "homepage"

# IP 제한 포함
python scripts/manage_keys.py issue \
  --name "homepage" \
  --ip "203.0.113.0/24,198.51.100.5/32"

# 목록 조회
python scripts/manage_keys.py list

# 비활성화 / 재활성화 / 폐기
python scripts/manage_keys.py disable k_f020fb0c1de8380aa706cd02bbeaf091
python scripts/manage_keys.py enable  k_f020fb0c1de8380aa706cd02bbeaf091
python scripts/manage_keys.py revoke  k_f020fb0c1de8380aa706cd02bbeaf091

# JSON → DB upsert (DB 준비 후 일괄 등록)
python scripts/manage_keys.py load-db
```

**`keys/api_keys.json` 파일 형식:**

```json
{
  "version": 1,
  "keys": [
    {
      "key_id": "k_f020fb0c1de8380aa706cd02bbeaf091",
      "secret": "<64자 hex>",
      "name": "homepage",
      "description": "기관 공공기관 홈페이지 게시판 PII API 연동 키",
      "rate_per_minute": 60,
      "rate_per_hour": 1000,
      "ip_allowlist": null,
      "is_admin": false,
      "created_by": "admin",
      "created_at": "2026-04-28T04:19:14+00:00",
      "enabled": true,
      "revoked_at": null
    }
  ]
}
```

> **주의**: `keys/` 디렉터리는 `.gitignore`에 등록되어 있습니다. secret이 저장된 파일을 절대 저장소에 커밋하지 마십시오.

### 2-4. 현재 발급된 키 (기관 홈페이지)

| 항목 | 값 |
|------|-----|
| `key_id` | `k_f020fb0c1de8380aa706cd02bbeaf091` |
| `name` | `homepage` |
| `rate` | 60/분, 1000/시간 |
| `secret` 위치 | `keys/api_keys.json` (서버 로컬) |
| 발급일 | 2026-04-28 |

---

## 3. 인증 (HMAC-SHA256)

모든 API 요청에 아래 **네 개** 헤더가 필요합니다.

| 헤더 | 형식 | 예시 |
|------|------|------|
| `X-Api-Key` | 발급받은 `key_id` | `k_f020fb0c1de8380aa706cd02bbeaf091` |
| `X-Timestamp` | UNIX 초 (UTC 정수) | `1745812754` |
| `X-Nonce` | 16자 이상 무작위 문자열 (요청마다 새로 생성) | `a7f3k9m2p0q8r5t1` |
| `X-Signature` | HMAC-SHA256 hex digest | `3d8a1f...` |

### 서명 생성 규칙 (Canonical String)

```
canonical = {timestamp}\n{nonce}\n{METHOD}\n{path}\n{sha256_hex(body)}
signature = HMAC-SHA256(secret, canonical.encode("utf-8")).hexdigest()
```

구체적인 구성 예시:

```
1745812754\n
a7f3k9m2p0q8r5t1\n
POST\n
/v1/detect/post\n
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

- `X-Timestamp`는 서버 시각 기준 **±5분(300초)** 이내여야 합니다.
- `X-Nonce`는 요청마다 반드시 새로 생성하십시오. 동일한 `(key_id, nonce)` 쌍은 **10분간** 재사용이 차단됩니다(리플레이 방어).
- body가 비어 있어도 sha256 digest를 포함해야 합니다 (`e3b0c44...` = 빈 body의 SHA-256).

### Python 서명 예시

```python
import hashlib, hmac, secrets, time

def sign_request(
    secret_key: str,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body_digest = hashlib.sha256(body).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_digest}"
    signature = hmac.new(
        secret_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Api-Key": KEY_ID,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }
```

---

## 4. API 엔드포인트 레퍼런스

### 외부 클라이언트용 엔드포인트

| 메서드 | 경로 | 인증 | 설명 |
|--------|------|------|------|
| `POST` | `/v1/detect/post` | HMAC | PII 검사 (본문 + 첨부파일) |
| `GET`  | `/v1/jobs/{job_id}` | HMAC | 비동기 작업 결과 조회 (24시간 보존) |
| `DELETE` | `/v1/jobs/{job_id}` | HMAC | 처리 결과 즉시 폐기 (callback 수신 후 호출자 측 retention 정책 반영) |
| `POST` | `/v1/feedback` | HMAC | 오탐/미탐 피드백 제출 |
| `GET`  | `/v1/legal/privacy-notice` | 없음 | 개인정보처리방침 |
| `GET`  | `/healthz`, `/v1/healthz` | 없음 | liveness — 프로세스 가동 여부 |
| `GET`  | `/readyz`, `/v1/readyz`   | 없음 | readiness — DB / Redis / 분석기 초기화까지 포함 |

---

## 5. 요청/응답 상세

### 4-1. POST /v1/detect/post

#### 요청 스키마

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "author": {
    "name": "홍길동",
    "user_id": "user_001",
    "ip": "203.0.113.5",
    "is_anonymous": false
  },
  "post": {
    "board_id": "free",
    "title": "문의 드립니다",
    "body": "문의사항은 010-0000-1234로 연락주세요."
  },
  "attachments": [
    {
      "attachment_id": "att_001",
      "filename": "resume.pdf",
      "size_bytes": 204800,
      "mime_type": "application/pdf",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "fetch_url": "https://storage.example.com/uploads/resume.pdf"
    }
  ],
  "callback_url": "https://www.example.com/webhooks/pii",
  "options": {
    "strictness": "medium"
  }
}
```

> ⚠️ **`author` 는 top-level 필드입니다** — `post.author` 가 아닙니다 (`app/api/schemas.py:DetectPostRequest`).

| 필드 | 필수 | 타입 | 설명 |
|------|------|------|------|
| `request_id` | **필수** | UUID v4 | 멱등성 키. 24시간 내 동일 ID 재전송 시 원본 응답 반환 |
| `author.name` | **필수** | string (1~100) | 작성자 이름 |
| `author.ip` | **필수** | string (1~45) | 작성자 IP (IPv4/IPv6) |
| `author.user_id` | 선택 | string (≤100) | 작성자 계정 ID |
| `author.is_anonymous` | 선택 | bool | 기본 `false`. 익명 게시판일 때 `true` |
| `post.board_id` | **필수** | string (≤64) | 게시판 식별자 |
| `post.title` | **필수** | string (≤500) | 게시글 제목 |
| `post.body` | **필수** | string (≤50,000) | 게시글 본문 |
| `attachments` | 선택 | array (≤5) | 첨부파일 목록. 있으면 `callback_url` 필수 |
| `attachments[].attachment_id` | **필수** | string (≤64) | 첨부파일 식별자 |
| `attachments[].filename` | **필수** | string (≤255) | 파일명 |
| `attachments[].size_bytes` | **필수** | integer (0~20,971,520) | 파일 크기 (≤ 20 MB) |
| `attachments[].mime_type` | **필수** | string | 지원 MIME 타입 (아래 목록) |
| `attachments[].sha256` | **필수** | string (64자) | SHA-256 hex. 워커가 다운로드 후 검증 |
| `attachments[].fetch_url` | **필수** | string (≤2048) | API 서버가 파일을 다운로드할 URL |
| `callback_url` | 조건부 | string (≤2048) | 첨부파일 있을 때 필수. 웹훅 수신 URL |
| `options.strictness` | 선택 | `low`/`medium`/`high` | 탐지 엄격도. 기본값 `medium` |

요청 본문 자체는 1 MB(`REQ-4030`) 한도, 첨부 합산은 개별 파일 20 MB × 최대 5개입니다.

#### 지원 첨부파일 MIME 타입 (Phase 4b 현행)

| 분류 | MIME | 처리 |
|------|------|------|
| PDF | `application/pdf` | 텍스트 레이어 직접 추출. 비어 있으면 페이지 렌더 → OCR. |
| Office (Open XML) | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | DOCX — `python-docx` 직접 파싱, OCR 미사용 |
| Office (Open XML) | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | XLSX — `openpyxl` 셀 텍스트, OCR 미사용 |
| Office (Open XML) | `application/vnd.openxmlformats-officedocument.presentationml.presentation` | PPTX — `python-pptx` 슬라이드 텍스트, OCR 미사용 |
| 텍스트 | `text/plain`, `text/markdown` | UTF-8 → CP949 fallback |
| 이미지 | `image/png`, `image/jpeg`, `image/tiff`, `image/bmp`, `image/webp`, `image/gif` | PaddleOCR (CPU 기본) → 실패 시 vLLM Qwen 폴백 |

> ⚠️ HWP/HWPX 및 OLE 레거시 (`.doc`/`.xls`/`.ppt`/`.zip`)는 `attachment_blocklist` deny-list 가 일괄 거부합니다 (`REQ-4035`). 운영자는 `/admin/blocklist` 에서 차단 사유를 확인할 수 있습니다.

---

#### Case A / B 응답 (HTTP 200)

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": "BLOCK",
  "code": "BLOCK-2001",
  "system_message": "KR RRN detected with high confidence",
  "user_message": "본문에 주민등록번호로 보이는 정보가 포함되어 있어 게시할 수 없습니다.",
  "developer_message": null,
  "detections": [
    {
      "field": "post.body",
      "entity_type": "KR_RRN",
      "code": "BLOCK-2001",
      "start": 5,
      "end": 18,
      "score": 0.95
    }
  ],
  "body_result": null,
  "job": null,
  "processed_at": "2026-05-07T07:00:01.234567+00:00",
  "processing_ms": 87
}
```

`detections[]` 의 각 항목은 `field` (`post.body` / `post.title` / `attachment.<id>`),
`entity_type` (`KR_RRN`, `KR_PHONE`, `EMAIL_ADDRESS` 등), `code`, `score`, `start`/`end`
오프셋을 포함합니다 (`app/api/schemas.py:Detection`). `developer_message` 는 `SVR-5xxx`
오류 응답에서만 채워집니다.

#### Case C 응답 (HTTP 202)

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": "PASS",
  "code": "ACK-3001",
  "system_message": "body PASS; attachment scan queued",
  "user_message": "본문은 이상이 없습니다. 첨부파일 검사가 진행 중입니다 (예상 30초 이내).",
  "developer_message": null,
  "detections": [],
  "body_result": {
    "verdict": "PASS",
    "code": "OK-0000",
    "detections": []
  },
  "job": {
    "job_id": "job_a1b2c3d4e5f6",
    "status_url": "/v1/jobs/job_a1b2c3d4e5f6",
    "estimated_completion_seconds": 30,
    "attachment_count": 1
  },
  "processed_at": "2026-05-07T07:00:01.500000+00:00",
  "processing_ms": 92
}
```

> ⚠️ `verdict` 는 Case C 에서도 `"PASS"` 입니다 (`Verdict` enum 은 `PASS`/`BLOCK` 2단계).
> 진행 중 상태는 `code = "ACK-3001"` + HTTP 202 로 식별하세요. `"PROCESSING"` 같은
> 별도 상태값은 더 이상 사용하지 않습니다 (Phase 9D 정리).
> `job` 객체는 `job_id` / `status_url` / `estimated_completion_seconds` /
> `attachment_count` 4개 필드만 가집니다 (`app/api/schemas.py:JobInfo`).

---

### 4-2. GET /v1/jobs/{job_id}

첨부파일 처리 결과를 폴링으로 조회합니다. 작업은 완료 후 24시간 보존되며,
호출자가 명시적으로 `DELETE /v1/jobs/{job_id}` 를 호출하면 즉시 폐기됩니다.

```
GET /v1/jobs/job_a1b2c3d4e5f6
X-Api-Key:    k_f020fb0c1de8380aa706cd02bbeaf091
X-Timestamp:  1745812754
X-Nonce:      3f9a2b8c4e1d6705
X-Signature:  <hex hmac>
```

**완료 응답 예시:**

```json
{
  "job_id": "job_a1b2c3d4e5f6",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "COMPLETED",
  "body_code": "OK-0000",
  "body_verdict": "PASS",
  "created_at": "2026-05-07T07:00:01+00:00",
  "completed_at": "2026-05-07T07:00:28+00:00",
  "webhook_attempts": 1,
  "webhook_delivered_at": "2026-05-07T07:00:29+00:00",
  "attachment_results": [
    {
      "attachment_id": "att_001",
      "filename": "id_card.png",
      "verdict": "BLOCK",
      "code": "BLOCK-2010",
      "detections": [
        {"field": "attachment.att_001", "entity_type": "KR_RRN", "code": "BLOCK-2001", "score": 0.97}
      ]
    }
  ]
}
```

`status` 값: `PENDING` → `PROCESSING` → `COMPLETED` / `FAILED` (대문자, DB 컬럼 그대로 노출).

### 4-3. DELETE /v1/jobs/{job_id}

호출자 측 retention 정책에 맞춰 즉시 폐기를 요청합니다. 호출 시 webhook 발송 이력
까지 함께 삭제됩니다. 응답은 `204 No Content` (미존재 시 `404 REQ-4040`).

---

## 6. 웹훅 수신 설정

Case C에서 첨부파일 처리 완료 시 `callback_url`로 POST 전송됩니다.

### 웹훅 페이로드 (`app/api/schemas.py:WebhookPayload`)

```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "job_id": "job_a1b2c3d4e5f6",
  "verdict": "BLOCK",
  "code": "BLOCK-2008",
  "user_message": "첨부파일에 개인정보가 포함되어 있어 게시할 수 없습니다.",
  "completed_at": "2026-05-07T07:00:28+00:00",
  "attachment_results": [
    {
      "attachment_id": "att_001",
      "filename": "id_card.png",
      "verdict": "BLOCK",
      "code": "BLOCK-2010",
      "detections": [
        {
          "field": "attachment.att_001",
          "entity_type": "KR_RRN",
          "code": "BLOCK-2001",
          "start": 0,
          "end": 14,
          "score": 0.97
        }
      ]
    }
  ]
}
```

> ⚠️ 필드 이름은 `verdict` 입니다 — 이전 판본(`overall_verdict`)은 잘못된 표기였습니다.
>
> Phase 9D 변경: 마스킹된 이미지/PDF 산출물(`masked_url`)은 더 이상 제공
> 되지 않습니다. PII 가 검출되면 즉시 BLOCK 으로 거절되며, 사용자가
> 직접 PII 를 제거 후 재등록해야 합니다.
>
> `attachment_results[].user_message` 는 더 이상 발송되지 않습니다 (페이로드
> 슬림화). 첨부 단위 안내 문구는 호출자가 `code` 기반으로 직접 매핑하세요.

### 서명 검증 (필수)

웹훅은 `/v1/detect/post` 호출과 **동일한 canonical** 형식으로 서명됩니다 — 단순한
`timestamp + body` 가 아닙니다 (`app/workers/webhook_sender.py:_canonical_string`).

```
canonical = "{timestamp}\n{nonce}\n{method}\n{path}\n{sha256_hex(body)}"
signature = HMAC-SHA256(webhook_signing_secret, canonical.encode("utf-8")).hexdigest()
```

수신 서버 검증 예시:

```python
import hashlib, hmac
from urllib.parse import urlparse

def verify_webhook(
    secret: str,
    timestamp: str,    # X-Timestamp 헤더 (UNIX 초)
    nonce: str,        # X-Nonce 헤더
    method: str,       # "POST"
    callback_url: str, # 등록한 callback_url 자체
    body_bytes: bytes, # 수신 body 원문 (parse 전)
    signature: str,    # X-Signature 헤더
) -> bool:
    path = urlparse(callback_url).path or "/"
    body_digest = hashlib.sha256(body_bytes).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_digest}"
    expected = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

서명 시크릿은 운영팀이 사전에 공유한 `webhook_signing_secret` 환경변수입니다 (API
호출용 `secret` 과 별개의 값). 서명 미검증 webhook 은 즉시 401 로 거절하세요.

### 웹훅 수신 서버 응답

- `2xx` 반환 → 성공, 재전송 없음
- `4xx` / `5xx` 또는 타임아웃 → 지수 백오프 재전송 (최대 5회: 1s → 4s → 16s → 64s → 256s)

### verdict 처리 흐름

| `verdict` | `code` 예 | 클라이언트 처리 |
|-----------|----------|----------------|
| `PASS`  | `OK-0000` | 게시 허용 |
| `BLOCK` | `BLOCK-2008`, `BLOCK-2010`, … | 게시 차단, `attachment_results[].code` 로 사유 안내 |
| `ERROR` | `SVR-5xxx`, `REQ-4040`/`4041`/`4042` | 첨부별로 처리 실패 — 운영팀 확인 또는 사용자 재업로드 안내 |

`attachment_results[].verdict` 가 `ERROR` 인 항목과 `BLOCK` 인 항목이 같은 webhook 에
혼재할 수 있으므로 (`SVR-5xxx` 인 첨부 1개와 `BLOCK` 첨부 1개) 항목 단위로 분기하세요.

---

## 7. 에러 코드 전체 목록

### PASS (HTTP 200)

| 코드 | 의미 | 클라이언트 처리 |
|------|------|----------------|
| `OK-0000` | PII 없음 | 게시 허용 |
| `OK-0001` | 미약한 신호, 정책상 허용 | 게시 허용 |

### WARN — deprecated since Phase 9D (audit 호환 위해 코드 상수 보존, 신규 발생 안 함)

| 코드 | 의미 | 비고 |
|------|------|------|
| `WARN-1001` ~ `WARN-1099` | 전화번호·이메일·주소·인명 등 약한 PII 신호 | Phase 9D 이후 신규 발생하지 않음 |

### BLOCK (HTTP 200)

| 코드 | 의미 |
|------|------|
| `BLOCK-2001` | 주민등록번호 |
| `BLOCK-2002` | 운전면허번호 |
| `BLOCK-2003` | 여권번호 |
| `BLOCK-2004` | 외국인등록번호 |
| `BLOCK-2005` | 신용카드번호 |
| `BLOCK-2006` | 계좌번호 |
| `BLOCK-2007` | 내부 임직원 정보 (deny-list) |
| `BLOCK-2008` | 복합 PII (여러 종류 동시 감지) |
| `BLOCK-2010` | 첨부파일 내 PII |
| `BLOCK-2011` | 이미지 OCR로 PII 감지 |
| `BLOCK-2012` | 신분증 이미지 의심 |
| `BLOCK-2099` | 기타 강한 PII 신호 |

> BLOCK 응답은 모두 HTTP 200입니다. `verdict` 필드로 판단하세요.

### ACK (HTTP 202)

| 코드 | 의미 |
|------|------|
| `ACK-3001` | 첨부파일 검사 진행 중 |
| `ACK-3002` | 처리 대기열 과부하로 지연 |
| `ACK-3010` | 피드백 접수 완료 |

### REQ (클라이언트 오류, HTTP 4xx)

| 코드 | HTTP | 의미 | 처리 |
|------|------|------|------|
| `REQ-4001` | 400 | 필수 필드 누락 | 요청 수정 |
| `REQ-4002` | 400 | author 필드 형식 오류 | 요청 수정 |
| `REQ-4003` | 400 | JSON 파싱 오류 | 요청 수정 |
| `REQ-4004` | 400 | request_id UUID 형식 오류 | UUID v4 사용 |
| `REQ-4005` | 400 | 중복 request_id | 새 UUID 사용 또는 원본 응답 사용 |
| `REQ-4010` | 401 | HMAC 서명 불일치 | 서명 로직 확인 |
| `REQ-4011` | 401 | API 키 없음/무효 | X-Api-Key 헤더 확인 |
| `REQ-4012` | 401 | timestamp 범위 초과 | 서버 시각과 동기화 |
| `REQ-4013` | 401 | 재전송 감지 | 새 timestamp 사용 |
| `REQ-4014` | 403 | API 키 폐기됨 | 새 API 키 발급 요청 |
| `REQ-4015` | 403 | 허용 IP 외 접근 | 발신 IP 확인 |
| `REQ-4020` | 429 | Rate limit 초과 | 지수 백오프 후 재시도 |
| `REQ-4030` | 413 | 요청 본문 초과 (1 MB) | 본문 분할 |
| `REQ-4031` | 413 | 첨부파일 크기 초과 | 파일 크기 확인 |
| `REQ-4032` | 400 | 첨부파일 개수 초과 | 개수 줄임 |
| `REQ-4033` | 415 | 지원하지 않는 MIME 타입 | MIME 타입 확인 |
| `REQ-4040` | 422 | 첨부파일 다운로드 실패 | fetch_url 접근 가능 여부 확인 |
| `REQ-4041` | 422 | SHA-256 불일치 | sha256 필드 재계산 |
| `REQ-4042` | 422 | 첨부파일 손상 | 파일 재업로드 |
| `REQ-4043` | 422 | PDF 페이지 수 초과 | 페이지 수 줄임 |
| `REQ-4050` | 422 | 악성코드 탐지 | 파일 확인 |
| `REQ-4051` | 422 | 암호화된 파일 | 암호 해제 후 업로드 |

### SVR (서버 오류, HTTP 5xx) — 재시도 가능

| 코드 | HTTP | 의미 |
|------|------|------|
| `SVR-5001` | 500 | 내부 분석기 오류 |
| `SVR-5002` | 503 | 분석기 초기화 중 |
| `SVR-5003` | 503 | DB 연결 오류 |
| `SVR-5004` | 503 | OCR 엔진 다운 |
| `SVR-5005` | 503 | 처리 대기열 포화 |
| `SVR-5006` | 504 | 처리 타임아웃 |
| `SVR-5099` | 500 | 기타 서버 오류 |

`SVR-5xxx` 응답은 모두 재시도 가능합니다. 지수 백오프(1s → 2s → 4s → 8s)를 사용하세요.

---

## 8. 클라이언트 구현 예시

> ⚠️ 모든 클라이언트는 4개 헤더(`X-Api-Key` / `X-Timestamp` / `X-Nonce` / `X-Signature`) 를
> 모두 보내야 합니다. canonical 형식은 §3 의 `{timestamp}\n{nonce}\n{METHOD}\n{path}\n{sha256_hex(body)}` 그대로입니다 —
> 이전 판본의 ISO-8601 timestamp / nonce 누락 / `timestamp+body` 스타일 서명은 모두
> 잘못된 예시였으니 사용 중이라면 즉시 교체하세요.

### Python

```python
import hashlib
import hmac
import json
import secrets
import time
import uuid

import httpx

API_BASE = "https://pii-api.example.com"
KEY_ID = "k_f020fb0c1de8380aa706cd02bbeaf091"
SECRET = "your_secret_key_here"


def sign(secret: str, *, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body_digest = hashlib.sha256(body).hexdigest()
    canonical = f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_digest}"
    signature = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return {
        "X-Api-Key": KEY_ID,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def detect_post(body_text: str) -> dict:
    payload = {
        "request_id": str(uuid.uuid4()),
        "author": {"name": "홍길동", "user_id": "u001", "ip": "203.0.113.5"},
        "post": {"board_id": "free", "title": "문의", "body": body_text},
        "options": {"strictness": "medium"},
    }
    # ensure_ascii=False 가 서명 대상 바이트와 실제 전송 바이트를 일치시키는 핵심 — 둘이 어긋나면 REQ-4010.
    body_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = sign(SECRET, method="POST", path="/v1/detect/post", body=body_bytes)
    headers["Content-Type"] = "application/json"

    resp = httpx.post(f"{API_BASE}/v1/detect/post", content=body_bytes, headers=headers)
    return resp.json()


result = detect_post("안녕하세요. 연락처는 010-0000-1234입니다.")
print(result["verdict"])   # "PASS" 또는 "BLOCK"
print(result["user_message"])
```

### Java (Spring Boot)

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

public class PiiApiClient {
    private final String baseUrl;
    private final String keyId;
    private final String secret;

    public PiiApiClient(String baseUrl, String keyId, String secret) {
        this.baseUrl = baseUrl; this.keyId = keyId; this.secret = secret;
    }

    public Map<String, String> signHeaders(String method, String path, byte[] body) throws Exception {
        String timestamp = String.valueOf(Instant.now().getEpochSecond()); // UNIX 초 문자열
        String nonce = UUID.randomUUID().toString().replace("-", "");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String bodyDigest = HexFormat.of().formatHex(md.digest(body));
        String canonical = String.join("\n",
            timestamp, nonce, method.toUpperCase(), path, bodyDigest);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String signature = HexFormat.of().formatHex(
            mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));

        return Map.of(
            "X-Api-Key", keyId,
            "X-Timestamp", timestamp,
            "X-Nonce", nonce,
            "X-Signature", signature);
    }
}
```

### Node.js

```javascript
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

function signHeaders(secret, method, path, bodyBytes) {
  const timestamp = String(Math.floor(Date.now() / 1000));     // UNIX 초
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyDigest = crypto.createHash('sha256').update(bodyBytes).digest('hex');
  const canonical = `${timestamp}\n${nonce}\n${method.toUpperCase()}\n${path}\n${bodyDigest}`;
  const signature = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  return {
    'X-Api-Key': process.env.PII_KEY_ID,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
    'X-Signature': signature,
  };
}

async function detectPost(bodyText) {
  const payload = {
    request_id: uuidv4(),
    author: { name: '홍길동', user_id: 'u001', ip: '203.0.113.5' },
    post: { board_id: 'free', title: '문의', body: bodyText },
    options: { strictness: 'medium' },
  };
  const bodyBytes = Buffer.from(JSON.stringify(payload), 'utf8');
  const headers = signHeaders(process.env.PII_SECRET, 'POST', '/v1/detect/post', bodyBytes);
  headers['Content-Type'] = 'application/json';

  const resp = await fetch(`${process.env.PII_BASE}/v1/detect/post`, {
    method: 'POST', headers, body: bodyBytes,
  });
  return resp.json();
}
```

---

## 8-A. 탐지 엔진 — OCR / 인식기 커버리지

### 첨부 텍스트 추출 방식

dispatcher (`app/extractors/dispatcher.py`) 가 MIME 별로 다른 추출 경로를 탑니다.
**모든 문서를 PDF 로 변환하지 않으며, 형식이 텍스트 컨테이너인 경우 OCR 자체가 호출되지 않습니다**.

| 입력 | 추출 라이브러리 | OCR 호출? |
|------|----------------|----------|
| PDF (텍스트 레이어) | `pypdfium2` + `pdfplumber` | ❌ |
| PDF (스캔본) | `pypdfium2` 페이지 렌더 → PaddleOCR | ✅ 페이지 전체 |
| DOCX / XLSX / PPTX | `python-docx` / `openpyxl` / `python-pptx` | ❌ |
| HWPX | `pyhwpx` (XML 직접 파싱) | ❌ |
| 이미지 (PNG/JPEG/TIFF/BMP/WEBP/GIF) | PaddleOCR | ✅ |
| TXT / Markdown | UTF-8 → CP949 폴백 | ❌ |

PDF 의 스캔 여부 판정 (`app/extractors/pdf.py:_extract_sync`) 은 텍스트 레이어가 비어
있으면 `is_scan=True` 로 마킹하여 OCR 경로로 라우팅합니다.

### OCR 엔진

기본은 **PaddleOCR PP-OCRv5 (한국어, CPU)** — 자체 호스팅, 외부 송출 없음.
`OCR_ENGINE=vlm` 으로 전환하면 사내 vLLM (Qwen3.5-VL) 로 대체할 수 있습니다 (저화질 스캔/회전/표 레이아웃 회귀 시).
Paddle 이 예외를 던지면 dispatcher 가 자동으로 vLLM 으로 폴백하므로 이중화는 기본 동작입니다.

OCR 엔진 다운 시 응답 코드는 `SVR-5004` 입니다.

### KR_PHONE 인식 범위 (Phase 9X 확장)

| 분류 | 패턴 | 예 |
|------|------|----|
| 모바일 | `010 / 011 / 016 / 017 / 018 / 019` (hyphen / space / plain / +82) | `010-0000-1234`, `+82 11 0000 1234` |
| 유선 | 서울 `02`, 지역 `031~033`, `041~044`, `051~055`, `061~064` | `02-1234-5678`, `031-123-4567` |
| 인터넷·특수 | `070`, `080`, `050X` | `070-1234-5678`, `0505-123-4567` |
| 지역번호 없음 | `1234-5678` / `123-4567` | 본문 컨텍스트(`전화/연락/내선/사무실/팩스/phone/tel/mobile/fax`) 가 가까이 있으면 BLOCK 경계 통과 |

지역번호 없는 표기는 base score 0.45 — 단독으로는 medium 임계 (0.78) 미만이라 PASS,
컨텍스트 부스트로 BLOCK 으로 올라갑니다. 이 설계는 `주문번호 1234-5678` 같은
비전화 패턴의 오탐을 방지하기 위해서입니다.

`KR_PHONE` 외에도 `KR_RRN`, `KR_BUSINESS_NUM`, `KR_DRIVER_LICENSE`, `KR_PASSPORT`,
`EMAIL_ADDRESS`, `CREDIT_CARD`, `IBAN` 등 (`app/core/recognizers/`) 이 동일한
strictness/score 정책을 따릅니다.

---

## 9. 재시도 및 에러 처리 전략

```
응답 수신
    │
    ├── HTTP 200 + verdict = "PASS" / "BLOCK"  → 정상 처리
    │
    ├── HTTP 202 + code = "ACK-3001"           → 첨부 비동기 검사 진행 중
    │     └── 웹훅 미수신 시 GET /v1/jobs/{id} 폴링 (30초 간격, 최대 10분)
    │
    ├── REQ-4020 (429)  → Retry-After 헤더 준수 또는 60초 대기
    │
    ├── REQ-4005 (400)  → 원본 캐시된 응답 재사용 (멱등성 보장)
    │
    ├── SVR-5xxx (5xx)  → 지수 백오프 재시도
    │     1s → 2s → 4s → 8s → 포기 후 운영팀 알림
    │
    └── REQ-4xxx (기타) → 재시도 없음, 요청 로직 수정 필요
```

### 멱등성 활용

같은 `request_id`로 재전송 시 서버는 캐시된 원본 응답을 반환합니다. 네트워크 오류 후 재시도 시 **동일한 `request_id`를 재사용**하면 중복 처리 없이 원본 결과를 받을 수 있습니다.

```python
# 멱등성 재시도 예시
request_id = str(uuid.uuid4())   # 요청 생성 시 1회만 발급
for attempt in range(3):
    try:
        result = send_request(request_id, ...)
        break
    except NetworkError:
        time.sleep(2 ** attempt)
```

---

## 10. 피드백 제출

탐지 결과가 오탐(잘못 차단)이거나 미탐(놓친 PII)인 경우 피드백을 제출할 수 있습니다.

```http
POST /v1/feedback
Content-Type: application/json
X-Api-Key: 3
X-Timestamp: ...
X-Signature: ...

{
  "request_id": "550e8400-...",
  "attachment_job_id": "a1b2c3d4-...",
  "feedback_type": "false_positive",
  "reason": "회사 대표전화인데 개인정보로 탐지되었습니다.",
  "reporter_email": "user@example.com"
}
```

| 필드 | 필수 | 값 |
|------|------|-----|
| `request_id` | **필수** | 원본 요청 ID |
| `attachment_job_id` | 선택 | 첨부파일 관련 피드백 시 |
| `feedback_type` | **필수** | `false_positive` / `false_negative` |
| `reason` | 선택 | 상세 사유 |
| `reporter_email` | 선택 | 수신 알림용 (서버에 단방향 해시로만 저장) |

응답: `ACK-3010` (HTTP 202)
