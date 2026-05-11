# PII Detection & Masking API — 설치 가이드

> 대상: 시스템 관리자 / DevOps 엔지니어  
> 최종 수정: 2026-04-26  
> Python 3.12 · PostgreSQL 16 · Redis 7

---

## 목차

1. [사전 요구사항](#1-사전-요구사항)
2. [빠른 시작 (Docker Compose)](#2-빠른-시작-docker-compose)
3. [수동 설치](#3-수동-설치)
4. [환경 변수 설정](#4-환경-변수-설정)
5. [데이터베이스 초기화](#5-데이터베이스-초기화)
6. [API 키 발급](#6-api-키-발급)
7. [OCR 엔진 설정](#7-ocr-엔진-설정)
8. [Nginx 리버스 프록시](#8-nginx-리버스-프록시)
9. [동작 확인](#9-동작-확인)
10. [업그레이드 절차](#10-업그레이드-절차)

---

## 1. 사전 요구사항

### 필수

| 구성 요소 | 최소 버전 | 비고 |
|-----------|----------|------|
| Docker Engine | 24.x | docker compose v2 플러그인 포함 |
| Python | 3.12 | 수동 설치 시만 필요 |
| PostgreSQL | 16 | `pii` 스키마 사용 |
| Redis | 7 | Rate limiting · 중복 요청 캐시 |
| ClamAV | 1.3 | TCP INSTREAM 모드 (`clamd`) |

### 선택

| 구성 요소 | 용도 |
|-----------|------|
| Nginx | TLS 종단 · 신뢰 영역 분리 |
| PaddleOCR PP-OCRv5 (한국어, CPU) | OCR 기본 엔진 — 런타임에 번들, 첫 실행 시 모델 자동 다운로드 |
| vLLM + Qwen3.5-VL | OCR 폴백 / 옵트인 — `OCR_ENGINE=vlm` 또는 Paddle 예외 시 자동 호출 (GPU 서버) |
| Prometheus + Grafana | 메트릭 수집 · 시각화 |

### 하드웨어 권장 사양

| 환경 | CPU | RAM | 디스크 |
|------|-----|-----|--------|
| 개발 | 4 코어 | 8 GB | 20 GB |
| 운영 (100 RPS) | 8 코어 | 16 GB | 100 GB SSD |
| OCR 포함 | GPU 권장 (A100/4090) | 32 GB | 200 GB SSD |

---

## 2. 빠른 시작 (Docker Compose)

로컬 개발 및 스테이징 환경에서 권장하는 방법입니다.

### 2-1. 저장소 클론

```bash
git clone https://github.com/your-org/pii-api.git
cd pii-api
```

### 2-2. 환경 변수 파일 생성

```bash
cp .env.example .env
```

`.env` 파일에서 최소 아래 항목을 실제 값으로 수정합니다.

```dotenv
# 32바이트 랜덤 hex 키 생성: python3 -c "import secrets; print(secrets.token_hex(32))"
PII_ENCRYPTION_KEY=<32바이트_hex>

# 웹훅 HMAC 서명 키
WEBHOOK_SIGNING_SECRET=<랜덤_문자열>

# 관리자 접속 허용 CIDR (빈 값 → 관리자 API 비활성화)
ADMIN_IP_ALLOWLIST=127.0.0.1/32,10.0.0.0/8

# 회사 정보 (개인정보처리방침 자동 생성용)
COMPANY_NAME=기관
COMPANY_CONTACT_EMAIL=privacy@example.com
```

### 2-3. 컨테이너 시작

```bash
cd deploy
docker compose up --build -d
```

> ClamAV는 바이러스 DB를 최초 다운로드할 때 **2~5분**이 소요됩니다.  
> `docker compose logs -f clamav`로 `LOADED` 메시지를 확인한 뒤 진행합니다.

### 2-4. DB 마이그레이션 실행

```bash
docker compose exec api alembic upgrade head
```

### 2-5. 동작 확인

```bash
curl http://localhost:8000/healthz
# {"status":"ok"}

curl http://localhost:8000/readyz
# {"status":"ok","db":"ok","redis":"ok"}
```

---

## 3. 수동 설치

Docker를 사용하지 않는 경우 또는 별도 인프라를 이용하는 경우의 절차입니다.

### 3-1. Python 환경 구성

```bash
# uv 설치 (권장)
curl -Ls https://astral.sh/uv/install.sh | sh

# 의존성 설치 (PaddleOCR 포함, 별도 extras 불필요)
uv sync
```

> Phase 4b 부터 `paddleocr` / `paddlepaddle` 가 main runtime 의존성에 포함되어 있어 `[ocr]` extras 는 no-op 입니다.

### 3-2. 시스템 서비스 (systemd)

`/etc/systemd/system/pii-api.service` 예시:

```ini
[Unit]
Description=PII Detection & Masking API
After=network.target postgresql.service redis.service

[Service]
User=pii
WorkingDirectory=/opt/pii-api
EnvironmentFile=/opt/pii-api/.env
ExecStart=/opt/pii-api/.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now pii-api
```

### 3-3. spaCy 모델 설치

한국어 NER 모델은 최초 1회 다운로드가 필요합니다.

```bash
python -m spacy download ko_core_news_lg
```

---

## 4. 환경 변수 설정

모든 설정은 환경 변수 또는 `.env` 파일로 주입합니다. 커밋에 포함하지 마십시오.

### 4-1. 데이터베이스 / Redis

| 변수 | 설명 | 예시 |
|------|------|------|
| `DATABASE_URL` | asyncpg 연결 URI | `postgresql+asyncpg://pii:pass@localhost:5432/pii` |
| `DATABASE_URL_SYNC` | psycopg 동기 연결 (Alembic) | `postgresql+psycopg://pii:pass@localhost:5432/pii` |
| `DB_SCHEMA` | PostgreSQL 스키마 이름 | `pii` |
| `REDIS_URL` | Redis 연결 URI | `redis://localhost:6379/0` |

### 4-2. 보안

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `PII_ENCRYPTION_KEY` | AES-256 마스터 키 (32바이트 hex) | **필수** |
| `PII_ENCRYPTION_KEY_ID` | 현재 키 ID (키 로테이션 시 증가) | `1` |
| `PII_ENCRYPTION_OLD_KEYS` | 구버전 키 JSON `{"1":"<hex>"}` | `{}` |
| `WEBHOOK_SIGNING_SECRET` | 웹훅 HMAC 서명 키 | **필수** |
| `ADMIN_IP_ALLOWLIST` | 관리자 API CIDR 목록 (CSV) | `` (비활성) |
| `IP_ALLOWLIST` | 전체 API IP 허용 목록 | `` (제한 없음) |
| `MAX_REQUEST_BODY_BYTES` | HTTP 요청 본문 최대 크기 | `1048576` (1 MB) |

### 4-3. OCR

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `OCR_ENGINE` | `paddle` (기본) 또는 `vlm` | `paddle` |
| `VLM_ENDPOINT` | vLLM API 엔드포인트 — Paddle 폴백 또는 `OCR_ENGINE=vlm` 시 사용 | `http://localhost:18000/v1` |
| `VLM_MODEL_ID` | 모델 식별자 | `Qwen/Qwen3.5-27B-GPTQ-Int4` |
| `VLM_API_KEY` | vLLM API 키 (선택) | `` |
| `OCR_REQUEST_TIMEOUT_SECONDS` | OCR 요청 타임아웃 | `120` |

### 4-4. 알림

| 변수 | 설명 |
|------|------|
| `SMTP_HOST` / `SMTP_PORT` | SMTP 서버 |
| `SMTP_USER` / `SMTP_PASSWORD` | SMTP 인증 |
| `ALERT_EMAIL_FROM` | 발신 주소 |
| `ALERT_EMAIL_TO` | 수신 주소 (CSV) |
| `FEEDBACK_ALERT_THRESHOLD` | 알림 임계값 (건수) |
| `FEEDBACK_ALERT_INTERVAL_SECONDS` | 알림 최소 간격 (초) |

---

## 5. 데이터베이스 초기화

### 5-1. PostgreSQL 스키마 및 사용자 생성

```sql
-- psql로 postgres superuser로 접속하여 실행
CREATE USER pii WITH PASSWORD 'your_strong_password';
CREATE DATABASE pii OWNER pii;
\c pii
CREATE SCHEMA pii AUTHORIZATION pii;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

### 5-2. Alembic 마이그레이션

```bash
# 전체 마이그레이션 적용
alembic upgrade head

# 현재 상태 확인
alembic current

# 마이그레이션 이력 확인
alembic history
```

마이그레이션은 아래 순서로 적용됩니다.

| 리비전 | 내용 |
|--------|------|
| `6d8c4d6…` (Phase 2a) | 기본 ORM 모델 |
| `2401f4a8d84b` (Phase 4) | ExtractionJob |
| `5a885a8844a1` (Phase 5) | MaskedArtifact |
| `8e1f5d2a9c30` (Phase 6) | AuditEvent + append-only 트리거 |
| `9f3a7c2e1b40` (Phase 7) | PiiPolicy · PiiFeedback · pattern_mode |
| `9f3a7c2e1b41` (Phase 7) | AlerterState |

---

## 6. API 키 발급

### 6-1. 외부 클라이언트용 키 발급

```bash
python -m app.cli apikey create \
    --name "bulletin-board-prod" \
    --description "게시판 서비스 운영 키"
```

출력 예시:

```
key_id : 3
secret : sk-a1b2c3d4e5f6...   ← 이 값은 한 번만 표시됨. 반드시 저장하십시오.
```

### 6-2. 관리자 키 발급

```bash
python -m app.cli apikey create \
    --name "admin-ops" \
    --admin \
    --description "운영팀 관리자 키"
```

### 6-3. 키 목록 확인

```bash
python -m app.cli apikey list
```

### 6-4. 키 폐기

```bash
python -m app.cli apikey revoke --key-id 3
```

### 6-5. 클라이언트 요청 예시

```bash
# HMAC-SHA256 서명 헤더 포함 요청
REQUEST_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BODY='{"request_id":"'$REQUEST_ID'","post":{"body":"안녕하세요. 주민등록번호 900101-1234567입니다."}}'
SIGNATURE=$(echo -n "${TIMESTAMP}\n${BODY}" | \
    openssl dgst -sha256 -hmac "YOUR_SECRET_KEY" -hex | awk '{print $2}')

curl -X POST http://localhost:8000/v1/detect/post \
    -H "Content-Type: application/json" \
    -H "X-Api-Key: YOUR_KEY_ID" \
    -H "X-Timestamp: $TIMESTAMP" \
    -H "X-Signature: $SIGNATURE" \
    -d "$BODY"
```

---

## 7. OCR 엔진 설정

### 7-1. PaddleOCR 엔진 (기본, CPU)

`paddleocr` / `paddlepaddle` 은 main runtime 의존성에 포함되어 있어 별도 설치가 필요 없습니다 — `pip install -e .` 만으로 OCR 파이프라인이 자족합니다.

```dotenv
OCR_ENGINE=paddle
OCR_REQUEST_TIMEOUT_SECONDS=120
```

- 첫 실행 시 PP-OCRv5 모델(~500 MB) 을 자동 다운로드 (`~/.paddleocr/`).
- 에어갭 환경에서는 인터넷 연결된 머신에서 모델을 한 번 받아 같은 경로로 복사하거나 `PADDLE_OCR_HOME` 환경 변수로 모델 디렉터리를 지정합니다.
- 모델 워밍업은 첫 호출에서 ~3–5초 발생하니 헬스체크에서 제외하세요.

### 7-2. vLLM 엔진 (옵트인 / Paddle 폴백)

저화질 스캔, 회전된 페이지, 표 레이아웃 회귀 등에서 정확도가 더 필요할 때 켭니다. Paddle 이 예외를 던지면 디스패처가 자동으로 vLLM 으로 폴백하므로 옵트인 없이도 보조 엔진으로 동작합니다.

```bash
# vLLM 서버 구동 예시 (별도 GPU 서버)
vllm serve Qwen/Qwen3.5-VL \
    --port 18000 \
    --max-model-len 8192
```

`.env` 설정:

```dotenv
OCR_ENGINE=vlm                                 # 명시적으로 vLLM 우선
VLM_ENDPOINT=http://192.168.1.100:18000/v1
VLM_MODEL_ID=Qwen/Qwen3.5-VL
OCR_REQUEST_TIMEOUT_SECONDS=120
```

> 첫 번째 요청은 모델 웜업으로 **30초+** 소요될 수 있습니다.

---

## 8. Nginx 리버스 프록시

`deploy/nginx.conf`를 참조하여 신뢰 영역을 분리합니다.

```nginx
# 외부 신뢰 영역 — 게시판 서비스에서 접근
server {
    listen 443 ssl;
    server_name pii-api.example.com;
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # 관리자 경로는 외부에서 완전 차단
    location /v1/admin/ { return 404; }

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_read_timeout 180s;
    }
}

# 내부 신뢰 영역 — 사내망 전용
server {
    listen 8443 ssl;
    server_name pii-admin.example.internal;

    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny  all;

    location /v1/admin/ {
        proxy_pass http://127.0.0.1:8000;
    }
}
```

---

## 9. 동작 확인

### 9-1. 헬스체크

```bash
# Liveness (I/O 없음 — LB 헬스체크용)
curl http://localhost:8000/healthz
# {"status":"ok"}

# Readiness (DB + Redis 연결 확인)
curl http://localhost:8000/readyz
# {"status":"ok","db":"ok","redis":"ok"}
```

### 9-2. 텍스트 PII 탐지 (Case B)

```bash
curl -s -X POST http://localhost:8000/v1/detect/post \
    -H "Content-Type: application/json" \
    -H "X-Api-Key: 1" \
    -H "X-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -H "X-Signature: test" \
    -d '{
      "request_id": "00000000-0000-0000-0000-000000000001",
      "post": {"body": "문의: 010-0000-1234로 연락주세요."}
    }' | python3 -m json.tool
```

### 9-3. 관리자 감사로그 조회

```bash
# 관리자 키 + 내부망에서만 응답
curl -H "X-Api-Key: ADMIN_KEY_ID" \
     -H "X-Timestamp: ..." \
     -H "X-Signature: ..." \
     http://pii-admin.example.internal:8443/v1/admin/audit-events?limit=20
```

### 9-4. Prometheus 메트릭

```bash
curl http://localhost:8000/v1/admin/metrics   # 관리자 키 필요
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
# ...
```

---

## 10. 업그레이드 절차

```bash
# 1. 새 이미지 빌드 및 마이그레이션 적용
git pull origin main
cd deploy
docker compose build api
docker compose run --rm api alembic upgrade head

# 2. 무중단 재시작
docker compose up -d --no-deps api

# 3. 동작 확인
curl http://localhost:8000/readyz
```

### AES 키 로테이션

```bash
# 1. 새 키 생성
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
OLD_KEY_ID=1
OLD_KEY=<기존_키_hex>

# 2. .env 업데이트
PII_ENCRYPTION_KEY=$NEW_KEY
PII_ENCRYPTION_KEY_ID=2
PII_ENCRYPTION_OLD_KEYS={"1":"$OLD_KEY"}

# 3. 서비스 재시작 (신규 암호화는 키ID=2, 구버전 복호화는 키ID=1 사용)
docker compose up -d --no-deps api
```

---

## 트러블슈팅

| 증상 | 원인 | 조치 |
|------|------|------|
| `readyz` → `"db":"error"` | DB 연결 실패 | `DATABASE_URL` 확인, PostgreSQL 상태 확인 |
| `readyz` → `"redis":"error"` | Redis 연결 실패 | `REDIS_URL` 확인, Redis 상태 확인 |
| OCR 응답 없음 (SVR-5004) | Paddle 초기화 실패 + VLM 폴백도 다운 | `OCR_ENGINE` 확인, `~/.paddleocr` 모델 다운로드 여부 확인, VLM 폴백 사용 시 `VLM_ENDPOINT` 확인 |
| 관리자 API 404 | `ADMIN_IP_ALLOWLIST` 미설정 | `.env`에 CIDR 추가 후 재시작 |
| ClamAV 연결 실패 | clamd 미구동 | `docker compose up clamav` 또는 소프트 실패 허용 |
| `REQ-4030` | 요청 본문 초과 | `MAX_REQUEST_BODY_BYTES` 조정 |

로그 확인:

```bash
docker compose logs -f api
# 또는
journalctl -u pii-api -f
```
