# Open PII Filter — PII Detection & Pre-publication Gate API

기관 공공 홈페이지 / 게시판 등 **외부에 공개되는 텍스트·첨부파일이 게시되기 전에 개인정보(PII)를 식별·차단**하기 위한 한국어 중심의 self-hosted REST API.

---

## 프로젝트 목적

공공기관·기업 홈페이지의 자유 게시판·민원 창구·문의 게시판에는 작성자가 의도치 않게 **주민등록번호·연락처·계좌번호·신분증 사진** 등을 그대로 올리는 사고가 반복됩니다. 한 번 외부에 노출된 개인정보는 색인·캐싱·스크래핑을 통해 사실상 회수 불가능하며, 운영 기관은 개인정보 보호법 위반 책임을 집니다.

본 프로젝트는 그 사고 자체를 **게시 시점 이전에 차단**하기 위한 게이트웨이입니다.

- 게시 직전 호출되는 **단일 REST 엔드포인트** (`POST /v1/detect/post`)
- **자체 호스팅** — 외부 클라우드 LLM 으로 PII 가 송출되는 경로 없음 (사내 vLLM 도 옵트인)
- **한국어 PII 에 특화** — 주민등록번호 / 운전면허번호 / 여권번호 / 외국인등록번호 / 사업자등록번호 / 한국 전화번호 (지역번호 없는 표기 포함) 의 체크섬·컨텍스트 기반 인식
- **첨부파일까지 동일 게이트** — PDF·DOCX·XLSX·PPTX·텍스트·이미지 본문을 추출/OCR 후 같은 정책으로 검사

---

## 프로젝트 설명

### 처리 모델 — 단일 엔드포인트 + 비동기 첨부

- **Case A** — 본문에 BLOCK 급 PII → 즉시 HTTP 200 BLOCK, 첨부 검사 생략
- **Case B** — 본문 PASS + 첨부 없음 → 즉시 HTTP 200 PASS
- **Case C** — 본문 PASS + 첨부 있음 → HTTP 202 ACK + 워커가 `fetch_url` 로 받아 OCR/파싱 후 `callback_url` 로 webhook 회신

### 탐지 엔진 스택

- **Microsoft Presidio** 위에 한국어 커스텀 인식기 (`app/core/recognizers/`) — 정규식 + 체크섬 + 컨텍스트 부스트
- **spaCy `ko_core_news_lg`** 토크나이저
- **3-tier strictness** (low / medium / high) — 게시판 성격에 따라 클라이언트가 임계값 선택

### 첨부 텍스트 추출 — 형식별 분기

| 형식 | 라이브러리 | OCR? |
|------|-----------|------|
| PDF (텍스트 레이어) | pypdfium2 + pdfplumber | ❌ |
| PDF (스캔본) | pypdfium2 → PaddleOCR | ✅ |
| DOCX / XLSX / PPTX | python-docx / openpyxl / python-pptx | ❌ |
| HWPX | lxml (XML 직접 파싱) | ❌ |
| 이미지 | PaddleOCR (CPU 기본) → vLLM Qwen3.5-VL 폴백 | ✅ |
| TXT / MD | UTF-8 → CP949 폴백 | ❌ |

HWP·HWPX·ZIP·OLE 레거시 (`.doc`/`.xls`/`.ppt`) 는 `attachment_blocklist` deny-list 가 일괄 거절 (`REQ-4035`).

### 보안·운영 특성

- HMAC-SHA256 + API Key + ±5분 timestamp + nonce 재사용 차단
- IP allowlist (외부 `:443` / 관리자 `:8443` 신뢰영역 분리)
- append-only `audit_events` (BEFORE UPDATE/DELETE 트리거, 1년 보존)
- AES-256-GCM envelope 암호화 헬퍼 (키 로테이션 대응)
- 평문 PII 는 **로그·메트릭·트레이스·DB 어디에도 저장되지 않음**
- Prometheus 메트릭 + `/admin/*` 운영자 대시보드 (검사 토글, 검사 테스트, 차단 이력, 패턴 관리)
- **AGPL / SSPL** 라이선스 라이브러리 직접 의존 금지 (PyMuPDF / pyhwp 차단)

상세 — [`docs/system_architecture.md`](docs/system_architecture.md) · [`docs/data_flow.md`](docs/data_flow.md) · [`docs/api_integration.md`](docs/api_integration.md)

---

## 소프트웨어 구성 및 역할

운영 환경에서 동작하는 각 소프트웨어/라이브러리의 역할을 한 번에 정리한 표입니다. 전체 목록·라이선스·핀 버전은 관리자 대시보드 `/admin/dependencies` 에서 항상 최신 상태를 확인할 수 있습니다.

### 애플리케이션 런타임

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **FastAPI** (+ Starlette / Uvicorn) | MIT / BSD-3 | REST API 프레임워크 + ASGI 서버. `POST /v1/detect/post` 등 모든 엔드포인트 호스팅 |
| **Pydantic v2** + **pydantic-settings** | MIT | 요청/응답 스키마 검증, `.env` 기반 Settings |
| **python-multipart** | Apache-2.0 | `multipart/form-data` 파싱 — `/admin/test` 첨부 업로드 |
| **Jinja2** | BSD-3 | 관리자 대시보드 (`/admin/*`) 템플릿 렌더링 |

### PII 탐지 엔진

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **Microsoft Presidio (analyzer)** | MIT | PII 분석 프레임워크 — 커스텀 인식기 등록/실행, decision-process 노출 |
| **spaCy** + `ko_core_news_lg` | MIT / CC BY-SA 4.0 | 한국어 토크나이저 (Phase 9E 이후 NER 미사용) |
| **커스텀 KR 인식기** | GPL-3.0 (본 저장소) | 주민등록번호·운전면허·여권·외국인등록·사업자번호·KR_PHONE (지역번호 없는 표기 포함) 정규식 + 체크섬 + 컨텍스트 부스트 |

### 파일 추출 / OCR

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **pypdfium2** | Apache-2.0 / BSD-3 | PDF 페이지 렌더 (스캔본 OCR 입력 생성) |
| **pdfplumber** | MIT | PDF 텍스트 레이어 추출 (스캔본은 자동으로 OCR 경로로 라우팅) |
| **python-docx** | MIT | DOCX 단락/표 텍스트 추출 |
| **openpyxl** | MIT | XLSX 셀 텍스트 추출 (Phase 4b) |
| **python-pptx** | MIT | PPTX 슬라이드/표 텍스트 추출 (Phase 4b) |
| **lxml** | BSD-3 | HWPX XML 직접 파싱 (별도 HWP 라이브러리 미사용) |
| **PaddleOCR PP-OCRv5 (한국어, CPU)** | Apache-2.0 | 이미지 OCR **기본 엔진** — in-process, 외부 송출 없음 |
| **vLLM + Qwen3.5-VL** | Apache-2.0 | OCR 폴백 / 옵트인 (`OCR_ENGINE=vlm`) — 사내 GPU 서버, 외부 클라우드 호출 없음 |
| **Pillow** | MIT-CMU | 이미지 로딩 / EXIF 회전 / 다운스케일 |

### 저장소 / 메시징

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **PostgreSQL 16** | PostgreSQL | 주 데이터베이스 — API 키 / 감사 이벤트 / 정책 / 작업 상태 / 피드백. pgcrypto AES 사용 |
| **SQLAlchemy 2.x (async)** + **asyncpg** | MIT / Apache-2.0 | 런타임 ORM (asyncio) |
| **psycopg2-binary** | LGPL-3.0 | Alembic 마이그레이션 전용 동기 드라이버 |
| **Alembic** | MIT | DB 스키마 마이그레이션 |
| **Redis 7** + **redis-py** | RSALv2/SSPL (서버) · MIT (클라이언트) | GCRA 토큰 버킷 rate-limit · HMAC nonce 중복 캐시 (사내 자체 호스팅) |

### 보안 / 통신

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **httpx** | BSD-3 | 비동기 HTTP 클라이언트 — 첨부 fetch, webhook 송신, ASGI 인-프로세스 테스트 |
| **clamd** + **ClamAV 1.3** | LGPL-3.0 · GPL-2.0 | 첨부 INSTREAM 악성코드 스캔 (소프트 실패 허용) |
| **cryptography** | Apache-2.0 / BSD | AES-256-GCM envelope 암호화 (`app/security/encryption.py`, 키 로테이션 대응) |
| **Nginx** | BSD-2 | TLS 종단 · 외부 `:443` / 관리자 `:8443` 신뢰영역 분리 |

### 운영 / 관측

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **prometheus-client** | Apache-2.0 | `/v1/admin/metrics` 노출 — `detect_total`, `block_total`, `ocr_duration_seconds`, `attachment_size_bytes` |
| **Typer** | MIT | API 키 / 패턴 관리 CLI (`python -m app.cli`) |
| **Docker / Docker Compose** | Apache-2.0 | 컨테이너 빌드 · 로컬 의존성 묶음 |

### 개발 / CI 도구

| 소프트웨어 | 라이선스 | 역할 |
|-----------|---------|------|
| **Ruff** | MIT | 린트 + 포매터 (CI 게이트) |
| **mypy (strict)** | MIT | 타입 체크 (CI 게이트) |
| **bandit** | Apache-2.0 | 보안 정적 분석 |
| **pip-audit** | Apache-2.0 | 의존성 취약점 스캔 |
| **pytest** + **pytest-asyncio** | MIT / Apache-2.0 | 단위 / 통합 테스트 러너 — 총 328 케이스 ([`docs/test_catalog.md`](docs/test_catalog.md)) |
| **Locust** | MIT | 부하 테스트 (`tests/load/`) |
| **reportlab** (테스트 전용) | BSD-3 | 합성 PDF / 스캔 PDF 픽스처 생성 |
| **pre-commit** | MIT | pre-commit 훅 관리 |

> **AGPL / SSPL 라이브러리 직접 의존 금지** — PyMuPDF (AGPL), pyhwp (AGPL) 등 외부 노출 API 에서 강한 copyleft 전파를 일으키는 라이브러리는 차단. MongoDB / Redis 서버 자체의 SSPL 은 외부 데몬으로 사용하는 한 무관.

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
# 필요: Python 3.12+, uv, PostgreSQL 16, Redis 7, ClamAV 1.3 (선택)
cp .env.example .env
uv sync
python -m spacy download ko_core_news_lg
alembic upgrade head
uvicorn app.main:app --reload   # http://127.0.0.1:8000
```

### 사전 조건 점검

`pytest` 를 돌리기 전에 환경이 준비됐는지 한 번에 점검할 수 있습니다.

```bash
.venv/bin/python scripts/check_test_prereqs.py
```

점검 항목:
- Python 3.12 이상
- 핵심 런타임 패키지 (FastAPI / Presidio / spaCy / PaddleOCR / SQLAlchemy / Redis 등) import 가능 여부
- spaCy `ko_core_news_lg` 모델 설치 여부
- PostgreSQL · Redis TCP 도달성 (`.env` 의 `DATABASE_URL` / `REDIS_URL`)
- ClamAV TCP (선택 — 없으면 ⚠ 경고, 관련 테스트는 자동 skip)
- VLM 엔드포인트 (선택 — `OCR_ENGINE=paddle` 기본이면 skip)

필수 항목 실패 시 종료 코드 1, 통과 시 0. 자세한 항목 목록은 [`docs/test_catalog.md`](docs/test_catalog.md) §공통 사전 조건 참고.

---

## 단일 서버 운영 주의사항

모든 컴포넌트(FastAPI + PostgreSQL + Redis + ClamAV + PaddleOCR)를 한 호스트의 Docker Compose 로 운영할 때 권장 사양과 운영 가이드입니다. vLLM 은 사용하지 않고 PaddleOCR(CPU) 로 모든 OCR 을 처리한다는 전제.

### 권장 사양 (단일 서버, vLLM 미사용)

| 부하 가정 | CPU | RAM | Disk |
|---|---|---|---|
| **최소** (PoC / 게시판 ≤ 50 posts/시간 / 첨부 ≤ 10%) | 4 vCPU | 8 GB | 100 GB SSD |
| **표준 권장** (100~500 posts/시간 / 첨부 ≤ 30%) | **8 vCPU** | **16 GB** | **200 GB SSD** |
| **여유** (첨부 빈도 50%+, OCR 페이지 다수) | 16 vCPU | 32 GB | 500 GB SSD |

부하 테스트(`docs/load_test_report.md`)상 본문 분석 한정으로 단일 인스턴스 ~60 RPS / p99 ≈ 1 s. OCR 첨부가 핵심 병목.

### CPU 요구 — AVX2 필수

PaddleOCR / spaCy 추론은 AVX2 명령어를 적극 활용합니다. **AVX2 미지원 CPU 에서는 OCR 이 5~10 배 느려지므로 운영 환경에서 사실상 사용 불가**합니다.

**AVX2 지원 CPU (x86_64)**

| 벤더 | 세대/제품군 | 출시 시점 |
|---|---|---|
| **Intel Core** | Haswell (4th gen, i3/i5/i7-4xxx) 이후 — 4th ~ 14th gen | 2013 ~ |
| **Intel Xeon** | E3/E5/E7 v3 이후, Xeon Scalable(Skylake-SP) 전 세대 | 2014 ~ |
| **Intel Atom** | Tremont(C5xxx, N6xxx) 이후 (Goldmont Plus 는 부분 지원) | 2020 ~ |
| **AMD Ryzen** | Zen1(Ryzen 1000) 이후 — 모든 Zen2/Zen3/Zen4/Zen5 | 2017 ~ |
| **AMD EPYC** | Naples(7001) 이후 — Rome/Milan/Genoa/Bergamo 전부 | 2017 ~ |
| **AMD Threadripper** | 전 모델 | 2017 ~ |

> ⚠ **미지원**: Intel Pentium/Celeron 저전력 모델 일부, Intel Atom Bay Trail/Cherry Trail/Apollo Lake, 모든 **ARM CPU** (Apple Silicon, AWS Graviton, Ampere Altra 등 — Neon 으로 동작은 하지만 성능 저하). 운영 환경 권장 X.

**클라우드 인스턴스 — AVX2 지원 확인된 패밀리**

| 클라우드 | 지원 | 비지원 |
|---|---|---|
| AWS EC2 | t2 / t3 / t3a / m5 / m5a / c5 / c5a / r5 / r5a 이상 | Graviton(t4g/m6g/c6g/r6g 등) |
| GCP | n1 / n2 / n2d / c2 / c2d / e2 이상 | Tau T2A(ARM) |
| Azure | D / E / F-series v3 이상 | Ampere Altra(Dpsv5 등 ARM) |

**런타임 확인**: `grep -m1 avx2 /proc/cpuinfo` (출력 있어야 OK)

### 메모리 예산 (16 GB 기준 피크)

```
FastAPI + Presidio + spaCy + PaddleOCR 모델 + 인식기 캐시 ........ ~2.5 GB
PostgreSQL 16 (shared_buffers 512 MB) ........................... ~1.0 GB
Redis 7 (idempotency 24h + rate-limit + nonce 캐시) ............. ~0.3 GB
ClamAV daemon (시그니처 풀로드) ................................. ~1.5 GB
첨부 추출/OCR 작업 transient peak ............................... ~2.0 GB
OS / kernel / page cache / 컨테이너 오버헤드 .................... ~2.0 GB
─────────────────────────────────────────────────────────────────
합계 ≈ 9.3 GB                       여유 ≈ 6.7 GB ✅
```

### 운영 체크리스트

1. **AVX2 확인 후 배포** — `grep -m1 avx2 /proc/cpuinfo` 로 사전 점검. 미지원 시 호스트 교체 필요.
2. **`OMP_NUM_THREADS=1` / `MKL_NUM_THREADS=1`** — 컨테이너 env 로 고정. PaddleOCR 내부 스레드가 코어를 점유해 본문 분석 latency 가 튀는 것을 방지.
3. **swap 비활성화** (RAM 16 GB 이상 호스트) — OCR 워커가 swap 에 빠지면 한 첨부에 분 단위 소요. `swapoff -a` + `vm.swappiness=0`.
4. **Postgres 튜닝** — `shared_buffers=512MB`, `work_mem=16MB`, `effective_cache_size=4GB` 권장.
5. **ClamAV `freshclam`** — 별도 schedule (cron / systemd timer). 시그니처 업데이트 중 RAM 이 일시적으로 +1 GB 사용.
6. **PoC 로그 회전** — `POC_MODE=true` 운영 시 `POC_LOG_FILE` 은 무제한 append. `logrotate` 일/주 단위 설정 필수.
7. **외부 통신 방화벽** — 8000/tcp (또는 nginx 80/443). outbound 80/443 (첨부 fetch + ClamAV 시그니처 + webhook), 내부 5432/6379/3310.
8. **컨테이너 디스크 모니터링** — `pgdata` 볼륨 + audit 1년 보존 + PoC 로그. 200 GB 기준 5년 이상 여유.

### 디스크 사용 추정 (1년 기준)

| 항목 | 크기 |
|---|---|
| 컨테이너 이미지 + 모델 (spaCy 600 MB + PaddleOCR 200 MB + venv 3 GB) | ~5 GB |
| Postgres `detections` 30일 retention (AES-256 암호화) | ~1~2 GB |
| Postgres `audit_events` 365일 retention | ~1~3 GB |
| PoC 로그 (`POC_LOG_FILE`) — logrotate 가정 | ~1~5 GB |
| Redis AOF | ~500 MB |

> 상세 운영 절차 → [`docs/operations.md`](docs/operations.md)

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **텍스트 PII 탐지** | 주민등록번호, 운전면허, 여권, 전화번호, 이메일, 계좌번호 등 |
| **첨부파일 분석** | PDF, DOCX, XLSX, PPTX, 텍스트(.txt/.md), 이미지 (비동기 처리 + 웹훅) |
| **이미지 OCR** | PaddleOCR (CPU, 기본) / vLLM Qwen3.5-27B-GPTQ-Int4 (저품질 스캔용 옵트인) |
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
  └─ Image      → PaddleOCR PP-OCRv5 (CPU 기본) — 실패 시 vLLM Qwen3.5-27B-GPTQ-Int4 fallback
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

`system_settings.attachment_scan_enabled` (기본 ON) 을 OFF 로 두면 첨부가
있어도 다운로드/추출/분석 모두 skip 하고 본문 결과만 즉시 반환합니다.
ClamAV / VLM / 추출기 같은 외부 의존이 장애 중일 때 운영 부담을 즉시
줄이는 용도입니다.

**관리자 대시보드 토글**: `/admin/settings` 페이지의 "첨부파일 검사" 카드
에서 즉시 ON/OFF 가능. 폼 제출은 `POST /admin/settings/attachment-scan`
로 라우팅되며 변경은 `data/system_settings.json` 에 영속됩니다 (재배포
필요 없음).

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
- **OCR**: PaddleOCR PP-OCRv5 (한국어, CPU, 기본) / vLLM Qwen3.5-27B-GPTQ-Int4 (`OCR_ENGINE=vlm` 으로 전환 — 저품질 스캔/회전/표 레이아웃 회귀 시)
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
