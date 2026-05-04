# Phase 3 — 인증·인가·Rate Limiting (완료 보고)

기간: 2026-04-25
태그: `phase-3-complete`

## 통과 기준 점검 (요구사항 §Phase 3 / T3.1~T3.10)

| ID    | 요구사항                                                | 결과   | 검증 위치                                                 |
| ----- | ------------------------------------------------------- | ------ | --------------------------------------------------------- |
| T3.1  | 유효한 HMAC → 200 응답                                  | ✅ PASS | `tests/integration/test_auth_hmac.py::test_t3_1_*`        |
| T3.2  | 잘못된 서명 → 401 (REQ-4010)                            | ✅ PASS | `test_auth_hmac.py::test_t3_2_*`                          |
| T3.3  | 5분 초과 timestamp → 401 (REQ-4012)                     | ✅ PASS | `test_auth_hmac.py::test_t3_3_*`                          |
| T3.4  | 동일 (timestamp, nonce) 재전송 → 401 (REQ-4013)         | ✅ PASS | `test_auth_hmac.py::test_t3_4_*`                          |
| T3.5  | API Key 없음 → 401 (REQ-4011)                           | ✅ PASS | `test_auth_hmac.py::test_t3_5_*`                          |
| T3.6  | 폐기된 API Key → 403 (REQ-4014)                         | ✅ PASS | `test_auth_hmac.py::test_t3_6_*`                          |
| T3.7  | 분당 60회 초과 → 429 + Retry-After                      | ✅ PASS | `tests/integration/test_rate_limit.py::test_t3_7_*`       |
| T3.8  | 화이트리스트 외 IP → 403 (REQ-4015)                     | ✅ PASS | `tests/integration/test_ip_allowlist.py::test_t3_8_*`     |
| T3.9  | 1MB 초과 요청 본문 → 413 (REQ-4030)                     | ✅ PASS | `tests/integration/test_body_size_limit.py::test_t3_9_*`  |
| T3.10 | 100 RPS 부하 → 정상 응답률 > 99%                        | ✅ PASS | `test_load_smoke.py` (100/100 = 100%, in-process)         |

## 산출물

### DB 스키마 (Alembic)

| Revision        | 내용                                                                            |
| --------------- | ------------------------------------------------------------------------------- |
| `ff6df8c4d0ad`  | `pii.api_keys` (key_id/secret_hash/name/ip_allowlist/rate_per_minute/rate_per_hour/enabled/revoked_at) + `pii.api_key_nonces` (key_id, nonce PK; used_at index) |

### 보안 모듈

- `app/security/api_key.py` — issue/revoke/list helpers + salted SHA-256
  hash of `(key_id ":" secret)`. 평문 secret은 발급 시점 1회만 노출.
- `app/security/hmac_auth.py` — HMAC-SHA256 검증, ±5분 timestamp 윈도우,
  nonce 단일 사용 (Postgres `ON CONFLICT DO NOTHING` + RETURNING).
  Canonical: `{ts}\n{nonce}\n{METHOD}\n{PATH}\n{sha256_hex(body)}`.
- `app/security/rate_limit.py` — Redis Lua GCRA 토큰 버킷.
  분당/시간당 두 버킷 모두 통과해야 허용. Retry-After 초 산출.
- `app/security/ip_allowlist.py` — 글로벌+퍼키 CIDR 매칭 (ipaddress).
- `app/security/body_size.py` — Starlette 미들웨어. Content-Length 또는
  스트리밍 검증, 1MB 초과 시 REQ-4030(413) 반환.
- `app/security/auth.py` — 4 검사를 1개 디펜던시(`require_auth`)로
  합성. 실패 순서: HMAC → revoked → IP → rate-limit.

### CLI

`python -m app.cli apikey ...`
- `issue --name X --rate-per-minute 60 --rate-per-hour 1000 --ip-allowlist 10.0.0.0/24`
  → `(key_id, secret)` 1회 출력
- `list [--include-revoked]`
- `disable <key_id>` / `enable <key_id>`
- `revoke <key_id>` (영구 폐기, `revoked_at = now()`)

### Nginx 샘플 (`deploy/nginx.conf`)

- TLSv1.2/1.3, IP allow regex, `client_max_body_size 1m`
- `X-Forwarded-For` 전달 → 앱 단의 `_client_ip()` 가 사용
- 별도 `pii_audit` 로그 포맷 (`request_id`, `apikey`, status)

## HMAC 설계 메모

서명 키는 `secret_hash`(=SHA-256(key_id":"secret))로 사용한다. 즉 클라이언트
도 secret 원문을 SHA-256 처리한 값으로 서명을 만들어야 한다. 이렇게 한 이유:
- 평문 secret은 DB에 절대 저장하지 않는다 (유출 시 직접 사용 불가).
- 서버는 secret 원문 없이도 HMAC 검증이 가능하다.
- bcrypt 같은 단방향 함수는 매 요청마다 100ms+ 비용 → < 5ms 목표 위반.

이 trade-off는 코드 docstring에 명시되어 있다.

## 동시성·테스트 격리

- `pytest-asyncio` 의 loop scope를 `session` 으로 통합 → 한 프로세스 내 모든
  테스트가 같은 이벤트 루프 공유. asyncpg/redis 연결을 lru_cache 하더라도
  교차 테스트 "Event loop is closed" 가 발생하지 않음.
- 테스트는 `client` 픽스처(auth bypass via dependency_overrides)와
  `client_anon` (실제 require_auth 실행) 두 개를 제공.

## 품질 게이트

- `ruff check app/ tests/` — All checks passed
- `mypy app/` — 50 source files, 0 issues (strict 모드)
- `bandit -r app/ -q` — High severity 0건
- `pytest tests/` — **138 passed** (123 → +15: T3.1~T3.10 신규)
- 부하 테스트 100/100 = 100% (in-process; 실 환경은 uvicorn worker 수에 따라 스케일)

## 운영 메모

- **운영 주의**: nonce 테이블은 자연 증가. `app.security.hmac_auth.vacuum_old_nonces()`
  를 cron 등에서 10~30분 주기로 호출 (현재 10분 retention).
- **Redis 비암호**: 개발 환경. 운영 전환 시 `requirepass` + `REDIS_URL` 갱신
  체크리스트는 `memory/project_db_config.md` 에 기록됨.
- **TLS**: 앱은 평문 HTTP. TLS는 Nginx 단에서 처리 (`deploy/nginx.conf`).
- **bandit Medium**: 4건 모두 Low 심각도, asyncpg/typer 등 라이브러리 경고
  성격. spec 통과 기준은 High 0건.

## 운영자 리뷰 후속 (phase-3d)

| Q | 결정 | 변경 |
| - | --- | --- |
| Q1 | 표준 HMAC: 평문 secret을 DB·클라이언트 모두 사용 | 마이그레이션 `7d2e9a8b3c14` 가 `secret_hash → secret` 컬럼 리네임 |
| Q2 | 인증 실패 시 IP 토큰 차감 → 분당 10회 초과면 429 | `app/security/auth.py::_ip_failure_burst` |
| Q3 | 인증 실패 응답 envelope 평면화 (`{"detail": …}` 제거) | `EnvelopeHTTPException` + FastAPI exception_handler |
| Q4 | nonce vacuum을 lifespan 백그라운드 태스크로 자동 실행 (10분 주기) | `app/workers/nonce_vacuum.py` |
| Q5 | `X-Forwarded-For` 신뢰 → `Settings.trust_forwarded_for` 플래그(기본 `false`) | `app/config.py` + `_client_ip()` 분기 |

추가 테스트: `tests/integration/test_ip_burst_throttle.py` (Q2 검증).

## 다음 단계 (Phase 4 — 첨부파일 텍스트 추출 + Case C)

- PDF/DOCX/HWPX 추출기, ClamAV 통합
- `/v1/jobs/{job_id}` 비동기 작업 상태 조회
- Webhook 발송기 (HMAC 서명 + 지수 백오프)
- 22개 시나리오 (T4.1~T4.23)
