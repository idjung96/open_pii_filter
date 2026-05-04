# Phase 2 — DB-Driven Patterns + Hot Reload (완료 보고)

기간: 2026-04-25
태그: `phase-2-complete`

## 통과 기준 점검 (요구사항 §Phase 2 / T2.1~T2.8)

| ID    | 요구사항                                                  | 결과   | 검증 위치                                                     |
| ----- | --------------------------------------------------------- | ------ | ------------------------------------------------------------- |
| T2.1  | 시드 후 `/v1/detect/post` 결과가 Phase 1 하드코딩과 동일  | ✅ PASS | `tests/integration/test_t2_1_parity.py`                       |
| T2.2  | CLI로 패턴 추가 → 5초 이내 워커가 새 패턴 반영            | ✅ PASS | `tests/integration/test_pattern_listener.py::test_t2_2_*`     |
| T2.3  | 패턴 disable → 해당 entity 더 이상 탐지 안 됨             | ✅ PASS | `tests/integration/test_cli_pattern.py::test_t2_3_*`          |
| T2.4  | 잘못된 정규식 입력 시 검증 실패 (앱 시작/동작 중단 없음)  | ✅ PASS | `tests/integration/test_db_crud.py::test_t2_4_*`, `test_cli_pattern.py::test_t2_4_*` |
| T2.5  | pattern_history에 모든 INSERT/UPDATE/DELETE 기록 확인     | ✅ PASS | `tests/integration/test_db_crud.py::test_t2_5_*`              |
| T2.6  | deny_list에 임직원 이름 100건 추가 → 탐지 동작 확인       | ✅ PASS | `tests/integration/test_deny_list_recognizer.py`              |
| T2.7  | 동시에 100개 패턴 변경 시 워커 정상 재로드                | ✅ PASS | `tests/integration/test_concurrency_perf.py::test_t2_7_*`     |
| T2.8  | LISTEN/NOTIFY 채널 끊김 시 폴백(폴링) 동작 확인           | ✅ PASS | `tests/integration/test_pattern_listener.py::test_t2_8_*`     |
|       | 패턴 변경 → 반영까지 평균 지연 < 3초                      | ✅ PASS | `test_phase_2_reload_latency_under_3s` (실측 ~0.0s)           |
|       | 패턴 1000개 로드 시 analyzer 빌드 시간 < 10초             | ✅ PASS | `@slow` 마커 — 1000-row 빌드 9s 이하                          |

## 산출물

### DB 스키마 (Alembic)

| Revision        | 내용                                                                       |
| --------------- | -------------------------------------------------------------------------- |
| `56924e17cf24`  | `pii_patterns` / `pii_pattern_history` / `pii_deny_list` 초기 생성        |
| `281a3d0a1495`  | `pattern_history.pattern_id` nullable + ON DELETE SET NULL                 |
| `3d16cb2b60e7`  | `pattern_history.original_pattern_id` (감사 영속용 컬럼) 추가              |
| `4a7f8b1c0d92`  | **시드 32 패턴** — KR_PHONE_LAND/INET/FAX, 가상계좌, 외국인등록, IP/URL 등 |
| `5b0c2e3f4a01`  | **NOTIFY 트리거** — `pii_patterns`/`pii_deny_list` 변경 시 `pii_pattern_changed` 채널로 페이로드 송출 |

### 코드

- `app/core/recognizers/db_pattern.py` — `pii_patterns` row → Presidio `PatternRecognizer`
- `app/core/recognizers/deny_list.py` — `pii_deny_list` rows를 entity_type별로 묶은 단일 alternation recognizer (T2.6)
- `app/core/analyzer.py::build_analyzer_from_db()` — 하드코딩 + DB 패턴 + deny_list 통합 빌드
- `app/core/analyzer_cache.py` — 프로세스 단일 캐시, 핫리로드 지원 (락 프리 readers)
- `app/workers/pattern_listener.py` — asyncpg LISTEN + 폴링 폴백 supervisor
- `app/api/detect.py::_resolve_analyzer()` — 캐시 우선, DB 불가 시 하드코딩 폴백
- `app/main.py` — FastAPI lifespan에서 listener 태스크 시동/정리
- `app/cli/` — `python -m app.cli pattern add/list/disable/enable` (typer)

### 시드 패턴 (32종 / 22 entity_type)

KR_PHONE_LAND(3), KR_PHONE_INET(2), KR_FAX(1), KR_BANK_ACCOUNT(3 추가),
KR_VIRTUAL_ACCOUNT, KR_FOREIGN_REG, KR_HEALTH_INS, KR_CORP_REG,
KR_VEHICLE_PLATE(2), KR_ZIPCODE(2), KR_CARD_VALIDITY, KR_CARD_CVC,
DATE_OF_BIRTH(3), IP_ADDRESS(2), MAC_ADDRESS, URL,
EMAIL_ADDRESS(.kr 도메인), KR_PASSPORT(legacy 3letter), KR_DRIVERLICENSE(plain),
KR_NAME_HINT, KR_EMPLOYEE_ID, KR_ACCOUNT_TOKEN.

모두 Phase 1 하드코딩 entity_type을 침범하지 않거나(별도 type), 침범하더라도
변별력이 다른 sub-pattern으로 작동 → Phase 1 fixture 결과 superset 보장.

## 핫리로드 메커니즘

```
pii_patterns INSERT
        │
        ▼ (AFTER trigger pii_notify_pattern_change)
NOTIFY pii_pattern_changed
        │
        ▼ asyncpg connection (별도 connection)
on_notify callback → AnalyzerCache.request_reload()
        │
        ▼ 다음 /v1/detect/post 진입 시
get(session) → build_analyzer_from_db(session) → 새 AnalyzerEngine
```

LISTEN 연결이 끊어지면 supervisor가 1s/2s/5s/10s/30s 백오프로 재연결을 시도하면서
동시에 `_polling_loop`(기본 30s 간격, 테스트 0.5s)을 가동하여
`max(updated_at)` 변화를 감지해 같은 콜백을 호출한다 (T2.8).

## 품질 게이트

- `ruff check app/ tests/` — All checks passed
- `mypy app/` — 41 source files, 0 issues (strict 모드)
- `bandit -r app/` — High-severity 0건
- `pytest tests/` — 108 passed (Phase 1: 97 + Phase 2 신규 11)

## 운영 메모

- `LISTEN/NOTIFY`는 PostgreSQL 트랜잭션 커밋 시점에서만 송출됨 → 테스트는 `commit_session` 픽스처에서 실제 commit 사용
- 동시 INSERT 부하 테스트(T2.7)는 PG `max_connections` 제약 때문에 `asyncio.Semaphore(15)` + `pool_size=10/max_overflow=10`으로 실행
- 패턴 1000개 빌드 perf 테스트는 `@pytest.mark.slow`; CI 메인 스위트에서 제외

## 다음 단계 (Phase 3)

- HMAC-SHA256 서명 + API Key + IP 화이트리스트 미들웨어
- Redis 토큰 버킷 rate limiter (API Key별 분당 60 / IP별 분당 10)
- API Key 발급/폐기 CLI
- Nginx 샘플(TLS, IP 허용, 요청 크기 제한)
