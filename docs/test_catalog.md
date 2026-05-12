# 테스트 케이스 카탈로그

> 최종 갱신: 2026-05-08  
> 본 문서는 저장소에 들어 있는 **모든 자동 회귀 테스트 케이스**를 한눈에 보기 위한 색인입니다.
> 첨부파일 처리 기능에 대한 **시나리오 명세** (각 케이스마다 자동 + 수동 검증 절차) 는
> [`docs/phase_4b_attachment_test_spec.md`](phase_4b_attachment_test_spec.md) 를 함께 참고하세요.

## 현황 (2026-05-08)

| 분류 | 파일 | 테스트 케이스 |
|------|------|---------------|
| Unit | 18 | 162 |
| Integration | 32 | 166 |
| **합계** | **50** | **328** |

부하 테스트는 별도 카테고리 — [`tests/load/`](../tests/load/) (Locust, `--slow` 마커).

## 실행 방법

```bash
# 전체 (단위 + 통합)
.venv/bin/pytest tests/unit tests/integration -q

# 빠른 피드백 — 단위 테스트만
.venv/bin/pytest tests/unit -q

# 특정 파일
.venv/bin/pytest tests/unit/test_kr_phone_recognizer.py -v

# 마커 — 부하/장기 실행
.venv/bin/pytest -m slow
```

CI 게이트 (`.github/workflows/ci.yml`) — `ruff check . && ruff format --check . && mypy app/ && pytest`.
DB 없이 import 가능한 케이스만 CI 에서 자동 수집되며, **PostgreSQL/Redis 실제 연결이 필요한 케이스**는 사전 조건이 충족돼야 통과합니다 (`docker compose up` 또는 로컬 데몬).

## 공통 사전 조건

- Python 3.12+, `uv sync` 로 의존성 설치
- spaCy 모델: `python -m spacy download ko_core_news_lg`
- PostgreSQL 16 + Redis 7 기동 (통합 테스트의 약 절반)
- ClamAV 는 선택 — 없으면 `tests/integration/test_phase4_extractors.py::test_clamav_unavailable` 등이 자동 skip
- VLM 엔드포인트도 선택 — `OCR_ENGINE=paddle` 가 기본이므로 vLLM 미가동 환경에서도 OCR 회귀는 PaddleOCR 로 통과
- **모든 fixture 는 합성 PII** (`tests/fixtures/synthetic_pii_generator.py`). 실제 개인정보 사용 금지

---

## 1. Unit 테스트 (162 cases / 18 files)

### 1.1 응답·정책·코드

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_codes.py` | 11 | `ResponseCode` 카탈로그 무결성, `build_response` 템플릿 채움, verdict ↔ HTTP 매핑 (T1.11~T1.17) |
| `test_policies.py` | 29 | `(entity_type, score band) → response_code` 매핑, 3-tier strictness 임계값, deny-list override, log-only 강등 (Phase 1c→9D) |
| `test_user_message_kr.py` | 4 | `build_response` 한국어 entity-label 접미사 (`주민등록번호 등`) |
| `test_entity_labels.py` | 6 | Korean entity-label mapping 헬퍼 (`entity_type → 한국어 표기`) |

### 1.2 탐지 엔진 & 인식기

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_analyzer.py` | 7 | Presidio + 커스텀 KR 인식기 통합 — RRN/Phone/Email/사업자번호 4-format 검출 (T1.1~T1.10) |
| `test_kr_phone_recognizer.py` | 25 | KR_PHONE 확장 — 모바일 010-019, 유선 02/031-064, 070/080/050X, 지역번호 없는 표기 (`1234-5678`) 의 context-gated BLOCK |
| `test_dedup.py` | 2 | top-3 per span 중복 제거 (Phase 9E-A) |
| `test_detect.py` | 14 | `POST /v1/detect/post` 핸들러 단위 — 요청 검증 → 분석 → 응답 매핑 (T1.18~T1.28) |
| `test_blocklist_cache.py` | 7 | `app.core.blocklist_cache` lookup + reload (Phase 4b) |

### 1.3 파일 추출 (Phase 4b)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_dispatcher_phase4b.py` | 3 | MIME → 추출기 라우팅 매트릭스 (PDF/DOCX/XLSX/PPTX/이미지/TXT/HWPX/HWP5) |
| `test_extract_xlsx.py` | 3 | `openpyxl` 셀 텍스트 추출 + multi-sheet 직렬화 |
| `test_extract_pptx.py` | 3 | `python-pptx` 슬라이드 텍스트 + 표 셀 추출 |

### 1.4 보안·암호화

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_encryption.py` | 10 | AES-256-GCM envelope encode/decode, 키 로테이션, 변조 감지 (Phase 6, T6.2) |

### 1.5 워커·운영

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_send_delete_request.py` | 7 | `webhook_sender.send_delete_request` — 5xx 재시도, 4xx 즉시 포기, HMAC 서명 |
| `test_metrics_collector.py` | 7 | Prometheus 지표 — `detect_total`, `block_total`, `ocr_duration_seconds`, `attachment_size_bytes` |
| `test_healthz.py` | 2 | `/healthz` liveness (Phase 0, T0.2) |
| `test_config.py` | 2 | `.env` 파싱 + Settings 검증 |

### 1.6 합성 데이터

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_synthetic_generator.py` | 20 | RRN/사업자번호 체크섬·Luhn 알고리즘, 안전 범위 (`010-0000-XXXX`/`@example.com`), 부정 케이스 (T6.1~T6.7) |

---

## 2. Integration 테스트 (166 cases / 32 files)

### 2.1 인증·인가 (Phase 3)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_auth_hmac.py` | 6 | HMAC 헤더 4종 누락/위조/timestamp skew/nonce 재사용 (T3.1~T3.6) |
| `test_ip_allowlist.py` | 4 | API 키 단위 IP allowlist 매칭 (T3.8) |
| `test_ip_burst_throttle.py` | 1 | 동일 IP 401 연속 시 throttling (Q2) |
| `test_rate_limit.py` | 2 | per-API-key / per-IP GCRA rate limit (T3.7) |
| `test_body_size_limit.py` | 2 | 요청 본문 1 MiB 한도 → REQ-4030 (T3.9) |
| `test_load_smoke.py` | 1 | 100 RPS smoke — ≥99% 성공 (T3.10) |

### 2.2 본문 PII (Phase 1)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_deny_list_recognizer.py` | 2 | 100명 직원명 deny-list 매칭 — `build_analyzer_with_deny_list` (T2.6) |
| `test_deny_list_particle.py` | 10 | 조사 부착 (`원효대사와`, `홍길동에게`) 매칭 — UX-3 |
| `test_db_crud.py` | 2 | deny-list CRUD (Phase 2) |

### 2.3 첨부 파이프라인 (Phase 4 / 4b)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_phase4_extractors.py` | 14 | PDF/DOCX/HWPX/이미지/TXT 추출 단위 (T4.1~T4.12) |
| `test_phase4_case_c.py` | 14 | 비동기 fan-out (asyncio worker → DB → webhook), 멱등성 캐시 (T4.13~T4.23) |
| `test_attachment_pipeline_e2e.py` | 19 | 동기 gate — 형식별 MIME 분기 + deny-list (Phase 4b/E) |
| `test_attachment_policy_phase4b.py` | 4 | `detect_post` gate — HWP deny + size/count cap (T4b.7~T4b.10) |
| `test_callback_delete.py` | 3 | callback_url DELETE — BLOCK 시 호출자 retention 정책 반영 (T4b.14~T4b.16) |
| `test_admin_blocklist_api.py` | 6 | `/admin/blocklist` CRUD (T4b.1) |
| `test_exception_ip_audit_only.py` | 2 | exception IP 의 audit-only 모드 — 응답은 PASS 강제 (T4b.11~T4b.13) |
| `test_dashboard_attachment_toggle.py` | 3 | `/admin/settings/attachment-scan` 토글 (Phase 4b/F) |

### 2.4 OCR (Phase 5)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_phase5_ocr.py` | 14 | 이미지 OCR 게이트, VLM SVR-5004 매핑, paddle→vlm 폴백, `OCR_ENGINE=vlm` 분기 (T5.1~T5.8) |
| `test_phase5_scan_pdf.py` | 2 | 스캔 PDF 자동 OCR 라우팅 |
| `test_paddle_ocr_pipeline.py` | 4 | PaddleOCR 기본 엔진 — ID 카드 RRN / 명함 전화번호 / 폴백 / vlm 분기 (Phase 4b) |

### 2.5 감사·로깅·암호화 (Phase 6)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_phase6_audit.py` | 8 | `audit_events` insert + BEFORE UPDATE/DELETE 트리거 + admin API (T6.4~T6.5) |
| `test_phase6_logs_no_pii.py` | 11 | 로그 scrubber — 합성 PII 가 응답 로그에 절대 누출되지 않음 (T6.1) |
| `test_phase6_response_no_plaintext.py` | 3 | 응답 envelope 의 `Detection` 가 PII 평문 비노출 (T6.6) |
| `test_phase6_ttl.py` | 2 | audit 1년 / extraction_jobs 24h GC (T6.3) |

### 2.6 정책·피드백·운영자 (Phase 7)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_phase7_policies.py` | 3 | DB-driven `pii_policies` — log-only override, 패턴별 강등 |
| `test_phase7_feedback.py` | 3 | `POST /v1/feedback` — 오탐/미탐 접수 (T7.4) |
| `test_phase7_alerter.py` | 4 | 피드백 SMTP 알림 (operator-decision A) |
| `test_phase7_stats.py` | 5 | `/admin/stats` 집계 (T7.5) |
| `test_phase7_privacy_notice.py` | 3 | 공개 `/v1/legal/privacy-notice` (operator-decision D) |

### 2.7 메트릭 · E2E (Phase 8)

| 파일 | 케이스 | 검증 영역 |
|------|--------|----------|
| `test_phase8_e2e.py` | 2 | 전체 흐름 ASGI 인-프로세스 E2E (T8.1) |
| `test_phase8_failure_modes.py` | 5 | 의존 시스템 다운 시 graceful degradation — DB/Redis/ClamAV/OCR (T8.3) |
| `test_phase8_metrics.py` | 2 | Prometheus exporter `/v1/admin/metrics` (T8.4) |

---

## 3. 부하 테스트 (Locust)

| 위치 | 시나리오 | 비고 |
|------|---------|------|
| [`tests/load/locustfile.py`](../tests/load/locustfile.py) | `POST /v1/detect/post` 합성 본문 / 첨부 mix | `tests/load/README.md` 참고 |
| [`docs/load_test_report.md`](load_test_report.md) | 100 RPS 결과 보고서 | Phase 8 T8.2 |

`pytest -m slow` 로 묶인 케이스도 부하성 — 단위/통합 기본 실행에서는 자동 제외됩니다.

---

## 4. 합성 데이터 정책

> ⚠️ **실제 PII 사용 금지** — 개발자 본인의 정보도 안 됩니다 (`CLAUDE.md` § Synthetic Test Data).

- 모든 fixture 는 `tests/fixtures/synthetic_pii_generator.py` 의 안전 범위 사용:
  - 휴대폰: `010-0000-XXXX`
  - 이메일: `@example.com`, `@test.local`
  - 주민등록번호: 합성 — 체크섬은 유효하나 실재 발급되지 않은 범위
- 각 fixture 파일 머리에 `# SYNTHETIC DATA - NOT REAL PII` 주석 부착
- CI 의 `real_pii_scan.py` 가 PR 마다 fixture 디렉터리를 스캔해 실 PII 패턴 발견 시 즉시 실패

---

## 5. 신규 테스트 추가 가이드

- **위치**: 단위면 `tests/unit/test_<영역>.py`, 통합이면 `tests/integration/test_<phase>_<영역>.py`
- **합성 PII 만** — 새 패턴이 필요하면 `synthetic_pii_generator.py` 에 헬퍼 먼저 추가
- 새 기능을 도입할 때 같은 PR 에 테스트 포함 (CI 게이트가 mypy strict + 80% 커버리지 요구)
- 첨부/OCR 관련 신규 케이스는 [`docs/phase_4b_attachment_test_spec.md`](phase_4b_attachment_test_spec.md) 에 TC 행도 함께 추가
- `request_id` 등 멱등성 키는 매 테스트 마다 `uuid.uuid4()` 새로 발급 (충돌 시 캐시 응답이 돌아옴)

---

## 6. 관련 문서

- [`phase_4b_attachment_test_spec.md`](phase_4b_attachment_test_spec.md) — 첨부 기능 시나리오 명세 (자동 + 수동 검증 절차)
- [`api_integration.md`](api_integration.md) — 외부 클라이언트 연동 가이드 (응답 코드 / HMAC / webhook)
- [`system_architecture.md`](system_architecture.md) — 컴포넌트 다이어그램 / 요청 흐름
- [`data_flow.md`](data_flow.md) — 데이터 저장 위치 / 파기 절차
- [`load_test_report.md`](load_test_report.md) — 100 RPS 부하 결과
- `phase_N_completion.md` — 각 단계별 완료 보고서 (테스트 결과 스냅샷)
