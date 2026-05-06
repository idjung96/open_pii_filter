# Phase 4b — 첨부파일 처리 기능 테스트 케이스 명세

본 문서는 `attachment` 브랜치 (Phase A~F) 의 변경사항을 검증하는 **테스트 케이스 카탈로그**입니다.
각 케이스는 `자동화` 컬럼에 자동 회귀 위치(파일/테스트명)를, `수동` 컬럼에 운영 환경에서 직접 확인할
방법(curl 명령 등) 을 함께 명시합니다.

## 사전 조건 (공통)

- PII filter 서버가 9000 포트에서 기동 중 (`uvicorn app.main:app --host 0.0.0.0 --port 9000`)
- PostgreSQL/Redis 실행 중, alembic head 적용 완료
- spaCy `ko_core_news_lg` 모델 설치 완료
- 모든 테스트 데이터는 **합성 PII** (`tests/fixtures/synthetic_pii_generator.py`) 만 사용
- 자동 회귀 실행: `.venv/bin/pytest tests/unit tests/integration -q`

## 응답 코드 요약

| 코드 | HTTP | 의미 |
|---|---|---|
| `OK-0000` | 200 | PASS — 게시 가능 |
| `BLOCK-2001~2099` | 200 | 본문/첨부에서 PII 검출 |
| `ACK-3001` | 202 | Case C — 첨부 비동기 처리 시작 |
| `REQ-4031` | 413 | 첨부 크기 한도 초과 (20 MiB) |
| `REQ-4032` | 413 | 첨부 개수 한도 초과 (5개) |
| `REQ-4033` | 415 | 미지원 MIME |
| `REQ-4035` | 415 | **deny list 매칭** — 압축/HWP/HWPX/legacy OLE |
| `REQ-4015` | 403 | admin 권한 부족 |

---

## 1. 허용 형식 처리 (Phase B/E)

| ID | 목적 | 입력 | 기대 결과 | 자동화 | 수동 검증 |
|---|---|---|---|---|---|
| TC-1.1 | PDF (텍스트) 통과 | `application/pdf`, ≤20MB | 202 + `code=ACK-3001` + `job_id` | `tests/integration/test_attachment_pipeline_e2e.py::test_allowed_formats_enqueue_case_c[doc.pdf]` | curl POST `/v1/detect/post` |
| TC-1.2 | XLSX 통과 | OOXML spreadsheet | 202 + `ACK-3001` | 동상 `[report.xlsx]` | 동상 |
| TC-1.3 | PPTX 통과 | OOXML presentation | 202 + `ACK-3001` | 동상 `[deck.pptx]` | 동상 |
| TC-1.4 | DOCX 통과 | OOXML wordprocessing | 202 + `ACK-3001` | 동상 `[memo.docx]` | 동상 |
| TC-1.5 | Markdown 통과 | `text/markdown` | 202 + `ACK-3001` | 동상 `[notes.md]` | 동상 |
| TC-1.6 | 텍스트 통과 | `text/plain` | 202 + `ACK-3001` | 동상 `[plain.txt]` | 동상 |
| TC-1.7 | JPEG 통과 | `image/jpeg` | 202 + `ACK-3001` | 동상 `[photo.jpg]` | 동상 |
| TC-1.8 | PNG 통과 | `image/png` | 202 + `ACK-3001` | 동상 `[scan.png]` | 동상 |

### 추출기 단위 검증
| ID | 목적 | 자동화 |
|---|---|---|
| TC-1.9 | XLSX 모든 셀 텍스트 + 숫자 cell stringify | `tests/unit/test_extract_xlsx.py::test_extract_xlsx_returns_text_from_every_cell` |
| TC-1.10 | XLSX 암호화(MS-CFB) → REQ-4051 | `tests/unit/test_extract_xlsx.py::test_extract_xlsx_rejects_encrypted_blob` |
| TC-1.11 | XLSX 깨진 ZIP → REQ-4042 | `tests/unit/test_extract_xlsx.py::test_extract_xlsx_rejects_corrupt_zip` |
| TC-1.12 | PPTX 슬라이드 + 발표자 노트 추출 | `tests/unit/test_extract_pptx.py::test_extract_pptx_returns_text_and_notes` |
| TC-1.13 | PPTX 암호화 → REQ-4051 | `tests/unit/test_extract_pptx.py::test_extract_pptx_rejects_encrypted_blob` |
| TC-1.14 | PPTX 깨진 ZIP → REQ-4042 | `tests/unit/test_extract_pptx.py::test_extract_pptx_rejects_corrupt_zip` |
| TC-1.15 | Dispatcher MIME → 추출기 라우팅 매트릭스 | `tests/unit/test_dispatcher_phase4b.py::test_dispatch_routes_each_new_format_to_text` |

---

## 2. 차단 형식 (Phase A/E)

REQ-4035 가 발생하는 deny list 항목은 마이그레이션 시드 (총 31 행) 에 포함됩니다.

| ID | 입력 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-2.1 | `leaks.zip` / `application/zip` | 415 + `REQ-4035` + `user_message`에 파일명 | `test_denied_formats_rejected_with_req_4035[leaks.zip]` |
| TC-2.2 | `backup.rar` / `application/vnd.rar` | 415 + `REQ-4035` | 동상 `[backup.rar]` |
| TC-2.3 | `logs.7z` | 415 + `REQ-4035` | 동상 `[logs.7z]` |
| TC-2.4 | `report.hwp` / `application/x-hwp` | 415 + `REQ-4035` | 동상 `[report.hwp]` |
| TC-2.5 | `report.hwpx` / `application/hwp+zip` | 415 + `REQ-4035` | 동상 `[report.hwpx]` |
| TC-2.6 | `legacy.doc` / `application/msword` | 415 + `REQ-4035` | 동상 `[legacy.doc]` |
| TC-2.7 | `legacy.xls` / `application/vnd.ms-excel` | 415 + `REQ-4035` | 동상 `[legacy.xls]` |
| TC-2.8 | `legacy.ppt` / `application/vnd.ms-powerpoint` | 415 + `REQ-4035` | 동상 `[legacy.ppt]` |
| TC-2.9 | 확장자만 deny ( MIME 임의) | 415 + `REQ-4035` (확장자 매칭) | `tests/unit/test_blocklist_cache.py::test_is_blocked_matches_extension_case_insensitive` |
| TC-2.10 | MIME 만 deny (확장자 임의) | 415 + `REQ-4035` (mime 매칭) | `tests/unit/test_blocklist_cache.py::test_is_blocked_matches_mime_when_extension_lies` |
| TC-2.11 | 혼합 batch — 한 개 deny 면 전체 거절 | 415 + `REQ-4035` + 첫 차단 파일명 | `test_attachment_pipeline_e2e.py::test_mixed_batch_with_one_denied_rejects_request` |

### 수동 검증 (curl)
```bash
curl -X POST http://localhost:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "00000000-0000-0000-0000-000000000001",
    "author": {"name":"tester","ip":"203.0.113.1"},
    "post": {"board_id":"qna","title":"테스트","body":"본문"},
    "attachments":[{
      "attachment_id":"a1","filename":"leak.zip","size_bytes":1024,
      "mime_type":"application/zip",
      "sha256":"'$(printf 'x%.0s' {1..1024} | sha256sum | cut -d" " -f1)'",
      "fetch_url":"https://files.example.test/x.bin"
    }],
    "callback_url":"https://board.example.test/cb"
  }'
# 기대: HTTP 415, code=REQ-4035
```

---

## 3. 한도 검증 (Phase A)

| ID | 입력 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-3.1 | 첨부 1건이 20 MiB + 1 byte | 413 + `REQ-4031` | `test_attachment_policy_phase4b.py::test_attachment_over_20mib_returns_size_error` |
| TC-3.2 | 첨부 정확히 20 MiB | 202 + `ACK-3001` | (paramteric 추가 가능) |
| TC-3.3 | 첨부 6개 | 413 + `REQ-4032` | `test_attachment_pipeline_e2e.py::test_six_attachments_returns_count_limit_error` |
| TC-3.4 | 첨부 5개 + 모두 허용 형식 | 202 + `attachment_count=5` | (수동 검증 권장) |

---

## 4. 첨부 검사 토글 (Phase A/F)

| ID | 시나리오 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-4.1 | `attachment_scan_enabled=False` 후 첨부 있는 요청 | 200 + `job=null` (Case B fallback) | `test_attachment_pipeline_e2e.py::test_scan_toggle_off_degrades_every_format_to_case_b` |
| TC-4.2 | 대시보드 폼 제출 — checkbox 비활성 | 303 + `system_settings.attachment_scan_enabled=False` | `test_dashboard_attachment_toggle.py::test_post_toggle_off_persists_value` |
| TC-4.3 | 대시보드 폼 제출 — `enabled=on` | 303 + `True` | `test_dashboard_attachment_toggle.py::test_post_toggle_on_persists_value` |
| TC-4.4 | 토글 OFF→ON 전환 후 detect 동작 변화 | OFF 시 200/`job=null`, ON 시 202/`ACK-3001` | `test_dashboard_attachment_toggle.py::test_detect_observes_toggle` |

### 수동 검증 (대시보드)
1. 브라우저로 `http://localhost:9000/admin/login` 접속 → 로그인
2. `/admin/settings` 진입 → "첨부파일 검사" 카드 확인
3. 토글 OFF → 저장 → `data/system_settings.json` 에 `"attachment_scan_enabled": false` 확인
4. 첨부가 있는 detect 요청 호출 → HTTP 200 + `job=null` 확인
5. 토글 ON 으로 복귀

---

## 5. 예외 IP audit-only (Phase C)

| ID | 시나리오 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-5.1 | 예외 IP + RRN 본문 | 200 + `verdict=PASS` + `code=OK-0000`, audit 로그엔 `KR_RRN` 기록 | `test_exception_ip_audit_only.py::test_exception_ip_with_rrn_body_returns_pass` |
| TC-5.2 | 일반 IP + RRN 본문 | 200 + `verdict=BLOCK` + `user_message` 에 한국어 라벨 | `test_exception_ip_audit_only.py::test_non_exception_ip_with_rrn_body_returns_block_with_label` |
| TC-5.3 | 예외 IP + HWP 첨부 | 검사 진행, deny list 우회, 결과는 PASS | (수동 검증 권장 — exception_ips 행 추가 후) |

### 수동 검증
```bash
# 예외 IP 등록
PGPASSWORD=$DB_PASS psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c \
  "INSERT INTO pii.exception_ips (cidr, label, enabled) VALUES ('203.0.113.42/32','test',true)
   ON CONFLICT (cidr) DO UPDATE SET enabled=true;"

# 캐시 갱신은 lifespan 기동 시 1회 — 운영 시 컨테이너 재기동 또는
# 별도 reload 트리거 필요. 테스트 환경에서는 서버 재시작.

# 그 후 예외 IP 작성자로 RRN 포함 본문 POST → verdict=PASS 확인
```

---

## 6. 검출 PII 한국어 라벨 (Phase C)

| ID | 시나리오 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-6.1 | BLOCK + RRN 검출 | `user_message` 끝에 `(검출된 항목: 주민등록번호)` | `tests/unit/test_user_message_kr.py::test_block_response_appends_korean_summary` |
| TC-6.2 | BLOCK + 다중 entity (RRN + PHONE) | `(검출된 항목: 주민등록번호, 전화번호)` | 동상 (test 함수 내 다중 detection 케이스) |
| TC-6.3 | BLOCK + entity_type 코드 (KR_RRN 등) 노출 금지 | §2.5 forbidden 필터 통과 | `test_block_response_does_not_leak_raw_entity_codes` |
| TC-6.4 | PASS 시 라벨 미노출 (예외 IP audit-only 포함) | `검출된 항목` 문자열 없음 | `test_pass_response_does_not_get_summary_suffix` |
| TC-6.5 | BLOCK 인데 detections 비어 있음 | 라벨 미합성, 원래 template 만 | `test_block_with_no_detections_keeps_template_only` |
| TC-6.6 | 라벨 매핑 sanity (KR 6종 + 일반) | `KR_RRN→주민등록번호` 등 | `tests/unit/test_entity_labels.py` 5건 |

---

## 7. callback_url DELETE (Phase D)

| ID | 시나리오 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-7.1 | 첨부 BLOCK → DELETE 1회 호출 | DELETE 헤더에 HMAC, body 에 `{request_id, job_id, code, reason}` | `test_callback_delete.py::test_block_attachment_triggers_delete` |
| TC-7.2 | 첨부 PASS → DELETE 호출 안 함 | `delete_sender` 미호출 | `test_callback_delete.py::test_pass_verdict_skips_delete` |
| TC-7.3 | 예외 IP audit-only + BLOCK 검출 → DELETE 호출 안 함 | `delete_sender` 미호출 (verdict 이 PASS 로 강등됐으므로) | `test_callback_delete.py::test_audit_only_skips_delete` |
| TC-7.4 | DELETE 2xx | 1회 시도 후 True | `test_send_delete_request.py::test_send_delete_returns_true_on_first_2xx` |
| TC-7.5 | DELETE 4xx (non-retryable) | 1회 시도 후 False, 재시도 없음 | `test_send_delete_returns_false_on_non_retryable` |
| TC-7.6 | DELETE 5xx | 5회 (1/4/16/64/256s) 재시도 후 False | `test_send_delete_retries_on_5xx_then_gives_up` |
| TC-7.7 | DELETE timeout 첫 시도 → 두번째 2xx | True | `test_send_delete_swallows_transport_errors_and_retries` |
| TC-7.8 | HMAC 서명 검증 | `X-Timestamp/X-Nonce/X-Signature`, canonical hash 일치 | `test_send_delete_signs_with_hmac_when_secret_set` |
| TC-7.9 | 본문 correlation IDs 포함 | request_id/job_id/code/reason 포함 | `test_send_delete_body_carries_correlation_ids` |
| TC-7.10 | 본문 BLOCK (Case A) — DELETE 호출 안 함 | (수동 검증) Case A 는 동기 응답으로 끝남 | (수동 검증 권장) |

### 로깅 검증 (수동)
서버 로그에서 다음 패턴이 차례로 보여야 합니다 (BLOCK 시):
```
INFO callback_delete: scheduling DELETE for blocked job job_xxx ...
INFO callback_delete: dispatching DELETE for blocked post <request_id>/<job_id>
INFO callback_delete: delivered for <request_id>/<job_id> on attempt 1 (status 204)
```
또는 실패 시:
```
WARNING callback_delete: attempt 1/5 ... raised <error>
INFO callback_delete: backing off 4.0s before attempt 2/5 ...
ERROR callback_delete: exhausted 5 attempts ... — post may still be live
```

---

## 8. Admin Blocklist API (Phase A)

| ID | 시나리오 | 기대 결과 | 자동화 |
|---|---|---|---|
| TC-8.1 | `GET /v1/admin/attachment-blocklist` (admin) | 200 + 시드된 31 행 (HWP/HWPX/zip/rar 등 포함) | `test_admin_blocklist_api.py::test_list_blocklist_returns_seeded_rows` |
| TC-8.2 | `POST` 항목 추가 → 캐시 즉시 반영 | 201 + `is_blocked()` True | `test_post_adds_row_and_reloads_cache` |
| TC-8.3 | `DELETE` 항목 제거 → 캐시 즉시 반영 | 204 + `is_blocked()` False | `test_delete_unloads_cache` |
| TC-8.4 | `DELETE` 존재하지 않는 row | 404 | `test_delete_missing_row_returns_404` |
| TC-8.5 | 비-admin 호출 | 403 + `REQ-4015` | `test_non_admin_is_rejected` |
| TC-8.6 | `admin_ip_allowlist` 비어있음 | 404 (라우터 미마운트) | `test_router_not_mounted_when_allowlist_empty` |

### 수동 검증 (curl, 관리자 키 + IP allowlist 통과 가정)
```bash
# 시드 확인
curl -H "X-API-Key: ..." -H "X-Timestamp: ..." -H "X-Nonce: ..." -H "X-Signature: ..." \
  http://localhost:9000/v1/admin/attachment-blocklist | jq '.rows | length'
# 기대: 31

# 새 항목 추가
curl -X POST http://localhost:9000/v1/admin/attachment-blocklist \
  -H 'Content-Type: application/json' \
  -H "...HMAC..." \
  -d '{"extension":"xyz","reason":"test"}'
# 기대: 201
```

---

## 9. 메트릭 (Prometheus, 사전 작업물 + Phase A 영향 확인)

| ID | 메트릭 | 검증 방법 |
|---|---|---|
| TC-9.1 | `pii_detect_requests_total{verdict="BLOCK"}` 가 BLOCK 응답마다 증가 | `tests/unit/test_metrics_collector.py` (Phase 직전 머지) |
| TC-9.2 | `attachment_size_bytes_bucket` 첨부 1건당 1회 관측 | 동상 |
| TC-9.3 | `ocr_duration_seconds{engine="vlm"}` OCR 호출 시 관측 | 동상 |

---

## 10. 회귀 보호 — Phase A~F 요약

| Phase | 자동화 테스트 파일 | 테스트 수 |
|---|---|---|
| A foundation | `test_blocklist_cache.py`, `test_admin_blocklist_api.py`, `test_attachment_policy_phase4b.py` | 7 + 6 + 4 |
| B extractors | `test_extract_xlsx.py`, `test_extract_pptx.py`, `test_dispatcher_phase4b.py` | 3 + 3 + 3 |
| C policy | `test_entity_labels.py`, `test_user_message_kr.py`, `test_exception_ip_audit_only.py` | 6 + 4 + 2 |
| D callback delete | `test_send_delete_request.py`, `test_callback_delete.py` | 7 + 3 |
| E e2e | `test_attachment_pipeline_e2e.py` | 19 |
| F dashboard | `test_dashboard_attachment_toggle.py` | 3 |

총 신규/수정 테스트 **약 70 개** (parametric 펼침 포함).
사전 존재 테스트 (`test_phase4_*`, `test_phase5_*`, `test_phase6_*`, `test_phase7_*`, `test_phase8_*`)
모두 회귀 통과.

---

## 11. 수동 통합 검증 체크리스트 (배포 전)

운영 환경 배포 직전 다음을 차례로 확인합니다.

- [ ] `alembic upgrade head` 실행 → `pii.attachment_blocklist` 테이블 + 31 시드 행 존재
- [ ] `GET /healthz` 200 OK
- [ ] `GET /admin/login` 페이지 렌더 정상
- [ ] `/admin/settings` 페이지에 "첨부파일 검사" / "API 사용 이력 상세 저장" 두 카드 보임
- [ ] 토글 OFF → JSON 파일 갱신 → 첨부 있는 detect 호출 시 200 + `job=null`
- [ ] 토글 ON 복귀 → 동일 호출이 다시 202 + `ACK-3001`
- [ ] `zip` 첨부 호출 시 415 + `REQ-4035`
- [ ] 정상 PDF 첨부 호출 시 202, 비동기 워커가 webhook POST 까지 마무리
- [ ] PII 가 포함된 첨부 시나리오 → webhook 결과 BLOCK + DELETE 후속 호출이 callback_url 로 전송됨
- [ ] callback_url 측 서버에서 HMAC 검증 통과
- [ ] 로그에 `callback_delete: …` correlation 라인이 request_id/job_id 와 함께 보임
- [ ] 예외 IP 등록된 작성자로 같은 시나리오 → verdict=PASS, DELETE 호출 없음, audit 로그엔 검출 entity_type 기록
