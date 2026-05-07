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

### OCR 엔진 (PaddleOCR 기본 + VLM 옵트인)
| ID | 목적 | 자동화 |
|---|---|---|
| TC-1.7a | PaddleOCR — 합성 ID 카드 PNG → RRN 텍스트 추출 | `tests/integration/test_paddle_ocr_pipeline.py::test_paddle_runs_on_id_card_sample` |
| TC-1.7b | PaddleOCR — 합성 명함 PNG → 전화번호 텍스트 추출 | `test_paddle_extracts_phone_from_business_card` |
| TC-1.7c | PaddleOCR 실패 → VLM 자동 fallback | `test_paddle_failure_falls_back_to_vlm` |
| TC-1.7d | `OCR_ENGINE=vlm` 설정 시 paddle 우회 | `test_vlm_setting_skips_paddle` |

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

## 11. 수동 통합 검증 런북 (배포 전)

자동화는 핸들러 분기와 헬퍼를 잡지만, 외부 시스템 (mock callback server,
대시보드 브라우저 렌더, ClamAV 등) 과의 결합은 운영자가 직접 실행해야
신뢰도가 확보됩니다. 이 런북은 그대로 복붙해서 실행 가능한 단계로
구성됩니다.

각 절차는 `[TC-…]` 로 자동화 케이스에 cross-link 되어 있고, 마지막에
**Pass / Fail / N/A** 칸을 두어 검증 결과를 기록합니다.

### 11.0 사전 환경 셋업

다음 모든 절차는 한 번만 실행합니다.

```bash
# ── 1) 서버 기동 ───────────────────────────────────────────────────────
cd /path/to/open_pii_filter
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 9000 &
SERVER_PID=$!

# ── 2) DB 환경 변수 (.env 와 동일하게) ───────────────────────────────
export DB_HOST=127.0.0.1
export DB_USER=kims
export DB_PASS=...      # 운영자가 직접 채움
export DB_NAME=pii_api
export PGPASSWORD=$DB_PASS

# ── 3) 마이그레이션 적용 + 시드 확인 [TC-A.1] ────────────────────────
.venv/bin/alembic upgrade head
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c \
  "SELECT COUNT(*) FROM pii.attachment_blocklist;"
# 기대: count = 31

# ── 4) Mock callback server (포트 9999 — DELETE/POST 모두 수신) ──────
# 별도 터미널에서:
mkdir -p /tmp/cb_log
python3 - <<'PY' &
import http.server, json, sys, datetime
class H(http.server.BaseHTTPRequestHandler):
    def _log(self, method, body):
        with open("/tmp/cb_log/calls.jsonl", "a") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.utcnow().isoformat(),
                "method": method,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", errors="replace"),
            }) + "\n")
    def do_POST(self):
        n = int(self.headers.get("content-length") or "0")
        body = self.rfile.read(n) if n else b""
        self._log("POST", body)
        self.send_response(204); self.end_headers()
    def do_DELETE(self):
        n = int(self.headers.get("content-length") or "0")
        body = self.rfile.read(n) if n else b""
        self._log("DELETE", body)
        self.send_response(204); self.end_headers()
http.server.HTTPServer(("127.0.0.1", 9999), H).serve_forever()
PY
CB_PID=$!
echo "callback mock pid=$CB_PID  log=/tmp/cb_log/calls.jsonl"
```

> **정리는 §11.11 에서**. 절차 전체가 끝날 때까지 두 프로세스를 띄워둡니다.

---

### 11.1 헬스 + 마이그레이션 + 시드 [TC-A.1, TC-8.1]

```bash
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:9000/healthz
# 기대 출력: 200
```

```bash
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c \
  "SELECT extension, mime_type, reason
     FROM pii.attachment_blocklist
    WHERE extension IN ('hwp','hwpx','zip','7z')
    ORDER BY extension;"
```
기대: 4 행 이상, 각 `reason` 채워짐.

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.1 | ☐ | ☐ | ☐ |

---

### 11.2 대시보드 렌더 [TC-F]

브라우저로 다음을 확인합니다.

1. `http://localhost:9000/admin/login` — 로그인 폼이 보이고, dev 환경 한해
   현재 비밀번호로 로그인 성공.
2. 로그인 후 `http://localhost:9000/admin/settings` 진입.
3. 페이지에 다음 두 카드가 모두 보입니다.
   - **API 사용 이력 상세 저장** (audit_detail_enabled)
   - **첨부파일 검사** (attachment_scan_enabled) ← 이번 PR 추가

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.2 | ☐ | ☐ | ☐ |

---

### 11.3 첨부 검사 토글 OFF → 첨부 있는 detect → Case B [TC-4.1, TC-4.2, TC-4.4]

```bash
# 11.3.1 토글 OFF (대시보드 카드의 "저장" 버튼이 같은 효과)
# 직접 JSON 갱신:
echo '{"audit_detail_enabled": true, "attachment_scan_enabled": false}' \
  > data/system_settings.json
# 또는 대시보드에서 토글 후 저장 (HTTP 303 리다이렉트 확인).

# 11.3.2 첨부 있는 detect 호출
SHA=$(printf 'x%.0s' {1..1024} | sha256sum | cut -d' ' -f1)
curl -sS -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000004001",
  "author":{"name":"manual","ip":"203.0.113.5"},
  "post":{"board_id":"qna","title":"toggle off test","body":"본문에는 PII 가 없습니다."},
  "attachments":[{
    "attachment_id":"a1","filename":"ok.pdf","size_bytes":1024,
    "mime_type":"application/pdf","sha256":"$SHA",
    "fetch_url":"http://127.0.0.1:9999/files/ok.pdf"
  }],
  "callback_url":"http://127.0.0.1:9999/cb"
}
JSON
)" | jq '{code, verdict, has_job: (.job != null)}'
# 기대: {"code":"OK-...", "verdict":"PASS"|"BLOCK", "has_job":false}
```

```bash
# 11.3.3 토글 ON 복귀
echo '{"audit_detail_enabled": true, "attachment_scan_enabled": true}' \
  > data/system_settings.json

# 11.3.4 동일 요청 (request_id 만 갱신) 호출 → Case C
curl -sS -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000004002",
  "author":{"name":"manual","ip":"203.0.113.5"},
  "post":{"board_id":"qna","title":"toggle on test","body":"본문에는 PII 가 없습니다."},
  "attachments":[{
    "attachment_id":"a1","filename":"ok.pdf","size_bytes":1024,
    "mime_type":"application/pdf","sha256":"$SHA",
    "fetch_url":"http://127.0.0.1:9999/files/ok.pdf"
  }],
  "callback_url":"http://127.0.0.1:9999/cb"
}
JSON
)" | jq '{code, has_job: (.job != null), job_id: (.job.job_id // null)}'
# 기대: {"code":"ACK-3001","has_job":true,"job_id":"job_..."}
```

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.3 OFF (Case B) | ☐ | ☐ | ☐ |
| 11.3 ON (Case C) | ☐ | ☐ | ☐ |

---

### 11.4 deny list 거절 — zip 첨부 [TC-2.1, TC-9.1]

```bash
SHA=$(printf 'x%.0s' {1..1024} | sha256sum | cut -d' ' -f1)
curl -sS -o /tmp/resp.json -w "HTTP %{http_code}\n" \
  -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000002001",
  "author":{"name":"manual","ip":"203.0.113.5"},
  "post":{"board_id":"qna","title":"zip test","body":"본문"},
  "attachments":[{
    "attachment_id":"a1","filename":"leak.zip","size_bytes":1024,
    "mime_type":"application/zip","sha256":"$SHA",
    "fetch_url":"http://127.0.0.1:9999/files/x"
  }],
  "callback_url":"http://127.0.0.1:9999/cb"
}
JSON
)"
jq '{code, user_message}' < /tmp/resp.json
```
기대 출력:
```
HTTP 415
{"code":"REQ-4035","user_message":"첨부파일 'leak.zip' 의 형식(format on deny list)은 등록할 수 없습니다."}
```

`/tmp/cb_log/calls.jsonl` 에 새 항목이 들어가지 **않아야** 합니다 (게이트가
요청 수신 시점에 차단).

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.4 | ☐ | ☐ | ☐ |

---

### 11.5 정상 PDF + Case C webhook 도착 [TC-1.1]

> **사전 조건**: §11.0 의 mock callback 서버가 9999 포트에서 떠 있어야 함.
> 실제 PDF 페이로드 fetch 도 같은 mock 으로 받습니다.

```bash
# 11.5.1 mock 서버에 합성 PDF 를 올려둠 (text-bearing)
.venv/bin/python -c "
from tests.fixtures.attachments.create_fixtures import make_text_pdf
import pathlib
out = pathlib.Path('/tmp/cb_log/synthetic.pdf'); out.write_bytes(make_text_pdf())
print(out, 'sha256=', __import__('hashlib').sha256(out.read_bytes()).hexdigest())
print('size=', out.stat().st_size)
"
# 기대 출력에서 'sha256=' 와 'size=' 값을 메모.

# 11.5.2 mock 서버를 정적 파일 서버로 재기동 — 또는 별도 포트로 띄움
# 가장 간단: §11.0 의 BaseHTTPRequestHandler 에 do_GET 핸들러 추가하거나
# 별도 'python3 -m http.server -d /tmp/cb_log 9998' 를 새 터미널에 띄움
( cd /tmp/cb_log && python3 -m http.server 9998 >/dev/null 2>&1 ) &
GET_PID=$!

# 11.5.3 detect 호출 — fetch_url 은 9998, callback_url 은 9999
SHA=<위 단계의 sha256 값>
SIZE=<위 단계의 size 값>
curl -sS -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000005001",
  "author":{"name":"manual","ip":"203.0.113.5"},
  "post":{"board_id":"qna","title":"pdf case-c","body":"본문에는 PII 가 없습니다."},
  "attachments":[{
    "attachment_id":"a1","filename":"synthetic.pdf","size_bytes":$SIZE,
    "mime_type":"application/pdf","sha256":"$SHA",
    "fetch_url":"http://127.0.0.1:9998/synthetic.pdf"
  }],
  "callback_url":"http://127.0.0.1:9999/cb"
}
JSON
)" | jq .

# 11.5.4 webhook 도착 확인 (~수 초 안에)
sleep 5
tail -n 5 /tmp/cb_log/calls.jsonl | jq '{method, path}'
# 기대: 마지막 항목이 method=POST, path=/cb
```

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.5 | ☐ | ☐ | ☐ |

---

### 11.6 PII 포함 PDF → webhook BLOCK + DELETE 호출 [TC-7.1, TC-7.8, TC-7.9]

§11.5 의 mock 환경을 그대로 사용합니다. 합성 PII 가 포함된 PDF 를 새로
만들어 올린 뒤 detect 호출.

```bash
.venv/bin/python -c "
from tests.fixtures.attachments.create_fixtures import _build_pdf
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator
g = SyntheticPIIGenerator(seed=11_006)
data = _build_pdf([f'합성 RRN: {g.gen_rrn()} 끝.'])
import pathlib, hashlib
out = pathlib.Path('/tmp/cb_log/with_rrn.pdf'); out.write_bytes(data)
print('sha256=', hashlib.sha256(data).hexdigest())
print('size=', len(data))
"
# 위 sha256/size 를 메모 후 detect 호출 (filename=with_rrn.pdf,
# fetch_url=http://127.0.0.1:9998/with_rrn.pdf) — 11.5.3 과 같은 형식.

# 1) 결과 webhook 도착 확인
sleep 8
jq 'select(.method=="POST")' < /tmp/cb_log/calls.jsonl | tail -n 1 \
  | jq '{verdict: (.body | fromjson | .verdict), code: (.body | fromjson | .code)}'
# 기대: {"verdict":"BLOCK","code":"BLOCK-2010"}

# 2) DELETE 후속 호출 확인 (Phase D)
jq 'select(.method=="DELETE")' < /tmp/cb_log/calls.jsonl | tail -n 1 \
  | jq '{path,body,sig:(.headers["X-Signature"][:16] + "...")}'
# 기대: path=/cb, body 에 request_id/job_id/code 포함, X-Signature 64자 hex.

# 3) HMAC 서명 재계산으로 무결성 확인 (선택)
.venv/bin/python - <<'PY'
import json, hashlib, hmac, os, pathlib
secret = os.environ.get("WEBHOOK_SIGNING_SECRET","").encode()
last = [json.loads(l) for l in pathlib.Path("/tmp/cb_log/calls.jsonl").read_text().splitlines()
        if json.loads(l)["method"]=="DELETE"][-1]
ts, n = last["headers"]["X-Timestamp"], last["headers"]["X-Nonce"]
body = last["body"].encode()
canonical = f"{ts}\n{n}\nDELETE\n/cb\n{hashlib.sha256(body).hexdigest()}"
expected = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
print("server-sig:", last["headers"]["X-Signature"])
print("recomputed:", expected, "match=", expected==last["headers"]["X-Signature"])
PY
```

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.6 BLOCK webhook | ☐ | ☐ | ☐ |
| 11.6 DELETE 도착 | ☐ | ☐ | ☐ |
| 11.6 HMAC 서명 검증 | ☐ | ☐ | ☐ |

---

### 11.7 callback_delete 로깅 — correlation IDs 보임 [Phase D 로깅]

uvicorn 콘솔 로그(또는 운영 환경 로그 어그리게이터)에서 §11.6 의 BLOCK
요청 직후 다음 패턴이 차례로 보여야 합니다:

```
INFO callback_delete: scheduling DELETE for blocked job job_xxx (request=..., code=BLOCK-2010)
INFO callback_delete: dispatching DELETE for blocked post <request_id>/<job_id>
INFO callback_delete: delivered for <request_id>/<job_id> on attempt 1 (status 204)
```

`extra={request_id, job_id, attempt, status, callback_url, ...}` 가 담긴
구조화 로그가 보이는지 확인합니다 (운영에서는 JSON 핸들러가 키-값을 분리
출력합니다).

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.7 | ☐ | ☐ | ☐ |

---

### 11.8 예외 IP audit-only — verdict PASS, audit 에 entity_type 보존 [TC-5.1, TC-5.3, TC-7.3]

```bash
# 11.8.1 예외 IP 등록 + 캐시 reload (서버 재기동 또는 admin reload)
psql -h $DB_HOST -U $DB_USER -d $DB_NAME <<'SQL'
INSERT INTO pii.exception_ips (cidr, label, enabled)
VALUES ('203.0.113.42/32', 'manual-runbook', true)
ON CONFLICT (cidr) DO UPDATE SET enabled = true, label = excluded.label;
SQL
# lifespan 시점에 cache 를 1회 reload 하므로 변경 반영을 위해 서버 재기동
kill $SERVER_PID; wait $SERVER_PID 2>/dev/null
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 9000 &
SERVER_PID=$!
sleep 2

# 11.8.2 RRN 본문 + 예외 IP 작성자
.venv/bin/python -c "
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator
print(SyntheticPIIGenerator(seed=11_008).gen_rrn())
" | tee /tmp/rrn.txt
RRN=$(cat /tmp/rrn.txt)
curl -sS -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000005108",
  "author":{"name":"manual","ip":"203.0.113.42"},
  "post":{"board_id":"qna","title":"audit-only","body":"본문 합성 RRN: $RRN"}
}
JSON
)" | jq '{verdict, code, user_message}'
# 기대: {"verdict":"PASS","code":"OK-0000","user_message":"게시 가능합니다."}

# 11.8.3 audit_events 에 검출 entity_type 가 남았는지 확인
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c \
  "SELECT response_code, detected_entity_types FROM pii.audit_events
    WHERE request_id::text='00000000-0000-0000-0000-000000005108'
    ORDER BY occurred_at DESC LIMIT 1;"
# 기대: response_code=OK-0000, detected_entity_types LIKE '%KR_RRN%'
```

`/tmp/cb_log/calls.jsonl` 에 DELETE 항목이 추가되지 **않아야** 합니다.

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.8 verdict PASS | ☐ | ☐ | ☐ |
| 11.8 audit 에 entity_type 기록 | ☐ | ☐ | ☐ |
| 11.8 DELETE 미호출 | ☐ | ☐ | ☐ |

---

### 11.9 한국어 라벨 — 일반 IP BLOCK 응답 [TC-5.2, TC-6.1]

§11.8.2 의 동일 요청을 일반 IP (`203.0.113.5`) 로 다시 호출:

```bash
curl -sS -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000005109",
  "author":{"name":"manual","ip":"203.0.113.5"},
  "post":{"board_id":"qna","title":"label test","body":"본문 합성 RRN: $RRN"}
}
JSON
)" | jq '{verdict, code, user_message}'
```
기대 출력 (요지):
- `verdict: "BLOCK"`
- `user_message` 끝에 `(검출된 항목: 주민등록번호)` 포함
- `KR_RRN` 같은 raw 코드는 미노출

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.9 verdict BLOCK | ☐ | ☐ | ☐ |
| 11.9 한국어 라벨 노출 | ☐ | ☐ | ☐ |
| 11.9 raw 코드 미노출 | ☐ | ☐ | ☐ |

---

### 11.10 Admin blocklist API — CRUD round-trip [TC-8.1~TC-8.6]

> **사전**: 운영 환경 admin API 키 + IP allowlist 통과. 로컬 검증 시
> `/v1/admin/*` 라우터를 마운트하려면 `.env` 의 `ADMIN_IP_ALLOWLIST` 가
> 비어있지 않아야 함 (예: `127.0.0.0/8`). `is_admin=true` 인 키 발급은
> `python -m app.cli apikey issue --name manual --is-admin` 등으로.

```bash
# 11.10.1 list 21
gh_admin_get () { ... HMAC 서명 helper, 로컬 환경에 맞게 ... }
gh_admin_get GET /v1/admin/attachment-blocklist | jq '.rows | length'
# 기대: 31 (시드)

# 11.10.2 항목 추가
gh_admin_get POST /v1/admin/attachment-blocklist \
  '{"extension":"manualtest1","reason":"runbook"}' | jq '.id'
# 기대: 새 row id 출력

# 11.10.3 첨부 검사 — 새 확장자 차단 확인
SHA=$(printf 'x%.0s' {1..1024} | sha256sum | cut -d' ' -f1)
curl -sS -X POST http://127.0.0.1:9000/v1/detect/post \
  -H 'Content-Type: application/json' \
  -d "$(cat <<JSON
{
  "request_id":"00000000-0000-0000-0000-000000005110",
  "author":{"name":"manual","ip":"203.0.113.5"},
  "post":{"board_id":"qna","title":"blocklist test","body":"본문"},
  "attachments":[{
    "attachment_id":"a1","filename":"x.manualtest1","size_bytes":1024,
    "mime_type":"application/octet-stream","sha256":"$SHA",
    "fetch_url":"http://127.0.0.1:9999/x"
  }],
  "callback_url":"http://127.0.0.1:9999/cb"
}
JSON
)" | jq '{code,status:"check"}'
# 기대: code=REQ-4035

# 11.10.4 항목 제거 → 같은 요청이 통과해야 함
gh_admin_get DELETE /v1/admin/attachment-blocklist/$NEW_ID
# 기대: HTTP 204
```

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.10 list | ☐ | ☐ | ☐ |
| 11.10 add | ☐ | ☐ | ☐ |
| 11.10 added 차단 적용 | ☐ | ☐ | ☐ |
| 11.10 delete | ☐ | ☐ | ☐ |

---

### 11.11 정리

```bash
# 1) 예외 IP 행 정리
psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c \
  "DELETE FROM pii.exception_ips WHERE label = 'manual-runbook';"

# 2) 임시 토글 원복
echo '{"audit_detail_enabled": true, "attachment_scan_enabled": true}' \
  > data/system_settings.json

# 3) 프로세스 종료
kill $SERVER_PID 2>/dev/null
kill $CB_PID 2>/dev/null
kill $GET_PID 2>/dev/null

# 4) 로그 보존 — 운영 인시던트 분석 용도로 30 일 권장
mv /tmp/cb_log /tmp/cb_log.$(date +%Y%m%d-%H%M)
```

| | Pass | Fail | N/A |
|---|---|---|---|
| 11.11 | ☐ | ☐ | ☐ |

---

### 11.12 결과 시트 (운영자 작성)

| 검증자 | 일시 | 환경 | 11.1 | 11.2 | 11.3 | 11.4 | 11.5 | 11.6 | 11.7 | 11.8 | 11.9 | 11.10 | 11.11 | 비고 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | | | | |
