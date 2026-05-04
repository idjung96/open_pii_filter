# Phase 7 Completion — Policy Engine, Feedback, Stats, Shadow Mode

> **Phase 9D (2026-05) 변경 알림**
> 본 보고서가 기술하는 마스킹/익명화 파이프라인은 Phase 9D 에서 폐기됐습니다.
> 마스킹 결과 응답(`masked`/`masked_url`), `MaskedArtifact` 테이블, `/v1/masked-artifacts/{token}` 엔드포인트, WARN 등급은 더 이상 동작하지 않습니다.
> 현재 동작은 PASS/BLOCK 2단계이며 PII 탐지 시 게시가 거부됩니다. 자세한 내용은 `docs/api_integration.md` 참고.

> 산출물 요약: DB 정책 엔진 + 오탐 피드백 + 운영 통계 + shadow 패턴 모드 + 시간당 피드백 알림 + 공개용 개인정보 처리방침 엔드포인트.

## 1. DB schema (Alembic)

| 마이그레이션 | 변경 |
|---|---|
| `9f3a7c2e1b40_phase_7a_policies_feedback_pattern_mode` | `pii.pii_policies` 신설, `pii.pii_feedback` 신설, `pii_patterns.enabled BOOL` → `pii_patterns.mode TEXT('enabled'/'shadow'/'disabled')`, `audit_events.shadow_hit_types TEXT`, `pii_policies` 변경에 NOTIFY 트리거 |
| `9f3a7c2e1b41_phase_7b_alerter_state` | `pii.alerter_state` (피드백 알림 anti-flap 보호) |

`pii.pii_policies` 핵심 컬럼: `entity_type`, `score_min`, `score_max`, `action ∈ {BLOCK, WARN, MASK, LOG_ONLY, PASS}`, `mode ∈ {enabled, shadow, disabled}`, `user_message_template?`. CHECK 제약으로 action/mode/score band 무결성 보장.

`pii.pii_feedback`: `request_id`, `original_code`, `reason TEXT`, `reporter_hash CHAR(64)`. **이메일 평문은 절대 저장하지 않음** — `reporter_email`이 들어오면 `SHA-256(salt + email)` 해시로만 보관 (`Settings.pii_encryption_key`를 salt로 재사용).

## 2. Action 의미

| action | verdict 영향 | 응답 코드 | 마스킹 강제 | 감사로그 entity_type 기록 |
|---|---|---|---|---|
| BLOCK | BLOCK | code-default (예: BLOCK-2001) | 예 | 예 (visible) |
| WARN | WARN | code-default (예: WARN-1001) | 아니오 | 예 (visible) |
| MASK | PASS (단, 마스킹 적용) | `WARN-1010` | **예** | 예 (visible) |
| LOG_ONLY | 영향 없음 (PASS로 간주) | OK-0000 | 아니오 | 예 (audit only — caller 응답에서는 사라짐) |
| PASS | 영향 없음 | OK-0000 | 아니오 | 아니오 |

`MASK`는 호출자가 **반드시 마스킹된 본문을 게시**하도록 의도된 동작이며 verdict는 PASS이지만 `WARN-1010` 코드가 surfaced되어 사용자가 자동 마스킹이 일어났음을 인지하도록 user_message가 노출된다 (`이 부분은 자동으로 가려졌습니다`). BLOCK과 달리 게시는 허용.

`LOG_ONLY`는 운영자가 신규/약한 패턴이 false-positive율이 높을 때 호출자 응답에서는 숨기지만 audit_events에는 entity_type을 남기는 용도. shadow 모드와의 차이: shadow는 패턴 자체가 trial 중인 경우(분석 엔진 자체가 분리), LOG_ONLY는 운영자가 정한 정책 결정.

## 3. Hot-reload

`pii_patterns`, `pii_policies` 양쪽 모두 NOTIFY 트리거가 `pii_pattern_changed` 채널로 broadcast. 기존 `app/workers/pattern_listener.py`가 이 신호를 받아 `analyzer_cache.request_reload()`와 `policy_cache.request_reload()`를 동시에 호출. 다음 요청에서 두 캐시 모두 새로 빌드.

LISTEN 연결이 끊기면 polling fallback (30초 간격)이 동일하게 작동하므로 트리거 누락 시에도 30초 안에 자동 동기화됨.

## 4. Shadow 분석기

`AnalyzerCache`는 두 개의 엔진을 보관:

- **production**: `mode='enabled'` 패턴만 등록
- **shadow**: `mode IN ('enabled','shadow')` 패턴 등록 (즉, production + shadow rows)

요청 시:
1. production 엔진으로 verdict 결정
2. (shadow 패턴이 1개라도 있을 때만) **응답 빌드 후** shadow 엔진을 비동기로 1회 더 돌려서 production이 잡지 못한 entity_type을 `audit_events.shadow_hit_types`에 기록
3. shadow는 verdict를 절대 변경하지 않음 (감사 전용)

지연 budget: shadow가 비활성이면 추가 비용 없음. shadow 활성 시에도 production 응답이 먼저 caller에게 반환된 뒤 shadow가 background에서 추가 분석을 수행.

## 5. 운영 워크플로 — 신규 패턴 도입

1. 신규 패턴은 `pattern add ... --mode shadow` (CLI 기본값)로 추가됨. 본 운영 verdict에는 영향 없음.
2. `GET /v1/admin/stats/detections?since=...&include_shadow=true` 로 shadow 패턴이 어떤 entity 추세를 잡는지 모니터링.
3. 노이즈가 적고 신호가 충분히 검증되면 `python -m app.cli pattern enable <id>` 로 production 모드 승격.
4. 반대 방향(production → shadow)은 `python -m app.cli pattern shadow <id>` (롤백 시), 비활성화는 `pattern disable <id>`.

같은 패턴이 정책으로도 동시에 관리됨:

```bash
# RRN을 high score 구간에서만 BLOCK (저신뢰는 LOG_ONLY로 풀어주는 정책 예)
python -m app.cli pattern policy add --entity-type KR_RRN --action BLOCK \
    --score-min 0.85 --score-max 1.0 --mode enabled

python -m app.cli pattern policy add --entity-type KR_RRN --action LOG_ONLY \
    --score-min 0.50 --score-max 0.84 --mode enabled
```

`pii_policies` 우선순위는 `(score_max - score_min)` 작을수록 (= 더 좁은 band) 우선이며, 같은 폭이면 `score_min` 높은 쪽이 우선. DB 미매칭 시 `app/core/policies.py`의 코드 매핑이 fallback.

## 6. 신규 엔드포인트

| 메서드 | 경로 | 인증 | 용도 |
|---|---|---|---|
| POST | `/v1/feedback` | HMAC + API key | 오탐/미탐 피드백 (응답 `ACK-3010`, HTTP 202) |
| GET | `/v1/admin/stats/detections` | admin | hourly bucket × entity_type (옵션 `?include_shadow=true`) |
| GET | `/v1/admin/stats/verdicts` | admin | block/warn/pass 비율 |
| GET | `/v1/admin/stats/feedback` | admin | 최근 피드백 + `original_code` 분포 |
| GET | `/v1/legal/privacy-notice` | **public** | 회사/DPO 변수 치환된 개인정보 처리방침 (Markdown) |

`admin` 게이트는 Phase 6의 `require_admin`을 그대로 재사용 (IP allowlist + `is_admin=true`); `admin_ip_allowlist`가 비어 있으면 admin 라우터 자체가 마운트되지 않아 외부 스캐너에는 404.

## 7. 시간당 피드백 알림 (operator-decision A)

`app/workers/feedback_alerter.py`가 lifespan에서 1시간 간격으로 회전. 직전 정시 단위 1시간 동안 `pii_feedback` 누적 건수가 `Settings.feedback_alert_threshold` (기본 10) 이상이면 1통의 SMTP 메일을 발송:

- Subject: `[PII API] feedback volume alert: <N> reports/hour`
- Body: 윈도우 시각, 총 건수, top-5 `original_code`, top-5 reason 스니펫(80자 컷 + PII 패턴 마스킹 후), 검토 링크
- TLS: 587번 포트면 STARTTLS, 465면 SSL, 그 외 평문
- Anti-flap: `pii.alerter_state` 단일 행이 `last_alert_at >= window_end` 이면 재발송 차단 (재시작 안전)

`Settings.smtp_host` 또는 `Settings.alert_email_to` 가 비어 있으면 WARNING 1회 로깅 후 idle.

## 8. 개인정보 처리방침 (operator-decision D)

`app/api/legal.py`가 `docs/privacy_notice.md`를 읽어 다음 placeholder를 `Settings`에서 치환:

- `{{COMPANY_NAME}}`, `{{COMPANY}}` ← `Settings.company_name`
- `{{COMPANY_CONTACT_EMAIL}}`, `{{CONTACT}}` ← `Settings.company_contact_email`
- `{{COMPANY_CONTACT_PHONE}}` ← `Settings.company_contact_phone`
- `{{DATA_PROTECTION_OFFICER_NAME}}`, `{{DPO_NAME}}` ← `Settings.data_protection_officer_name`
- `{{DATA_PROTECTION_OFFICER_EMAIL}}`, `{{DPO_EMAIL}}` ← `Settings.data_protection_officer_email`

설정 값이 비어 있으면 placeholder가 **그대로 남아** 운영자가 누락을 즉시 인지할 수 있도록 의도. 인증 없는 public 엔드포인트로 `main.py`에서 무조건 mount.

## 9. 응답 코드 (신설)

```
ACK-3010 — Feedback received           (HTTP 202, verdict=PROCESSING)
WARN-1010 — Sensitive content auto-redacted (HTTP 200, verdict=WARN)
```

기존 코드는 변경되지 않았으며, MASK 행위에 대해서는 WARN-1010만 신규로 사용된다. LOG_ONLY 행위의 호출자 노출 코드는 OK-0000.

## 10. 테스트 (T7.1~T7.6 + 추가)

- `tests/integration/test_phase7_policies.py` — T7.1 (RRN BLOCK), T7.2 (LOG_ONLY drops visible + audited), T7.3 (hot-reload), T7.6 (shadow 패턴은 verdict 무영향 + audit 기록)
- `tests/integration/test_phase7_feedback.py` — T7.4 (POST + 해시 저장 + audit)
- `tests/integration/test_phase7_stats.py` — T7.5 (detections/verdicts/feedback 집계 + non-admin 403 + 미마운트 404)
- `tests/integration/test_phase7_alerter.py` — 임계 미만/초과/anti-flap/SMTP 미설정 4종
- `tests/integration/test_phase7_privacy_notice.py` — 변수 치환 / 빈 설정 / public 접근

기존 197개 테스트 모두 통과 + Phase 7 신규 19개 통과 = **216 passed**.

## 11. 품질 게이트 결과

```
uv run ruff check app/ tests/ --fix    → All checks passed!
uv run mypy app/                       → Success: no issues found in 84 source files
uv run pytest <Phase 1-7 suite>        → 216 passed
```

## 12. Phase 7 범위 외 (Phase 8 후속 검토)

- Prometheus `/metrics` (operator decision C) — Phase 8 후 결정
- 단일 이미지 Docker / Locust load tests / ops doc — Phase 8
- 실제 false-positive ML retraining 파이프라인 — Phase 8 이후 (피드백 데이터셋이 충분히 모이면)
- Web UI / Grafana dashboards — operator는 SQL 또는 stats API로 직접 조회
