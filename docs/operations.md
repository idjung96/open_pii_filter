# PII Detection API 운영 가이드 (Phase 8 — T8.7)

본 문서는 PII Detection & Masking API 의 배포·운영·장애 대응 절차를
정리합니다. 운영자가 첫 배포부터 정기 운영까지 단독으로 수행할 수
있도록 모든 명령은 그대로 실행 가능한 형태로 기재합니다.

---

## 1. 시스템 개요

### 1.1 컨테이너 / 신뢰 영역

```
                ┌─────────────────────────────────────────────────────────┐
   인터넷  ───► │  nginx (TLS 종단, IP allowlist, body cap)               │
                │     │                                                   │
                │     ▼                                                   │
                │  pii-api 컨테이너 (uvicorn + FastAPI + asyncio workers)│
                │     │  ├─ 본문 PII 검출 (Presidio + spaCy)             │
                │     │  ├─ 첨부 검출 (PDF/DOCX/HWPX/이미지 OCR)         │
                │     │  └─ asyncio: nonce vacuum, job/audit cleanup,     │
                │     │     feedback alerter, pattern listener            │
                │     ▼                                                   │
                │  PostgreSQL 16  ◄──── pgcrypto 적용                     │
                │  Redis 7        ◄──── token-bucket rate limit           │
                │  ClamAV (선택)  ◄──── 첨부 악성코드 스캔                │
                └─────────────────────────────────────────────────────────┘
```

### 1.2 외부 / 내부 엔드포인트 매트릭스

| 엔드포인트 | 신뢰 영역 | 인증 | 비고 |
|------------|-----------|------|------|
| `POST /v1/detect/post` | 외부 | HMAC + API Key + IP allowlist | 메인 API |
| `GET /v1/jobs/{id}` | 외부 | HMAC + API Key | 비동기 결과 조회 (24h 보존) |
| `POST /v1/feedback` | 외부 | HMAC + API Key | 사용자 피드백 |
| `GET /v1/legal/privacy-notice` | 외부 | 없음 | 공개 (Phase 7 운영자 결정 D) |
| `GET /healthz`, `GET /v1/healthz` | 내부 | 없음 | k8s liveness — I/O 없음 |
| `GET /readyz`, `GET /v1/readyz` | 내부 | 없음 | k8s readiness — DB+Redis ping |
| `GET /v1/admin/audit-events` | 내부 | HMAC + admin key + admin IP allowlist | 감사 이벤트 조회 |
| `GET /v1/admin/stats/*` | 내부 | 동일 | 운영 통계 |
| `GET /v1/admin/metrics` | 내부 | 동일 | **Phase 8** Prometheus exposition |

> **Admin 라우터의 mount 조건**: `Settings.admin_ip_allowlist` 가
> 비어 있으면 audit/stats 라우터는 mount 자체가 되지 않아 외부 스캐너에
> 404 를 반환합니다. metrics 라우터는 unconditional mount + gate
> rejection 패턴을 사용합니다.

---

## 2. 배포 절차

### 2.1 Docker Compose (단일 호스트)

```bash
# 1. 레포 체크아웃
git clone <repo-url> pii-api
cd pii-api

# 2. .env 작성
cp .env.example .env
# 아래 7가지를 반드시 채워야 함 — Production 배포 체크리스트:
#   - DATABASE_URL / DATABASE_URL_SYNC
#   - REDIS_URL
#   - PII_ENCRYPTION_KEY (32-byte hex; openssl rand -hex 32)
#   - ADMIN_IP_ALLOWLIST (운영자 망 CIDR)
#   - SMTP_* (피드백 알람을 받을 경우)
#   - COMPANY_* (privacy notice 템플릿 변수)
#   - WEBHOOK_SIGNING_SECRET (콜백 HMAC 서명)

# 3. Alembic 스키마 마이그레이션 (최초 1회 + 업그레이드 시)
docker compose -f deploy/docker-compose.yml run --rm api \
  alembic -c /app/alembic.ini upgrade head

# 4. 본 실행
docker compose -f deploy/docker-compose.yml up -d --build

# 5. 헬스체크
curl -fsS http://localhost:8000/readyz
```

### 2.2 Kubernetes (참조 매니페스트)

`deploy/docker-compose.yml` 의 환경 변수를 `Deployment` + `Service` +
`Ingress` 매니페스트로 옮깁니다. 권장 리소스 / probe 설정은
`docs/load_test_report.md` §4.2 참조.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: pii-api }
spec:
  replicas: 2-3
  template:
    spec:
      containers:
        - name: api
          image: registry.example.com/pii-api:phase-8
          ports: [{ containerPort: 8000 }]
          envFrom: [{ secretRef: { name: pii-api-secrets }}]
          readinessProbe:
            httpGet: { path: /readyz, port: 8000 }
            periodSeconds: 5
          livenessProbe:
            httpGet: { path: /healthz, port: 8000 }
            periodSeconds: 10
          resources:
            requests: { cpu: "1", memory: "1.5Gi" }
            limits:   { cpu: "2", memory: "2.5Gi" }
```

### 2.3 .env 작성 체크리스트

| 변수 | 필수 | 검증 방법 |
|------|------|-----------|
| `DATABASE_URL` | ✅ | `psql "$DATABASE_URL" -c 'select 1'` |
| `DATABASE_URL_SYNC` | ✅ | Alembic 마이그레이션 동작 확인 |
| `REDIS_URL` | ✅ | `redis-cli -u "$REDIS_URL" ping` → PONG |
| `PII_ENCRYPTION_KEY` | ✅ | `openssl rand -hex 32` 로 생성 |
| `ADMIN_IP_ALLOWLIST` | 권장 | 비우면 admin 라우터 미작동 |
| `WEBHOOK_SIGNING_SECRET` | Case C 사용시 ✅ | 콜백 수신 측과 공유 |
| `SMTP_*` | 알람 필요시 ✅ | `feedback_alerter_loop` 가 알람 송신 |
| `COMPANY_*` | 권장 | `privacy_notice.md` 템플릿 placeholder 치환 |
| `TRUST_FORWARDED_FOR` | nginx 뒤일 때 `true` | nginx 설정과 정합 |

---

## 3. 롤백 절차

### 3.1 컨테이너 롤백

릴리스 태그는 `git tag phase-N-complete` 명명 규약을 따릅니다.

```bash
# 1. 직전 안정 태그 확인
docker images registry.example.com/pii-api --format "{{.Tag}}\t{{.CreatedSince}}"

# 2. 컴포즈 파일의 image 태그를 직전 버전으로 변경
sed -i 's/pii-api:phase-8/pii-api:phase-7/' deploy/docker-compose.yml

# 3. 재배포
docker compose -f deploy/docker-compose.yml up -d
```

### 3.2 Alembic downgrade (주의)

```bash
# 현재 head 확인
alembic -c alembic.ini current

# 직전 버전으로 downgrade — DDL 변경이 데이터 호환되어야 함
alembic -c alembic.ini downgrade -1
```

> ⚠️ **주의**: Phase 6 의 audit 트리거, Phase 7 의 정책 테이블처럼
> 비파괴적 변경은 downgrade 가능하지만, 데이터 형변환 (예: encrypted
> 컬럼 추가) 후의 downgrade 는 데이터 손실을 야기합니다. 운영 환경에서는
> downgrade 보다 hot-fix forward migration 을 우선 검토하십시오.

---

## 4. 장애 대응 런북

### 4.1 응답 코드별 1차 대응

| 코드 | 의미 | 1차 대응 |
|------|------|----------|
| `SVR-5001` | 분석기 내부 오류 | uvicorn 로그에서 traceback 확인 → 재현 케이스 격리 → analyzer cache 초기화 (재시작) |
| `SVR-5002` | 분석기 미준비 | 컨테이너 cold-start 직후 흔함 → `/readyz` 가 200 인지 확인, 시작 후 ~5초 대기 |
| `SVR-5003` | DB 미가용 | PostgreSQL 헬스체크 / 네트워크 / 연결 풀 확인 |
| `SVR-5004` | OCR 워커 다운 | VLM endpoint (`vlm_endpoint`) reachability 확인, 헬스체크 |
| `SVR-5005` | 큐 포화 | 진행 중 작업 수 확인 (`/v1/admin/stats/*` 또는 `extraction_jobs` 테이블), 레플리카 증설 |
| `SVR-5006` | 처리 시간 초과 | 본문 5 s 초과 — 본문 길이 / 분석기 cache 상태 / DB latency 점검 |
| `REQ-4040` | 첨부 fetch 실패 | 발급 측 fetch_url 가용성, 네트워크 정책, sha256 일치 확인 |
| `REQ-4042` | 첨부 손상 | 파서 예외 — 파일 포맷 / 파일 자체 무결성 확인 |
| `REQ-4050` | 악성코드 검출 | ClamAV 시그니처 확인, 발급 측 통보 |
| `REQ-4015` | IP / 권한 거부 | `ip_allowlist` / `admin_ip_allowlist` / API key `is_admin` 정합성 확인 |
| `REQ-4020` | rate limit 초과 | API key 의 `rate_per_minute/hour` 한계, 운영망 IP 폭주 점검 |

### 4.2 PG 장애 분기

1. **fully down**: 모든 DB-의존 엔드포인트가 `SVR-5003` 반환.
   본문 검출 (Case A/B) 은 `_resolve_runtime` 의 fallback 으로 in-memory
   분석기 사용 → 200 응답 가능 (단, idempotency / audit 미동작).
2. **read-only**: PostgreSQL 의 read-only 모드 진입 시 PII 정책 / 패턴
   변경이 차단되며, audit / nonce / job 테이블 INSERT 도 실패.
   → DB 복구가 우선.
3. **slow query**: `/readyz` 가 1.5 s 안에 PING 응답을 못 받으면 503.
   k8s 가 자동으로 트래픽 drain.

### 4.3 Redis 장애 분기

- **Down**: rate-limit 검사 자체가 실패 (`auth.py` 의 `_ip_failure_burst`).
  현재 동작은 token-bucket 검사가 raise → 401/429 가 아닌 500 으로
  surface 될 수 있음. 운영 환경에서는 Redis HA (sentinel/cluster) 권장.
- **Slow**: 모든 요청이 rate-limit 검사로 인해 대기 → p95 spike.

### 4.4 VLM 엔드포인트 장애

이미지 첨부에 한해 영향. 다른 첨부 (텍스트 PDF, DOCX) 는 영향 없음.
이미지 첨부는 `REQ-4040` 또는 `SVR-5004` 로 reject.

### 4.5 Encryption key 누락

`PII_ENCRYPTION_KEY` 가 미설정 상태에서 `encrypt_str` 호출 시
`EncryptionError` 발생 → 컨테이너 시작은 성공 (lazy validation) 하지만
첫 사용 시 즉시 실패. 운영 환경에서는 시작 직후 `make verify-crypto`
같은 smoke test 로 키 정합성 검증.

---

## 5. 모니터링

### 5.1 Prometheus 쿼리 예시

```promql
# 본문 검출 p95 latency
histogram_quantile(
  0.95,
  sum by (le, path) (rate(http_request_duration_seconds_bucket{path="/v1/detect/post"}[5m]))
)

# 분당 요청 수 (성공/실패 분리)
sum by (response_code) (rate(http_requests_total[1m])) * 60

# PII 검출 분포 (entity_type 별)
sum by (entity_type, verdict) (rate(pii_detections_total[5m]))

# 첨부 처리 backlog 추정
sum(increase(extraction_jobs_total{status="PROCESSING"}[10m]))
  - sum(increase(extraction_jobs_total{status=~"COMPLETED|FAILED"}[10m]))

# Rate-limit 거부 폭주
sum by (scope) (rate(rate_limit_rejections_total[5m]))
```

### 5.2 Grafana 대시보드 import

기본 Prometheus 대시보드 (Node Exporter, Python process metrics) 와
함께 다음 패널을 추가합니다:

- **Top: Request Rate / Error Rate / p95 Latency** (RED)
- **Middle: PII Detection Mix** (entity_type 별 stacked area)
- **Bottom: Job Pipeline** (PROCESSING/COMPLETED/FAILED counts)

JSON 포맷 대시보드는 운영팀이 별도로 관리 (본 문서 범위 외).

### 5.3 Alertmanager 연동

`deploy/prometheus_alerts.yml` 의 모든 alert 는 다음 라벨을 사용합니다:

- `service: pii-api` — 라우팅 키
- `severity: critical | warning | info` — 우선순위

Alertmanager 설정 예 (`alertmanager.yml`):

```yaml
route:
  group_by: ['alertname', 'service']
  receiver: 'pii-api-pager'
  routes:
    - matchers: [service="pii-api", severity="critical"]
      receiver: 'pii-api-pager'
    - matchers: [service="pii-api", severity="warning"]
      receiver: 'pii-api-slack'
    - matchers: [service="pii-api", severity="info"]
      receiver: 'pii-api-email'
```

---

## 6. 패턴 / 정책 추가 절차

본 API 는 detection rule 변경을 **shadow → canary → enabled** 의 3단계
워크플로로 운영합니다.

### 6.1 Shadow 모드 — 실제 verdict 영향 없음, audit 만 기록

```bash
# 1. 새 패턴을 shadow 로 등록
python -m app.cli pattern add \
  --entity-type KR_NEW_TYPE \
  --regex '<regex>' \
  --score 0.85 \
  --shadow      # ← 핵심 플래그

# 2. 24~72시간 트래픽 누적
# 3. 통계 확인
curl -sH "..." 'https://api/v1/admin/stats/detections?include_shadow=true' | jq .
```

`shadow_buckets` 가 비어 있다면 매칭이 너무 좁고, 정상 트래픽보다
훨씬 많은 매칭이 나오면 false positive 위험이 큽니다.

### 6.2 Promote 단계

```bash
# Shadow 결과가 만족스러우면 production 으로 승격
python -m app.cli pattern enable --entity-type KR_NEW_TYPE
```

Pattern listener (asyncio 워커) 가 `LISTEN/NOTIFY` 로 변경을 감지하여
모든 레플리카가 30 초 이내에 새 패턴을 사용합니다 (분석기 cache hot
reload).

### 6.3 Rollback

```bash
python -m app.cli pattern disable --entity-type KR_NEW_TYPE
# 즉시 모든 레플리카에서 비활성화 — verdict 영향 정지
```

---

## 7. 백업 / 복구

### 7.1 PostgreSQL pg_dump 주기

```bash
# 일 1회 전체 덤프 (권장)
0 4 * * * pg_dump -Fc -h <host> -U pii pii > /backups/pii-$(date +\%F).dump

# 보존: 30일 (audit 보존 정책과 정합)
find /backups -name 'pii-*.dump' -mtime +30 -delete
```

### 7.2 복구

```bash
# 1. 새 DB 생성
createdb -h <host> -U postgres pii_restore

# 2. 덤프 복구
pg_restore -h <host> -U postgres -d pii_restore /backups/pii-2026-04-25.dump

# 3. 애플리케이션 DATABASE_URL 변경 후 재시작
# 4. /readyz 확인
```

---

## 8. 키 회전

### 8.1 PII_ENCRYPTION_KEY 회전

암호화는 envelope 형식 (`v + key_id + nonce + ct + tag`) 으로 저장되어
key_id 별로 분기된 cipher 를 사용합니다. 회전 절차:

```bash
# 1. 새 32-byte 키 생성
NEW_KEY=$(openssl rand -hex 32)
NEW_KID=2  # 직전 ID 보다 1 증가

# 2. 직전 키를 grace period 동안 보존
PII_ENCRYPTION_OLD_KEYS='{"1":"<직전 키 hex>"}'
PII_ENCRYPTION_KEY=$NEW_KEY
PII_ENCRYPTION_KEY_ID=$NEW_KID

# 3. 컨테이너 재시작 — 신규 데이터는 key_id=2 로 저장,
#    구 데이터는 key_id=1 로 복호화
docker compose restart api

# 4. 모든 detection_results 행이 key_id=2 로 재암호화될 때까지 대기
#    (백그라운드 마이그레이션 — Phase 8 운영 결정 사항)

# 5. PII_ENCRYPTION_OLD_KEYS 에서 "1" 제거 → 컨테이너 재시작
```

### 8.2 Admin API 키 회전

```bash
# 1. 새 admin 키 발급
python -m app.cli api_key issue --name admin-2026-Q2 --is-admin
# → key_id, secret 출력 → 안전 저장소 (Vault / 1Password) 에 저장

# 2. 새 키로 운영 도구 / Prometheus scrape config 갱신

# 3. 직전 키 비활성화
python -m app.cli api_key revoke <직전 key_id>
```

### 8.3 Webhook signing secret 회전

발급 측과 수신 측 모두 동시에 갱신해야 합니다 — 무중단 회전 어려움.
사전 통보 후 점검 시간 (15 분 이내) 에 양측 동시 적용 권장.

---

## 9. 운영자 체크리스트 (월간)

매월 1회 다음 항목을 점검하고 결과를 운영 로그에 기록합니다:

- [ ] **보존 기간 검증**:
  - `audit_log_retention_days` 365일 정책대로 cleanup 워커가 동작 중인가?
    (`SELECT count(*), min(occurred_at) FROM pii.audit_events;`)
  - `detection_retention_days` 30일 정책대로 정리되고 있는가?
- [ ] **비밀 회전**:
  - `PII_ENCRYPTION_KEY` 1년 이상 미회전인가? → 회전
  - `WEBHOOK_SIGNING_SECRET` 6개월 이상인가? → 회전
  - Admin API 키 90일 이상인가? → 회전
- [ ] **보안 패치**:
  - `make security` (bandit) High 결과 0건 유지
  - `uv run pip-audit --skip-editable` High/Critical CVE 0건 유지
  - 베이스 이미지 (`python:3.12-slim`) 최신 patch 반영 후 재빌드
- [ ] **디스크 사용량**:
  - PostgreSQL data 디렉터리 < 70 % 사용
  - 컨테이너 로그 < 1 GB (rotate 정책 점검)
- [ ] **알람 점검**:
  - 지난 한달간 발화한 alert 들의 acknowledgement / resolve 시간 검토
  - `feedback_alert_threshold` 가 노이즈 레벨인지 확인
- [ ] **런북 갱신**:
  - 새로 발생한 장애 사례를 §4.1 표에 추가
  - Phase 9+ 신규 응답 코드 반영

---

## 부록 A. 자주 사용하는 명령

```bash
# 컨테이너 상태
docker compose -f deploy/docker-compose.yml ps

# 로그 (마지막 200줄)
docker compose -f deploy/docker-compose.yml logs --tail=200 -f api

# 헬스체크 (외부)
curl -fsS https://api.example.com/healthz
curl -fsS https://api.example.com/readyz

# 메트릭 (admin gate 통과 후)
curl -sH "X-API-Key: ..." -H "X-Timestamp: ..." -H "X-Nonce: ..." \
     -H "X-Signature: ..." https://api.example.com/v1/admin/metrics

# DB 한 번 깨우기 (마이그레이션 / 콘솔)
docker compose -f deploy/docker-compose.yml exec postgres \
    psql -U pii -d pii -c '\dt pii.*'

# 패턴 / 정책 콘솔
python -m app.cli pattern list
python -m app.cli pattern add --help

# Phase 별 마이그레이션 히스토리
alembic -c alembic.ini history
```

## 부록 B. 관련 문서

- `PII_API_Development_Requirements.md` — 사양 단일 출처 (비공개 내부 문서)
- `docs/data_flow.md` — 데이터 흐름도
- `docs/privacy_notice.md` — 개인정보처리방침 (공개 endpoint 노출)
- `docs/load_test_report.md` — Phase 8 부하 테스트 결과
- `docs/security_scan_report.md` — Phase 8 보안 스캔 결과
- `docs/phase_*_completion.md` — Phase 별 완료 보고서
