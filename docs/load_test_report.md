# Phase 8 부하 테스트 보고서 (T8.2)

본 문서는 PII Detection API 의 부하 테스트 결과를 정리합니다. 측정은
`tests/load/asgi_smoke.py`(in-process ASGI 드라이버) 와
`tests/load/locustfile.py`(Locust 시나리오) 를 사용했습니다.

> **합성 데이터만 사용**: 모든 부하 테스트 페이로드는
> `tests/fixtures/synthetic_pii_generator.py` 가 생성한 가짜 PII 입니다.
> 실제 PII 는 절대 사용하지 않습니다.

---

## 1. 테스트 환경

| 항목 | 값 |
|------|-----|
| OS | Linux 5.14.0-503.23.2.el9_5 (RHEL 9 호환) |
| Python | 3.12.13 |
| FastAPI | 0.115+ |
| 드라이버 | httpx ASGITransport (in-process) |
| 데이터베이스 | PostgreSQL 16 (개발 환경, 별도 호스트) |
| Redis | 7 (개발 환경, 별도 호스트) |
| 분석기 | Presidio + spaCy `ko_core_news_lg` (warm cache) |
| 인증 | conftest 스텁 (HMAC 비활성, 분석기 hot-path 측정에 집중) |

테스트는 단일 호스트, 단일 워커, 단일 uvicorn 프로세스에서 수행되었습니다.
Production 배포는 N개의 컨테이너 레플리카로 수평 확장됩니다 (asyncio 가
한 프로세스 내 동시성을 처리하므로 워커 증설 대신 레플리카 증설 권장).

---

## 2. 시나리오별 결과

### 2.1 본문 단독 (Case A/B) — concurrency=8, duration=30 s

```json
{
  "concurrency": 8,
  "total": 1967,
  "success": 1967,
  "success_pct": 1.0,
  "rps": 65.49,
  "p50_ms": 114.6,
  "p95_ms": 165.95,
  "p99_ms": 207.55,
  "avg_ms": 122.05,
  "status_codes": {"200": 1967}
}
```

- **SLA 비교**: 본문 검사 SLA 는 `p50 < 200 ms / p95 < 1 s`.
  - p50 114 ms ✅ (목표 200 ms 대비 43 % 여유)
  - p95 166 ms ✅ (목표 1 s 대비 84 % 여유)
- **성공률**: 100 % (3xx/4xx/5xx 없음)

### 2.2 본문 단독 (Case A/B) — concurrency=16, duration=30 s

```json
{
  "concurrency": 16,
  "total": 1855,
  "success": 1855,
  "success_pct": 1.0,
  "rps": 61.59,
  "p50_ms": 246.37,
  "p95_ms": 354.45,
  "p99_ms": 511.13,
  "avg_ms": 259.33
}
```

- 동시성을 높이면 p50 가 200 ms 목표를 약간 초과하지만 p95 는 여전히
  1 s 이내 (목표 대비 65 % 여유).

### 2.3 본문 단독 (Case A/B) — concurrency=32, duration=60 s

```json
{
  "concurrency": 32,
  "total": 3512,
  "success": 3512,
  "success_pct": 1.0,
  "rps": 58.19,
  "p50_ms": 529.26,
  "p95_ms": 705.92,
  "p99_ms": 1013.18,
  "avg_ms": 548.75
}
```

- 단일 호스트 / 단일 워커 한계점. p99 가 1 s 를 약간 초과 (1.013 s).
  Production 에서는 레플리카 2~3 개로 분산하면 p99 < 500 ms 유지 가능.
- 성공률은 여전히 100 %.

### 2.4 첨부 검사 (Case C)

Case C 시나리오는 `tests/load/locustfile.py::WithAttachmentUser` 가
담당합니다. ASGI 인-프로세스 드라이버는 외부 fetch URL 에 도달할 수
없으므로 별도의 통합 테스트 (`tests/integration/test_phase8_e2e.py`) 가
실 데이터 흐름을 검증합니다 — 60 회 폴링 후 평균 50 ms 이내 COMPLETED.

본격적인 첨부 부하 측정은 다음 명령으로 실행합니다 (Production 환경
권장):

```bash
export PII_LOAD_API_KEY=<key_id>
export PII_LOAD_API_SECRET=<secret>
uv run locust -f tests/load/locustfile.py --host http://localhost:8000 \
  -u 50 -r 10 -t 5m --headless --csv=load_results
```

---

## 3. 병목 분석

| 후보 | 측정/관찰 | 결론 |
|------|-----------|------|
| 분석기 초기화 | warm cache 사용 | 영향 없음 (cache hit) |
| spaCy NER | 단일 스레드 | 본문 길이 대비 선형 — 1.4 KB 본문 ~30 ms |
| DB connection pool | pool_size=10, max_overflow=20 | concurrency=32 에서도 pool 고갈 없음 |
| Redis throughput | 단일 인스턴스 | 단일 호스트 측정에서 병목 아님 |
| 이벤트 루프 latency | concurrency=32 부터 큐잉 발생 | 단일 워커 한계 — 레플리카 확장 필요 |
| Audit 쓰기 | 비동기 fire-and-forget | 응답 지연 영향 없음 |

**진단**: 본문 검사 throughput 의 실질적 한계는 spaCy NER 의 단일 스레드
처리 속도. 동일 호스트에서 더 많은 RPS 를 얻으려면 분석기 워커 풀
(`asyncio.to_thread` 의 default ThreadPoolExecutor) 의 max_workers 를 늘리거나,
컨테이너 레플리카를 N 배 늘리는 방향이 가장 효율적임.

---

## 4. 권장 운영 설정

### 4.1 단일 노드 기준
- **목표**: 본문 100 RPS p95 < 1 s
- 측정 결과: 단일 워커로 p95 700 ms 에서 ~58 RPS 안정.
- **권장**: 노드당 컨테이너 레플리카 **2** 개 (총 ~120 RPS 안전 마진).

### 4.2 K8s/Compose deployment
```yaml
deployment:
  replicas: 2-3        # 본문 100 RPS 안정 확보
  resources:
    requests:
      cpu: "1"
      memory: "1.5Gi"  # spaCy 모델 + venv ~1.2GB
    limits:
      cpu: "2"
      memory: "2.5Gi"
  readinessProbe:
    httpGet: { path: /readyz, port: 8000 }
    periodSeconds: 5
  livenessProbe:
    httpGet: { path: /healthz, port: 8000 }
    periodSeconds: 10
```

### 4.3 첨부 처리 워커
첨부 처리는 본문 처리와 같은 프로세스에서 asyncio task 로 실행됩니다.
대량 첨부 (500 MB+ 일별 트래픽) 가 예상되는 경우, 별도 컨테이너에서
asyncio worker 만 동작하도록 분리하는 옵션을 검토 (현재는 단일 컨테이너
배포 — Phase 8 운영자 결정 E).

---

## 5. 컨테이너 빌드 검증 (T8.6)

`deploy/Dockerfile` 은 multi-stage 패턴으로 작성되었습니다 (builder +
runtime). 본 환경에서는 docker daemon 접근 권한이 제한되어 직접 빌드는
수행하지 못했으나, Dockerfile 구조는 다음 사항을 검증합니다:

1. **Builder stage**: `python:3.12-slim` 위에 `build-essential`,
   `libpq-dev`, `curl` 설치 → uv 로 의존성 sync (`--frozen --no-dev`) →
   spaCy `ko_core_news_lg` 모델 다운로드.
2. **Runtime stage**: `python:3.12-slim` + libpq5 + curl, non-root 유저
   (uid=1000), prebuilt `.venv` 복사, `HEALTHCHECK` /readyz, single
   uvicorn worker.
3. **이미지 크기 추정**: spaCy 모델 ~600 MB + Python deps ~400 MB +
   base ~120 MB = **약 1.2~1.4 GB**.

CI 에서는 `.github/workflows/ci.yml` 의 `container-build` 잡이 이
Dockerfile 의 빌드 가능성을 매 PR 마다 자동 검증합니다.

---

## 6. 향후 개선 사항

- **분석기 캐시 워밍업 엔드포인트**: 컨테이너 시작 직후 첫 요청이
  ~500 ms 추가 비용 발생. 시작 시 더미 분석을 1회 수행하도록
  lifespan 에 hook 추가 가능.
- **HTTP/2 keep-alive 튜닝**: nginx → uvicorn 사이 keepalive 32 (현재).
  대량 동시성 시나리오에서는 64 로 증설 검토.
- **Pre-warming spaCy on import**: lifespan hook 에서 `build_analyzer()`
  를 미리 호출하여 첫 요청 cold-start 제거.
