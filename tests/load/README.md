# Phase 8 Load Tests

Locust scenarios for the PII Detection API.

## Running

### 1. Start the API locally
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. (Optional) Issue an API key for HMAC signing
```bash
python -m app.cli api_key issue --name load-test
# copy printed key_id + secret
export PII_LOAD_API_KEY=<key_id>
export PII_LOAD_API_SECRET=<secret>
```

If the variables are unset the runner falls back to unauthenticated
calls — useful for ASGI smoke runs against a stubbed-auth instance.

### 3. Run Locust

Headless run, 60 seconds at 50 users:
```bash
uv run locust -f tests/load/locustfile.py \
  --host http://127.0.0.1:8000 \
  -u 50 -r 10 -t 60s \
  --headless --csv=load_results
```

Interactive UI on http://127.0.0.1:8089:
```bash
uv run locust -f tests/load/locustfile.py --host http://127.0.0.1:8000
```

## Scenarios

| User class            | Weight | Verb / path                   | Notes |
|-----------------------|--------|--------------------------------|-------|
| `BodyOnlyUser`        | 80     | `POST /v1/detect/post` body    | 5% trigger BLOCK, 40% trigger WARN, rest PASS |
| `WithAttachmentUser`  | 15     | `POST /v1/detect/post` Case C  | Synthetic PDF URL (fetch will fail in offline tests) |
| `JobPollUser`         | 5      | `GET /v1/jobs/{id}`            | Polls jobs created by `WithAttachmentUser` |

All payloads are produced by `tests.fixtures.synthetic_pii_generator`.
**No real PII is ever sent.**

## Targets (Phase 8 SLA)

- **본문 검사**: 100 RPS, p50 < 200 ms, p95 < 1 s
- **첨부 검사**: 50/min, p95 < 30 s

The actual numbers we observed on this host are recorded in
[`docs/load_test_report.md`](../../docs/load_test_report.md).

## Distributed mode

For higher throughput, run a master + N workers:
```bash
# master
uv run locust -f tests/load/locustfile.py --master --host http://127.0.0.1:8000

# workers (one per CPU core)
uv run locust -f tests/load/locustfile.py --worker --master-host=127.0.0.1
```
