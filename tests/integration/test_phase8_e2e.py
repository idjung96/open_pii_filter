# SYNTHETIC DATA - NOT REAL PII
"""Phase 8 — 전체 end-to-end 흐름 회귀 방지 (T8.1).

ASGI 인-프로세스 앱에 대해 운영 트래픽과 동일한 단계를 그대로 재현:

* `issue_api_key()` 로 실제 API 키 발급 (DB에 row 생성)
* 실제 HMAC envelope 서명
* `POST /v1/detect/post` (본문 + PDF 첨부 1개)
* `/v1/jobs/{id}` 폴링으로 비동기 잡이 COMPLETED 가 될 때까지 대기
* 워커가 callback_url 로 보낸 webhook payload 가 캡처되는지 확인
* 본문만 보내는 happy path 50회 반복하여 평균 지연 < 500 ms (스펙
  200 ms p50 에서 CI 머신 노이즈 감안해 500 ms 로 완화)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from sqlalchemy import text

from app.api.schemas import Attachment
from app.config import get_settings
from app.security.api_key import issue_api_key
from app.security.hmac_auth import compute_signature
from app.security.idempotency import get_cache
from app.security.rate_limit import get_redis
from tests.fixtures.attachments.create_fixtures import make_text_pdf

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Helpers ───────────────────────────────────────────────────────────────
def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler,  # type: ignore[no-untyped-def]
) -> None:
    """워커의 모든 httpx 호출 (fetch / webhook) 을 MockTransport 로 가로챈다.

    실제 네트워크 호출 없이 첨부 다운로드와 webhook 전달을 시뮬레이션해
    테스트가 결정적으로 돌아가게 한다.
    """
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def _signed_headers(
    *,
    key_id: str,
    secret: str,
    method: str,
    path: str,
    body: bytes = b"",
) -> dict[str, str]:
    ts = str(int(time.time()))
    n = uuid.uuid4().hex
    sig = compute_signature(
        secret=secret,
        timestamp=ts,
        nonce=n,
        method=method,
        path=path,
        body=body,
    )
    return {
        "X-API-Key": key_id,
        "X-Timestamp": ts,
        "X-Nonce": n,
        "X-Signature": sig,
        "content-type": "application/json",
    }


@pytest.fixture
async def e2e_key(db_session: AsyncSession) -> tuple[str, str]:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    engine = create_async_engine(get_settings().database_url, poolclass=NullPool, future=True)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        row, secret = await issue_api_key(
            s,
            name=f"e2e-{uuid.uuid4().hex[:6]}",
            rate_per_minute=100_000,
            rate_per_hour=10_000_000,
            created_by="pytest",
        )
        await s.commit()
        key_id = row.key_id
    yield key_id, secret
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.api_keys WHERE key_id = :k"), {"k": key_id})
        await s.execute(
            text("DELETE FROM pii.api_key_nonces WHERE key_id = :k"),
            {"k": key_id},
        )
        await s.commit()
    r = get_redis()
    await r.delete(f"rl:apikey:{key_id}:m", f"rl:apikey:{key_id}:h")


@pytest.fixture(autouse=True)
def _flush_idempotency_cache() -> None:
    get_cache().clear()


# ── T8.1: 첨부 + webhook 까지 포함한 비동기 전체 흐름 ───────────────────
async def test_t8_1_full_async_flow_with_webhook(
    client_anon,
    e2e_key: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Case C — 실제 HMAC 인증 + ASGI 클라이언트 + 가짜 webhook 핸들러.

    검증 단계:
      1. 본문 + 첨부 PDF 로 `POST /v1/detect/post` 가 202 ACK-3001 반환
      2. 워커가 fetch_url 로 PDF 를 받아 분석 후 COMPLETED 상태로 전이
      3. `/v1/jobs/{id}` 폴링이 결국 COMPLETED 를 보고
      4. 워커가 callback_url 로 webhook 을 POST — `webhook_calls` 에 캡처됨

    이 흐름 중 한 단계라도 깨지면 운영 비동기 처리가 무력화되므로 가장
    중요한 통합 회귀 가드.
    """
    key_id, secret = e2e_key
    pdf = make_text_pdf()
    attachment = Attachment(
        attachment_id="att_001",
        filename="report.pdf",
        size_bytes=len(pdf),
        mime_type="application/pdf",
        sha256=hashlib.sha256(pdf).hexdigest(),
        fetch_url="https://files.example.com/report.pdf",
    )

    # Capture webhook deliveries.
    webhook_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "callback" in request.url.host:
            try:
                webhook_calls.append(
                    {
                        "url": str(request.url),
                        "json": request.read().decode("utf-8"),
                    }
                )
            except Exception:  # pragma: no cover — best-effort capture
                webhook_calls.append({"url": str(request.url), "json": "<n/a>"})
            return httpx.Response(200)
        # Fetch path.
        return httpx.Response(200, content=pdf)

    _install_transport(monkeypatch, handler)

    request_id = str(uuid.uuid4())
    body = {
        "request_id": request_id,
        "post": {"board_id": "general", "title": "x", "body": "오늘 날씨가 좋네요"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
        "attachments": [attachment.model_dump()],
        "callback_url": "https://callback.example.com/hook",
    }
    raw_body = json.dumps(body).encode("utf-8")
    headers = _signed_headers(
        key_id=key_id,
        secret=secret,
        method="POST",
        path="/v1/detect/post",
        body=raw_body,
    )
    resp = await client_anon.post("/v1/detect/post", content=raw_body, headers=headers)
    assert resp.status_code == 202, resp.text
    payload = resp.json()
    assert payload["code"] == "ACK-3001"
    job_id = payload["job"]["job_id"]

    # Poll /v1/jobs/{id} until COMPLETED (the worker is fire-and-forget
    # asyncio in the same process).
    final_status = None
    for _ in range(60):
        get_path = f"/v1/jobs/{job_id}"
        h = _signed_headers(
            key_id=key_id,
            secret=secret,
            method="GET",
            path=get_path,
        )
        r = await client_anon.get(get_path, headers=h)
        if r.status_code == 200 and r.json()["status"] in {"COMPLETED", "FAILED"}:
            final_status = r.json()["status"]
            break
        await asyncio.sleep(0.05)
    assert final_status == "COMPLETED", f"job did not complete; last status={final_status}"

    # The webhook should have been delivered (or attempted) at least once.
    assert webhook_calls, "no webhook POST captured"
    captured = webhook_calls[-1]
    assert "callback.example.com" in captured["url"]


# ── 본문만 보내는 happy path 50회 반복 — 지연 시간 예산 ─────────────────
async def test_t8_1_body_only_latency_budget(
    client_anon,
    e2e_key: tuple[str, str],
) -> None:
    """본문만 50건 순차 호출했을 때 평균 지연 < 500 ms.

    스펙 SLA 는 p50 200 ms / p95 1 s 이지만 공유 CI 환경 노이즈를 감안해
    평균 500 ms 로 완화한 헤드룸 가드. 매 호출마다 새 request_id + nonce 를
    써서 멱등성 캐시·리플레이 방어가 우회되지 않도록 한다 (실제 회수만큼
    분석기 핫패스를 두드림). 더 빡빡한 SLO 검증은 `docs/load_test_report.md`
    의 운영자 산출물에서 별도 진행.
    """
    key_id, secret = e2e_key
    iterations = 50
    durations: list[float] = []

    for _ in range(iterations):
        request_id = str(uuid.uuid4())
        body = {
            "request_id": request_id,
            "post": {"board_id": "g", "title": "x", "body": "오늘 날씨가 좋네요"},
            "author": {"name": "x", "ip": "127.0.0.1"},
        }
        raw_body = json.dumps(body).encode("utf-8")
        headers = _signed_headers(
            key_id=key_id,
            secret=secret,
            method="POST",
            path="/v1/detect/post",
            body=raw_body,
        )
        t0 = time.perf_counter()
        resp = await client_anon.post("/v1/detect/post", content=raw_body, headers=headers)
        durations.append(time.perf_counter() - t0)
        assert resp.status_code == 200, resp.text

    avg = sum(durations) / len(durations)
    p95 = sorted(durations)[int(len(durations) * 0.95) - 1]
    print(
        f"\n[T8.1] body-only over {iterations} runs: avg={avg * 1000:.1f}ms, p95={p95 * 1000:.1f}ms"
    )
    # Generous headroom — spec is 200 ms p50, 1 s p95; we assert avg<500 ms
    # to pass on CI/Docker shared hardware. Tighter SLO assertions belong
    # in the load_test_report.md operator deliverable.
    assert avg < 0.5, f"average latency {avg * 1000:.1f}ms exceeds 500ms budget"
