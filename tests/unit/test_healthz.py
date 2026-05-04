"""Phase 0 T0.2: /healthz returns {status: ok}."""

from httpx import AsyncClient


async def test_healthz_returns_ok(client: AsyncClient) -> None:
    res = await client.get("/healthz")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


async def test_v1_healthz_returns_env(client: AsyncClient) -> None:
    res = await client.get("/v1/healthz")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "env" in body
