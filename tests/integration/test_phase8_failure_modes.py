# SYNTHETIC DATA - NOT REAL PII
"""Phase 8 — 의존 시스템 장애 주입 회귀 방지 (T8.3).

각 종속 인프라가 다운됐을 때 사용자 응답 수준에서의 graceful degradation
정책을 검증한다:

* **PostgreSQL 다운** — `_resolve_runtime` 의 캐시 호출이 실패하면 in-memory
  fallback 분석기 + 빈 정책 리스트로 자동 전환되어 본문-only detect 호출은
  여전히 200 PASS 를 돌려준다. audit 행 기록 실패는 백그라운드에서 silent
  drop 되고 서비스가 멈추지 않는다.
* **Redis 다운** — rate-limit 게이트는 `require_auth` 경로에서만 발동하므로
  stub 인증 하에서는 우회되어 200 응답이 유지된다. 즉 "rate-limit fail-open"
  정책을 핀(pin).
* **암호화 키 미설정** — `encrypt_str` 호출 시 즉시 `EncryptionError` (silent
  실패 금지). 서비스 자체는 부팅하되 암호화가 필요한 경로는 큰 소리로 실패.
* **`/readyz` DB ping 실패** → 503 + `degraded` status + 어떤 컴포넌트가
  실패했는지 응답 본문에 표시. `/healthz` 는 의존성 무관 200 OK 유지.

monkeypatch 로 장애를 시뮬레이션 — 실제 서비스를 내리지 않고 사용자 가시
동작만 검증한다.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.auth import require_auth
from app.security.hmac_auth import AuthedCaller


def _stub_caller() -> AuthedCaller:
    return AuthedCaller(
        key_id="failure-stub",
        name="pytest",
        rate_per_minute=10_000,
        rate_per_hour=10_000_000,
        ip_allowlist=None,
        client_ip="127.0.0.1",
    )


# ── PG down: detect still returns 200 thanks to in-memory fallback ────────
async def test_pg_down_body_detect_still_returns_200(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When _resolve_runtime hits a DB error it falls back to the hard-
    coded analyzer + empty policy list, so a body-only detect call still
    succeeds. Audit row write fails silently in the background."""
    import app.api.detect as detect_mod

    async def boom_runtime():
        raise RuntimeError("pg down (simulated)")

    # The fallback path lives in `_resolve_runtime`'s except clause; we
    # instead make the *cache* path raise so the except clause is taken.
    class _FailingCache:
        async def get(self, _session):
            raise RuntimeError("pg down (simulated)")

        async def get_shadow(self, _session):
            raise RuntimeError("pg down (simulated)")

    monkeypatch.setattr(detect_mod, "get_analyzer_cache", lambda: _FailingCache())

    app.dependency_overrides[require_auth] = _stub_caller
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/detect/post",
                json={
                    "request_id": str(uuid.uuid4()),
                    "post": {"board_id": "g", "title": "x", "body": "y"},
                    "author": {"name": "x", "ip": "127.0.0.1"},
                },
            )
    finally:
        app.dependency_overrides.pop(require_auth, None)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # PASS verdict from the in-memory fallback analyzer.
    assert body["verdict"] == "PASS"


# ── Redis down: stubbed-auth detect still returns 200 ─────────────────────
async def test_redis_down_does_not_break_detect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rate limiter only enforces during the require_auth path. Under
    stub auth the limiter is bypassed, so even a redis outage doesn't
    break body-only detect."""
    import app.security.rate_limit as rl_mod

    def boom_redis():
        raise RuntimeError("redis down (simulated)")

    monkeypatch.setattr(rl_mod, "get_redis", boom_redis)

    app.dependency_overrides[require_auth] = _stub_caller
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/v1/detect/post",
                json={
                    "request_id": str(uuid.uuid4()),
                    "post": {"board_id": "g", "title": "x", "body": "y"},
                    "author": {"name": "x", "ip": "127.0.0.1"},
                },
            )
    finally:
        app.dependency_overrides.pop(require_auth, None)

    assert resp.status_code == 200


# ── Encryption key missing: encrypt_str raises EncryptionError loudly ─────
def test_missing_encryption_key_fails_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling encrypt_str without a configured key raises EncryptionError
    (rather than returning corrupt ciphertext or a silent empty value)."""
    from app.config import Settings
    from app.security import encryption as enc_mod

    base = Settings().model_dump()
    base["pii_encryption_key"] = ""
    fake = lambda: Settings(**base)  # noqa: E731
    monkeypatch.setattr("app.config.get_settings", fake)
    monkeypatch.setattr(enc_mod, "get_settings", fake)
    enc_mod.get_cipher.cache_clear()

    with pytest.raises(enc_mod.EncryptionError):
        enc_mod.encrypt_str("any plaintext")

    # Restore the real cipher so the test isolation doesn't break later
    # tests that depend on encryption being available.
    enc_mod.get_cipher.cache_clear()


# ── /readyz reports failure when DB is unreachable ────────────────────────
async def test_readyz_reports_db_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the readiness DB ping fails, /readyz returns 503 with the
    failing component flagged."""
    import app.api.health as health_mod

    async def boom_db():
        return False, "RuntimeError: pg down (simulated)"

    monkeypatch.setattr(health_mod, "_check_db", boom_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["ok"] is False


# ── /healthz always returns 200 (liveness is "process is up") ─────────────
async def test_healthz_always_200_no_io() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
