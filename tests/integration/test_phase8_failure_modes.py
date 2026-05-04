# SYNTHETIC DATA - NOT REAL PII
"""Phase 8 — failure injection (T8.3).

Verifies graceful degradation when downstream dependencies fail:

* PG down — caller sees a meaningful error envelope. The detect path
  uses ``_resolve_runtime`` which already falls back to the in-memory
  analyzer on DB failure (see ``app/api/detect.py``), so a body-only
  detect call still returns 200 with the analyzer fallback. Audit + the
  attachment-job persistence layer surface SVR-5xxx envelopes when DB
  errors propagate beyond the fallback.
* Redis down — rate limiter fails open (the per-IP burst check in
  ``app/security/auth.py`` runs only on auth failure; under stub auth
  the call still succeeds). The caller-rate-limit gate is best-effort.
* Encryption key missing — ``app.security.encryption.get_cipher`` raises
  ``EncryptionError`` on first use rather than at import, so the service
  boots but any caller of ``encrypt_str`` gets a loud failure.

These tests use monkeypatch to simulate failure rather than tearing
down real services. The goal is to assert the *user-visible behaviour*
when the dependency is unavailable, not to test the dependency itself.
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
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
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
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        resp = await c.get("/readyz")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"]["ok"] is False


# ── /healthz always returns 200 (liveness is "process is up") ─────────────
async def test_healthz_always_200_no_io() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        resp = await c.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
