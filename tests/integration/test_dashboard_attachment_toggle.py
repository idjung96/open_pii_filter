# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/F — admin dashboard `attachment_scan_enabled` toggle.

Verifies the new `POST /admin/settings/attachment-scan` route:

- bypassing the dashboard session (via FastAPI's `dependency_overrides`)
  so the test does not have to manage cookies + IP allowlist
- writing the toggle to `data/system_settings.json` via `ss.set_value`
- reading it back through `ss.get` so subsequent detect requests see
  the new value
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dashboard import get_dashboard_session
from app.core import system_settings as ss
from app.main import app

if TYPE_CHECKING:
    pass


@pytest.fixture(autouse=True)
def _bypass_dashboard_session() -> None:
    """Skip the cookie + IP allowlist check for the duration of each test."""
    app.dependency_overrides[get_dashboard_session] = lambda: "pytest-session"
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_dashboard_session, None)


@pytest.fixture(autouse=True)
def _restore_settings_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect the JSON-on-disk store to a per-test tmp path so the
    real `data/system_settings.json` never moves."""
    test_file = tmp_path / "system_settings.json"
    monkeypatch.setattr(ss, "_FILE", test_file)
    yield


def _att(*, filename: str, mime: str, size: int = 4096) -> dict[str, Any]:
    digest = hashlib.sha256(b"x" * size).hexdigest()
    return {
        "attachment_id": uuid.uuid4().hex[:16],
        "filename": filename,
        "size_bytes": size,
        "mime_type": mime,
        "sha256": digest,
        "fetch_url": "https://files.example.test/x.bin",
    }


def _detect_payload(*, attachments: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "request_id": str(uuid.uuid4()),
        "author": {"name": "pytest", "ip": "203.0.113.5"},
        "post": {
            "board_id": "qna",
            "title": "synthetic title",
            "body": "본문에는 PII 가 없습니다.",
        },
        "attachments": attachments,
        "callback_url": "https://board.example.test/cb",
    }


# ── T4b.17: POST writes the toggle to disk ─────────────────────────────────
async def test_post_toggle_off_persists_value() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Send no `enabled` field → checkbox unchecked → False.
        resp = await ac.post("/admin/settings/attachment-scan", data={})
    # 303 See Other redirects back to the GET settings page.
    assert resp.status_code == 303, resp.text
    assert ss.get("attachment_scan_enabled") is False
    payload = json.loads(ss._FILE.read_text(encoding="utf-8"))
    assert payload["attachment_scan_enabled"] is False


# ── T4b.18: POST with `enabled=on` flips it back to True ──────────────────
async def test_post_toggle_on_persists_value() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/admin/settings/attachment-scan", data={})
        assert ss.get("attachment_scan_enabled") is False
        resp = await ac.post("/admin/settings/attachment-scan", data={"enabled": "on"})
    assert resp.status_code == 303
    assert ss.get("attachment_scan_enabled") is True


# ── T4b.19: detect endpoint observes the toggle change ─────────────────────
async def test_detect_observes_toggle(
    client: AsyncClient,  # auth-bypassed detect client (conftest)
) -> None:
    """End-to-end: flip the toggle off through the dashboard route, then
    a Case-C-shaped detect call must come back as Case B (no job_id);
    flip it back on and the same call returns 202 / ACK-3001 again."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin:
        # Flip OFF.
        resp = await admin.post("/admin/settings/attachment-scan", data={})
        assert resp.status_code == 303

    body = _detect_payload(attachments=[_att(filename="ok.pdf", mime="application/pdf")])
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["job"] is None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin:
        # Flip ON.
        resp = await admin.post("/admin/settings/attachment-scan", data={"enabled": "on"})
        assert resp.status_code == 303

    body = _detect_payload(attachments=[_att(filename="ok.pdf", mime="application/pdf")])
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 202, resp.text
    assert resp.json()["job"] is not None
