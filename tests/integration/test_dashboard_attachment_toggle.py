# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/F — 운영자 대시보드 `attachment_scan_enabled` 토글 회귀 방지.

`POST /admin/settings/attachment-scan` 라우트가 다음을 정확히 수행하는지
검증한다:

  - 운영자 대시보드 IP allowlist / 세션 쿠키 검사를
    `dependency_overrides` 로 우회 (테스트 자체가 게이트 회귀를 보려는 것은
    아님 — 이 부분은 다른 테스트가 담당)
  - 토글 값을 `data/system_settings.json` 으로 영속화 (`ss.set_value`)
  - 후속 `/v1/detect/post` 호출이 새 값을 즉시 관찰 가능 — 토글 OFF 면
    첨부가 있어도 Case B (job_id 없음) 로 떨어지고, 다시 ON 하면 202
    ACK-3001 로 돌아옴
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


# ── T4b.17: POST → 토글 값이 디스크에 영속화 ─────────────────────────────
async def test_post_toggle_off_persists_value() -> None:
    """체크박스 미선택 (enabled 필드 부재) → False 로 저장 + JSON 파일에 반영.

    HTML form 의 checkbox 는 체크 해제 시 아예 키가 빠진 채로 POST 되므로
    "enabled 가 없으면 False" 로 해석되어야 한다 (회귀: present-only 검사).
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # `enabled` 필드 없이 POST → 체크 해제 → False.
        resp = await ac.post("/admin/settings/attachment-scan", data={})
    # 303 See Other 로 settings 페이지로 리다이렉트.
    assert resp.status_code == 303, resp.text
    assert ss.get("attachment_scan_enabled") is False
    payload = json.loads(ss._FILE.read_text(encoding="utf-8"))
    assert payload["attachment_scan_enabled"] is False


# ── T4b.18: POST `enabled=on` → True 로 복귀 ─────────────────────────────
async def test_post_toggle_on_persists_value() -> None:
    """False 로 떨어뜨린 토글을 `enabled=on` 으로 다시 True 화 가능.

    토글이 일방향 (한 번 끄면 코드 수정 없이는 못 켜는) 으로 망가지면 운영
    재개가 안 되므로 양방향 전환을 모두 회귀 가드.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/admin/settings/attachment-scan", data={})
        assert ss.get("attachment_scan_enabled") is False
        resp = await ac.post("/admin/settings/attachment-scan", data={"enabled": "on"})
    assert resp.status_code == 303
    assert ss.get("attachment_scan_enabled") is True


# ── T4b.19: detect 엔드포인트가 토글 변경을 즉시 관찰 ───────────────────
async def test_detect_observes_toggle(
    client: AsyncClient,  # auth-bypassed detect client (conftest)
) -> None:
    """End-to-end — 토글 OFF 후 첨부 있는 호출이 Case B (job_id 없음) 로 떨어지고,
    토글 ON 후에는 같은 호출이 다시 202 ACK-3001 로 돌아온다.

    `system_settings.json` 의 영속 값이 핫리로드되어 detect 핸들러에 즉시
    반영되는지 확인 — 재시작 없이 운영자가 즉석에서 첨부 검사를 끄고
    켤 수 있어야 운영 비상 시 빠른 대응이 가능하다.
    """
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
