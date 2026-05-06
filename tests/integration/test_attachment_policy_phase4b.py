# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `detect_post` gate behaviour (T4b.7~T4b.10).

The auth-bypassed `client` fixture (conftest) drives the endpoint with
synthetic Case-C requests; we never reach the real fetch / extractor
pipeline because the gates we exercise reject the request before that
point.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import TYPE_CHECKING, Any

from app.core import system_settings as ss
from app.core.blocklist_cache import reload_blocklist
from app.db.session import get_sessionmaker

if TYPE_CHECKING:
    from httpx import AsyncClient

# Reuse the seeded blocklist from the migration. We sync the cache here
# so the gate matches at request time even when the per-test event loop
# starts cold.


async def _ensure_blocklist_loaded() -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        await reload_blocklist(s)


def _payload(
    *,
    request_id: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    callback_url: str = "https://board.example.test/cb",
    body: str = "안녕하세요. 본문 내용입니다.",
) -> dict[str, Any]:
    return {
        "request_id": request_id or str(uuid.uuid4()),
        "author": {
            "name": "pytest",
            "ip": "203.0.113.5",  # not in any exception list by default
        },
        "post": {
            "board_id": "qna",
            "title": "synthetic title",
            "body": body,
        },
        "attachments": attachments,
        "callback_url": callback_url,
    }


def _att(
    *,
    filename: str,
    mime: str,
    size: int = 1024,
    fetch_url: str = "https://files.example.test/x.bin",
) -> dict[str, Any]:
    digest = hashlib.sha256(b"x" * size).hexdigest()
    return {
        "attachment_id": uuid.uuid4().hex[:16],
        "filename": filename,
        "size_bytes": size,
        "mime_type": mime,
        "sha256": digest,
        "fetch_url": fetch_url,
    }


# ── T4b.7: zip blocked by extension on the deny list (REQ-4035) ─────────────
async def test_zip_attachment_blocked_by_extension(client: AsyncClient) -> None:
    await _ensure_blocklist_loaded()
    body = _payload(
        attachments=[_att(filename="leaks.zip", mime="application/zip")],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 415, resp.text
    payload = resp.json()
    assert payload["code"] == "REQ-4035"
    assert "leaks.zip" in payload["user_message"]


# ── T4b.8: hwp blocked even with a faked allow-list mime ───────────────────
async def test_hwp_filename_is_blocked(client: AsyncClient) -> None:
    await _ensure_blocklist_loaded()
    body = _payload(
        attachments=[_att(filename="report.hwp", mime="application/octet-stream")],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 415, resp.text
    assert resp.json()["code"] == "REQ-4035"


# ── T4b.9: 20 MiB + 1 over-limit → REQ-4031 (size, not blocklist) ──────────
async def test_attachment_over_20mib_returns_size_error(client: AsyncClient) -> None:
    await _ensure_blocklist_loaded()
    over_limit = 20 * 1024 * 1024 + 1
    body = _payload(
        attachments=[
            _att(filename="big.pdf", mime="application/pdf", size=over_limit),
        ],
    )
    resp = await client.post("/v1/detect/post", json=body)
    payload = resp.json()
    assert payload["code"] == "REQ-4031", payload
    # Size envelope is HTTP 413 on this endpoint.
    assert resp.status_code == 413


# ── T4b.10: attachment_scan_enabled=false → Case B response ────────────────
async def test_scan_toggle_off_skips_case_c(
    client: AsyncClient,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """When the operator flips the kill switch, Case-C requests degrade
    cleanly to Case B (immediate body-only response, no job_id)."""
    await _ensure_blocklist_loaded()

    monkeypatch.setattr(ss, "get", lambda key: False if key == "attachment_scan_enabled" else None)

    body = _payload(
        attachments=[
            # A normally-allowed PDF — would otherwise enter Case C.
            _att(filename="ok.pdf", mime="application/pdf", size=2048),
        ],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    # Case B keeps `job` field absent (Case C populates it).
    assert payload.get("job") is None
    assert payload["verdict"] in {"PASS", "BLOCK"}
