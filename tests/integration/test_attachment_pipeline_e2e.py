# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/E — synchronous gate behaviour for every attachment shape.

The synchronous half of the Case-C pipeline runs entirely in the
request handler and is exhaustively covered here:

- Allowed formats (pdf, xlsx, pptx, docx, md, txt, jpeg, png) are
  accepted with HTTP 202 / ACK-3001 and a `job_id`.
- Denied formats (zip, rar, 7z, hwp, hwpx, doc, xls, ppt) are rejected
  with HTTP 415 / REQ-4035.
- `attachment_scan_enabled` OFF degrades any attached request to
  Case B (HTTP 200, no job_id).

The async worker side is exercised separately by
`test_phase4_case_c.py` and `test_callback_delete.py`; this suite
focuses on the gate matrix so a regression there surfaces fast.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import TYPE_CHECKING, Any

import pytest

from app.core import system_settings as ss
from app.core.blocklist_cache import reload_blocklist
from app.db.session import get_sessionmaker

if TYPE_CHECKING:
    from httpx import AsyncClient


async def _ensure_blocklist_loaded() -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        await reload_blocklist(s)


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


def _payload(*, attachments: list[dict[str, Any]]) -> dict[str, Any]:
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


# ── Allowed formats accepted into Case C (HTTP 202 / ACK-3001) ─────────────
@pytest.mark.parametrize(
    ("filename", "mime"),
    [
        ("doc.pdf", "application/pdf"),
        (
            "report.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        (
            "deck.pptx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        (
            "memo.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        ("notes.md", "text/markdown"),
        ("plain.txt", "text/plain"),
        ("photo.jpg", "image/jpeg"),
        ("scan.png", "image/png"),
    ],
)
async def test_allowed_formats_enqueue_case_c(
    client: AsyncClient,
    filename: str,
    mime: str,
) -> None:
    await _ensure_blocklist_loaded()
    body = _payload(attachments=[_att(filename=filename, mime=mime)])
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 202, resp.text
    payload = resp.json()
    assert payload["code"] == "ACK-3001"
    assert payload["job"] is not None
    assert payload["job"]["attachment_count"] == 1


# ── Denied formats rejected by the deny list (HTTP 415 / REQ-4035) ─────────
@pytest.mark.parametrize(
    ("filename", "mime"),
    [
        ("leaks.zip", "application/zip"),
        ("backup.rar", "application/vnd.rar"),
        ("logs.7z", "application/x-7z-compressed"),
        ("report.hwp", "application/x-hwp"),
        ("report.hwpx", "application/hwp+zip"),
        ("legacy.doc", "application/msword"),
        ("legacy.xls", "application/vnd.ms-excel"),
        ("legacy.ppt", "application/vnd.ms-powerpoint"),
    ],
)
async def test_denied_formats_rejected_with_req_4035(
    client: AsyncClient,
    filename: str,
    mime: str,
) -> None:
    await _ensure_blocklist_loaded()
    body = _payload(attachments=[_att(filename=filename, mime=mime)])
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 415, resp.text
    payload = resp.json()
    assert payload["code"] == "REQ-4035"
    assert filename in payload["user_message"]


# ── attachment_scan_enabled=False: any Case-C-shaped request → Case B ──────
async def test_scan_toggle_off_degrades_every_format_to_case_b(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the kill switch is off the gateway never enters Case C — even
    a normally-allowed PDF returns 200 with no job_id, so the user is
    not left waiting for a webhook that will never fire."""
    await _ensure_blocklist_loaded()
    monkeypatch.setattr(
        ss,
        "get",
        lambda key: False if key == "attachment_scan_enabled" else None,
    )
    body = _payload(attachments=[_att(filename="ok.pdf", mime="application/pdf")])
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["job"] is None
    assert payload["verdict"] in {"PASS", "BLOCK"}


# ── Mixed batch: allowed + denied → reject the request as a whole ──────────
async def test_mixed_batch_with_one_denied_rejects_request(
    client: AsyncClient,
) -> None:
    """The validator scans attachments in order; one denied file must
    short-circuit the request even when the other entries are fine."""
    await _ensure_blocklist_loaded()
    body = _payload(
        attachments=[
            _att(filename="ok.pdf", mime="application/pdf"),
            _att(filename="bad.zip", mime="application/zip"),
        ],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 415, resp.text
    payload = resp.json()
    assert payload["code"] == "REQ-4035"
    assert "bad.zip" in payload["user_message"]


# ── 6th attachment → REQ-4032 (count limit, unrelated to deny list) ────────
async def test_six_attachments_returns_count_limit_error(
    client: AsyncClient,
) -> None:
    await _ensure_blocklist_loaded()
    body = _payload(
        attachments=[_att(filename=f"file{i}.pdf", mime="application/pdf") for i in range(6)],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.json()["code"] == "REQ-4032"
