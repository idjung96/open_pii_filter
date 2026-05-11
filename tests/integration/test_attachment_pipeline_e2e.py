# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/E — 모든 첨부 형식의 동기 게이트 동작 회귀 방지.

Case-C 파이프라인의 동기 절반 (요청 핸들러 내부) 을 형식 매트릭스 전체에
걸쳐 검증한다 — 19건의 케이스로 다음 영역을 빠짐없이 커버:

- **허용 형식** (pdf / xlsx / pptx / docx / md / txt / jpeg / png) → HTTP 202
  ACK-3001 + `job_id` 발급 (비동기 워커로 인계)
- **거절 형식** (zip / rar / 7z / hwp / hwpx / 레거시 doc/xls/ppt) → HTTP 415
  REQ-4035 (deny-list 매칭)
- `attachment_scan_enabled` OFF → 어떤 첨부가 있어도 Case B 로 강등
  (HTTP 200, `job_id` 없음, 첨부 검사 skip)

비동기 워커 쪽 검증 (fetch / OCR / webhook) 은 `test_phase4_case_c.py` 와
`test_callback_delete.py` 가 별도로 담당. 이 모듈은
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
