# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `detect_post` 첨부 게이트 회귀 방지 (T4b.7~T4b.10).

`detect_post` 핸들러가 첨부 분석 파이프라인에 진입하기 *전에* 적용되는
4가지 게이트를 확인한다:

  - T4b.7: ZIP 확장자 → deny-list 매칭 → REQ-4035
  - T4b.8: HWP 파일명 → mime 위장 무관 deny-list 매칭 → REQ-4035
  - T4b.9: 20 MiB 초과 첨부 → REQ-4031 (size, deny-list 이전 단계)
  - T4b.10: 운영자 토글 OFF → 모든 Case-C 가 Case B 로 강등

auth-bypass 된 conftest `client` fixture 를 사용 — 실제 fetch / 추출
파이프라인까지는 도달하지 않고 게이트만 따로 검증.
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


# ── T4b.7: zip 확장자 → deny-list 매칭 → REQ-4035 ───────────────────────
async def test_zip_attachment_blocked_by_extension(client: AsyncClient) -> None:
    """`.zip` 확장자가 deny-list 에 의해 415 / REQ-4035 로 거절되고, user_message
    에 파일명이 포함되어 어느 파일이 거절됐는지 명시되어야 한다.

    압축 파일은 OCR/추출 인프라가 무력화될 수 있어 1차로 차단.
    """
    await _ensure_blocklist_loaded()
    body = _payload(
        attachments=[_att(filename="leaks.zip", mime="application/zip")],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 415, resp.text
    payload = resp.json()
    assert payload["code"] == "REQ-4035"
    assert "leaks.zip" in payload["user_message"]


# ── T4b.8: HWP 파일명 → MIME 위장 무관 deny-list 차단 ────────────────────
async def test_hwp_filename_is_blocked(client: AsyncClient) -> None:
    """파일명이 `.hwp` 면 MIME 을 `application/octet-stream` 으로 위장해도 거절.

    악의적 우회 시도 (실제 HWP 파일이 일반 바이너리 MIME 으로 들어오는
    경우) 가 deny-list 의 확장자 매칭에서 잡혀야 한다.
    """
    await _ensure_blocklist_loaded()
    body = _payload(
        attachments=[_att(filename="report.hwp", mime="application/octet-stream")],
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 415, resp.text
    assert resp.json()["code"] == "REQ-4035"


# ── T4b.9: 20 MiB + 1 byte → 사이즈 한도 REQ-4031 (deny-list 보다 먼저) ──
async def test_attachment_over_20mib_returns_size_error(client: AsyncClient) -> None:
    """20 MiB 초과 첨부 → REQ-4031 / 413 — deny-list 매칭보다 우선.

    PDF 등 허용 형식이라도 크기 한도가 먼저 적용되어야 OCR/추출 자원 보호.
    응답 envelope 은 HTTP 413 으로 클라이언트가 즉시 사이즈 문제로 인식.
    """
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
    # 이 엔드포인트에서 사이즈 envelope 은 HTTP 413.
    assert resp.status_code == 413


# ── T4b.10: attachment_scan_enabled=false → Case B 로 강등 ───────────────
async def test_scan_toggle_off_skips_case_c(
    client: AsyncClient,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """운영자가 kill switch 를 끄면 Case-C 호출이 Case B 로 깔끔하게 강등.

    원래 비동기 분석이 시작되어야 할 첨부 있는 요청이 즉시 body-only 응답
    (job 필드 None) 으로 돌아온다. 첨부 검사 인프라에 문제가 생겼을 때
    운영자가 1초 안에 통과 모드로 전환 가능해야 한다는 SLA.
    """
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
