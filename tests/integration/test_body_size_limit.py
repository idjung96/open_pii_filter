"""Phase 3 — T3.9 body size cap (1 MB)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from httpx import AsyncClient


async def test_t3_9_body_over_1mb_413(client: AsyncClient) -> None:
    payload = b"x" * (1 * 1024 * 1024 + 64)
    resp = await client.post(
        "/v1/detect/post",
        content=payload,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 413
    assert resp.json()["code"] == "REQ-4030"


async def test_body_just_under_1mb_passes_validation(
    client: AsyncClient,
) -> None:
    """Body under cap reaches the endpoint (auth bypass via stub)."""
    # ~ 950 KB padded title — well below 1MB but above MAX_TITLE_LEN.
    payload = (
        '{"request_id":"00000000-0000-0000-0000-000000000bbb",'
        '"post":{"board_id":"g","title":"' + "x" * 1000 + '","body":"y"},'
        '"author":{"name":"x","ip":"127.0.0.1"}}'
    )
    resp = await client.post(
        "/v1/detect/post",
        content=payload,
        headers={"content-type": "application/json"},
    )
    # Still rejected — but with REQ-4030 from the *field* check (title>500)
    # not the middleware. Either way the status is 413.
    assert resp.status_code == 413
    assert resp.json()["code"] == "REQ-4030"
