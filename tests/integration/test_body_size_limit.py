"""Phase 3 — T3.9 본문 크기 상한 (1 MB) 회귀 방지.

`BodySizeLimitMiddleware` 가 1 MB 초과 페이로드를 401/422 가 아닌 의도된
413 `REQ-4030` 으로 거절하는지 검증한다. 미들웨어가 빠지거나 한도가
의도치 않게 변경되면 메모리 폭주 / DoS 사고로 이어지므로 핵심 가드.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from httpx import AsyncClient


async def test_t3_9_body_over_1mb_413(client: AsyncClient) -> None:
    """1 MB + 64 byte 페이로드는 미들웨어 단계에서 즉시 413 REQ-4030 거절.

    핸들러/pydantic 검증에 도달하기 전 BodySizeLimitMiddleware 에서 끊는다
    — 분석기 메모리 사용을 한도 안에 묶는 1차 방어선.
    """
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
    """1 MB 미만이라도 필드 단위 제약 (`title` 500자) 을 어기면 REQ-4030.

    미들웨어를 통과해도 pydantic 의 `MAX_TITLE_LEN` 검증이 REQ-4030 / 413
    으로 떨어진다는 사실을 핀(pin). 즉 두 경로 (미들웨어 / 핸들러) 어디서
    한도가 깨져도 동일한 사용자 친화 코드로 응답.
    """
    # 제목만 ~ 950 KB 까지 늘림 — 1 MB 미만이지만 MAX_TITLE_LEN 초과.
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
    # 거절은 동일하게 413/REQ-4030 — 다만 출처가 미들웨어가 아니라 필드 검증.
    assert resp.status_code == 413
    assert resp.json()["code"] == "REQ-4030"
