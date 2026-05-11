"""Phase 3 — Q2: 인증 실패가 반복될 때 발신 IP 별 throttling 회귀 방지.

동일 IP 에서 잘못된 API 키로 짧은 시간에 반복 호출하면 처음 N건은 정상적
인 401 (`REQ-4011`) 로 거절되지만, IP 단위 rate-limit 예산이 소진되면 그
이후는 429 (`REQ-4020`) + `Retry-After` 헤더로 차단되어야 한다. brute-force
공격을 회피하면서도 합법적 클라이언트가 폭주하지 않도록 보호하는 가드.
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

from app.security.rate_limit import get_redis

if TYPE_CHECKING:
    from httpx import AsyncClient


async def test_q2_ip_burst_after_failures_throttles(
    client_anon: AsyncClient,
) -> None:
    """동일 IP 의 11번째 잘못된 인증 시도 → 429 REQ-4020 + Retry-After.

    설정상 IP 단위 fallback rate 가 10건/분 이므로 10건까지는 401 (REQ-4011),
    11번째부터 429 가 떨어져야 한다. Redis 키를 fixture-out 으로 비워 다른
    테스트의 누적 카운트에 영향받지 않게 했고, 429 응답이 나오면 즉시 break
    해서 전체 12회 호출이 끝까지 가지 않는지도 확인한다.
    """
    # The default per-IP fallback rate is 10/min; flush any leftover.
    r = get_redis()
    await r.delete("rl:ip:127.0.0.1:m")  # ASGITransport client.host = '127.0.0.1'

    statuses: list[int] = []
    for _ in range(12):
        resp = await client_anon.post(
            "/v1/detect/post",
            content=b"{}",
            headers={
                "X-API-Key": "k_does_not_exist",
                "X-Timestamp": str(int(time.time())),
                "X-Nonce": uuid.uuid4().hex,
                "X-Signature": "0" * 64,
                "content-type": "application/json",
            },
        )
        statuses.append(resp.status_code)
        if resp.status_code == 429:
            assert int(resp.headers.get("Retry-After", "0")) >= 1
            assert resp.json()["code"] == "REQ-4020"
            break
    else:  # pragma: no cover — the loop should hit 429 and break
        msg = f"never throttled; statuses={statuses}"
        raise AssertionError(msg)

    # All earlier statuses should be the original 401 (REQ-4011).
    pre_throttle = statuses[:-1]
    assert pre_throttle, "should have at least one 401 before 429"
    assert all(s == 401 for s in pre_throttle), pre_throttle

    # Cleanup
    await r.delete("rl:ip:127.0.0.1:m")
