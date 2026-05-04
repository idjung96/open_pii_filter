"""Phase 3 — Q2: per-IP brute-force throttling on auth failures.

Repeated invalid-key attempts from the same IP should produce 401 only
until the IP rate-limit budget is exhausted; further attempts get
REQ-4020 (429 + Retry-After).
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
    """11th consecutive bogus auth from one IP → 429."""
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
