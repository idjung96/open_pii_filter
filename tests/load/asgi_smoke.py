# SYNTHETIC DATA - NOT REAL PII
"""ASGI in-process load smoke test (Phase 8, T8.2).

Runs the API behind ``httpx.ASGITransport`` (no real network) and drives
it with a configurable number of concurrent body-only POSTs. The numbers
this captures feed ``docs/load_test_report.md``.

Why not Locust here?
--------------------
Locust assumes a real HTTP listener. In CI / sandboxed environments we
often can't bind to a port; the in-process driver gives the real
analyzer + middleware + DB code path with zero network overhead so the
result is a *floor* on what the production deployment can sustain.

For the real distributed-load story see ``locustfile.py`` + the README.

Usage
-----
    uv run python -m tests.load.asgi_smoke --duration 60 --concurrency 32
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import uuid

import httpx

from app.main import app
from app.security.auth import require_auth
from app.security.hmac_auth import AuthedCaller


def _stub_caller() -> AuthedCaller:
    return AuthedCaller(
        key_id="load-stub",
        name="asgi_smoke",
        rate_per_minute=1_000_000,
        rate_per_hour=100_000_000,
        ip_allowlist=None,
        client_ip="127.0.0.1",
    )


async def _one_call(client: httpx.AsyncClient) -> tuple[int, float]:
    body = {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": "g", "title": "x", "body": "y"},
        "author": {"name": "x", "ip": "127.0.0.1"},
    }
    raw = json.dumps(body).encode("utf-8")
    t0 = time.perf_counter()
    r = await client.post(
        "/v1/detect/post",
        content=raw,
        headers={"content-type": "application/json"},
    )
    return r.status_code, time.perf_counter() - t0


async def _worker(
    client: httpx.AsyncClient,
    deadline: float,
    out_status: list[int],
    out_lat: list[float],
) -> None:
    while time.perf_counter() < deadline:
        status, lat = await _one_call(client)
        out_status.append(status)
        out_lat.append(lat)


async def main(duration_s: float, concurrency: int) -> dict[str, object]:
    """Drive ``concurrency`` workers for ``duration_s`` seconds; return stats."""
    app.dependency_overrides[require_auth] = _stub_caller
    statuses: list[int] = []
    latencies: list[float] = []

    started = time.perf_counter()
    deadline = started + duration_s
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            await asyncio.gather(
                *[_worker(client, deadline, statuses, latencies) for _ in range(concurrency)]
            )
    finally:
        app.dependency_overrides.pop(require_auth, None)
    elapsed = time.perf_counter() - started

    success = sum(1 for s in statuses if s == 200)
    rps = len(statuses) / elapsed if elapsed > 0 else 0.0
    p50 = statistics.median(latencies) * 1000 if latencies else 0.0
    p95_idx = max(0, int(len(latencies) * 0.95) - 1)
    p99_idx = max(0, int(len(latencies) * 0.99) - 1)
    sorted_lat = sorted(latencies)
    p95 = sorted_lat[p95_idx] * 1000 if latencies else 0.0
    p99 = sorted_lat[p99_idx] * 1000 if latencies else 0.0
    avg = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0
    success_pct = success / len(statuses) if statuses else 0.0
    return {
        "duration_s": elapsed,
        "concurrency": concurrency,
        "total": len(statuses),
        "success": success,
        "success_pct": success_pct,
        "rps": rps,
        "p50_ms": p50,
        "p95_ms": p95,
        "p99_ms": p99,
        "avg_ms": avg,
        "status_codes": dict(_count(statuses)),
    }


def _count(items: list[int]) -> dict[int, int]:
    out: dict[int, int] = {}
    for x in items:
        out[x] = out.get(x, 0) + 1
    return out


def _cli() -> None:
    p = argparse.ArgumentParser(description="ASGI in-process load smoke test")
    p.add_argument("--duration", type=float, default=10.0, help="run duration (s)")
    p.add_argument("--concurrency", type=int, default=16, help="concurrent workers")
    args = p.parse_args()
    stats = asyncio.run(main(args.duration, args.concurrency))
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    _cli()
