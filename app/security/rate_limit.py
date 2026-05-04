"""Redis-backed token-bucket rate limiter (Phase 3, T3.7).

Two buckets per caller:
  - per minute  (default 60)
  - per hour    (default 1000)

Both must allow the request; the *first* one to deny dictates the
``Retry-After`` value the client sees. A separate IP-scoped bucket
(default 10/min) acts as a fallback for unauthenticated traffic.

Atomic check-and-decrement is implemented via a small Lua script so the
read-modify-write is a single Redis round-trip.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

import redis.asyncio as redis_async
from redis.commands.core import AsyncScript

from app.config import get_settings

# Generic Cell Rate Algorithm — bucket with refill rate `rate` (per second)
# and capacity `capacity`. KEYS[1] holds the encoded "tokens|ts" state.
#
# Returns: {allowed (0|1), retry_after_seconds, remaining_tokens}
_LUA_TOKEN_BUCKET = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end

local delta = math.max(0, now - ts)
tokens = math.min(capacity, tokens + delta * rate)

local allowed = 0
local retry_after = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_after = math.ceil((cost - tokens) / rate)
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
local ttl = math.ceil(capacity / rate) + 60
redis.call('EXPIRE', key, ttl)

return {allowed, retry_after, tokens}
"""  # noqa: S105 — Lua source, not a credential


@dataclass(frozen=True)
class RateLimitOutcome:
    allowed: bool
    retry_after: int      # seconds; 0 when allowed
    remaining: float      # tokens left in the bucket


class RateLimiter:
    """Async token-bucket limiter against a single Redis instance."""

    def __init__(self, client: redis_async.Redis) -> None:
        self._redis = client
        self._script: AsyncScript = client.register_script(_LUA_TOKEN_BUCKET)

    async def consume(
        self,
        bucket_key: str,
        *,
        capacity: int,
        rate_per_second: float,
        cost: int = 1,
    ) -> RateLimitOutcome:
        now = time.time()
        result = await self._script(
            keys=[bucket_key],
            args=[rate_per_second, capacity, now, cost],
        )
        allowed, retry_after, tokens = result
        return RateLimitOutcome(
            allowed=bool(int(allowed)),
            retry_after=int(retry_after),
            remaining=float(tokens),
        )

    async def check_caller(
        self, *, key_id: str, per_minute: int, per_hour: int
    ) -> RateLimitOutcome:
        """Per API-key check — both buckets must allow."""
        m = await self.consume(
            f"rl:apikey:{key_id}:m",
            capacity=per_minute,
            rate_per_second=per_minute / 60,
        )
        if not m.allowed:
            return m
        return await self.consume(
            f"rl:apikey:{key_id}:h",
            capacity=per_hour,
            rate_per_second=per_hour / 3600,
        )

    async def check_ip(self, *, ip: str, per_minute: int = 10) -> RateLimitOutcome:
        """Per-IP fallback for unauthenticated traffic."""
        return await self.consume(
            f"rl:ip:{ip}:m",
            capacity=per_minute,
            rate_per_second=per_minute / 60,
        )


# ── Module-level singleton ────────────────────────────────────────────────
_LIMITER: RateLimiter | None = None
_REDIS: redis_async.Redis | None = None


def get_redis() -> redis_async.Redis:
    global _REDIS
    if _REDIS is None:
        _REDIS = redis_async.from_url(
            get_settings().redis_url, decode_responses=True
        )
    return _REDIS


def get_limiter() -> RateLimiter:
    global _LIMITER
    if _LIMITER is None:
        _LIMITER = RateLimiter(get_redis())
    return _LIMITER


def reset_for_tests() -> None:
    """Drop cached limiter/redis so tests get a fresh client per loop."""
    global _LIMITER, _REDIS
    _LIMITER = None
    _REDIS = None


# Helper for retry_after seconds — exposed for tests/middleware
def seconds_until_refill(
    *, capacity: int, rate_per_minute: int  # noqa: ARG001
) -> int:
    """How long a fully drained bucket needs to allow at least one token."""
    rate = rate_per_minute / 60
    return max(1, math.ceil(1 / rate))
