# SYNTHETIC DATA - NOT REAL PII
"""Phase 3 — `app.security.rate_limit` 토큰 버킷 경계 회귀 방지.

운영 Redis 없이 검증 가능한 영역만 unit-level 에서 본다:

  - `seconds_until_refill` pure helper (rate_per_minute → 초 변환)
  - `RateLimitOutcome` dataclass surface + frozen
  - `reset_for_tests` 가 모듈 singleton 비움
  - `RateLimiter.consume` 의 키 / 인자 전달 (script mock)
  - `check_caller` 의 minute / hour 합성 의미 — minute 거절 시 hour 미소비
  - `check_ip` 의 기본 per_minute=10 동작 + key prefix

Lua 스크립트 자체 로직 검증은 Redis-against-the-wire 통합 테스트에서.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.security.rate_limit import (
    RateLimiter,
    RateLimitOutcome,
    reset_for_tests,
    seconds_until_refill,
)


# ── seconds_until_refill — pure 변환 ─────────────────────────────────────
@pytest.mark.parametrize(
    ("rate_per_minute", "expected"),
    [
        (60, 1),  # 60/min → rate=1/s → 1초 필요
        (30, 2),
        (1, 60),  # 1/min → rate=1/60/s → 60초 필요
        (120, 1),  # 120/min → rate=2/s → 0.5초 ceil → 1
        (3600, 1),  # 3600/min → rate=60/s → 1초 (ceil min 1)
        (10, 6),  # 10/min → 6초
        (2, 30),  # 2/min → 30초
    ],
)
def test_seconds_until_refill_basic(rate_per_minute: int, expected: int) -> None:
    """다양한 rate 에서 `seconds_until_refill` 의 변환 정확성."""
    assert (
        seconds_until_refill(capacity=10, rate_per_minute=rate_per_minute)
        == expected
    )


def test_seconds_until_refill_minimum_is_one_second() -> None:
    """변환 결과가 0 이 될 수 있는 매우 빠른 rate 도 최소 1초로 clamp.

    Retry-After 헤더에 0 을 보내면 클라이언트가 즉시 재시도 → 폭주 위험.
    """
    assert seconds_until_refill(capacity=100, rate_per_minute=60000) == 1


def test_seconds_until_refill_capacity_is_for_api_stability_only() -> None:
    """`capacity` 인자는 API 안정성 위해 보존되었을 뿐 결과에 영향 없음."""
    a = seconds_until_refill(capacity=1, rate_per_minute=60)
    b = seconds_until_refill(capacity=10_000, rate_per_minute=60)
    assert a == b == 1


# ── RateLimitOutcome dataclass ────────────────────────────────────────────
def test_rate_limit_outcome_fields() -> None:
    """3 필드 (allowed / retry_after / remaining) 가 정확."""
    out = RateLimitOutcome(allowed=True, retry_after=0, remaining=5.0)
    assert out.allowed is True
    assert out.retry_after == 0
    assert out.remaining == 5.0


def test_rate_limit_outcome_is_frozen() -> None:
    """frozen dataclass — 결과 변조 불가."""
    out = RateLimitOutcome(allowed=False, retry_after=12, remaining=0.0)
    with pytest.raises(AttributeError):
        out.allowed = True  # type: ignore[misc]


def test_rate_limit_outcome_equality() -> None:
    """값 동일 → 같은 객체로 비교 (dataclass eq=True)."""
    a = RateLimitOutcome(allowed=False, retry_after=12, remaining=0.0)
    b = RateLimitOutcome(allowed=False, retry_after=12, remaining=0.0)
    assert a == b


# ── reset_for_tests — singleton 초기화 ──────────────────────────────────
def test_reset_for_tests_clears_singletons() -> None:
    """reset 후 module-level _LIMITER / _REDIS 가 None."""
    import app.security.rate_limit as rl

    rl._LIMITER = MagicMock()  # fake state 주입
    rl._REDIS = MagicMock()
    reset_for_tests()
    assert rl._LIMITER is None
    assert rl._REDIS is None


# ── RateLimiter.consume — script mock 으로 키/인자 전달 검증 ───────────
class _MockScript:
    """register_script 호출 결과를 흉내내는 mock."""

    def __init__(self, return_value: list) -> None:
        self.return_value = return_value
        self.calls: list[dict] = []

    async def __call__(self, *, keys: list[str], args: list) -> list:
        self.calls.append({"keys": list(keys), "args": list(args)})
        return self.return_value


def _make_limiter(script_return: list) -> tuple[RateLimiter, _MockScript]:
    """script 응답값을 미리 정한 RateLimiter 와 mock script 페어 생성."""
    script = _MockScript(script_return)
    fake_redis = MagicMock()
    fake_redis.register_script = MagicMock(return_value=script)
    limiter = RateLimiter(fake_redis)  # type: ignore[arg-type]
    return limiter, script


async def test_consume_returns_allowed_outcome() -> None:
    """script 가 [1, 0, 5] 반환 → allowed=True / retry_after=0 / remaining=5."""
    limiter, _ = _make_limiter([1, 0, 5])
    out = await limiter.consume(
        "test:key", capacity=10, rate_per_second=1.0
    )
    assert out.allowed is True
    assert out.retry_after == 0
    assert out.remaining == 5.0


async def test_consume_returns_denied_outcome() -> None:
    """script 가 [0, 12, 0] 반환 → allowed=False / retry_after=12 / remaining=0."""
    limiter, _ = _make_limiter([0, 12, 0])
    out = await limiter.consume(
        "test:key", capacity=10, rate_per_second=1.0
    )
    assert out.allowed is False
    assert out.retry_after == 12
    assert out.remaining == 0.0


async def test_consume_passes_key_and_args_correctly() -> None:
    """script 호출 시 keys=[bucket_key], args=[rate, capacity, now, cost] 형태."""
    limiter, script = _make_limiter([1, 0, 9])
    await limiter.consume(
        "rl:apikey:k1:m", capacity=60, rate_per_second=1.0, cost=1
    )
    assert len(script.calls) == 1
    call = script.calls[0]
    assert call["keys"] == ["rl:apikey:k1:m"]
    # args 순서: [rate_per_second, capacity, now, cost]
    assert call["args"][0] == 1.0
    assert call["args"][1] == 60
    assert call["args"][3] == 1  # cost
    # args[2] (now) 는 현재 시각 — 합리적 범위만 확인.
    import time

    now = time.time()
    assert abs(call["args"][2] - now) < 5.0


async def test_consume_custom_cost() -> None:
    """cost 인자가 그대로 script 에 전달."""
    limiter, script = _make_limiter([1, 0, 7])
    await limiter.consume(
        "test:k", capacity=10, rate_per_second=1.0, cost=3
    )
    assert script.calls[0]["args"][3] == 3


# ── check_caller — minute / hour 합성 ───────────────────────────────────
async def test_check_caller_consumes_both_buckets_when_minute_allows() -> None:
    """minute 가 허용 시 hour 까지 진행 — script 가 2회 호출."""
    limiter, script = _make_limiter([1, 0, 5])
    out = await limiter.check_caller(key_id="k1", per_minute=60, per_hour=1000)
    assert out.allowed is True
    assert len(script.calls) == 2

    # 첫 호출은 minute 버킷, 두 번째는 hour.
    assert script.calls[0]["keys"] == ["rl:apikey:k1:m"]
    assert script.calls[1]["keys"] == ["rl:apikey:k1:h"]


async def test_check_caller_skips_hour_when_minute_denies() -> None:
    """minute 단계에서 거절되면 hour 는 소비하지 않음 — fast fail.

    이 동작이 깨지면 minute 한도 초과 후 hour 토큰까지 소비되어 회복이
    느려진다.
    """
    limiter, script = _make_limiter([0, 30, 0])  # minute 거절
    out = await limiter.check_caller(key_id="k1", per_minute=60, per_hour=1000)
    assert out.allowed is False
    assert out.retry_after == 30
    # script 는 minute 한 번만 호출.
    assert len(script.calls) == 1
    assert script.calls[0]["keys"] == ["rl:apikey:k1:m"]


async def test_check_caller_minute_rate_is_per_minute_divided_by_60() -> None:
    """minute 버킷의 rate_per_second = per_minute / 60."""
    limiter, script = _make_limiter([0, 1, 0])
    await limiter.check_caller(key_id="k1", per_minute=120, per_hour=1000)
    minute_rate = script.calls[0]["args"][0]
    assert minute_rate == pytest.approx(2.0)  # 120/60


async def test_check_caller_hour_rate_is_per_hour_divided_by_3600() -> None:
    """hour 버킷의 rate_per_second = per_hour / 3600."""
    limiter, script = _make_limiter([1, 0, 5])
    await limiter.check_caller(key_id="k1", per_minute=60, per_hour=7200)
    hour_rate = script.calls[1]["args"][0]
    assert hour_rate == pytest.approx(2.0)  # 7200/3600


async def test_check_caller_capacities_passed_correctly() -> None:
    """minute capacity = per_minute, hour capacity = per_hour."""
    limiter, script = _make_limiter([1, 0, 5])
    await limiter.check_caller(key_id="k1", per_minute=60, per_hour=1000)
    assert script.calls[0]["args"][1] == 60
    assert script.calls[1]["args"][1] == 1000


# ── check_ip — IP scope 기본값 ──────────────────────────────────────────
async def test_check_ip_uses_ip_key_prefix() -> None:
    """IP 버킷 키는 `rl:ip:{ip}:m` 형식."""
    limiter, script = _make_limiter([1, 0, 9])
    await limiter.check_ip(ip="203.0.113.5")
    assert script.calls[0]["keys"] == ["rl:ip:203.0.113.5:m"]


async def test_check_ip_default_per_minute_is_10() -> None:
    """IP scope 기본 per_minute=10 (Phase 3 스펙)."""
    limiter, script = _make_limiter([1, 0, 9])
    await limiter.check_ip(ip="203.0.113.5")
    # capacity == 10, rate == 10/60
    assert script.calls[0]["args"][1] == 10
    assert script.calls[0]["args"][0] == pytest.approx(10 / 60)


async def test_check_ip_custom_per_minute() -> None:
    """per_minute 명시 시 그 값이 그대로 capacity."""
    limiter, script = _make_limiter([1, 0, 5])
    await limiter.check_ip(ip="203.0.113.5", per_minute=30)
    assert script.calls[0]["args"][1] == 30


async def test_check_ip_returns_denied_outcome() -> None:
    """script 가 거절 응답 시 outcome.allowed=False."""
    limiter, _ = _make_limiter([0, 8, 0])
    out = await limiter.check_ip(ip="203.0.113.5")
    assert out.allowed is False
    assert out.retry_after == 8
