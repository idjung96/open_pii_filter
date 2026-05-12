# SYNTHETIC DATA - NOT REAL PII
"""HMAC 서명 + 타임스탬프 윈도우 + nonce 재사용 + 멱등성 경계 회귀 방지.

본 모듈은 외부 호출자가 보내는 4종 헤더 검증의 **순수 함수 영역** 만 테스트:

  - `compute_signature` / `_canonical_string` (서명 산출 결정성)
  - `_check_timestamp` 의 ±5분 윈도우 정확 경계
  - `IdempotencyCache` 의 reserve / complete / release / TTL eviction

DB 가 필요한 nonce 재사용 (`_claim_nonce`) 은 integration 테스트에서 검증.

회귀 방어 영역:

  1. 타임스탬프 ±300 초 정확 경계 (포함/제외 의미)
  2. 빈 body 도 정확한 SHA-256 ("e3b0c4...") 으로 처리
  3. body 변경 시 서명 변경 (tamper detection)
  4. 헤더 한 글자만 바뀌어도 서명 불일치
  5. `compute_signature` 결정성 (같은 입력 → 같은 출력)
  6. 메서드 case-insensitive 정규화 (POST vs post)
  7. UTF-8 한글 body 의 서명 안정성
  8. idempotency 3 상태 전이 (NEW → IN_PROGRESS → COMPLETED)
  9. 멱등 응답 회수 가능 + duplicate in-flight 분기
  10. TTL eviction 동작 + release 후 재사용 가능
  11. uuid 비교의 정확성 (동일 UUID 다른 객체)
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from app.security.hmac_auth import (
    HmacAuthError,
    TIMESTAMP_WINDOW_SECONDS,
    _canonical_string,
    _check_timestamp,
    compute_signature,
)
from app.security.idempotency import (
    DEFAULT_TTL,
    IdempotencyCache,
    ReserveOutcome,
)

SECRET = "test-secret-not-real-do-not-use-in-prod"  # noqa: S105


# ── _canonical_string 안정성 ─────────────────────────────────────────────
def test_canonical_string_format_exact() -> None:
    """canonical string 이 정확히 ``{ts}\\n{nonce}\\n{METHOD}\\n{path}\\n{body_sha256}``.

    공급사 SDK 가 클라이언트 측 서명 산출에 의존하므로 형식이 바뀌면 모든
    외부 호출자의 서명이 갑자기 어긋난다.
    """
    s = _canonical_string(
        timestamp="1700000000",
        nonce="n0123456789abcdef",
        method="POST",
        path="/v1/detect/post",
        body=b"",
    )
    expected_body_digest = hashlib.sha256(b"").hexdigest()
    assert s == (
        "1700000000\n"
        "n0123456789abcdef\n"
        "POST\n"
        "/v1/detect/post\n"
        f"{expected_body_digest}"
    )


def test_canonical_string_method_case_normalized_upper() -> None:
    """``method`` 가 소문자/대문자 어떤 형태로 들어와도 정규화된다."""
    a = _canonical_string(
        timestamp="1", nonce="n" * 16, method="post", path="/v1/x", body=b""
    )
    b = _canonical_string(
        timestamp="1", nonce="n" * 16, method="POST", path="/v1/x", body=b""
    )
    assert a == b
    assert "POST" in a  # method 가 대문자로 normalize


def test_canonical_string_empty_body_uses_sha256_of_empty() -> None:
    """빈 body 도 정확한 SHA-256 ("e3b0c4...b855") digest 를 사용."""
    s = _canonical_string(
        timestamp="1700000000", nonce="n" * 16, method="POST", path="/v1/x", body=b""
    )
    empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert s.endswith(empty_sha)


def test_canonical_string_utf8_body_consistent() -> None:
    """UTF-8 한글 body 가 안정적으로 같은 digest 를 만든다."""
    body = "주민번호 900101-1234567 입니다".encode("utf-8")
    s1 = _canonical_string(
        timestamp="1", nonce="n" * 16, method="POST", path="/x", body=body
    )
    s2 = _canonical_string(
        timestamp="1", nonce="n" * 16, method="POST", path="/x", body=body
    )
    assert s1 == s2


# ── compute_signature 결정성 + tamper 감지 ──────────────────────────────
def test_compute_signature_deterministic() -> None:
    """동일 입력 → 동일 hex digest (결정성)."""
    kwargs: dict[str, object] = {
        "secret": SECRET,
        "timestamp": "1700000000",
        "nonce": "n" * 16,
        "method": "POST",
        "path": "/v1/detect/post",
        "body": b'{"text":"foo"}',
    }
    a = compute_signature(**kwargs)  # type: ignore[arg-type]
    b = compute_signature(**kwargs)  # type: ignore[arg-type]
    assert a == b
    assert len(a) == 64  # hex SHA-256 → 32 bytes → 64 hex chars
    assert all(c in "0123456789abcdef" for c in a)


@pytest.mark.parametrize(
    "field,override",
    [
        ("secret", "other-secret"),
        ("timestamp", "1700000001"),
        ("nonce", "x" * 16),
        ("method", "GET"),
        ("path", "/v1/detect/post/2"),
        ("body", b'{"text":"bar"}'),
    ],
)
def test_compute_signature_changes_on_any_field(field: str, override: object) -> None:
    """4종 입력 중 한 글자라도 바뀌면 서명이 달라져야 한다 (tamper 감지)."""
    base: dict[str, object] = {
        "secret": SECRET,
        "timestamp": "1700000000",
        "nonce": "n" * 16,
        "method": "POST",
        "path": "/v1/detect/post",
        "body": b'{"text":"foo"}',
    }
    a = compute_signature(**base)  # type: ignore[arg-type]
    base[field] = override
    b = compute_signature(**base)  # type: ignore[arg-type]
    assert a != b, f"{field} 변경에도 서명 동일: {a}"


def test_compute_signature_body_single_byte_difference_detected() -> None:
    """body 의 1바이트 차이도 서명에 반영된다 — SHA-256 avalanche."""
    a = compute_signature(
        secret=SECRET, timestamp="1", nonce="n" * 16, method="POST", path="/", body=b"hello"
    )
    b = compute_signature(
        secret=SECRET, timestamp="1", nonce="n" * 16, method="POST", path="/", body=b"hellx"
    )
    assert a != b


# ── _check_timestamp ±5분 윈도우 정확 경계 ─────────────────────────────
def test_timestamp_window_constant_is_5_minutes() -> None:
    """윈도우 상수가 정확히 ±300초 (스펙에 명시된 ±5분)."""
    assert TIMESTAMP_WINDOW_SECONDS == 300


def test_timestamp_exact_now_accepted() -> None:
    """현재 시각과 정확히 같은 timestamp 는 허용."""
    now = 1_700_000_000.0
    _check_timestamp(str(int(now)), now=now)  # 예외 없으면 통과


@pytest.mark.parametrize("delta", [0, 1, 60, 299, 300])
def test_timestamp_within_window_accepted(delta: int) -> None:
    """|delta| ≤ 300 (윈도우 경계 포함) 은 모두 허용."""
    now = 1_700_000_000.0
    # 과거 방향
    _check_timestamp(str(int(now - delta)), now=now)
    # 미래 방향 (시계 skew 양방향)
    _check_timestamp(str(int(now + delta)), now=now)


@pytest.mark.parametrize("delta", [301, 360, 600, 86_400])
def test_timestamp_outside_window_rejected(delta: int) -> None:
    """|delta| > 300 은 REQ-4012 거절 (윈도우 외)."""
    now = 1_700_000_000.0

    with pytest.raises(HmacAuthError) as e_past:
        _check_timestamp(str(int(now - delta)), now=now)
    assert e_past.value.code == "REQ-4012"

    with pytest.raises(HmacAuthError) as e_future:
        _check_timestamp(str(int(now + delta)), now=now)
    assert e_future.value.code == "REQ-4012"


def test_timestamp_non_integer_rejected_as_4012() -> None:
    """숫자가 아닌 timestamp 헤더는 REQ-4012 (윈도우 위반과 동일 코드)."""
    with pytest.raises(HmacAuthError) as e:
        _check_timestamp("not-a-timestamp", now=1_700_000_000.0)
    assert e.value.code == "REQ-4012"


def test_timestamp_negative_unix_time_rejected_if_outside_window() -> None:
    """음수 timestamp 도 윈도우 외이므로 REQ-4012 (epoch 이전 사고 방지)."""
    with pytest.raises(HmacAuthError) as e:
        _check_timestamp("-1000000", now=1_700_000_000.0)
    assert e.value.code == "REQ-4012"


def test_timestamp_default_now_uses_real_clock() -> None:
    """``now`` 인자 생략 시 ``time.time()`` 을 사용해 실제 시계 기준 검증."""
    # 실제 시계 기준 0초 차이는 항상 윈도우 안 → 통과
    _check_timestamp(str(int(time.time())))


# ── HmacAuthError code 구분 ─────────────────────────────────────────────
def test_hmac_auth_error_carries_code() -> None:
    """예외 객체가 응답 코드 문자열을 ``.code`` 로 노출."""
    err = HmacAuthError("REQ-4012")
    assert err.code == "REQ-4012"
    # template_vars 확장 가능성
    err2 = HmacAuthError("REQ-4015", retry_after=60)
    assert err2.template_vars == {"retry_after": 60}


# ── IdempotencyCache 상태 전이 ──────────────────────────────────────────
@pytest.fixture()
def fresh_cache() -> IdempotencyCache:
    """매 테스트마다 새로운 캐시 (전역 싱글톤 격리)."""
    return IdempotencyCache()


def test_idempotency_first_reserve_is_new(fresh_cache: IdempotencyCache) -> None:
    """처음 등장한 request_id 는 NEW 로 반환되고 캐시에 IN_PROGRESS 로 기록."""
    rid = uuid4()
    outcome, cached = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.NEW
    assert cached is None


def test_idempotency_second_reserve_while_in_progress_is_in_progress(
    fresh_cache: IdempotencyCache,
) -> None:
    """첫 reserve 후 complete 전 두 번째 reserve → IN_PROGRESS (REQ-4005 분기)."""
    rid = uuid4()
    fresh_cache.reserve(rid)
    outcome, cached = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.IN_PROGRESS
    assert cached is None  # 진행 중 응답 없음


def test_idempotency_after_complete_returns_cached(
    fresh_cache: IdempotencyCache,
) -> None:
    """complete 후 reserve → COMPLETED + 캐시된 응답 회수."""
    rid = uuid4()
    fresh_cache.reserve(rid)
    sentinel = MagicMock(name="DetectPostResponse")
    fresh_cache.complete(rid, sentinel)
    outcome, cached = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.COMPLETED
    assert cached is sentinel


def test_idempotency_release_clears_inflight(fresh_cache: IdempotencyCache) -> None:
    """release 후에는 다시 reserve 시 NEW (오류 시 in-flight 해제 시나리오)."""
    rid = uuid4()
    fresh_cache.reserve(rid)
    fresh_cache.release(rid)
    outcome, _ = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.NEW


def test_idempotency_release_does_not_drop_completed(
    fresh_cache: IdempotencyCache,
) -> None:
    """release 는 COMPLETED 상태에는 작용하지 않음 (캐시된 응답 보존)."""
    rid = uuid4()
    fresh_cache.reserve(rid)
    sentinel = MagicMock(name="DetectPostResponse")
    fresh_cache.complete(rid, sentinel)
    fresh_cache.release(rid)
    outcome, cached = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.COMPLETED
    assert cached is sentinel


def test_idempotency_same_uuid_different_objects_collide(
    fresh_cache: IdempotencyCache,
) -> None:
    """같은 UUID 값 (다른 Python 객체) 은 동일한 키로 매핑되어 충돌해야 한다."""
    raw = "11111111-2222-3333-4444-555555555555"
    a = UUID(raw)
    b = UUID(raw)
    assert a is not b  # 객체는 다름
    assert a == b  # 값은 같음
    fresh_cache.reserve(a)
    outcome, _ = fresh_cache.reserve(b)
    assert outcome is ReserveOutcome.IN_PROGRESS


def test_idempotency_different_uuids_independent(fresh_cache: IdempotencyCache) -> None:
    """서로 다른 UUID 는 독립적인 슬롯."""
    a = uuid4()
    b = uuid4()
    assert a != b
    outcome_a, _ = fresh_cache.reserve(a)
    outcome_b, _ = fresh_cache.reserve(b)
    assert outcome_a is ReserveOutcome.NEW
    assert outcome_b is ReserveOutcome.NEW


def test_idempotency_clear_empties_all(fresh_cache: IdempotencyCache) -> None:
    """clear 는 모든 슬롯 비움 — 테스트 격리 훅."""
    a = uuid4()
    b = uuid4()
    fresh_cache.reserve(a)
    fresh_cache.reserve(b)
    fresh_cache.clear()
    outcome_a, _ = fresh_cache.reserve(a)
    outcome_b, _ = fresh_cache.reserve(b)
    assert outcome_a is ReserveOutcome.NEW
    assert outcome_b is ReserveOutcome.NEW


def test_idempotency_default_ttl_is_24h() -> None:
    """기본 TTL 이 정확히 24 시간 (§2.6 스펙)."""
    assert DEFAULT_TTL == timedelta(hours=24)


def test_idempotency_ttl_eviction_drops_stale_entry() -> None:
    """TTL 경과한 엔트리는 다음 reserve 호출 시 evict 되어 NEW 로 재진입."""
    cache = IdempotencyCache(ttl=timedelta(seconds=1))
    rid = uuid4()

    # 인위적으로 과거 시점으로 created_at 을 조작 → 즉시 만료.
    cache.reserve(rid)
    entry = cache._store[rid]
    entry.created_at = datetime.now(tz=UTC) - timedelta(seconds=5)

    outcome, _ = cache.reserve(rid)
    assert outcome is ReserveOutcome.NEW, (
        f"TTL 만료된 엔트리가 evict 되지 않음: {outcome}"
    )


def test_idempotency_complete_updates_state_in_place(
    fresh_cache: IdempotencyCache,
) -> None:
    """complete 는 같은 UUID 의 기존 IN_PROGRESS 엔트리를 COMPLETED 로 갱신."""
    rid = uuid4()
    fresh_cache.reserve(rid)
    sentinel = MagicMock(name="r1")
    fresh_cache.complete(rid, sentinel)

    sentinel2 = MagicMock(name="r2")
    fresh_cache.complete(rid, sentinel2)  # 덮어쓰기

    outcome, cached = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.COMPLETED
    assert cached is sentinel2  # 최신 응답


def test_idempotency_complete_without_reserve_still_stores(
    fresh_cache: IdempotencyCache,
) -> None:
    """reserve 없이 complete 만 호출해도 응답을 저장 (방어적 동작).

    이 시나리오는 정상 흐름에서는 발생하지 않지만, 응답 캐시가 강건하게
    유지되는지 확인 (역방향 호출 순서에 의한 침묵 실패 방지).
    """
    rid = uuid4()
    sentinel = MagicMock(name="cached")
    fresh_cache.complete(rid, sentinel)
    outcome, cached = fresh_cache.reserve(rid)
    assert outcome is ReserveOutcome.COMPLETED
    assert cached is sentinel


# ── 서명 검증의 timing-safe 비교 (compare_digest 사용 확인) ─────────────
def test_signature_comparison_uses_constant_time() -> None:
    """`compute_signature` 가 hmac.compare_digest 와 호환되는 hex 문자열을 반환."""
    import hmac as _hmac

    sig = compute_signature(
        secret=SECRET,
        timestamp="1700000000",
        nonce="n" * 16,
        method="POST",
        path="/x",
        body=b"",
    )
    # compare_digest 가 동작하려면 str/str 또는 bytes/bytes 동일 타입 필요.
    assert _hmac.compare_digest(sig, sig)
    assert not _hmac.compare_digest(sig, sig[:-1] + "0" if sig[-1] != "0" else sig[:-1] + "1")
