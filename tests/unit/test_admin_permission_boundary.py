# SYNTHETIC DATA - NOT REAL PII
"""Admin 권한 + IP allowlist 경계 회귀 방지 (Phase 6 / 8).

`/v1/admin/*` 엔드포인트는 3-gate 권한 모델:

  1. `require_auth` — HMAC + API key + rate limit (다른 단위 테스트에서 검증)
  2. ``caller.is_admin == True`` — DB row 의 admin 플래그
  3. caller IP ∈ ``Settings.admin_ip_allowlist`` (CIDR 매칭)

본 모듈은 **순수 함수** 영역만 본다:

  - `app.security.ip_allowlist._matches` 의 CIDR 매칭 정확성
  - `is_allowed` 의 key/global 조합 truth table
  - `enforce` 의 예외 propagation + ``.ip`` 보존
  - `AuthedCaller` 의 ``is_admin`` 기본값 False
  - `_admin_allowlist` parser 의 trim / 빈 토큰 무시

DB / Depends 가 필요한 통합 흐름은 `tests/integration/test_*admin*` 에 위임.
"""

from __future__ import annotations

import pytest

from app.security.hmac_auth import AuthedCaller
from app.security.ip_allowlist import (
    IpNotAllowedError,
    _matches,
    enforce,
    is_allowed,
)


# ── _matches — CIDR 매칭 정확성 ─────────────────────────────────────────
@pytest.mark.parametrize(
    ("ip", "cidrs", "expected"),
    [
        # /32 single host
        ("203.0.113.5", ["203.0.113.5/32"], True),
        ("203.0.113.6", ["203.0.113.5/32"], False),
        # /24 subnet
        ("203.0.113.5", ["203.0.113.0/24"], True),
        ("203.0.114.5", ["203.0.113.0/24"], False),
        ("203.0.113.255", ["203.0.113.0/24"], True),
        ("203.0.113.0", ["203.0.113.0/24"], True),
        # /16 wider subnet
        ("203.0.113.5", ["203.0.0.0/16"], True),
        ("203.1.0.0", ["203.0.0.0/16"], False),
        # Multiple CIDRs — match in any
        ("10.0.0.1", ["192.168.0.0/24", "10.0.0.0/24"], True),
        ("172.16.0.1", ["192.168.0.0/24", "10.0.0.0/24"], False),
        # IPv6
        ("2001:db8::1", ["2001:db8::/32"], True),
        ("2001:db9::1", ["2001:db8::/32"], False),
    ],
)
def test_matches_cidr_basic(ip: str, cidrs: list[str], expected: bool) -> None:
    """CIDR 매칭의 핵심 케이스 — /32 정확 매칭, /24 서브넷, /16 광역, IPv6."""
    assert _matches(ip, cidrs) is expected


def test_matches_returns_false_for_invalid_ip() -> None:
    """잘못된 IP 형식은 항상 False — 예외 전파 금지."""
    assert _matches("not-an-ip", ["203.0.113.0/24"]) is False
    assert _matches("999.999.999.999", ["203.0.113.0/24"]) is False
    assert _matches("", ["203.0.113.0/24"]) is False


def test_matches_skips_invalid_cidr_entries() -> None:
    """CIDR 리스트의 잘못된 항목은 silent skip — 다른 entry 로 진행.

    운영자가 settings 에 잘못된 CIDR 한 줄을 넣어도 전체 allowlist 가 죽으면
    안 된다 (그러나 invalid 가 matchable 한 것처럼 동작해서도 안 됨).
    """
    assert _matches("203.0.113.5", ["not-a-cidr", "203.0.113.0/24"]) is True
    # 모두 invalid 면 False.
    assert _matches("203.0.113.5", ["not-a-cidr", "totally-broken"]) is False


def test_matches_handles_whitespace_in_cidrs() -> None:
    """CIDR 항목의 양옆 공백은 strip — settings CSV 파싱 robustness."""
    assert _matches("203.0.113.5", ["  203.0.113.0/24  "]) is True


def test_matches_empty_cidr_list_returns_false() -> None:
    """빈 리스트 — 매칭할 게 없으니 False (정책: empty = match nothing 가아니라
    `is_allowed` 레벨에서 empty 처리 분기). _matches 단독으로는 False."""
    assert _matches("203.0.113.5", []) is False


# ── is_allowed truth table ──────────────────────────────────────────────
@pytest.mark.parametrize(
    ("ip", "key_allowlist", "global_allowlist", "expected"),
    [
        # 둘 다 None / empty → 제한 없음 → 항상 허용
        ("203.0.113.5", None, None, True),
        ("203.0.113.5", [], [], True),
        # global 만 설정 + 매칭 → 허용
        ("203.0.113.5", None, ["203.0.113.0/24"], True),
        # global 만 설정 + 미매칭 → 거절
        ("203.0.113.5", None, ["198.51.100.0/24"], False),
        # key 만 설정 + 매칭 → 허용
        ("203.0.113.5", ["203.0.113.0/24"], None, True),
        # key 만 설정 + 미매칭 → 거절
        ("203.0.113.5", ["198.51.100.0/24"], None, False),
        # 둘 다 설정 + 둘 다 매칭 → 허용
        (
            "203.0.113.5",
            ["203.0.113.0/24"],
            ["203.0.0.0/16"],
            True,
        ),
        # 둘 다 설정 + global 만 매칭 → 거절 (둘 다 통과해야 함)
        (
            "203.0.113.5",
            ["198.51.100.0/24"],
            ["203.0.0.0/16"],
            False,
        ),
        # 둘 다 설정 + key 만 매칭 → 거절
        (
            "203.0.113.5",
            ["203.0.113.0/24"],
            ["198.51.100.0/24"],
            False,
        ),
    ],
)
def test_is_allowed_truth_table(
    ip: str,
    key_allowlist: list[str] | None,
    global_allowlist: list[str] | None,
    expected: bool,
) -> None:
    """key / global allowlist 의 모든 조합이 둘 다 통과 (AND) 의미를 가진다."""
    assert (
        is_allowed(ip, key_allowlist=key_allowlist, global_allowlist=global_allowlist) is expected
    )


def test_is_allowed_invalid_ip_with_any_allowlist_denies() -> None:
    """invalid IP + allowlist 가 있을 때 거절 — fail-closed.

    `_matches` 가 False 를 반환하므로 `not _matches` 가 True 가 되어 거절.
    """
    assert not is_allowed("not-an-ip", global_allowlist=["203.0.113.0/24"])
    # allowlist 가 비어 있으면 invalid IP 도 허용 — "제한 없음" 의미.
    assert is_allowed("not-an-ip")


# ── enforce — 예외 ip 보존 ──────────────────────────────────────────────
def test_enforce_raises_with_ip_attribute() -> None:
    """`enforce` 가 거절 시 IpNotAllowedError 에 실제 IP 보존."""
    with pytest.raises(IpNotAllowedError) as e:
        enforce("203.0.113.5", global_allowlist=["198.51.100.0/24"])
    assert e.value.ip == "203.0.113.5"


def test_enforce_silently_passes_when_allowed() -> None:
    """매칭 시 예외 없이 None 반환."""
    result = enforce("203.0.113.5", global_allowlist=["203.0.113.0/24"])
    assert result is None


def test_enforce_no_lists_always_passes() -> None:
    """allowlist 가 모두 None/empty → 무제한 통과."""
    enforce("203.0.113.5")
    enforce("2001:db8::1", key_allowlist=None, global_allowlist=None)
    enforce("any.weird.string-x", key_allowlist=[], global_allowlist=[])  # 제한 없으니 OK


def test_enforce_with_both_lists_uses_and_semantics() -> None:
    """key / global 둘 다 설정되어 있고 한쪽만 매칭하면 거절."""
    with pytest.raises(IpNotAllowedError):
        enforce(
            "203.0.113.5",
            key_allowlist=["203.0.113.0/24"],
            global_allowlist=["198.51.100.0/24"],
        )


def test_ip_not_allowed_error_carries_ip() -> None:
    """예외 객체가 `.ip` 속성 + `str()` 에 IP 노출."""
    err = IpNotAllowedError("10.0.0.1")
    assert err.ip == "10.0.0.1"
    assert "10.0.0.1" in str(err)


# ── AuthedCaller `is_admin` 기본값 ──────────────────────────────────────
def test_authed_caller_is_admin_defaults_to_false() -> None:
    """`is_admin` 인자를 생략하면 항상 False — 권한 fail-closed 기본."""
    caller = AuthedCaller(
        key_id="k1",
        name="test-key",
        rate_per_minute=60,
        rate_per_hour=3600,
        ip_allowlist=None,
        client_ip="203.0.113.5",
    )
    assert caller.is_admin is False


def test_authed_caller_is_admin_can_be_true() -> None:
    """`is_admin=True` 를 명시적으로 받아야만 admin 권한."""
    caller = AuthedCaller(
        key_id="k1",
        name="admin-key",
        rate_per_minute=60,
        rate_per_hour=3600,
        ip_allowlist=None,
        client_ip="203.0.113.5",
        is_admin=True,
    )
    assert caller.is_admin is True


def test_authed_caller_is_frozen() -> None:
    """frozen dataclass — 권한 필드를 런타임 변조 불가."""
    caller = AuthedCaller(
        key_id="k1",
        name="x",
        rate_per_minute=60,
        rate_per_hour=3600,
        ip_allowlist=None,
        client_ip="203.0.113.5",
    )
    with pytest.raises(AttributeError):
        caller.is_admin = True  # type: ignore[misc]


def test_authed_caller_ip_allowlist_is_tuple() -> None:
    """ip_allowlist 가 tuple — 변조 불가 + hashable."""
    caller = AuthedCaller(
        key_id="k1",
        name="x",
        rate_per_minute=60,
        rate_per_hour=3600,
        ip_allowlist=("203.0.113.0/24", "10.0.0.0/8"),
        client_ip="203.0.113.5",
    )
    assert isinstance(caller.ip_allowlist, tuple)
    assert caller.ip_allowlist == ("203.0.113.0/24", "10.0.0.0/8")


# ── `_admin_allowlist` CSV 파서 ────────────────────────────────────────
def test_admin_allowlist_parser_handles_empty_setting() -> None:
    """`admin_ip_allowlist` 가 빈 문자열 → 빈 리스트."""
    from app.api.admin_audit import _admin_allowlist
    from app.config import get_settings

    settings = get_settings()
    # 본 테스트는 settings 가 빈 admin_ip_allowlist 인 조건 (기본).
    # production 에서는 router 미장착으로 처리되지만, 파서 자체는 안전해야 한다.
    raw_before = settings.admin_ip_allowlist
    try:
        # type-ignore: pydantic model이지만 본 테스트는 mutation 후 복구.
        object.__setattr__(settings, "admin_ip_allowlist", "")
        assert _admin_allowlist() == []
    finally:
        object.__setattr__(settings, "admin_ip_allowlist", raw_before)


def test_admin_allowlist_parser_trims_and_drops_empties() -> None:
    """`'  203.0.113.0/24 ,, 10.0.0.0/8  '` → 정상 2-element 리스트."""
    from app.api.admin_audit import _admin_allowlist
    from app.config import get_settings

    settings = get_settings()
    raw_before = settings.admin_ip_allowlist
    try:
        object.__setattr__(settings, "admin_ip_allowlist", "  203.0.113.0/24 ,, 10.0.0.0/8  ")
        result = _admin_allowlist()
        assert result == ["203.0.113.0/24", "10.0.0.0/8"]
    finally:
        object.__setattr__(settings, "admin_ip_allowlist", raw_before)


def test_admin_allowlist_parser_handles_single_entry() -> None:
    """단일 CIDR 도 정상 파싱."""
    from app.api.admin_audit import _admin_allowlist
    from app.config import get_settings

    settings = get_settings()
    raw_before = settings.admin_ip_allowlist
    try:
        object.__setattr__(settings, "admin_ip_allowlist", "203.0.113.0/24")
        assert _admin_allowlist() == ["203.0.113.0/24"]
    finally:
        object.__setattr__(settings, "admin_ip_allowlist", raw_before)


def test_admin_allowlist_parser_handles_none() -> None:
    """`admin_ip_allowlist=None` → 빈 리스트 (정책: missing setting = 비활성)."""
    from app.api.admin_audit import _admin_allowlist
    from app.config import get_settings

    settings = get_settings()
    raw_before = settings.admin_ip_allowlist
    try:
        object.__setattr__(settings, "admin_ip_allowlist", None)
        assert _admin_allowlist() == []
    finally:
        object.__setattr__(settings, "admin_ip_allowlist", raw_before)


# ── 시나리오 — admin gate 의 합성 동작 ─────────────────────────────────
def test_admin_gate_three_layers_compose_to_and() -> None:
    """admin gate 의 3 조건 (auth + is_admin + IP) 합성 의미.

    본 테스트는 require_admin 함수 자체를 호출하는 대신, 세 조건 각각의
    필요충분성을 truth table 로 핀(pin) — 한 조건이라도 깨지면 거절.
    """
    # 시나리오: admin=True, IP 매칭 → 통과
    ok_caller = AuthedCaller(
        key_id="k",
        name="x",
        rate_per_minute=60,
        rate_per_hour=3600,
        ip_allowlist=None,
        client_ip="203.0.113.5",
        is_admin=True,
    )
    assert is_allowed(ok_caller.client_ip, global_allowlist=["203.0.113.0/24"])
    assert ok_caller.is_admin

    # 시나리오: admin=True, IP 미매칭 → 거절
    assert not is_allowed("203.0.113.5", global_allowlist=["198.51.100.0/24"])

    # 시나리오: admin=False (auth 통과해도) → require_admin 단에서 거절
    not_admin = ok_caller.__class__(
        key_id="k",
        name="x",
        rate_per_minute=60,
        rate_per_hour=3600,
        ip_allowlist=None,
        client_ip="203.0.113.5",
        is_admin=False,
    )
    assert not not_admin.is_admin
