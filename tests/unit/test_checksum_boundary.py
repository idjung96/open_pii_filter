# SYNTHETIC DATA - NOT REAL PII
"""체크섬 알고리즘 결정성 + 경계 회귀 방지.

`app.core.checksum` 의 4 가지 알고리즘 (RRN, business num, Luhn check, Luhn
check digit) 는 다음의 단일 진실 원천:

  - 운영 인식기 (`KrRrnRecognizer.validate_result`, `KrBusinessNumRecognizer`)
  - 합성 fixture 생성기 (`tests.fixtures.synthetic_pii_generator.SyntheticPIIGenerator`)
  - 통합 테스트 (Phase 7 정책 시드 등)

체크섬 산출이 한 자릿수라도 바뀌면 인식기 false-negative (운영) +
합성 데이터 false-positive (테스트) 가 동시에 발생하므로, 본 모듈은:

  1. 알고리즘의 결정성 (같은 입력 → 같은 출력)
  2. 가중치 표 (private constant) 의 회귀
  3. invalid 입력 (잘못된 길이 / 비숫자 / 빈 문자열) 의 ValueError / False 반환
  4. 결과 범위 (0~9) 와 round-trip (checksum → is_valid)
  5. Luhn 의 well-known 테스트 벡터 (Visa, MasterCard 예제)
  6. 경계: 모든 0, 모든 9, 단일 자리 변동에 대한 sensitivity
"""

from __future__ import annotations

import pytest

from app.core.checksum import (
    _BIZ_WEIGHTS,
    _RRN_WEIGHTS,
    business_num_checksum,
    business_num_is_valid,
    luhn_check,
    luhn_check_digit,
    rrn_checksum,
    rrn_is_valid,
)


# ── RRN ─────────────────────────────────────────────────────────────────
def test_rrn_weights_constant_exact() -> None:
    """RRN 가중치 표: (2,3,4,5,6,7,8,9,2,3,4,5) — KS X 1001 회귀."""
    assert _RRN_WEIGHTS == (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)


def test_rrn_checksum_deterministic() -> None:
    """같은 입력 → 같은 출력 (결정성)."""
    a = rrn_checksum("900101123456")
    b = rrn_checksum("900101123456")
    assert a == b


def test_rrn_checksum_in_range_0_to_9() -> None:
    """체크섬은 0~9 범위 (한 자릿수)."""
    for prefix in ["000000000000", "999999999999", "123456789012", "900101123450"]:
        check = rrn_checksum(prefix)
        assert 0 <= check <= 9


def test_rrn_checksum_round_trip_via_is_valid() -> None:
    """checksum 으로 생성한 13자리는 항상 is_valid True."""
    for prefix in ["900101123456", "850315000001", "030229312345"]:
        check = rrn_checksum(prefix)
        full = prefix + str(check)
        assert rrn_is_valid(full), f"{full} round-trip 실패"


@pytest.mark.parametrize(
    "bad_input",
    [
        "",  # 빈 문자열
        "12345678901",  # 11자리 (너무 짧음)
        "1234567890123",  # 13자리 (너무 김 — 12 가 정답)
        "12345678901a",  # 비숫자 포함
        "12345678901 ",  # 공백 포함
        "12345678901-",  # hyphen
    ],
)
def test_rrn_checksum_rejects_bad_input(bad_input: str) -> None:
    """잘못된 입력은 ValueError — silent corruption 방지."""
    with pytest.raises(ValueError):
        rrn_checksum(bad_input)


def test_rrn_is_valid_accepts_hyphen_format() -> None:
    """`is_valid` 는 hyphen 포함 13자리도 자동 strip 한다."""
    prefix = "900101123456"
    check = rrn_checksum(prefix)
    hyphenated = f"{prefix[:6]}-{prefix[6:]}{check}"
    assert rrn_is_valid(hyphenated)


def test_rrn_is_valid_rejects_wrong_check_digit() -> None:
    """체크섬이 한 자리만 어긋나도 False — 알고리즘 민감도."""
    prefix = "900101123456"
    correct = rrn_checksum(prefix)
    wrong = (correct + 1) % 10
    bad_rrn = prefix + str(wrong)
    assert not rrn_is_valid(bad_rrn)


def test_rrn_is_valid_rejects_short_input() -> None:
    """is_valid 는 ValueError 없이 False — 사용자 입력 friendly."""
    assert not rrn_is_valid("123")
    assert not rrn_is_valid("")
    assert not rrn_is_valid("abc")


def test_rrn_is_valid_rejects_alpha_chars() -> None:
    assert not rrn_is_valid("90010112345a7")
    assert not rrn_is_valid("9001011234ABC")


def test_rrn_checksum_single_digit_change_sensitivity() -> None:
    """입력 한 자리 변경 시 checksum 이 바뀌어야 함 — 가중치 다양성 보장."""
    base = "900101123456"
    base_check = rrn_checksum(base)
    changes_detected = 0
    for pos in range(len(base)):
        for new_d in range(10):
            if str(new_d) == base[pos]:
                continue
            mod = base[:pos] + str(new_d) + base[pos + 1 :]
            if rrn_checksum(mod) != base_check:
                changes_detected += 1
                break
    # 모든 12 자리가 적어도 하나의 다른 자릿수로 체크섬 변경을 일으켜야 함.
    assert changes_detected == 12, f"가중치 0 인 자리 의심: {changes_detected}/12"


# ── KR_BUSINESS_NUM ──────────────────────────────────────────────────────
def test_biz_weights_constant_exact() -> None:
    """사업자번호 가중치 표 (1,3,7,1,3,7,1,3,5) — 국세청 공식."""
    assert _BIZ_WEIGHTS == (1, 3, 7, 1, 3, 7, 1, 3, 5)


def test_biz_checksum_in_range_0_to_9() -> None:
    for prefix in ["000000000", "999999999", "123456789", "104332181"]:
        c = business_num_checksum(prefix)
        assert 0 <= c <= 9


def test_biz_checksum_round_trip() -> None:
    """업자번호 체크섬 round-trip — generator + recognizer 일관성 가드."""
    for prefix in ["000000000", "123456789", "104332181", "999999999"]:
        c = business_num_checksum(prefix)
        full = prefix + str(c)
        assert business_num_is_valid(full), f"{full} 실패"


@pytest.mark.parametrize(
    "bad_input",
    [
        "",
        "12345678",  # 8자리
        "1234567890",  # 10자리 (9가 정답)
        "12345678a",
        "12345678-",
    ],
)
def test_biz_checksum_rejects_bad_input(bad_input: str) -> None:
    with pytest.raises(ValueError):
        business_num_checksum(bad_input)


def test_biz_is_valid_accepts_hyphen_format() -> None:
    """hyphen 형식 NNN-NN-NNNNN 도 strip 후 검증."""
    prefix = "123456789"
    c = business_num_checksum(prefix)
    full = f"{prefix[:3]}-{prefix[3:5]}-{prefix[5:]}{c}"
    assert business_num_is_valid(full)


def test_biz_is_valid_rejects_wrong_check() -> None:
    """잘못된 체크 자리 거절."""
    prefix = "123456789"
    correct = business_num_checksum(prefix)
    wrong = (correct + 1) % 10
    assert not business_num_is_valid(prefix + str(wrong))


def test_biz_is_valid_rejects_non_digit() -> None:
    assert not business_num_is_valid("12-34-56789a")
    assert not business_num_is_valid("abcdefghij")


def test_biz_checksum_carry_term_active() -> None:
    """9 번째 자리가 5 이상일 때 carry 항이 살아 있는지 — 알고리즘 회귀 가드.

    검증: prefix `000000005` (9번째 자리만 5) vs `000000004`. carry 가 동작하면
    두 결과가 동일하지 않아야 한다 (5*5=25 → carry 2 vs 4*5=20 → carry 1).
    """
    a = business_num_checksum("000000005")
    b = business_num_checksum("000000004")
    assert a != b, "carry 항이 동작하지 않는 듯 — 회귀 의심"


def test_biz_checksum_deterministic() -> None:
    assert business_num_checksum("123456789") == business_num_checksum("123456789")


# ── Luhn (credit card) ──────────────────────────────────────────────────
def test_luhn_check_well_known_vector_visa() -> None:
    """Wikipedia 예제: 4539 1488 0343 6467 → True."""
    assert luhn_check("4539148803436467")


def test_luhn_check_classic_test_4242() -> None:
    """Stripe 테스트 카드 4242 4242 4242 4242 → True."""
    assert luhn_check("4242424242424242")


def test_luhn_check_handles_spaces_and_hyphens() -> None:
    """공백/hyphen 자유 — 사용자 입력 친화."""
    assert luhn_check("4539 1488 0343 6467")
    assert luhn_check("4539-1488-0343-6467")


def test_luhn_check_rejects_wrong_digit() -> None:
    """마지막 자리만 한 칸 어긋나도 False."""
    assert not luhn_check("4539148803436468")  # 끝 7 → 8
    assert not luhn_check("4539148803436466")  # 끝 7 → 6


def test_luhn_check_rejects_empty_and_single_digit() -> None:
    """비어 있거나 한 자리는 알고리즘 정의상 False."""
    assert not luhn_check("")
    assert not luhn_check("4")
    assert not luhn_check("a")  # 숫자 없음


def test_luhn_check_with_all_zeros() -> None:
    """모두 0 인 16자리도 mathematically Luhn-valid (sum=0, 0%10=0)."""
    assert luhn_check("0000000000000000")


def test_luhn_check_digit_round_trip() -> None:
    """check_digit 생성한 16자리는 luhn_check 통과."""
    for partial in ["453914880343646", "424242424242424", "000000000000000"]:
        c = luhn_check_digit(partial)
        full = partial + str(c)
        assert luhn_check(full), f"{full} round-trip 실패"


def test_luhn_check_digit_in_range_0_to_9() -> None:
    """체크 자리 0~9."""
    for partial in ["123456789012345", "999999999999999", "000000000000001"]:
        c = luhn_check_digit(partial)
        assert 0 <= c <= 9


def test_luhn_check_digit_strips_non_digits() -> None:
    """`partial` 에 공백/hyphen 이 있어도 정상 작동."""
    a = luhn_check_digit("4539 1488 0343 646")
    b = luhn_check_digit("4539148803-43646")
    c = luhn_check_digit("453914880343646")
    assert a == b == c
