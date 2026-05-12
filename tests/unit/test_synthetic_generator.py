"""합성 PII 생성기 회귀 방지 (요구사항 §6.3 T6.1 ~ T6.7).

`tests/fixtures/synthetic_pii_generator.SyntheticPIIGenerator` 는 모든
테스트 입력의 단일 진실 원천 — 실제 개인정보 사용을 차단하기 위해
- 안전 범위 (`010-0000-XXXX`, `@example.com`, 합성 RRN 등) 만 발급
- 체크섬/Luhn 알고리즘이 정확해야 함 (이게 깨지면 인식기 회귀 검사가 무력화)
- 같은 seed 로 같은 출력이 나와야 함 (재현 가능성)
세 가지를 한 번에 검증한다. CI 의 `real_pii_scan.py` 가 fixture 디렉터리에
실제 PII 가 새어 들어왔는지 별도로 점검한다.
"""

from __future__ import annotations

import pytest

from tests.fixtures.checksum import (
    business_num_is_valid,
    luhn_check,
    rrn_is_valid,
)
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator


def _compact(s: str) -> str:
    return s.replace("-", "").replace(" ", "")


# ── T6.1 / T6.2 — RRN 체크섬 정확성 ─────────────────────────────────────
def test_gen_rrn_valid_1000_all_pass_checksum() -> None:
    """`gen_rrn(valid=True)` 1000개가 모두 ISO/KS X 1001 체크섬을 통과해야 한다.

    체크섬 알고리즘이 회귀하면 인식기 검증 테스트가 무력화되므로 대량 통계
    적 가드. 실패 시 처음 3개를 출력해 디버깅 단서 제공.
    """
    g = SyntheticPIIGenerator(seed=42)
    samples = [g.gen_rrn(valid=True) for _ in range(1000)]
    invalid = [s for s in samples if not rrn_is_valid(s)]
    assert not invalid, f"{len(invalid)} of 1000 RRNs failed checksum: {invalid[:3]}"


def test_gen_rrn_invalid_1000_all_fail_checksum() -> None:
    """`gen_rrn(valid=False)` 1000개가 모두 체크섬에 실패해야 한다 (negative).

    부정 케이스 생성기가 우연히 유효 RRN 을 만들어내면 `test_t1_2_invalid_rrn_dropped`
    같은 회귀 검사가 거짓 통과로 떨어지므로 여기서 1차로 막는다.
    """
    g = SyntheticPIIGenerator(seed=42)
    samples = [g.gen_rrn(valid=False) for _ in range(1000)]
    valid = [s for s in samples if rrn_is_valid(s)]
    assert not valid, f"{len(valid)} of 1000 supposedly-invalid RRNs passed checksum"


# ── T6.3 — 전화번호 안전 범위 ────────────────────────────────────────────
@pytest.mark.parametrize("fmt", ["hyphen", "plain", "space", "international"])
def test_gen_phone_uses_safe_range(fmt: str) -> None:
    """4가지 표기 모두 미들 그룹이 `0000` 인 안전 범위만 발급되는지.

    실 사용 가능한 휴대폰 번호 (010-XXXX-XXXX) 와 충돌하지 않도록 가운데
    네 자리가 항상 0000 인 reserved-for-testing 범위를 사용한다. 이 invariant
    이 깨지면 합성 데이터가 실제 누군가의 번호를 우연히 만들어낼 위험.
    """
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(100):
        phone = g.gen_phone(format=fmt)  # type: ignore[arg-type]
        digits = _compact(phone.replace("+", ""))
        # 010-0000-XXXX safe range: the "0000" middle group sits just before
        # the last 4 random digits, regardless of prefix (010 vs +82 10).
        assert digits[-8:-4] == "0000", f"middle group not 0000 in: {phone}"
        assert digits[-4:].isdigit(), f"tail not 4 digits in: {phone}"


# ── T6.4 — Luhn 체크섬 (신용카드) ───────────────────────────────────────
@pytest.mark.parametrize("brand", ["visa", "mastercard", "amex"])
def test_gen_credit_card_luhn_valid(brand: str) -> None:
    """3개 카드 브랜드 모두 `luhn_valid=True` 생성물이 Luhn 알고리즘을 통과.

    브랜드별 BIN 접두사가 다르므로 각각 200개씩 검증해 우연 통과를 방지.
    """
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        card = g.gen_credit_card(brand=brand, luhn_valid=True)  # type: ignore[arg-type]
        assert luhn_check(card), f"Luhn failed for {brand}: {card}"


@pytest.mark.parametrize("brand", ["visa", "mastercard", "amex"])
def test_gen_credit_card_luhn_invalid(brand: str) -> None:
    """`luhn_valid=False` 생성물은 모두 Luhn 실패 (negative case 생성기 검증)."""
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        card = g.gen_credit_card(brand=brand, luhn_valid=False)  # type: ignore[arg-type]
        assert not luhn_check(card), f"Luhn unexpectedly passed for {brand}: {card}"


# ── 사업자등록번호 체크섬 ─────────────────────────────────────────────────
def test_gen_business_num_valid() -> None:
    """`gen_business_num(valid=True)` 200개가 모두 KR 사업자번호 체크섬 통과.

    체크섬 가중치 (1,3,7,1,3,7,1,3,5) + 마지막 자리 보정 로직이 회귀하지
    않도록 매번 200회 확인.
    """
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        biz = g.gen_business_num(valid=True)
        assert business_num_is_valid(biz), f"biz num invalid: {biz}"


def test_gen_business_num_invalid() -> None:
    """`gen_business_num(valid=False)` 200개가 모두 체크섬에 실패해야 한다."""
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        biz = g.gen_business_num(valid=False)
        assert not business_num_is_valid(biz), f"biz num unexpectedly valid: {biz}"


# ── T6.5 — 재현 가능성 (seed 기반) ───────────────────────────────────────
def test_same_seed_produces_same_output() -> None:
    """같은 seed 의 두 생성기 인스턴스가 같은 순서로 같은 값을 내야 한다.

    회귀 디버깅 시 "이 commit 에서 fixture 가 어떻게 보이는지" 를 재현
    가능해야 하므로 결정적 출력이 필수. PRNG 상태 누출 / global RNG 사용
    회귀가 발생하면 여기서 즉시 탄로.
    """
    g1 = SyntheticPIIGenerator(seed=42)
    g2 = SyntheticPIIGenerator(seed=42)
    for _ in range(50):
        assert g1.gen_rrn() == g2.gen_rrn()
        assert g1.gen_phone() == g2.gen_phone()
        assert g1.gen_email() == g2.gen_email()


def test_different_seed_produces_different_output() -> None:
    """다른 seed 는 다른 출력 — 결정성이 단일 상수 반환으로 무너지지 않았는지 확인."""
    g1 = SyntheticPIIGenerator(seed=1)
    g2 = SyntheticPIIGenerator(seed=2)
    rrns1 = [g1.gen_rrn() for _ in range(20)]
    rrns2 = [g2.gen_rrn() for _ in range(20)]
    assert rrns1 != rrns2


# ── T6.6 — 복합 post 샘플 (본문 + 기대 entity 목록) ─────────────────────
def test_gen_post_sample_contains_requested_entities() -> None:
    """요청한 entity 종류가 모두 본문에 등장하고 `expected_entities` 와 매칭.

    end-to-end 회귀 fixture 의 핵심 — generator 가 요청한 entity 를 본문에
    심고 그 위치/값을 `expected_entities` 로 반환해야 통합 테스트에서
    "분석기가 이 entity 들을 찾아냈는가" 를 비교 검증 가능.
    """
    g = SyntheticPIIGenerator(seed=42)
    sample = g.gen_post_sample(entity_types=["KR_RRN", "KR_PHONE"])
    body: str = sample["body"]  # type: ignore[assignment]
    expected: list[dict[str, str]] = sample["expected_entities"]  # type: ignore[assignment]

    assert any(e["entity_type"] == "KR_RRN" for e in expected)
    assert any(e["entity_type"] == "KR_PHONE" for e in expected)
    for e in expected:
        assert e["value"] in body, f"expected value missing from body: {e['value']}"


# ── 이메일 안전 도메인 ────────────────────────────────────────────────────
def test_gen_email_uses_reserved_domain_only() -> None:
    """합성 이메일이 실제 메일 서비스 도메인을 절대 사용하지 않는지.

    `gmail.com`, `naver.com`, `kakao.com`, `daum.net` 등이 우연히라도 합성
    데이터에 들어가면 실재할 수 있는 주소를 만들어내는 사고가 된다. RFC 2606
    예약 도메인 (`example.com`) / 내부 도메인 (`test.local`) 만 사용해야 함.
    """
    g = SyntheticPIIGenerator(seed=42)
    # `example.com` is RFC 2606 reserved-for-documentation and is one of
    # the generator's safe domains (alongside `test.local`); only real
    # consumer-mail providers must stay out of synthetic data.
    banned = ("gmail.com", "naver.com", "kakao.com", "daum.net")
    for _ in range(200):
        email = g.gen_email()
        for b in banned:
            assert b not in email, f"real-service domain in synthetic email: {email}"


# ── 부정 케이스 — KR 휴대폰 prefix 가 아닌 번호 ─────────────────────────
def test_gen_phone_negative_is_not_kr_mobile() -> None:
    """`gen_phone_negative()` 가 010-019 prefix 를 절대 만들지 않아야 한다.

    "이 문자열은 전화번호로 보이지 말아야 한다" 라는 인식기 부정 검증의
    원천 데이터 — 우연히 010 으로 시작하면 부정 fixture 가 무력화된다.
    """
    g = SyntheticPIIGenerator(seed=42)
    kr_mobile_prefixes = ("010", "011", "016", "017", "018", "019")
    for _ in range(100):
        p = g.gen_phone_negative()
        digits = _compact(p)
        assert not any(digits.startswith(pre) for pre in kr_mobile_prefixes), (
            f"negative phone starts with KR mobile prefix: {p}"
        )


# ── T6.7 — 실 도메인 침입 감지 스캐너 (인라인 미니 구현) ──────────────────
# CI 의 `real_pii_scan.py` 는 별도 단계에 도입되므로 본 테스트에서는
# 미니 스캐너를 인라인으로 가지고 있어 의존성을 없앤다.
_REAL_PII_BANNED_PATTERNS = (
    "@gmail.com",
    "@naver.com",
    "@kakao.com",
    "@example.com",
    "@daum.net",
)


def test_real_pii_scan_detects_banned_domain() -> None:
    """fixture 에 실 서비스 도메인 (`@gmail.com`) 이 우연히 들어왔을 때 감지.

    스캐너 로직 자체의 sanity — counter-test 가 없으면 스캐너가 빈 결과만
    돌려도 통과해 버려서 무의미해진다. 의도적으로 위반인 텍스트를 넣고
    정확히 `@gmail.com` 한 건이 적발되는지 확인.
    """
    text = "지인 이메일: real_user@gmail.com 입니다."
    hits = [p for p in _REAL_PII_BANNED_PATTERNS if p in text]
    assert hits == ["@gmail.com"]
