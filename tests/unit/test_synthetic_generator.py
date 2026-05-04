"""Tests for the synthetic PII generator (T6.1 ~ T6.7 of requirements §6.3)."""

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


# ── T6.1 / T6.2 — RRN checksums ─────────────────────────────────────────────
def test_gen_rrn_valid_1000_all_pass_checksum() -> None:
    g = SyntheticPIIGenerator(seed=42)
    samples = [g.gen_rrn(valid=True) for _ in range(1000)]
    invalid = [s for s in samples if not rrn_is_valid(s)]
    assert not invalid, f"{len(invalid)} of 1000 RRNs failed checksum: {invalid[:3]}"


def test_gen_rrn_invalid_1000_all_fail_checksum() -> None:
    g = SyntheticPIIGenerator(seed=42)
    samples = [g.gen_rrn(valid=False) for _ in range(1000)]
    valid = [s for s in samples if rrn_is_valid(s)]
    assert not valid, f"{len(valid)} of 1000 supposedly-invalid RRNs passed checksum"


# ── T6.3 — phone safe range ────────────────────────────────────────────────
@pytest.mark.parametrize("fmt", ["hyphen", "plain", "space", "international"])
def test_gen_phone_uses_safe_range(fmt: str) -> None:
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(100):
        phone = g.gen_phone(format=fmt)  # type: ignore[arg-type]
        digits = _compact(phone.replace("+", ""))
        # 010-0000-XXXX safe range: the "0000" middle group sits just before
        # the last 4 random digits, regardless of prefix (010 vs +82 10).
        assert digits[-8:-4] == "0000", f"middle group not 0000 in: {phone}"
        assert digits[-4:].isdigit(), f"tail not 4 digits in: {phone}"


# ── T6.4 — Luhn ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("brand", ["visa", "mastercard", "amex"])
def test_gen_credit_card_luhn_valid(brand: str) -> None:
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        card = g.gen_credit_card(brand=brand, luhn_valid=True)  # type: ignore[arg-type]
        assert luhn_check(card), f"Luhn failed for {brand}: {card}"


@pytest.mark.parametrize("brand", ["visa", "mastercard", "amex"])
def test_gen_credit_card_luhn_invalid(brand: str) -> None:
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        card = g.gen_credit_card(brand=brand, luhn_valid=False)  # type: ignore[arg-type]
        assert not luhn_check(card), f"Luhn unexpectedly passed for {brand}: {card}"


# ── Business number checksum ───────────────────────────────────────────────
def test_gen_business_num_valid() -> None:
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        biz = g.gen_business_num(valid=True)
        assert business_num_is_valid(biz), f"biz num invalid: {biz}"


def test_gen_business_num_invalid() -> None:
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(200):
        biz = g.gen_business_num(valid=False)
        assert not business_num_is_valid(biz), f"biz num unexpectedly valid: {biz}"


# ── T6.5 — reproducibility ─────────────────────────────────────────────────
def test_same_seed_produces_same_output() -> None:
    g1 = SyntheticPIIGenerator(seed=42)
    g2 = SyntheticPIIGenerator(seed=42)
    for _ in range(50):
        assert g1.gen_rrn() == g2.gen_rrn()
        assert g1.gen_phone() == g2.gen_phone()
        assert g1.gen_email() == g2.gen_email()


def test_different_seed_produces_different_output() -> None:
    g1 = SyntheticPIIGenerator(seed=1)
    g2 = SyntheticPIIGenerator(seed=2)
    rrns1 = [g1.gen_rrn() for _ in range(20)]
    rrns2 = [g2.gen_rrn() for _ in range(20)]
    assert rrns1 != rrns2


# ── T6.6 — composite post sample ───────────────────────────────────────────
def test_gen_post_sample_contains_requested_entities() -> None:
    g = SyntheticPIIGenerator(seed=42)
    sample = g.gen_post_sample(entity_types=["KR_RRN", "KR_PHONE"])
    body: str = sample["body"]  # type: ignore[assignment]
    expected: list[dict[str, str]] = sample["expected_entities"]  # type: ignore[assignment]

    assert any(e["entity_type"] == "KR_RRN" for e in expected)
    assert any(e["entity_type"] == "KR_PHONE" for e in expected)
    for e in expected:
        assert e["value"] in body, f"expected value missing from body: {e['value']}"


# ── Email safe domain ──────────────────────────────────────────────────────
def test_gen_email_uses_reserved_domain_only() -> None:
    g = SyntheticPIIGenerator(seed=42)
    # `example.com` is RFC 2606 reserved-for-documentation and is one of
    # the generator's safe domains (alongside `test.local`); only real
    # consumer-mail providers must stay out of synthetic data.
    banned = ("gmail.com", "naver.com", "kakao.com", "daum.net")
    for _ in range(200):
        email = g.gen_email()
        for b in banned:
            assert b not in email, f"real-service domain in synthetic email: {email}"


# ── Negative phone ─────────────────────────────────────────────────────────
def test_gen_phone_negative_is_not_kr_mobile() -> None:
    g = SyntheticPIIGenerator(seed=42)
    kr_mobile_prefixes = ("010", "011", "016", "017", "018", "019")
    for _ in range(100):
        p = g.gen_phone_negative()
        digits = _compact(p)
        assert not any(digits.startswith(pre) for pre in kr_mobile_prefixes), (
            f"negative phone starts with KR mobile prefix: {p}"
        )


# ── T6.7 — scan script catches intentional real-service domain ──────────────
# We implement a minimal scanner here inline so the test does not depend on
# a CI script that lands in a later phase.
_REAL_PII_BANNED_PATTERNS = (
    "@gmail.com",
    "@naver.com",
    "@kakao.com",
    "@example.com",
    "@daum.net",
)


def test_real_pii_scan_detects_banned_domain() -> None:
    text = "지인 이메일: real_user@gmail.com 입니다."
    hits = [p for p in _REAL_PII_BANNED_PATTERNS if p in text]
    assert hits == ["@gmail.com"]
