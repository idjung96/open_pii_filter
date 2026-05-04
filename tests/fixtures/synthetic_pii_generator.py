# SYNTHETIC DATA - NOT REAL PII
"""Deterministic synthetic PII data generator for tests.

Never uses real PII. See §6 of the requirements for authoritative rules.

Usage:
    g = SyntheticPIIGenerator(seed=42)
    rrn = g.gen_rrn(valid=True)
    phone = g.gen_phone(format="hyphen")
    post = g.gen_post_sample(entity_types=["KR_RRN", "KR_PHONE"])

All outputs are fabricated:
- Phones use the 010-0000-XXXX safe range (KISA test reserved)
- Emails use reserved domains (@example.com, @test.local)
- Addresses use non-existent building numbers
- Credit cards use ISO test numbers (Luhn-valid but never issued)
- Passports/driver licenses follow format only; numbers are random
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Literal

from tests.fixtures.checksum import (
    business_num_checksum,
    luhn_check_digit,
    rrn_checksum,
)

PhoneFormat = Literal["hyphen", "plain", "space", "international"]
CardBrand = Literal["visa", "mastercard", "amex"]
NameLocale = Literal["ko", "en"]

# ── Fabricated name pools (never real people) ───────────────────────────────
_KO_NAMES: tuple[str, ...] = (
    "홍길동",
    "김영희",
    "이철수",
    "박민지",
    "최서연",
    "정현우",
    "강다은",
    "윤지호",
    "임수빈",
    "한유진",
    "조민재",
    "오하린",
    "서지안",
    "배시우",
    "문예준",
    "권도윤",
    "황서준",
    "송하율",
    "백지안",
    "남궁서진",
)
_EN_NAMES: tuple[str, ...] = (
    "John Doe",
    "Jane Smith",
    "Alice Kim",
    "Bob Park",
    "Charlie Lee",
    "Diana Choi",
    "Eve Han",
    "Frank Oh",
    "Grace Yoon",
    "Henry Jung",
)

# Deny-list surname syllables — intentionally unrealistic combinations so
# there is zero chance of overlap with any real 기관 employee.
_DENY_LIST_NAMES: tuple[str, ...] = (
    "가나다",
    "라마바",
    "사아자",
    "차카타",
    "파하각",
    "난단람",
    "맘반삽",
)

# ── Reserved/safe domains and locations ─────────────────────────────────────
_SAFE_EMAIL_DOMAINS: tuple[str, ...] = (
    "example.com",
    "example.kr",
    "example.org",
    "test.local",
    "invalid",
)
_LOCATIONS: tuple[str, ...] = (
    "서울특별시 강남구 테헤란로 9999",
    "서울특별시 종로구 세종대로 8888 가상빌딩 101호",
    "경기도 성남시 분당구 불정로 7777",
    "부산광역시 해운대구 센텀로 6666 테스트타워",
    "대전광역시 유성구 대덕대로 5555",
)


@dataclass
class SyntheticPIIGenerator:
    """Reproducible random generator for synthetic PII samples."""

    seed: int = 42
    _rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)

    # ── KR_RRN (주민등록번호) ──────────────────────────────────────────────
    def gen_rrn(
        self,
        *,
        valid: bool = True,
        birth_year_range: tuple[int, int] = (1950, 2010),
    ) -> str:
        """Generate a 13-digit RRN with hyphen, e.g. '900101-1234567'.

        `valid=False` deliberately flips the last digit to break the checksum.
        """
        year = self._rng.randint(*birth_year_range)
        month = self._rng.randint(1, 12)
        # Use day<=28 to avoid month-length edge cases in positive samples.
        day = self._rng.randint(1, 28)
        yymmdd = f"{year % 100:02d}{month:02d}{day:02d}"

        # Gender/century code: 1/2 for 19xx, 3/4 for 20xx
        gender = self._rng.choice([3, 4] if year >= 2000 else [1, 2])

        # Individual 6-digit portion: 5 random + 1 checksum
        individual_5 = f"{self._rng.randint(0, 99999):05d}"
        first_twelve = yymmdd + str(gender) + individual_5
        check = rrn_checksum(first_twelve)
        if not valid:
            check = (check + 1) % 10  # intentionally wrong
        return f"{yymmdd}-{gender}{individual_5}{check}"

    # ── KR_PHONE (휴대폰) ─────────────────────────────────────────────────
    def gen_phone(self, *, format: PhoneFormat = "hyphen") -> str:
        """Generate a phone number in the 010-0000-XXXX safe range."""
        tail = f"{self._rng.randint(0, 9999):04d}"
        if format == "hyphen":
            return f"010-0000-{tail}"
        if format == "plain":
            return f"0100000{tail}"
        if format == "space":
            return f"010 0000 {tail}"
        if format == "international":
            return f"+82-10-0000-{tail}"
        raise ValueError(f"unknown phone format: {format}")

    def gen_phone_negative(self) -> str:
        """11-digit number that is NOT a valid KR mobile prefix.

        Useful for negative fixtures — should not be detected as KR_PHONE.
        """
        prefix = self._rng.choice(["030", "040", "080", "090"])
        rest = f"{self._rng.randint(0, 9999999):07d}"
        return f"{prefix}-{rest[:3]}-{rest[3:]}"

    # ── CREDIT_CARD ─────────────────────────────────────────────────────────
    def gen_credit_card(self, *, brand: CardBrand = "visa", luhn_valid: bool = True) -> str:
        """Generate a fabricated credit card number for the given brand."""
        if brand == "visa":
            prefix = "4"
            length = 16
        elif brand == "mastercard":
            prefix = str(self._rng.randint(51, 55))
            length = 16
        elif brand == "amex":
            prefix = self._rng.choice(["34", "37"])
            length = 15
        else:
            raise ValueError(f"unknown brand: {brand}")

        body_digits = length - len(prefix) - 1  # reserve last for check
        body = "".join(str(self._rng.randint(0, 9)) for _ in range(body_digits))
        partial = prefix + body
        check = luhn_check_digit(partial)
        if not luhn_valid:
            check = (check + 1) % 10
        return self._format_card(prefix + body + str(check), brand)

    @staticmethod
    def _format_card(digits: str, brand: CardBrand) -> str:
        if brand == "amex":  # 4-6-5
            return f"{digits[:4]}-{digits[4:10]}-{digits[10:]}"
        return "-".join(digits[i : i + 4] for i in range(0, len(digits), 4))

    # ── KR_BANK_ACCOUNT ─────────────────────────────────────────────────────
    def gen_bank_account(self, *, strength: Literal["strong", "weak"] = "strong") -> str:
        """Strong = hyphenated bank-specific pattern; weak = bare digits."""
        if strength == "strong":
            patterns = [
                lambda r: (
                    f"{r.randint(100, 999)}-{r.randint(10, 99):02d}-"
                    f"{r.randint(1000, 9999):04d}-{r.randint(100, 999):03d}"
                ),
                lambda r: f"110-{r.randint(100, 999)}-{r.randint(0, 999999):06d}",
                lambda r: (
                    f"{r.randint(100, 999)}-{r.randint(1000, 9999):04d}-"
                    f"{r.randint(1000, 9999):04d}-{r.randint(10, 99):02d}"
                ),
            ]
            return self._rng.choice(patterns)(self._rng)
        # weak: 10~14 digit plain number
        length = self._rng.randint(10, 14)
        return "".join(str(self._rng.randint(0, 9)) for _ in range(length))

    # ── EMAIL_ADDRESS ───────────────────────────────────────────────────────
    def gen_email(self) -> str:
        local = "".join(
            self._rng.choice("abcdefghijklmnopqrstuvwxyz0123456789._-") for _ in range(8)
        ).strip("._-")
        domain = self._rng.choice(_SAFE_EMAIL_DOMAINS)
        return f"{local or 'test'}@{domain}"

    # ── PERSON ─────────────────────────────────────────────────────────────
    def gen_person_name(self, *, locale: NameLocale = "ko") -> str:
        pool = _KO_NAMES if locale == "ko" else _EN_NAMES
        return self._rng.choice(pool)

    def gen_deny_list_name(self) -> str:
        """Fabricated syllables used to test employee deny-list logic."""
        return self._rng.choice(_DENY_LIST_NAMES)

    # ── LOCATION ───────────────────────────────────────────────────────────
    def gen_location(self) -> str:
        return self._rng.choice(_LOCATIONS)

    # ── KR_BUSINESS_NUM ────────────────────────────────────────────────────
    def gen_business_num(self, *, valid: bool = True) -> str:
        nine = "".join(str(self._rng.randint(0, 9)) for _ in range(9))
        check = business_num_checksum(nine)
        if not valid:
            check = (check + 1) % 10
        return f"{nine[:3]}-{nine[3:5]}-{nine[5:]}{check}"

    # ── KR_PASSPORT / KR_DRIVERLICENSE ──────────────────────────────────────
    def gen_passport(self) -> str:
        letter = self._rng.choice("MSROTP")
        digits = "".join(str(self._rng.randint(0, 9)) for _ in range(8))
        return f"{letter}{digits}"

    def gen_driver_license(self) -> str:
        region = f"{self._rng.randint(11, 28):02d}"
        year = f"{self._rng.randint(0, 99):02d}"
        serial = f"{self._rng.randint(0, 999999):06d}"
        check = f"{self._rng.randint(0, 99):02d}"
        return f"{region}-{year}-{serial}-{check}"

    # ── Composite post sample ──────────────────────────────────────────────
    def gen_post_sample(
        self,
        *,
        entity_types: list[str],
        density: Literal["low", "medium", "high"] = "low",
    ) -> dict[str, object]:
        """Generate a post body containing the requested entity types.

        Returns a dict with `title`, `body`, and `expected_entities` for
        downstream assertions. The body reads like a plausible citizen post.
        """
        repeats = {"low": 1, "medium": 2, "high": 3}[density]
        expected: list[dict[str, str]] = []
        sentences: list[str] = []

        for etype in entity_types:
            for _ in range(repeats):
                value, sentence = self._render_entity(etype)
                expected.append({"entity_type": etype, "value": value})
                sentences.append(sentence)

        # Shuffle sentences to avoid a predictable leading entity.
        self._rng.shuffle(sentences)
        body = "안녕하세요, 문의드립니다. " + " ".join(sentences) + " 확인 부탁드립니다."
        return {
            "title": "문의드립니다",
            "body": body,
            "expected_entities": expected,
        }

    def _render_entity(self, etype: str) -> tuple[str, str]:
        """Return (raw_value, sentence_containing_it) for the given entity."""
        if etype == "KR_RRN":
            v = self.gen_rrn()
            return v, f"주민번호는 {v} 입니다."
        if etype == "KR_PHONE":
            v = self.gen_phone()
            return v, f"연락처는 {v} 으로 주세요."
        if etype == "EMAIL_ADDRESS":
            v = self.gen_email()
            return v, f"이메일은 {v} 로 보내주시면 됩니다."
        if etype == "CREDIT_CARD":
            v = self.gen_credit_card()
            return v, f"카드 번호 {v} 관련 문의입니다."
        if etype == "KR_BANK_ACCOUNT":
            v = self.gen_bank_account()
            return v, f"입금 계좌는 {v} 입니다."
        if etype == "KR_BUSINESS_NUM":
            v = self.gen_business_num()
            return v, f"사업자번호 {v} 로 세금계산서 발행 부탁드립니다."
        if etype == "KR_PASSPORT":
            v = self.gen_passport()
            return v, f"여권번호 {v} 첨부합니다."
        if etype == "KR_DRIVERLICENSE":
            v = self.gen_driver_license()
            return v, f"운전면허 {v} 로 본인 확인 부탁드립니다."
        if etype == "PERSON":
            v = self.gen_person_name()
            return v, f"담당자는 {v} 님입니다."
        if etype == "LOCATION":
            v = self.gen_location()
            return v, f"주소는 {v} 입니다."
        raise ValueError(f"unsupported entity_type: {etype}")
