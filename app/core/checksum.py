"""Checksum algorithms for Korean identifiers and credit cards.

Implemented from scratch (no external library) so production
recognizers and synthetic-fixture generators share a single source of
truth. See §6.2 of the requirements for the authoritative
specifications.

Historically these helpers lived under ``tests/fixtures/checksum.py``,
but production recognizers (``app.core.recognizers.kr_rrn``,
``kr_business_num``) need them at runtime — and the container image
ships without ``tests/``. The module has been promoted to
``app.core.checksum`` and the original test path now re-exports from
here.
"""

from __future__ import annotations

# ── KR_RRN (주민등록번호) ────────────────────────────────────────────────────
# 13 digits total. The last digit is a checksum over the first 12 digits
# using weights [2,3,4,5,6,7,8,9,2,3,4,5]:
#   checksum = (11 - (sum(d[i]*w[i]) % 11)) % 10
_RRN_WEIGHTS = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)


def rrn_checksum(first_twelve: str) -> int:
    """Return the expected 13th digit for a given 12-digit RRN prefix."""
    if len(first_twelve) != 12 or not first_twelve.isdigit():
        raise ValueError("RRN prefix must be 12 numeric digits")
    s = sum(int(d) * w for d, w in zip(first_twelve, _RRN_WEIGHTS, strict=True))
    return (11 - (s % 11)) % 10


def rrn_is_valid(rrn: str) -> bool:
    """Check a bare 13-digit RRN (no hyphen) for a valid checksum."""
    compact = rrn.replace("-", "").strip()
    if len(compact) != 13 or not compact.isdigit():
        return False
    return int(compact[12]) == rrn_checksum(compact[:12])


# ── KR_BUSINESS_NUM (사업자등록번호) ────────────────────────────────────────
# 10 digits: XXX-XX-XXXXX. Weights [1,3,7,1,3,7,1,3,5] on digits 0..8,
# plus (d[8]*5)//10 carry term. Check = (10 - (sum + carry) % 10) % 10.
_BIZ_WEIGHTS = (1, 3, 7, 1, 3, 7, 1, 3, 5)


def business_num_checksum(first_nine: str) -> int:
    """Return the expected 10th digit for a 9-digit business number prefix."""
    if len(first_nine) != 9 or not first_nine.isdigit():
        raise ValueError("Business number prefix must be 9 numeric digits")
    s = sum(int(d) * w for d, w in zip(first_nine, _BIZ_WEIGHTS, strict=True))
    # The 9th digit's contribution has an overflow carry term added back.
    carry = (int(first_nine[8]) * 5) // 10
    return (10 - (s + carry) % 10) % 10


def business_num_is_valid(num: str) -> bool:
    """Check a 10-digit Korean business registration number."""
    compact = num.replace("-", "").strip()
    if len(compact) != 10 or not compact.isdigit():
        return False
    return int(compact[9]) == business_num_checksum(compact[:9])


# ── Luhn (credit card) ──────────────────────────────────────────────────────


def luhn_check(number: str) -> bool:
    """Return True if `number` (digits only, hyphens/spaces stripped) passes Luhn."""
    digits = [c for c in number if c.isdigit()]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(partial: str) -> int:
    """Return the Luhn check digit for a number missing its last digit."""
    digits = [int(c) for c in partial if c.isdigit()]
    total = 0
    # When we append the check digit, the partial digits shift one position.
    # So iterate partial digits from right, doubling every other starting
    # with the position *next to* the check digit.
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10
