"""KR_RRN — Korean Resident Registration Number (주민등록번호) recognizer.

Format: YYMMDD-CXXXXXC where:
  - YYMMDD: birth date (YY/MM/DD)
  - C (gender/century): 1,2 for 19xx; 3,4 for 20xx; 5~8 foreigners (handled separately)
  - XXXXX: 5 random digits
  - last C: ISO/KS X 1001 checksum

`validate_result` integration:
  - regex match alone        → keep pattern score (0.5-0.6)
  - checksum + date verified → Presidio promotes score to 1.0 (BLOCK)
  - checksum/date invalid    → Presidio drops the result entirely
"""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer

from tests.fixtures.checksum import rrn_checksum


class KrRrnRecognizer(PatternRecognizer):
    """KR_RRN recognizer with checksum + date validation."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krrrn_hyphen",
            regex=r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)",
            score=0.6,
        ),
        Pattern(
            name="krrrn_plain",
            regex=r"(?<!\d)\d{6}[1-4]\d{6}(?!\d)",
            score=0.5,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["주민", "주민번호", "주민등록", "RRN"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_RRN",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        """Confirm checksum + date are valid (True/False)."""
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 13:
            return False
        yy, mm, dd, c, rest = digits[0:2], digits[2:4], digits[4:6], digits[6], digits[7:13]
        try:
            month = int(mm)
            day = int(dd)
        except ValueError:
            return False
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return False
        if c not in {"1", "2", "3", "4"}:
            return False
        first_twelve = yy + mm + dd + c + rest[:5]
        check = int(digits[12])
        try:
            expected = rrn_checksum(first_twelve)
        except ValueError:
            return False
        return check == expected
