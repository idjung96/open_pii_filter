"""KR_BUSINESS_NUM — Korean business registration number (사업자등록번호) recognizer.

Format: NNN-NN-NNNNN (10 digits with two hyphens) where the last digit is
a checksum derived from weights (1,3,7,1,3,7,1,3,5) plus carry.

`validate_result` integration:
  - regex match alone   → keep pattern score (0.3-0.5)
  - checksum verified   → Presidio promotes score to 1.0
  - checksum invalid    → Presidio drops the result entirely
"""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer

from app.core.checksum import business_num_checksum


class KrBusinessNumRecognizer(PatternRecognizer):
    """KR business registration number recognizer with checksum validation."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krbiz_hyphen",
            regex=r"(?<!\d)\d{3}-\d{2}-\d{5}(?!\d)",
            score=0.5,
        ),
        Pattern(
            name="krbiz_plain",
            regex=r"(?<!\d)\d{10}(?!\d)",
            score=0.3,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["사업자", "사업자번호", "사업자등록", "법인"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_BUSINESS_NUM",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 10:
            return False
        try:
            expected = business_num_checksum(digits[:9])
        except ValueError:
            return False
        return int(digits[9]) == expected
