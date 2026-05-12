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

import datetime as _dt
import re
from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer

from app.core.checksum import rrn_checksum

# gender code → 출생년도 century 매핑.
#   1, 2 → 19xx
#   3, 4 → 20xx
#   (5~8 외국인 코드는 별도 entity 가 담당 — 본 인식기는 [1-4] 만 매칭)
_GENDER_TO_CENTURY: dict[str, int] = {"1": 1900, "2": 1900, "3": 2000, "4": 2000}


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
        """체크섬 + 달력 정확성 (월별 일수 + 윤년 포함) 까지 검증.

        오탐 방지를 위해 단순 ``1 <= day <= 31`` 검사가 아니라 실제 그 연/월의
        ``datetime.date(year, month, day)`` 생성을 시도해 Feb 30, Feb 29 (평년)
        같은 비유효 날짜를 모두 거절한다.
        """
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 13:
            return False
        yy, mm, dd, c, rest = digits[0:2], digits[2:4], digits[4:6], digits[6], digits[7:13]
        if c not in _GENDER_TO_CENTURY:
            return False
        century = _GENDER_TO_CENTURY[c]
        try:
            # 달력 정확성 — month/day 의 모든 invalid 조합 (Feb 30, 비윤년의
            # Feb 29, 4/6/9/11 월의 31일 등) 이 ValueError 로 떨어진다.
            _dt.date(century + int(yy), int(mm), int(dd))
        except ValueError:
            return False
        first_twelve = yy + mm + dd + c + rest[:5]
        check = int(digits[12])
        try:
            expected = rrn_checksum(first_twelve)
        except ValueError:
            return False
        return check == expected
