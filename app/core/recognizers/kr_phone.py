"""KR_PHONE — Korean mobile phone number recognizer.

Accepts 010-style mobile prefixes in 4 formats:
  - hyphen:        010-1234-5678
  - plain:         01012345678
  - space:         010 1234 5678
  - international: +82-10-1234-5678 / +82 10 1234 5678
"""

from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer


class KrPhoneRecognizer(PatternRecognizer):
    """KR mobile phone (010 series) recognizer."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krphone_hyphen",
            regex=r"(?<!\d)010[-]\d{3,4}[-]\d{4}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krphone_space",
            regex=r"(?<!\d)010[ ]\d{3,4}[ ]\d{4}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krphone_plain",
            regex=r"(?<!\d)010\d{7,8}(?!\d)",
            score=0.7,
        ),
        Pattern(
            name="krphone_intl",
            regex=r"\+82[-\s]?10[-\s]?\d{3,4}[-\s]?\d{4}",
            score=0.85,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["전화", "연락", "휴대폰", "핸드폰", "phone", "tel", "mobile"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_PHONE",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )
