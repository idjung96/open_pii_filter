"""KR_PASSPORT — Korean passport number recognizer.

Format: 1 letter (M, S, R, O, T, P, D, G — issuing categories) + 8 digits.
Some PA series passports use 2 letters; we accept 1~2 letters here.
"""

from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer


class KrPassportRecognizer(PatternRecognizer):
    """KR passport number recognizer (structural match)."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krpass_letter_8",
            regex=r"(?<![A-Za-z0-9])[MSROTPDG]\d{8}(?![A-Za-z0-9])",
            score=0.8,
        ),
        Pattern(
            name="krpass_2letter_7",
            regex=r"(?<![A-Za-z0-9])[A-Z]{2}\d{7}(?![A-Za-z0-9])",
            score=0.6,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["여권", "여권번호", "passport"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_PASSPORT",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )
