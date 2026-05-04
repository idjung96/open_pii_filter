"""KR_DRIVERLICENSE — Korean driver license number recognizer.

Format: RR-YY-NNNNNN-CC where:
  - RR: 2-digit region code (11~28 nominally, validated softly)
  - YY: 2-digit issuance year
  - NNNNNN: 6-digit serial
  - CC: 2-digit verification

Phase 1 only validates structure; Phase 5 may add region table check.
"""

from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer


class KrDriverLicenseRecognizer(PatternRecognizer):
    """KR driver license recognizer (structural match)."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krdl_hyphen",
            regex=r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)",
            score=0.8,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["운전면허", "면허번호", "면허"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_DRIVERLICENSE",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )
