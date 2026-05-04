"""KR_BANK_ACCOUNT — Korean bank account number recognizer.

Two recognizers, two strictness bands:
  - Strong: hyphen-separated patterns matching common Korean bank layouts
    (3-2-4-3, 3-3-6, 3-4-4-2). Score 0.85 → BLOCK band at medium strictness.
  - Weak:   bare 10~14 digit run with surrounding banking context. Score 0.5 →
    WARN at medium / suppressed at high.
"""

from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer


class KrBankAccountStrongRecognizer(PatternRecognizer):
    """High-confidence hyphenated Korean bank account formats."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krbank_3_2_4_3",
            regex=r"(?<!\d)\d{3}-\d{2}-\d{4}-\d{3}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krbank_3_3_6",
            regex=r"(?<!\d)\d{3}-\d{3}-\d{6}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krbank_3_4_4_2",
            regex=r"(?<!\d)\d{3}-\d{4}-\d{4}-\d{2}(?!\d)",
            score=0.85,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["계좌", "입금", "송금", "은행", "신한", "국민", "농협", "우리"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_BANK_ACCOUNT",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )


class KrBankAccountWeakRecognizer(PatternRecognizer):
    """Bare 10~14 digit run; only emitted as a weak signal."""

    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            name="krbank_bare_digits",
            regex=r"(?<!\d)\d{10,14}(?!\d)",
            score=0.5,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = ["계좌", "입금", "송금", "은행"]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_BANK_ACCOUNT_WEAK",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )
