"""KR_PHONE — Korean phone number recognizer.

Covers:

  * **Mobile** — 010 / 011 / 016 / 017 / 018 / 019 series.
  * **Landline** — Seoul ``02`` plus the regional prefixes
    031~033, 041~044, 051~055, 061~064.
  * **Internet & special** — 070 (인터넷전화), 080 (수신자 부담),
    050X 가상전화번호.
  * **International** — ``+82`` prefix variants of the mobile patterns.
  * **Bare format** — ``1234-5678`` / ``123-4567`` (지역번호 없는 표기).
    Scored low (0.45) so it only crosses the BLOCK threshold when a
    phone-context word (전화 / 연락 / 휴대폰 / phone / tel / …) is
    nearby. This is the "no area code, but still a phone format"
    case that 게시판 본문에 자주 나온다.

The mobile-only suite is preserved verbatim (krphone_hyphen / _space /
_plain / _intl) so existing test fixtures and policy mappings keep
working; landline / internet / bare patterns are additive.
"""

from __future__ import annotations

from typing import ClassVar

from presidio_analyzer import Pattern, PatternRecognizer

# Mobile prefix alternation — keeps fixed-width regex backreferences cheap.
_MOBILE = r"01[016789]"

# Korean landline + internet/special area codes, in a single alternation.
# Listed longest-first so the regex engine does not partially match a
# shorter prefix (e.g. ``050`` accidentally swallowing ``0505``).
_LANDLINE = (
    r"050\d|070|080|"  # internet phone, toll-free, virtual
    r"02|"  # Seoul
    r"03[1-3]|04[1-4]|05[1-5]|06[1-4]"  # regional landline
)


class KrPhoneRecognizer(PatternRecognizer):
    """KR phone (mobile + landline + internet) recognizer."""

    PATTERNS: ClassVar[list[Pattern]] = [
        # ── Mobile (legacy 4 patterns kept for fixture compatibility) ──
        Pattern(
            name="krphone_hyphen",
            regex=rf"(?<!\d)({_MOBILE})-\d{{3,4}}-\d{{4}}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krphone_space",
            regex=rf"(?<!\d)({_MOBILE})\s\d{{3,4}}\s\d{{4}}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krphone_plain",
            regex=rf"(?<!\d)({_MOBILE})\d{{7,8}}(?!\d)",
            score=0.7,
        ),
        # International ``+82`` strips the leading ``0`` from the mobile
        # prefix, so ``+82 10 …`` ⇄ ``010``, ``+82 11 …`` ⇄ ``011``, etc.
        Pattern(
            name="krphone_intl",
            regex=r"\+82[-\s]?1[016789][-\s]?\d{3,4}[-\s]?\d{4}",
            score=0.85,
        ),
        # ── Landline / internet / 050X with hyphen or space separators ──
        # Hyphen / space is the canonical visual cue for these numbers,
        # so we score them at the same 0.85 the mobile-hyphen pattern uses.
        Pattern(
            name="krphone_landline_hyphen",
            regex=rf"(?<!\d)({_LANDLINE})-\d{{3,4}}-\d{{4}}(?!\d)",
            score=0.85,
        ),
        Pattern(
            name="krphone_landline_space",
            regex=rf"(?<!\d)({_LANDLINE})\s\d{{3,4}}\s\d{{4}}(?!\d)",
            score=0.8,
        ),
        # Plain (no separators) — 9 to 11 digits depending on prefix.
        # Score lower than hyphen/space because `0212345678` is easy to
        # confuse with arbitrary digit strings; rely on context boost.
        Pattern(
            name="krphone_landline_plain",
            regex=rf"(?<!\d)({_LANDLINE})\d{{7,8}}(?!\d)",
            score=0.6,
        ),
        # ── Bare phone (지역번호 없음) ────────────────────────────────
        # 7 or 8 digits formatted as ``123-4567`` / ``1234-5678``. The
        # negative lookbehind ``(?<![\d-])`` ensures we don't double
        # match the second half of an area-coded number like
        # ``02-1234-5678``. Score 0.45 keeps this PASS by default at
        # medium strictness; Presidio's context boost (≈+0.35 when a
        # phone-context word is nearby) lifts it past 0.78 → BLOCK.
        Pattern(
            name="krphone_bare_hyphen",
            regex=r"(?<![\d-])\d{3,4}-\d{4}(?!\d)",
            score=0.45,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "전화",
        "전화번호",
        "연락",
        "연락처",
        "휴대폰",
        "핸드폰",
        "내선",
        "사무실",
        "팩스",
        "phone",
        "tel",
        "mobile",
        "fax",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KR_PHONE",
            patterns=list(self.PATTERNS),
            context=list(self.CONTEXT),
            supported_language="ko",
        )
