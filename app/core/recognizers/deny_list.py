"""Deny-list recognizer fed from `pii_deny_list` rows (T2.6).

Builds one Presidio recognizer per entity_type that performs exact match
against a fixed list of values (employee names, sensitive aliases, etc.).
The recognizer is regex-based: it joins the values with `|` after escaping
each one, with word-ish boundaries that work for Hangul.

Why per entity_type:
  - Different entity types have different scores and downstream codes.
  - Building one giant recognizer would hide the entity type and force
    a single score for everything.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from presidio_analyzer import Pattern, PatternRecognizer

if TYPE_CHECKING:
    from app.db.models import PiiDenyList


# Right boundary excludes the Hangul block intentionally so a deny-listed
# name can still match when followed by a Korean particle ("원효대사" in
# "원효대사와"). The trade-off is accepting limited false positives like
# "홍길동" matching inside "홍길동전" — acceptable for an explicit deny list.
_NON_WORD_LEFT = r"(?<![A-Za-z0-9가-힣])"
_NON_WORD_RIGHT = r"(?![A-Za-z0-9])"


def _build_alternation(values: Iterable[str]) -> str:
    """Escape each value and join with | wrapped in non-word boundaries."""
    escaped = sorted({re.escape(v) for v in values if v})
    if not escaped:
        return ""
    return _NON_WORD_LEFT + "(?:" + "|".join(escaped) + ")" + _NON_WORD_RIGHT


def build_deny_list_recognizers(
    rows: list[PiiDenyList],
) -> list[PatternRecognizer]:
    """Group rows by entity_type and emit one PatternRecognizer per group.

    Each row contributes its `value` to the alternation. The recognizer's
    score is the *max* score among the group's rows — a single high-score
    deny entry should not be diluted by lower-score peers in the same
    entity_type.
    """
    by_entity: dict[str, list[PiiDenyList]] = {}
    for r in rows:
        by_entity.setdefault(r.entity_type, []).append(r)

    out: list[PatternRecognizer] = []
    for entity_type, group in by_entity.items():
        regex = _build_alternation(g.value for g in group)
        if not regex:
            continue
        score = max(g.score for g in group)
        pattern = Pattern(
            name=f"deny::{entity_type}",
            regex=regex,
            score=score,
        )
        out.append(
            PatternRecognizer(
                supported_entity=entity_type,
                patterns=[pattern],
                supported_language="ko",
                name=f"deny_list::{entity_type}",
            )
        )
    return out
