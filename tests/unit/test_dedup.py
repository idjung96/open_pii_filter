"""Q2 (top-3 per span) — analyzer post-filter.

Phase 9E-A — NER (PERSON/LOCATION/ORGANIZATION) 인식기를 분석 엔진에서
제거하면서 Q5 (NER overlap drop) 도 함께 폐기. 본 모듈은 _topk_per_span
검증만 남긴다.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.api.detect import (
    MAX_DETECTIONS_PER_SPAN,
    _topk_per_span,
)


@dataclass
class _R:
    """Stub mimicking presidio_analyzer.RecognizerResult shape."""

    entity_type: str
    start: int
    end: int
    score: float


# ── Q2: only top-3 per exact (start, end) span ────────────────────────────
def test_q2_topk_caps_at_three_per_exact_span() -> None:
    raw = [
        _R("E_HIGH", 4, 18, 1.0),
        _R("E_MID1", 4, 18, 0.9),
        _R("E_MID2", 4, 18, 0.8),
        _R("E_LOW1", 4, 18, 0.5),
        _R("E_LOW2", 4, 18, 0.3),
    ]
    out = _topk_per_span(raw)  # type: ignore[arg-type]
    assert len(out) == MAX_DETECTIONS_PER_SPAN == 3
    types = [r.entity_type for r in out]
    # Sorted by score desc — top 3 must include the three highest.
    assert set(types) == {"E_HIGH", "E_MID1", "E_MID2"}


def test_q2_topk_does_not_merge_distinct_spans() -> None:
    raw = [
        _R("E1", 0, 5, 0.9),
        _R("E2", 6, 10, 0.9),
        _R("E3", 6, 10, 0.7),
    ]
    out = _topk_per_span(raw)  # type: ignore[arg-type]
    assert len(out) == 3
    # Two groups: (0,5) → 1 hit, (6,10) → 2 hits both kept (k=3).
    by_span = {(r.start, r.end) for r in out}
    assert by_span == {(0, 5), (6, 10)}
