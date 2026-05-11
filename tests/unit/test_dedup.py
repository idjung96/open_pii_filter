"""Q2 — span 단위 상위 K개 (`_topk_per_span`) 후필터 회귀 방지.

여러 인식기가 같은 `(start, end)` 구간을 동시에 매칭할 때 응답
`detections` 가 한없이 부풀지 않도록 동일 span 당 score 상위 K개
(`MAX_DETECTIONS_PER_SPAN = 3`) 만 남기는 후필터를 검증한다.

Phase 9E-A 메모: NER (PERSON/LOCATION/ORGANIZATION) 인식기를 분석 엔진
에서 제거하면서 Q5 (NER overlap drop) 도 함께 폐기. 본 모듈은
`_topk_per_span` 검증만 남긴다.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.api.detect import (
    MAX_DETECTIONS_PER_SPAN,
    _topk_per_span,
)


@dataclass
class _R:
    """presidio_analyzer.RecognizerResult 의 필드 형태를 흉내내는 stub.

    실제 Presidio 객체를 import 하지 않고도 `_topk_per_span` 의 정렬·
    그루핑 로직만 빠르게 검증할 수 있게 한다.
    """

    entity_type: str
    start: int
    end: int
    score: float


# ── Q2: 동일 (start, end) span 당 score 상위 3건만 살리기 ─────────────────
def test_q2_topk_caps_at_three_per_exact_span() -> None:
    """완전히 같은 `(4, 18)` span 에 5개가 들어오면 상위 3개만 남는지.

    Score 내림차순으로 정렬되어 `E_HIGH (1.0)`, `E_MID1 (0.9)`,
    `E_MID2 (0.8)` 만 통과하고 `E_LOW1/2` 는 잘려나가야 한다. 응답
    페이로드 비대화를 막는 가장 중요한 가드.
    """
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
    # score 내림차순으로 상위 3개 — 가장 높은 세 개를 반드시 포함.
    assert set(types) == {"E_HIGH", "E_MID1", "E_MID2"}


def test_q2_topk_does_not_merge_distinct_spans() -> None:
    """서로 다른 span 은 각자의 그룹으로 보존되어야 한다.

    `(0, 5)` 와 `(6, 10)` 두 그룹이 들어오면 각자의 top-K 가 따로
    적용되므로 합쳐서 K개로 잘리면 안 된다 (회귀: 전체 리스트를
    그룹과 무관하게 자르면 다른 entity 가 사라지는 사고 발생).
    """
    raw = [
        _R("E1", 0, 5, 0.9),
        _R("E2", 6, 10, 0.9),
        _R("E3", 6, 10, 0.7),
    ]
    out = _topk_per_span(raw)  # type: ignore[arg-type]
    assert len(out) == 3
    # 두 그룹: (0,5) → 1건, (6,10) → 2건. K=3 이므로 모두 살아남는다.
    by_span = {(r.start, r.end) for r in out}
    assert by_span == {(0, 5), (6, 10)}
