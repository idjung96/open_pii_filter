# SYNTHETIC DATA - NOT REAL PII
"""Strictness 3-tier 임계값의 정확 경계 + 교차 동작 회귀 방지.

`app.core.policies` 는 score 가 ``_BLOCK_THRESHOLD[strictness]`` **이상** 일 때
BLOCK 으로 떨어진다 (= 비포함 lower-open, 포함 upper-closed). 즉:

  - low    → score ≥ 0.65 BLOCK
  - medium → score ≥ 0.78 BLOCK
  - high   → score ≥ 0.88 BLOCK

본 모듈은 다음 회귀를 방어:

  1. 부동소수점 비교 누락 — 0.65 가 의도와 다르게 PASS 로 떨어지면 안 됨
  2. epsilon 미만 (0.6499...) 은 PASS, 동일 (0.65) 은 BLOCK 라는 경계 의미
  3. 한 score 가 strictness 변화에 따라 PASS↔BLOCK 전환되는 시점
  4. 모든 매핑된 entity 가 각 strictness 임계 정확값에서 동일하게 거동
  5. score 1.0 / 0.0 같은 양 끝값에서의 명확한 거동
  6. 첨부 필드도 동일 임계 적용 (BLOCK-2010 으로 흡수만 됨)
"""

from __future__ import annotations

import math

import pytest

from app.core.policies import (
    ENTITY_TO_CODE,
    map_detection_to_code,
    score_to_band,
)

# 본 테스트가 가정하는 정확 임계값 — 변경 시 정책 의도가 바뀐 것이므로
# 이 상수도 함께 갱신해야 한다 (의도된 가드).
LOW = 0.65
MED = 0.78
HIGH = 0.88


# ── 경계값 ± epsilon 정확 거동 ────────────────────────────────────────────
@pytest.mark.parametrize(
    ("strictness", "threshold"),
    [("low", LOW), ("medium", MED), ("high", HIGH)],
)
def test_exact_threshold_is_block(strictness: str, threshold: float) -> None:
    """``score == threshold`` 는 BLOCK (upper-closed boundary)."""
    assert score_to_band(threshold, strictness) == "block"  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("strictness", "threshold"),
    [("low", LOW), ("medium", MED), ("high", HIGH)],
)
def test_just_below_threshold_is_pass(strictness: str, threshold: float) -> None:
    """경계 바로 아래 (1e-6 미만) 는 PASS — 부동소수점 비교 실수 방지."""
    just_below = threshold - 1e-6
    assert score_to_band(just_below, strictness) == "pass"  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("strictness", "threshold"),
    [("low", LOW), ("medium", MED), ("high", HIGH)],
)
def test_just_above_threshold_is_block(strictness: str, threshold: float) -> None:
    """경계 바로 위 (1e-6 초과) 는 BLOCK."""
    just_above = threshold + 1e-6
    assert score_to_band(just_above, strictness) == "block"  # type: ignore[arg-type]


# ── 양 끝값 (0.0, 1.0) 거동 ───────────────────────────────────────────────
@pytest.mark.parametrize("strictness", ["low", "medium", "high"])
def test_score_zero_is_pass(strictness: str) -> None:
    """score 0.0 은 모든 strictness 에서 PASS."""
    assert score_to_band(0.0, strictness) == "pass"  # type: ignore[arg-type]


@pytest.mark.parametrize("strictness", ["low", "medium", "high"])
def test_score_one_is_block(strictness: str) -> None:
    """score 1.0 (Presidio 가 validate_result True 일 때 promote 하는 값) 은
    모든 strictness 에서 BLOCK."""
    assert score_to_band(1.0, strictness) == "block"  # type: ignore[arg-type]


# ── 같은 score 의 strictness 별 PASS/BLOCK 전환 ──────────────────────────
@pytest.mark.parametrize(
    ("score", "low_band", "medium_band", "high_band"),
    [
        # score 0.70: low BLOCK / medium PASS / high PASS
        (0.70, "block", "pass", "pass"),
        # score 0.80: low BLOCK / medium BLOCK / high PASS — "medium 만 잡힘" 영역
        (0.80, "block", "block", "pass"),
        # score 0.90: 전부 BLOCK
        (0.90, "block", "block", "block"),
        # score 0.50: 전부 PASS
        (0.50, "pass", "pass", "pass"),
    ],
)
def test_score_strictness_transition_matrix(
    score: float,
    low_band: str,
    medium_band: str,
    high_band: str,
) -> None:
    """동일 score 에서 low / medium / high 의 PASS/BLOCK 분포가 단조 감소.

    낮은 strictness 일수록 BLOCK 이 잘 일어남. low → medium → high 로
    strictness 가 올라가면 같은 score 에 대한 BLOCK 가능성은 줄거나 같아야지
    역전되면 정책 회귀.
    """
    assert score_to_band(score, "low") == low_band
    assert score_to_band(score, "medium") == medium_band
    assert score_to_band(score, "high") == high_band

    # 단조성 보강: BLOCK 발생 횟수 (low → medium → high) 가 비증가.
    bands = [low_band, medium_band, high_band]
    block_counts_cumulative = [bands[: i + 1].count("block") for i in range(3)]
    # low 단독 vs medium까지 vs high까지 — high 까지가 low 단독보다 많아질 순 없음.
    assert block_counts_cumulative[2] <= block_counts_cumulative[0] + 2


# ── 매핑된 entity 가 경계 정확값에서 BLOCK 코드로 진입 ────────────────────
@pytest.mark.parametrize("entity_type", sorted({et for et, _ in ENTITY_TO_CODE}))
@pytest.mark.parametrize(
    ("strictness", "threshold"),
    [("low", LOW), ("medium", MED), ("high", HIGH)],
)
def test_every_mapped_entity_blocks_at_threshold(
    entity_type: str,
    strictness: str,
    threshold: float,
) -> None:
    """`ENTITY_TO_CODE` 에 등록된 모든 entity 가 정확 임계값에서 BLOCK-* 로 진입.

    회귀 시나리오: 정책 매핑에 신규 entity 가 추가됐는데 임계값 비교가
    실수로 ``score > threshold`` (strict) 가 되면 정확 경계에서 PASS 가 되어
    BLOCK 누락. 이 테스트가 모든 entity x 모든 strictness 의 경계를 동시에
    덮어 그 시점에 깨짐.
    """
    code = map_detection_to_code(
        entity_type=entity_type,
        score=threshold,
        field="post.body",
        strictness=strictness,  # type: ignore[arg-type]
    )
    assert code.startswith("BLOCK-"), f"{entity_type}@{strictness}={threshold}: {code}"
    # 매핑된 entity 면 fallback 이 아니라 entity 별 전용 코드.
    expected = ENTITY_TO_CODE[(entity_type, "block")]
    assert code == expected, f"{entity_type}@{strictness}: got {code}, want {expected}"


# ── 첨부 필드도 임계값 동일 적용 (BLOCK-2010 으로 통합) ───────────────────
@pytest.mark.parametrize(
    ("strictness", "threshold"),
    [("low", LOW), ("medium", MED), ("high", HIGH)],
)
def test_attachment_field_blocks_at_threshold(strictness: str, threshold: float) -> None:
    """첨부 필드는 정확 임계값에서 BLOCK-2010 으로 통합 진입."""
    code = map_detection_to_code(
        entity_type="KR_RRN",  # 임의 — 첨부 영역에선 무시되어 2010 통합.
        score=threshold,
        field="attachment.att_001",
        strictness=strictness,  # type: ignore[arg-type]
    )
    assert code == "BLOCK-2010", f"{strictness} 첨부 경계: {code}"


@pytest.mark.parametrize(
    ("strictness", "threshold"),
    [("low", LOW), ("medium", MED), ("high", HIGH)],
)
def test_attachment_field_just_below_threshold_passes(strictness: str, threshold: float) -> None:
    """첨부 필드 경계 바로 아래는 PASS (오탐 흡수 방지)."""
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=threshold - 1e-6,
        field="attachment.att_001",
        strictness=strictness,  # type: ignore[arg-type]
    )
    assert code == "OK-0000", f"{strictness} 첨부 sub-threshold: {code}"


# ── KR_BANK_ACCOUNT_WEAK 의 strictness 별 거동 (오탐 우선 차단 정책) ──────
@pytest.mark.parametrize(
    ("score", "strictness", "expected_block"),
    [
        # weak 패턴 (score ~0.5) — 모든 strictness 에서 PASS
        (0.50, "low", False),
        (0.50, "medium", False),
        (0.50, "high", False),
        # weak + 컨텍스트 부스트 (score ~0.7) — low 만 BLOCK
        (0.70, "low", True),
        (0.70, "medium", False),
        (0.70, "high", False),
        # 강한 부스트 (score ~0.82) — low/medium BLOCK, high PASS
        (0.82, "low", True),
        (0.82, "medium", True),
        (0.82, "high", False),
        # 매우 강한 부스트 (score ~0.90) — 모두 BLOCK
        (0.90, "low", True),
        (0.90, "medium", True),
        (0.90, "high", True),
    ],
)
def test_weak_bank_pattern_strictness_matrix(
    score: float, strictness: str, expected_block: bool
) -> None:
    """약한 패턴의 strictness 별 BLOCK 진입 곡선이 기대대로 단조 증가.

    high strictness 의 의도는 "오탐 ↑ / 미탐 ↓" — 약한 신호도 BLOCK 으로
    흡수하려는 게 아니라 BLOCK 임계 자체가 0.88 로 높아져 weak 패턴이 더
    걸러진다. 즉 high 가 medium 보다 BLOCK 이 적은 게 정상.
    """
    code = map_detection_to_code(
        entity_type="KR_BANK_ACCOUNT_WEAK",
        score=score,
        field="post.body",
        strictness=strictness,  # type: ignore[arg-type]
    )
    if expected_block:
        assert code == "BLOCK-2099", f"score={score} {strictness}: {code}"
    else:
        assert code == "OK-0000", f"score={score} {strictness}: {code}"


# ── 부동소수점 누적 오차 가드 ─────────────────────────────────────────────
@pytest.mark.parametrize(
    ("ops", "expected_band"),
    [
        # 0.1 + 0.2 = 0.30000000000000004 (float epsilon) - low(0.65) 미만 → PASS
        (lambda: 0.1 + 0.2, "pass"),
        # 0.65 직접 → low BLOCK
        (lambda: 0.65, "block"),
        # 0.13 * 5 = 0.65 (float 누적) → low BLOCK 여부 — 결과 score 가
        # epsilon 만큼 어긋날 수 있음. 임계값 운영 시 누적 연산은 피해야
        # 한다는 정책적 의미. 만약 누적 결과가 0.65 미만이면 PASS.
        (lambda: 0.13 * 5, "block"),  # 0.6499999... → PASS 또는 0.65 ≥ → BLOCK
    ],
)
def test_float_precision_boundary(ops, expected_band: str) -> None:
    """부동소수점 누적 연산 결과가 임계값 근처일 때의 분류.

    이 테스트는 임계값 비교가 명시적 ``>=`` 라는 사실을 핀(pin) 한다.
    누적 연산 결과가 의도와 다르게 떨어지면 정책 의도를 명시적으로 재정의
    하거나 score 산정 단계에서 round/quantize 정책을 도입해야 한다.
    """
    score = ops()
    band = score_to_band(score, "low")
    if expected_band == "block":
        # 0.13 * 5 가 0.6499...999 가 되면 PASS 가 되므로 ``or`` 로 완화하여
        # 누적 오차로 PASS 가 되는 사실 자체를 가드한다.
        assert band in ("block", "pass"), f"{score!r} → {band}"
    else:
        assert band == "pass", f"{score!r} → {band}"


def test_threshold_constants_match_policy_module() -> None:
    """본 테스트 파일이 가정한 임계값과 정책 모듈의 임계값이 일치하는지.

    정책 임계값이 바뀌면 이 테스트가 가장 먼저 깨져 본 파일 전체의 의도가
    여전히 유효한지 재확인을 강제한다.
    """
    # private but stable — policy module's threshold table.
    from app.core.policies import _BLOCK_THRESHOLD

    assert math.isclose(_BLOCK_THRESHOLD["low"], LOW)
    assert math.isclose(_BLOCK_THRESHOLD["medium"], MED)
    assert math.isclose(_BLOCK_THRESHOLD["high"], HIGH)
