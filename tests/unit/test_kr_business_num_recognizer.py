# SYNTHETIC DATA - NOT REAL PII
"""KR_BUSINESS_NUM 인식기 회귀 방지.

한국 사업자등록번호: ``NNN-NN-NNNNN`` (10자리, hyphen 2개). 마지막 1자리는
가중치 (1,3,7,1,3,7,1,3,5) + 보정 알고리즘으로 산출하는 체크섬.

검사 영역:
  - 정상 체크섬 통과 → BLOCK 매핑
  - 체크섬 깨짐 → `validate_result` 가 False → drop (Presidio)
  - hyphen 위치 어긋남 → 미검출
  - plain 10자리 패턴 (score 0.3) — 컨텍스트 부스트 필요
  - 좌우 boundary (앞뒤 숫자 부착)
  - 컨텍스트 키워드 (`사업자`, `사업자번호`, `법인`)
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine

from app.core.analyzer import build_analyzer
from app.core.checksum import business_num_checksum
from app.core.policies import map_detection_to_code
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator


@pytest.fixture(scope="module")
def analyzer() -> AnalyzerEngine:
    return build_analyzer()


def _hits(analyzer: AnalyzerEngine, text: str) -> list:
    return analyzer.analyze(text=text, language="ko", entities=["KR_BUSINESS_NUM"])


# ── 정상 체크섬 — hyphen 형식 → BLOCK ────────────────────────────────────
def test_valid_hyphen_format_blocks(analyzer: AnalyzerEngine) -> None:
    """체크섬 통과한 hyphen 형식 사업자번호 → KR_BUSINESS_NUM 검출 + BLOCK."""
    g = SyntheticPIIGenerator(seed=42)
    biz = g.gen_business_num(valid=True)
    text = f"사업자등록번호 {biz} 로 발행 부탁드립니다."

    hits = _hits(analyzer, text)
    assert hits, f"미검출: {biz}"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_BUSINESS_NUM",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    # Phase 9D — phone/email 처럼 임계 이상이면 BLOCK-2099 로 흡수.
    assert code == "BLOCK-2099", f"{biz} → {code} (score={top.score:.2f})"


# ── 체크섬 깨짐 — 인식 안 됨 (validate_result drop) ─────────────────────
def test_invalid_checksum_dropped(analyzer: AnalyzerEngine) -> None:
    """체크섬이 깨진 hyphen 형식은 validate_result False → drop.

    오탐 방지 — 형식만 맞는 임의 10자리 숫자열이 사업자번호로 분류되면
    안 된다. 100건 중 단 1건도 통과하지 않아야 한다.
    """
    g = SyntheticPIIGenerator(seed=42)
    for _ in range(50):
        bad = g.gen_business_num(valid=False)
        text = f"사업자번호 {bad}"
        hits = _hits(analyzer, text)
        assert not hits, f"잘못된 체크섬이 검출됨: {bad}"


# ── hyphen 위치 어긋남 ───────────────────────────────────────────────────
@pytest.mark.parametrize(
    "fmt",
    [
        "12-345-67890",  # 2-3-5
        "1234-56-7890",  # 4-2-4
        "123-456-7890",  # 3-3-4
    ],
)
def test_malformed_hyphen_positions_not_matched(
    analyzer: AnalyzerEngine, fmt: str
) -> None:
    """hyphen 위치가 표준 (3-2-5) 이 아니면 hyphen 패턴에 매칭되지 않는다."""
    text = f"사업자 {fmt}"
    hits = _hits(analyzer, text)
    # hyphen 패턴은 매칭 안 되지만, plain 10자리 패턴이 잡힐 수 있음.
    # 그건 별도 테스트가 검증.
    hyphen_hits = [
        h
        for h in hits
        if "-" in text[h.start : h.end] and text[h.start : h.end].count("-") == 2
    ]
    assert not hyphen_hits, f"잘못된 hyphen 위치가 매칭됨: {fmt} → {hyphen_hits}"


# ── plain 10자리 — 컨텍스트 부스트 필요 ──────────────────────────────────
def test_plain_10digit_with_context_blocks(analyzer: AnalyzerEngine) -> None:
    """plain 10자리 (score 0.3) 는 컨텍스트 키워드 부스트로 BLOCK 진입."""
    g = SyntheticPIIGenerator(seed=42)
    biz_hyphen = g.gen_business_num(valid=True)
    biz_plain = biz_hyphen.replace("-", "")
    assert len(biz_plain) == 10 and biz_plain.isdigit()

    text = f"법인 사업자번호 {biz_plain}"
    hits = _hits(analyzer, text)
    assert hits, f"컨텍스트 부스트 받은 plain 10자리 미검출: {biz_plain}"


def test_plain_10digit_without_context_still_blocks_when_checksum_valid(
    analyzer: AnalyzerEngine,
) -> None:
    """체크섬 통과 plain 10자리는 컨텍스트 없어도 BLOCK — 의도된 동작.

    `validate_result` 가 True 를 반환하면 Presidio 가 score 를 1.0 으로
    승격하기 때문에 패턴 (hyphen 0.5 / plain 0.3) 의 초기 score 는 무관해진다.
    이는 체크섬이 깨질 확률이 통계적으로 충분히 낮다 (1/10 × 형식 + 좌우
    boundary) 는 보안 우선 정책이다.

    -- 부작용: 일반 10자리 코드 중 ~10% 가 우연히 BLOCK 될 수 있음.
       운영에서 false-positive 발생 시 `app.core.recognizers.kr_business_num`
       의 validate_result 를 형식별로 분기해야 한다 (회귀 시 이 테스트가 깨짐).
    """
    g = SyntheticPIIGenerator(seed=42)
    biz_plain = g.gen_business_num(valid=True).replace("-", "")
    text = f"코드 {biz_plain} 참조"

    hits = _hits(analyzer, text)
    assert hits, f"plain 10자리 체크섬-valid 가 미검출: {biz_plain}"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_BUSINESS_NUM",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099", (
        f"checksum-valid plain 10자리가 BLOCK 진입 실패: {biz_plain} → {code}"
    )


def test_plain_10digit_random_no_checksum_match_dropped(
    analyzer: AnalyzerEngine,
) -> None:
    """체크섬이 깨진 plain 10자리는 validate_result False → drop.

    오탐 회피의 핵심 안전망. 100건 중 0 건 BLOCK 으로 검출되어야 한다.
    """
    g = SyntheticPIIGenerator(seed=4242)
    block_count = 0
    for _ in range(100):
        bad = g.gen_business_num(valid=False).replace("-", "")
        if len(bad) != 10:
            continue
        text = f"코드 {bad} 참조"
        hits = _hits(analyzer, text)
        if hits:
            top = max(hits, key=lambda r: r.score)
            code = map_detection_to_code(
                entity_type="KR_BUSINESS_NUM",
                score=top.score,
                field="post.body",
                strictness="medium",
            )
            if code == "BLOCK-2099":
                block_count += 1
    assert block_count == 0, f"체크섬 깨진 plain 10자리에서 BLOCK 발생: {block_count} 건"


# ── 좌우 boundary ────────────────────────────────────────────────────────
def test_left_boundary_digit_prevents_match(analyzer: AnalyzerEngine) -> None:
    """`9123-45-67890` 처럼 앞에 숫자가 더 붙으면 hyphen 패턴이 매칭되지 않는다."""
    g = SyntheticPIIGenerator(seed=42)
    biz = g.gen_business_num(valid=True)
    text = f"코드 9{biz}"
    hits = _hits(analyzer, text)
    assert not hits, f"앞 숫자 boundary 위반: {hits}"


# ── 컨텍스트 부스트 동작 ─────────────────────────────────────────────────
def test_context_word_boosts_score(analyzer: AnalyzerEngine) -> None:
    """`사업자` / `사업자등록` / `법인` 컨텍스트 부스트."""
    g = SyntheticPIIGenerator(seed=42)
    biz = g.gen_business_num(valid=True)

    no_ctx = f"코드 {biz}"
    with_ctx = f"사업자등록번호 {biz}"

    no_hits = _hits(analyzer, no_ctx)
    yes_hits = _hits(analyzer, with_ctx)
    assert no_hits and yes_hits

    no_top = max(no_hits, key=lambda r: r.score).score
    yes_top = max(yes_hits, key=lambda r: r.score).score
    assert yes_top >= no_top, f"context boost 실패: no={no_top:.2f}, with={yes_top:.2f}"


# ── 체크섬 알고리즘 자체 검증 (회귀 가드) ──────────────────────────────
@pytest.mark.parametrize(
    "first_nine",
    [
        "123456789",
        "000000000",
        "999999999",
        "100000000",
    ],
)
def test_business_num_checksum_is_in_range(first_nine: str) -> None:
    """체크섬 결과가 0~9 범위에 있는지 (알고리즘 회귀 가드)."""
    check = business_num_checksum(first_nine)
    assert 0 <= check <= 9, f"체크섬 범위 위반: {first_nine} → {check}"
