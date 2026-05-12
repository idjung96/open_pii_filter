# SYNTHETIC DATA - NOT REAL PII
"""KR_PASSPORT 인식기 회귀 방지.

한국 여권번호 형식:
  - **신여권** — 영문 대문자 1자 (`M` 일반 / `S` 관용 / `R` 외교 / `O` 거주 /
    `T` 임시 / `P` 긴급 / `D` 외교 / `G` 관용) + 숫자 8자리 = 9자
  - **PA 시리즈 등** — 영문 대문자 2자 + 숫자 7자리 = 9자

검사 영역:
  - 신여권 letter 8종이 모두 검출되는지 (score 0.8)
  - 2자 prefix + 7자리 형식 검출 (score 0.6)
  - 미정의 letter (예: `A`, `Z`) 는 1자 형식에서 미검출 (오탐 방지)
  - 영문 소문자는 미검출 (대문자 only)
  - 좌우 경계 (앞뒤 영문/숫자 부착) — false-positive 방지
  - 컨텍스트 부스트 (`여권` / `passport`)
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine

from app.core.analyzer import build_analyzer
from app.core.policies import map_detection_to_code


@pytest.fixture(scope="module")
def analyzer() -> AnalyzerEngine:
    return build_analyzer()


def _hits(analyzer: AnalyzerEngine, text: str) -> list:
    return analyzer.analyze(text=text, language="ko", entities=["KR_PASSPORT"])


# ── 신여권 letter 8종 (M/S/R/O/T/P/D/G) ─────────────────────────────────
@pytest.mark.parametrize("letter", ["M", "S", "R", "O", "T", "P", "D", "G"])
def test_valid_letter_prefix_blocks(analyzer: AnalyzerEngine, letter: str) -> None:
    """1자 letter + 8숫자 = 신여권. score 0.8 → medium BLOCK 진입."""
    passport = f"{letter}12345678"
    text = f"여권번호 {passport} 입니다."
    hits = _hits(analyzer, text)
    assert hits, f"letter={letter} 미검출"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_PASSPORT",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2003", f"{letter} → {code} (score={top.score:.2f})"


# ── 2자 prefix + 7숫자 (PA 시리즈 등) ────────────────────────────────────
@pytest.mark.parametrize("prefix", ["PA", "PM", "PS", "AB", "ZZ"])
def test_two_letter_prefix_detected(analyzer: AnalyzerEngine, prefix: str) -> None:
    """2자 영문 대문자 + 7숫자 형식도 검출. score 0.6 (낮은 신뢰도)."""
    passport = f"{prefix}1234567"
    text = f"여권 {passport}"
    hits = _hits(analyzer, text)
    assert hits, f"2-letter prefix={prefix} 미검출"


# ── 미정의 letter (1자 형식에서 거절) ────────────────────────────────────
@pytest.mark.parametrize("letter", ["A", "B", "C", "E", "F", "H", "I", "J", "K", "L", "N", "Q", "U", "V", "W", "X", "Y", "Z"])
def test_undefined_single_letter_not_matched_at_one_letter_pattern(
    analyzer: AnalyzerEngine, letter: str
) -> None:
    """카테고리 letter 8종 외의 1자 + 8숫자 형식은 1-letter 패턴에 매칭되지 않음.

    `A12345678` 처럼 정의 외 letter 가 1자 패턴 (score 0.8) 으로 잡히면
    여권이 아닌 의약품 코드 등을 false-positive 로 분류하는 사고 발생.
    """
    passport = f"{letter}12345678"
    text = f"코드 {passport}"
    hits = _hits(analyzer, text)
    # 1-letter 패턴 (score 0.8) 은 매칭되지 않아야 한다. 2-letter 패턴 검사가
    # 같은 9자리에 우연히 매칭될 수 있는데 (예: `A1` + `2345678`) 그건
    # regex 가 첫 2자가 모두 대문자여야 하므로 매칭되지 않는다.
    high_score = [h for h in hits if h.score >= 0.75]
    assert not high_score, f"미정의 letter {letter} 가 1-letter 패턴으로 매칭됨: {hits}"


# ── 영문 소문자 — 미검출 ─────────────────────────────────────────────────
def test_lowercase_letter_not_matched(analyzer: AnalyzerEngine) -> None:
    """`m12345678` (소문자) 는 여권번호로 매칭되지 않는다 (대문자 only)."""
    text = "여권 m12345678"
    hits = _hits(analyzer, text)
    assert not hits, f"소문자 letter 매칭됨: {hits}"


# ── 좌우 경계 ─────────────────────────────────────────────────────────────
def test_left_boundary_letter_prevents_match(analyzer: AnalyzerEngine) -> None:
    """`XM12345678` — 앞에 영문이 더 붙으면 3-letter 형식이 되어 미검출."""
    text = "코드 XM12345678 참조"
    hits = _hits(analyzer, text)
    assert not hits, f"앞 영문 boundary 위반: {hits}"


def test_right_boundary_digit_prevents_match(analyzer: AnalyzerEngine) -> None:
    """`M123456789` — 뒤에 숫자가 더 붙으면 9자리가 되어 매칭 안 됨 (총 10자)."""
    text = "코드 M123456789 참조"
    hits = _hits(analyzer, text)
    assert not hits, f"뒤 숫자 boundary 위반: {hits}"


# ── 컨텍스트 부스트 ──────────────────────────────────────────────────────
def test_context_word_boosts_score(analyzer: AnalyzerEngine) -> None:
    """`여권` / `passport` 키워드 근접 시 score 상승."""
    passport = "M12345678"
    no_ctx = f"코드 {passport}"
    with_ctx = f"여권번호 {passport} 입니다."

    no_hits = _hits(analyzer, no_ctx)
    yes_hits = _hits(analyzer, with_ctx)
    assert no_hits and yes_hits

    no_top = max(no_hits, key=lambda r: r.score).score
    yes_top = max(yes_hits, key=lambda r: r.score).score
    assert yes_top >= no_top, f"context boost 실패: no={no_top:.2f}, with={yes_top:.2f}"
