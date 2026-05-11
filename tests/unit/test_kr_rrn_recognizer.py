# SYNTHETIC DATA - NOT REAL PII
"""Coverage for KR_RRN recognizer — hyphenless 13-digit inputs.

`KrRrnRecognizer` 는 ``YYMMDD-CXXXXXC`` 의 하이픈 / 비-하이픈 두 가지 형태를
모두 검출한다. 본 모듈은 게시판 본문에 자주 등장하는
**구분자 없는 13자리 정수** (예: ``9001011234567``) 가 정확히 RRN 으로
인식되고, Presidio 의 ``validate_result`` 가 체크섬·생년월일까지 통과시켜
BLOCK 등급으로 승격하는지 핀(pin) 한다.

오탐 방지 — 체크섬이 잘못된 임의의 13자리 숫자는 ``validate_result`` 에서
``False`` 를 받아 결과 리스트에서 삭제돼야 한다.
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine

from app.core.analyzer import build_analyzer
from app.core.policies import map_detection_to_code
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator


@pytest.fixture(scope="module")
def analyzer() -> AnalyzerEngine:
    return build_analyzer()


def _rrn_top_score(analyzer: AnalyzerEngine, text: str) -> float | None:
    results = analyzer.analyze(text=text, language="ko", entities=["KR_RRN"])
    if not results:
        return None
    return max(r.score for r in results)


# ── 단순 숫자 13자리 — 구분자 없는 RRN ─────────────────────────────────────
# 게시판 본문은 ``9001011234567`` 처럼 하이픈 없이 들어오는 경우가 흔하다.
# `krrrn_plain` 패턴 (score 0.5) 으로 1차 매칭 후 ``validate_result`` 가
# 체크섬을 통과시키면 Presidio 가 score 를 1.0 으로 승격 → BLOCK.
def test_plain_13digit_valid_rrn_is_detected(analyzer: AnalyzerEngine) -> None:
    """체크섬 유효한 13자리 plain RRN — 검출 + 점수 ≥ 0.5."""
    g = SyntheticPIIGenerator(seed=11)
    rrn_plain = g.gen_rrn(valid=True).replace("-", "")
    assert len(rrn_plain) == 13 and rrn_plain.isdigit(), rrn_plain

    score = _rrn_top_score(analyzer, rrn_plain)
    assert score is not None, f"plain 13-digit RRN 미검출: {rrn_plain}"
    assert score >= 0.5, f"unexpectedly low score {score:.2f}"


def test_plain_13digit_valid_rrn_blocks_at_medium(analyzer: AnalyzerEngine) -> None:
    """체크섬 + 생년월일 유효 → medium strictness 에서 BLOCK-2001."""
    g = SyntheticPIIGenerator(seed=13)
    rrn_plain = g.gen_rrn(valid=True).replace("-", "")
    text = f"본인 확인을 위해 {rrn_plain} 입력합니다."

    score = _rrn_top_score(analyzer, text)
    assert score is not None, f"plain 13-digit RRN 미검출 (with context): {rrn_plain}"
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2001", f"expected BLOCK-2001; got {code} (score={score:.2f})"


def test_plain_13digit_invalid_checksum_is_dropped(analyzer: AnalyzerEngine) -> None:
    """체크섬이 깨진 13자리는 ``validate_result`` 가 제거해야 한다.

    오탐 방지 — ``9001011234567`` 형태가 우연히 들어왔어도 체크섬을
    통과하지 않으면 KR_RRN 결과에 포함되지 않는다.
    """
    g = SyntheticPIIGenerator(seed=17)
    bad_rrn = g.gen_rrn(valid=False).replace("-", "")
    assert len(bad_rrn) == 13 and bad_rrn.isdigit(), bad_rrn

    results = analyzer.analyze(text=bad_rrn, language="ko", entities=["KR_RRN"])
    assert not any(r.entity_type == "KR_RRN" for r in results), (
        f"invalid-checksum RRN false positive: {bad_rrn} → {results}"
    )


def test_plain_13digit_random_digits_not_rrn(analyzer: AnalyzerEngine) -> None:
    """``1234567890123`` — 7번째 자리가 [1-4] 범위가 아니면 패턴 자체에
    매칭되지 않아야 한다 (gender/century code 가 5~8 외국인 코드 영역도
    아니므로)."""
    text = "주문번호 1234567890123 입니다."
    results = analyzer.analyze(text=text, language="ko", entities=["KR_RRN"])
    assert not any(r.entity_type == "KR_RRN" for r in results), (
        f"random 13-digit false positive: {results}"
    )
