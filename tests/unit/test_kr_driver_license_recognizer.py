# SYNTHETIC DATA - NOT REAL PII
"""KR_DRIVERLICENSE 인식기 회귀 방지.

운전면허번호는 ``RR-YY-NNNNNN-CC`` (지역 2 + 연도 2 + 일련 6 + 검증 2 = 12자리)
구조의 hyphen-separated 형식만 인식한다. 검사 영역:

  - 정상 형식이 BLOCK 으로 매핑되는지 (score 0.8 → medium/high 임계 통과)
  - hyphen 위치가 어긋난 변형은 미검출 (예: `11-22-3333-334455`)
  - 분리자 없는 12자리 plain 숫자열은 현재 미검출 (다른 인식기와 혼동 회피)
  - 좌우 경계 (앞뒤 숫자) — false-positive 방지
  - 컨텍스트 부스트 (`운전면허` / `면허번호`) 동작
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
    return analyzer.analyze(text=text, language="ko", entities=["KR_DRIVERLICENSE"])


# ── 정상 형식 ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "license_num",
    [
        "11-23-123456-78",  # 서울
        "12-05-098765-43",
        "21-15-555555-22",  # 부산
        "28-99-999999-11",  # 지역 28 (가장 큰 보통 코드)
    ],
)
def test_valid_hyphen_format_blocks(analyzer: AnalyzerEngine, license_num: str) -> None:
    """`RR-YY-NNNNNN-CC` 형식이 KR_DRIVERLICENSE 로 검출 + medium BLOCK 진입."""
    text = f"운전면허번호 {license_num} 입니다."
    hits = _hits(analyzer, text)
    assert hits, f"미검출: {license_num}"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_DRIVERLICENSE",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2002", f"{license_num} → {code} (score={top.score:.2f})"


# ── hyphen 위치 어긋남 — 매칭 안 됨 ──────────────────────────────────────
@pytest.mark.parametrize(
    "license_num",
    [
        "1-23-123456-78",  # 지역 1자리
        "11-2-123456-78",  # 연도 1자리
        "11-23-12345-78",  # 일련 5자리
        "11-23-1234567-78",  # 일련 7자리
        "11-23-123456-7",  # 검증 1자리
        "1123-12345678",  # hyphen 통째로 누락
    ],
)
def test_malformed_hyphens_not_matched(analyzer: AnalyzerEngine, license_num: str) -> None:
    """hyphen 위치가 어긋난 변형은 false-positive 가 되면 안 된다."""
    text = f"운전면허 {license_num}"
    hits = _hits(analyzer, text)
    assert not hits, f"잘못된 형식 매칭됨: {license_num} → {hits}"


# ── plain 12자리 — 분리자 없는 형태는 현재 미검출 ───────────────────────
def test_plain_12digits_not_matched(analyzer: AnalyzerEngine) -> None:
    """분리자 없는 12자리 숫자열은 KR_DRIVERLICENSE 로 분류되지 않는다.

    카드번호 / 전화 / 코드 등과 충돌 회피를 위한 의도된 동작 — 운전면허는
    실제 게시 시 hyphen 형식으로 적히는 경우가 압도적이라는 운영 결정.
    """
    text = "코드 112312345678 참조"
    hits = _hits(analyzer, text)
    assert not hits, f"plain 12자리가 운전면허로 매칭됨: {hits}"


# ── 좌우 경계 ────────────────────────────────────────────────────────────
def test_left_boundary_digit_prevents_match(analyzer: AnalyzerEngine) -> None:
    """앞에 숫자가 붙어 있으면 미검출 (15자리 코드가 면허로 오분류되지 않게)."""
    text = "참조 9 11-23-123456-78"  # 앞 공백 있음 — 매칭되어야 함
    hits = _hits(analyzer, text)
    assert hits, f"공백 boundary 정상 매칭 실패: {hits}"

    text2 = "참조 911-23-123456-78"  # 앞 숫자에 붙음
    hits2 = _hits(analyzer, text2)
    assert not hits2, f"앞 숫자 boundary 위반: {hits2}"


# ── 컨텍스트 부스트 ──────────────────────────────────────────────────────
def test_context_word_boosts_score(analyzer: AnalyzerEngine) -> None:
    """`운전면허` / `면허번호` / `면허` 컨텍스트 키워드 근접 시 score 상승."""
    license_num = "11-23-123456-78"
    no_ctx = f"코드 {license_num}"
    with_ctx = f"운전면허번호 {license_num} 확인 부탁드립니다."

    no_hits = _hits(analyzer, no_ctx)
    yes_hits = _hits(analyzer, with_ctx)
    assert no_hits and yes_hits

    no_top = max(no_hits, key=lambda r: r.score).score
    yes_top = max(yes_hits, key=lambda r: r.score).score
    assert yes_top >= no_top, f"컨텍스트 부스트 실패: no={no_top:.2f}, with={yes_top:.2f}"


# ── 본문 내 여러 면허번호 동시 검출 ─────────────────────────────────────
def test_multiple_licenses_in_one_body(analyzer: AnalyzerEngine) -> None:
    """본문에 면허번호 2개가 들어있으면 둘 다 검출되어야 한다."""
    a = "11-23-123456-78"
    b = "21-15-987654-22"
    text = f"본인 면허 {a}, 배우자 면허 {b} 입니다."
    hits = _hits(analyzer, text)
    matched_substrings = {text[h.start : h.end] for h in hits}
    assert a in matched_substrings, f"첫 면허 누락: {hits}"
    assert b in matched_substrings, f"둘째 면허 누락: {hits}"
