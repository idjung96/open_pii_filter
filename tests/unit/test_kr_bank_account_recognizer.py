# SYNTHETIC DATA - NOT REAL PII
"""KR_BANK_ACCOUNT 인식기 회귀 방지.

두 종류의 인식기가 협력:
  - **Strong** (`KrBankAccountStrongRecognizer`, score 0.85) — 한국 주요 은행
    분기별 hyphen 형식 3종 (3-2-4-3 / 3-3-6 / 3-4-4-2). 컨텍스트 없이도 BLOCK.
  - **Weak** (`KrBankAccountWeakRecognizer`, score 0.5) — 분리자 없는 10~14자리
    숫자열 + 은행 컨텍스트 키워드. score 부족 → medium 임계 (0.78) 미만 → PASS.
    high strictness 에서는 더 강한 PASS.

검사 영역:
  - strong 패턴 3종이 모두 BLOCK 진입
  - weak 패턴은 컨텍스트 부스트 시 score 상승, 미부스트 시 PASS
  - 은행명 키워드 (`신한`, `국민`, `농협`, `우리`) 컨텍스트
  - 좌우 boundary
  - high strictness 에서 weak 패턴이 PASS 로 떨어짐 (오탐 방지)
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
    return [
        r
        for r in analyzer.analyze(text=text, language="ko")
        if r.entity_type in ("KR_BANK_ACCOUNT", "KR_BANK_ACCOUNT_WEAK")
    ]


def _entity_hits(analyzer: AnalyzerEngine, text: str, *, entity_type: str) -> list:
    return analyzer.analyze(text=text, language="ko", entities=[entity_type])


# ── Strong 패턴 3종 → BLOCK ──────────────────────────────────────────────
@pytest.mark.parametrize(
    ("account", "expected_pattern"),
    [
        ("123-45-6789-012", "3_2_4_3"),
        ("123-456-789012", "3_3_6"),
        ("123-4567-8901-23", "3_4_4_2"),
    ],
)
def test_strong_hyphen_patterns_block_at_medium(
    analyzer: AnalyzerEngine, account: str, expected_pattern: str
) -> None:
    """3 종 strong hyphen 패턴이 컨텍스트 없이도 BLOCK 진입 (score 0.85).

    expected_pattern 은 어떤 분기가 매칭됐는지 회귀 디버깅 단서.
    """
    text = f"계좌번호 {account} 입니다."
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT")
    assert hits, f"미검출 ({expected_pattern}): {account}"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_BANK_ACCOUNT",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2006", f"{account} → {code} (score={top.score:.2f})"


# ── Weak 패턴 — 컨텍스트 있을 때만 의미 있는 score ──────────────────────
def test_weak_pattern_with_bank_context(analyzer: AnalyzerEngine) -> None:
    """은행 키워드 (`신한` / `국민` / `농협` / `우리`) 컨텍스트 시 weak 패턴 매칭."""
    text = "신한 12345678901234"  # 14자리 + 은행명
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT_WEAK")
    assert hits, f"은행 컨텍스트 weak 미검출: {text}"


def test_weak_pattern_without_context_passes_at_medium(
    analyzer: AnalyzerEngine,
) -> None:
    """컨텍스트 없는 weak 10~14자리는 medium PASS — 오탐 방지.

    일반 10~14자리 숫자열 (전화번호 / 카드번호 일부 / 식별자) 이 우연히
    weak 패턴에 잡혀도 score 부족으로 사용자 응답은 PASS 가 되어야 한다.
    """
    text = "참조 12345678901234"
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT_WEAK")
    if hits:
        top = max(hits, key=lambda r: r.score)
        code = map_detection_to_code(
            entity_type="KR_BANK_ACCOUNT_WEAK",
            score=top.score,
            field="post.body",
            strictness="medium",
        )
        assert code == "OK-0000", f"컨텍스트 없는 weak BLOCK: {code}"


def test_weak_pattern_pass_at_high_strictness(analyzer: AnalyzerEngine) -> None:
    """high strictness 에서는 weak 패턴이 컨텍스트 있어도 PASS.

    오탐 우선 차단 정책 — 강한 신호 (`KR_BANK_ACCOUNT` strong) 가 아니면
    high 등급에서 BLOCK 으로 만들지 않는다.
    """
    text = "신한 12345678901234"
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT_WEAK")
    if hits:
        top = max(hits, key=lambda r: r.score)
        code = map_detection_to_code(
            entity_type="KR_BANK_ACCOUNT_WEAK",
            score=top.score,
            field="post.body",
            strictness="high",
        )
        assert code == "OK-0000", f"high strictness 에서 weak BLOCK: {code}"


# ── 은행 키워드 별 컨텍스트 ───────────────────────────────────────────
@pytest.mark.parametrize("bank", ["신한", "국민", "농협", "우리", "은행", "계좌", "입금", "송금"])
def test_each_bank_context_keyword_boosts(analyzer: AnalyzerEngine, bank: str) -> None:
    """등록된 은행/금융 컨텍스트 키워드 8종 각각이 부스트 신호로 작동."""
    text = f"{bank} 계좌 123-45-6789-012"
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT")
    assert hits, f"{bank} 컨텍스트에서 매칭 실패"


# ── 좌우 boundary ─────────────────────────────────────────────────────────
def test_left_boundary_digit_prevents_strong_match(analyzer: AnalyzerEngine) -> None:
    """앞에 숫자가 더 붙으면 strong 패턴이 매칭되지 않는다."""
    text = "코드 9123-45-6789-012"
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT")
    assert not hits, f"앞 숫자 boundary 위반: {hits}"


def test_right_boundary_digit_prevents_strong_match(analyzer: AnalyzerEngine) -> None:
    """뒤에 숫자가 더 붙으면 strong 패턴이 매칭되지 않는다."""
    text = "코드 123-45-6789-0129 참조"
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT")
    assert not hits, f"뒤 숫자 boundary 위반: {hits}"


# ── 본문 내 여러 계좌 동시 검출 ──────────────────────────────────────────
def test_multiple_accounts_in_one_body(analyzer: AnalyzerEngine) -> None:
    """본문 안에 2개 계좌가 들어가 있으면 둘 다 검출."""
    a = "123-45-6789-012"
    b = "456-789-012345"
    text = f"본인 신한 {a}, 배우자 국민 {b}"
    hits = _entity_hits(analyzer, text, entity_type="KR_BANK_ACCOUNT")
    substrings = {text[h.start : h.end] for h in hits}
    assert a in substrings, f"첫 계좌 누락: {hits}"
    assert b in substrings, f"둘째 계좌 누락: {hits}"
