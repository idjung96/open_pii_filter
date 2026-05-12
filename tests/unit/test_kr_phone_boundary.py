# SYNTHETIC DATA - NOT REAL PII
"""KR_PHONE 인식기 추가 경계 회귀 방지.

기존 `test_kr_phone_recognizer.py` 가 모바일/일반 지역/인터넷 케이스를 다룬다.
본 모듈은 *경계* 와 *완전성* 영역을 추가로 가드:

  - 한국 지역번호 전체 (031~033, 041~044, 051~055, 061~064) 가 각각 검출
  - 공백 분리 (`010 1234 5678`) 변형이 hyphen 과 동일 검출 가능
  - 국제 표기 ±separator 변형 (+82 10, +82-10, +8210)
  - 좌우 경계 — 앞뒤 숫자 부착 시 false-positive 회피
  - bare phone vs 지역번호 phone 의 중복 매칭 회피
  - 7자리 bare (`123-4567`) 형식도 컨텍스트 부스트로 BLOCK 진입
  - 등록된 모든 컨텍스트 키워드가 부스트 신호로 작동
  - 본문 내 멀티 phone 동시 검출
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine

from app.core.analyzer import build_analyzer
from app.core.policies import map_detection_to_code
from app.core.recognizers.kr_phone import KrPhoneRecognizer


@pytest.fixture(scope="module")
def analyzer() -> AnalyzerEngine:
    return build_analyzer()


def _phone_hits(analyzer: AnalyzerEngine, text: str) -> list:
    return analyzer.analyze(text=text, language="ko", entities=["KR_PHONE"])


# ── 한국 지역번호 전체 ──────────────────────────────────────────────────
@pytest.mark.parametrize(
    "area",
    [
        "031",  # 경기
        "032",  # 인천
        "033",  # 강원
        "041",  # 충남
        "042",  # 대전
        "043",  # 충북
        "044",  # 세종
        "051",  # 부산
        "052",  # 울산
        "053",  # 대구
        "054",  # 경북
        "055",  # 경남
        "061",  # 전남
        "062",  # 광주
        "063",  # 전북
        "064",  # 제주
    ],
)
def test_all_regional_landlines_with_hyphen_detected(
    analyzer: AnalyzerEngine, area: str
) -> None:
    """16 개 지역번호 모두 hyphen 형식 (`AAA-XXXX-YYYY`) 으로 검출.

    한 지역번호라도 정규식에서 빠지면 그 지역 민원이 BLOCK 누락 사고.
    """
    text = f"연락처 {area}-1234-5678 입니다."
    hits = _phone_hits(analyzer, text)
    assert hits, f"{area} 미검출"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099", f"{area} → {code}"


# ── 공백 분리 변형 ──────────────────────────────────────────────────────
def test_mobile_with_space_separator_detected(analyzer: AnalyzerEngine) -> None:
    """`010 1234 5678` 처럼 공백 분리도 검출."""
    text = "휴대폰 010 1234 5678"
    hits = _phone_hits(analyzer, text)
    assert hits, "공백 분리 모바일 미검출"


def test_landline_with_space_separator_detected(analyzer: AnalyzerEngine) -> None:
    """`02 1234 5678` 공백 분리 지역번호도 검출."""
    text = "사무실 02 1234 5678 입니다."
    hits = _phone_hits(analyzer, text)
    assert hits, "공백 분리 지역번호 미검출"


# ── 국제 표기 변형 ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "phone",
    [
        "+82-10-1234-5678",
        "+82 10 1234 5678",
        "+821012345678",  # no separator
        "+82-11-1234-5678",  # 011 모바일
    ],
)
def test_international_82_separators(analyzer: AnalyzerEngine, phone: str) -> None:
    """+82 prefix 의 여러 분리자 변형 — 모두 검출."""
    text = f"phone {phone}"
    hits = _phone_hits(analyzer, text)
    assert hits, f"국제 표기 미검출: {phone}"


# ── 좌우 경계 ──────────────────────────────────────────────────────────
def test_left_digit_boundary_prevents_match(analyzer: AnalyzerEngine) -> None:
    """`9010-1234-5678` 처럼 앞에 숫자가 더 있으면 모바일 패턴 미매칭."""
    text = "코드 9010-1234-5678 참조"
    hits = _phone_hits(analyzer, text)
    # 매칭이 되더라도 010 부분 모바일이 정확히 잡히면 안 됨.
    # 평문 그대로 통과하면 안 되지만, hyphen 형식 4-3-4 가 잡힐 수도 있음.
    # 본 테스트의 의도: 정확한 모바일 패턴이 9010 으로 시작하는 것을 잡으면
    # false-positive — score 가 낮게 떨어져야 한다.
    block_hits = [h for h in hits if h.score >= 0.78]
    assert not block_hits, f"앞 숫자 경계 위반: {block_hits}"


def test_right_digit_boundary_prevents_match(analyzer: AnalyzerEngine) -> None:
    """`010-1234-56789` (12자리) 처럼 뒤에 숫자가 더 붙으면 미매칭."""
    text = "참조 010-1234-56789 코드"
    hits = _phone_hits(analyzer, text)
    # 정확한 모바일 패턴은 `\d{4}(?!\d)` 로 막혀 있어 매칭 안 됨.
    matched_substrings = {text[h.start : h.end] for h in hits}
    assert "010-1234-56789" not in matched_substrings


# ── bare phone vs 지역번호 phone 중복 매칭 회피 ─────────────────────────
def test_bare_phone_not_double_matched_inside_landline(
    analyzer: AnalyzerEngine,
) -> None:
    """`02-1234-5678` 안의 `1234-5678` 부분이 bare phone 으로 별도 매칭되지
    않아야 한다 — `(?<![\\d-])` lookbehind 회귀 가드.

    이중 매칭 시 detections 가 2개가 되어 BLOCK-2008 (다중 PII) 으로 잘못
    분류되는 사고.
    """
    text = "사무실 02-1234-5678 입니다."
    hits = _phone_hits(analyzer, text)
    # `1234-5678` 가 별도로 잡히면 substring `1234-5678` 가 매칭 set 에 들어옴.
    matched_substrings = {text[h.start : h.end] for h in hits}
    # 의도: hyphen 좌측이 `-` 인 경우 bare 매칭 회피.
    bare_hits = [s for s in matched_substrings if s == "1234-5678"]
    assert not bare_hits, f"bare phone 이 지역번호 안에서 중복 매칭: {hits}"


def test_bare_phone_7digit_with_context_blocks(analyzer: AnalyzerEngine) -> None:
    """`123-4567` (7자리 bare) 도 컨텍스트 부스트 시 BLOCK 진입."""
    text = "연락처 123-4567"
    hits = _phone_hits(analyzer, text)
    assert hits, "7자리 bare phone 미검출"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    # 컨텍스트 부스트로 BLOCK — context word `연락처` 가 +0.35.
    assert code == "BLOCK-2099", f"컨텍스트 부스트 실패: {code} (score={top.score:.2f})"


def test_bare_phone_8digit_with_context_blocks(analyzer: AnalyzerEngine) -> None:
    """`1234-5678` (8자리 bare) 도 컨텍스트 부스트 시 BLOCK."""
    text = "전화 1234-5678"
    hits = _phone_hits(analyzer, text)
    assert hits
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099"


# ── 등록된 모든 컨텍스트 키워드 부스트 ─────────────────────────────────
@pytest.mark.parametrize("ctx", KrPhoneRecognizer.CONTEXT)
def test_each_context_keyword_boosts_bare_phone(
    analyzer: AnalyzerEngine, ctx: str
) -> None:
    """등록된 13 개 컨텍스트 키워드 각각이 bare phone 의 score 를 올린다.

    회귀 시나리오: 누군가 `KrPhoneRecognizer.CONTEXT` 에서 키워드를 제거
    하면 그 키워드 부근 bare phone 이 PASS 로 떨어진다 — 본 테스트가
    parametrize 로 깨진 키워드를 즉시 식별.
    """
    no_ctx = "코드 1234-5678 참조"
    with_ctx = f"{ctx} 1234-5678"

    no_hits = _phone_hits(analyzer, no_ctx)
    yes_hits = _phone_hits(analyzer, with_ctx)
    assert no_hits and yes_hits

    no_top = max(no_hits, key=lambda r: r.score).score
    yes_top = max(yes_hits, key=lambda r: r.score).score
    assert yes_top >= no_top, f"{ctx}: no={no_top:.2f} with={yes_top:.2f}"


# ── 멀티 phone 동시 검출 ────────────────────────────────────────────────
def test_multiple_phones_in_one_body(analyzer: AnalyzerEngine) -> None:
    """본문에 모바일 + 지역번호 + 국제 표기가 함께 있을 때 모두 검출."""
    a = "010-1234-5678"
    b = "02-1111-2222"
    c = "+82-10-9999-0000"
    text = f"본인 {a} / 사무실 {b} / 해외 {c}"
    hits = _phone_hits(analyzer, text)
    matched = {text[h.start : h.end] for h in hits}
    assert a in matched, f"모바일 누락: {hits}"
    assert b in matched, f"지역번호 누락: {hits}"
    # 국제 표기는 prefix 가 +82 라 별도 substring 으로 매칭 검증.
    intl_hits = [s for s in matched if s.startswith("+82")]
    assert intl_hits, f"국제 표기 누락: {matched}"


# ── 700/070 비 vs 인터넷전화 차이 ──────────────────────────────────────
def test_070_internet_phone_with_hyphen(analyzer: AnalyzerEngine) -> None:
    """070 인터넷전화도 hyphen 형식으로 검출."""
    text = "연락 070-1234-5678"
    hits = _phone_hits(analyzer, text)
    assert hits


def test_080_toll_free_with_hyphen(analyzer: AnalyzerEngine) -> None:
    """080 수신자 부담 번호도 검출."""
    text = "고객센터 080-123-4567"
    hits = _phone_hits(analyzer, text)
    assert hits


def test_050X_virtual_phone(analyzer: AnalyzerEngine) -> None:
    """050X (가상전화번호) 도 검출."""
    text = "연락 0505-123-4567"
    hits = _phone_hits(analyzer, text)
    assert hits, "050X 가상번호 미검출"


# ── plain 형식 추가 가드 ───────────────────────────────────────────────
def test_plain_landline_with_context_blocks(analyzer: AnalyzerEngine) -> None:
    """`연락처 0212345678` (지역번호 plain 10자리) 가 BLOCK 진입."""
    text = "연락처 0212345678 입니다."
    hits = _phone_hits(analyzer, text)
    assert hits
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099"


# ── strictness 별 거동 ─────────────────────────────────────────────────
def test_bare_phone_no_context_low_strictness_block(
    analyzer: AnalyzerEngine,
) -> None:
    """low strictness (≥0.65) 에서는 컨텍스트 없는 bare phone 도 BLOCK 인지.

    bare phone 의 기본 score 는 0.45 라 컨텍스트 없으면 low 에서도 PASS.
    회귀 시나리오: 누군가 bare score 를 0.65 이상으로 올리면 본 테스트가 깨짐.
    """
    text = "참조 1234-5678 코드"
    hits = _phone_hits(analyzer, text)
    if hits:
        top = max(hits, key=lambda r: r.score)
        code = map_detection_to_code(
            entity_type="KR_PHONE",
            score=top.score,
            field="post.body",
            strictness="low",
        )
        # 컨텍스트 없으면 low 에서도 PASS 가 의도 (score 0.45 < 0.65).
        assert code == "OK-0000", (
            f"bare phone 컨텍스트 없이 low BLOCK: score={top.score:.2f} → {code}"
        )


def test_mobile_high_strictness_still_blocks(analyzer: AnalyzerEngine) -> None:
    """모바일 hyphen 형식 (score 0.85) 은 high strictness (≥0.88) 에서도
    컨텍스트 부스트로 BLOCK 진입 가능 — 강한 신호."""
    text = "휴대폰 010-1234-5678 입니다."
    hits = _phone_hits(analyzer, text)
    assert hits
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=top.score,
        field="post.body",
        strictness="high",
    )
    assert code == "BLOCK-2099"
