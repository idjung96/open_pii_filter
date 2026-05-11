# SYNTHETIC DATA - NOT REAL PII
"""확장된 KR_PHONE 인식기 회귀 방지.

Phase 9X 에서 KrPhoneRecognizer 가 010 모바일 4-format 만 보던 좁은
범위를 넘어 다음 영역까지 확장됐다:

- 모바일 prefix 6종 (010 / 011 / 016 / 017 / 018 / 019)
- 유선 (서울 02 / 031~033, 041~044, 051~055, 061~064)
- 인터넷·특수 (070, 080, 050X)
- 지역번호 없는 표기 (`1234-5678` / `123-4567`) — 컨텍스트 부스트 시 BLOCK
- 단순 숫자 11자리 (`01012345678`) / 10자리 (`0212345678`)

각 테스트는 strictness 별 임계값 동작을 핀(pin) 해 regex 가 좁아지거나
컨텍스트 부스트가 깨질 때 즉시 CI 가 잡아낸다.
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine

from app.core.analyzer import build_analyzer
from app.core.policies import map_detection_to_code


@pytest.fixture(scope="module")
def analyzer() -> AnalyzerEngine:
    return build_analyzer()


def _phone_top_score(analyzer: AnalyzerEngine, text: str) -> float | None:
    """텍스트에서 KR_PHONE 검출 결과 중 최고 점수만 추출 (없으면 `None`).

    여러 패턴이 동시에 매칭될 수 있어 가장 강한 신호만 보면 충분하다.
    """
    results = analyzer.analyze(text=text, language="ko", entities=["KR_PHONE"])
    if not results:
        return None
    return max(r.score for r in results)


# ── 모바일 prefix 6종 (010/011/016/017/018/019) 하이픈 표기 ──────────────
@pytest.mark.parametrize("prefix", ["010", "011", "016", "017", "018", "019"])
def test_mobile_prefix_with_hyphen_blocks_at_medium(analyzer: AnalyzerEngine, prefix: str) -> None:
    """`01X-0000-1234` 형태가 모든 모바일 prefix 에서 medium 임계 통과해야 한다.

    score 0.85 의 `krphone_hyphen` 패턴 — 컨텍스트 보조 없이도 임계 (0.78) 위.
    한 prefix 라도 점수가 떨어지면 즉시 회귀.
    """
    text = f"연락처는 {prefix}-0000-1234 입니다."
    score = _phone_top_score(analyzer, text)
    assert score is not None, f"missed phone with prefix {prefix}"
    assert score >= 0.78, f"score {score:.2f} below medium threshold for {prefix}"


# ── 유선전화 지역번호 (서울 02 / 031~064) ────────────────────────────────
@pytest.mark.parametrize(
    "phone",
    [
        "02-1234-5678",  # Seoul (3-digit local)
        "02-123-4567",  # Seoul (3-digit local, short)
        "031-123-4567",  # Gyeonggi
        "032-1234-5678",  # Incheon (4-digit local)
        "041-123-4567",
        "051-1234-5678",
        "053-123-4567",
        "061-123-4567",
        "064-123-4567",
    ],
)
def test_landline_with_hyphen_detected(analyzer: AnalyzerEngine, phone: str) -> None:
    """서울 (02) 부터 제주 (064) 까지 9가지 유선 번호가 KR_PHONE 으로 검출.

    하이픈 표기의 유선 번호는 모바일과 동일한 score 0.85 — 점수 검증보다는
    `is not None` 확인만으로 충분. 새 지역번호 추가 시 패턴 누락이 즉시 적발.
    """
    text = f"문의는 {phone} 로 부탁드립니다."
    score = _phone_top_score(analyzer, text)
    assert score is not None, f"missed landline {phone}"


# ── 070 (인터넷전화) / 080 (수신자부담) / 050X (가상번호) ───────────────
@pytest.mark.parametrize(
    "phone",
    [
        "070-1234-5678",  # 인터넷전화
        "080-123-4567",  # 수신자부담
        "0505-123-4567",  # 가상/포워딩
    ],
)
def test_internet_special_prefixes_detected(analyzer: AnalyzerEngine, phone: str) -> None:
    """특수 prefix (070/080/050X) 도 KR_PHONE 으로 검출되어야 한다.

    공공기관 고객센터·콜백 번호로 흔히 쓰이므로 검출 누락 시 운영 PII
    검사가 무력화된다.
    """
    text = f"고객센터 {phone}"
    score = _phone_top_score(analyzer, text)
    assert score is not None, f"missed special-prefix {phone}"


# ── 국제 표기 (+82) 모든 모바일 prefix 변형 ──────────────────────────────
@pytest.mark.parametrize(
    "phone",
    [
        "+82-10-1234-5678",
        "+82 11 1234 5678",
        "+82-19-123-4567",
    ],
)
def test_international_mobile_detected(analyzer: AnalyzerEngine, phone: str) -> None:
    """해외 발신 표기 (+82 + 모바일 prefix 의 첫 0 생략) 도 정확히 매칭.

    `+82-10-…` (010), `+82 11 …` (011), `+82-19-…` (019) 세 변형이 모두
    잡혀야 외국에서 한국 번호로 호출되는 케이스가 새지 않는다.
    """
    text = f"From abroad: {phone}"
    score = _phone_top_score(analyzer, text)
    assert score is not None, f"missed international {phone}"


# ── Bare format (지역번호 없음) — context boost lifts past medium ─────────
def test_bare_phone_with_phone_context_blocks_at_medium(
    analyzer: AnalyzerEngine,
) -> None:
    """`전화 1234-5678 로 연락` — 컨텍스트 부스트로 medium 임계 통과.

    base score 0.45 의 `krphone_bare_hyphen` 패턴은 단독으로는 임계 미만
    이지만, Presidio 의 컨텍스트 부스트 (`전화/연락` 등 키워드 근접) 가
    +0.35 가량을 더해 medium BLOCK 임계 (0.78) 를 넘어야 한다.
    """
    text = "전화 1234-5678 로 연락 부탁드립니다."
    score = _phone_top_score(analyzer, text)
    assert score is not None, "missed bare phone with strong context"
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099", f"expected BLOCK; got {code} (score={score:.2f})"


def test_bare_phone_three_four_pattern_detected(analyzer: AnalyzerEngine) -> None:
    """`내선 123-4567` — 구버전 7자리 (3-4) 표기도 컨텍스트와 함께 검출.

    내선 번호 / 옛 시외전화 표기 (`123-4567`) 도 컨텍스트가 있으면 잡혀야
    한다 (전화번호 형식의 다양성 커버리지).
    """
    text = "내선 123-4567 로 호출"
    score = _phone_top_score(analyzer, text)
    assert score is not None, "missed bare 7-digit phone with context"


def test_bare_phone_without_context_passes_at_medium(
    analyzer: AnalyzerEngine,
) -> None:
    """컨텍스트 없는 `1234-5678` 형 숫자는 BLOCK 아니라 PASS — 오탐 방지.

    `주문번호 1234-5678` 처럼 일반 번호와 우연히 형태가 겹치는 케이스에서
    전화번호로 오인하면 정상 게시물이 차단된다. base score 0.45 만으로는
    medium 임계 (0.78) 를 못 넘게 설계되어 있는지 확인.
    """
    text = "주문번호 1234-5678 처리 완료"
    score = _phone_top_score(analyzer, text) or 0.0
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "OK-0000", f"unexpected BLOCK on order id; score={score:.2f}"


# ── 부정 케이스 — 실제 KR prefix 가 아닌 임의 숫자열 ─────────────────────
def test_random_digit_string_not_phone(analyzer: AnalyzerEngine) -> None:
    """`030-1234567` — KR 에 실재하지 않는 prefix 는 KR_PHONE 으로 분류 안 됨.

    030/040/090 처럼 한국에 존재하지 않는 prefix 를 우연히 전화번호로
    잡으면 일반 코드/식별자가 차단되는 오탐 사고가 된다.
    """
    text = "코드 030-1234567 참조"
    results = analyzer.analyze(text=text, language="ko", entities=["KR_PHONE"])
    assert not any(r.entity_type == "KR_PHONE" for r in results), f"030 false-positive: {results}"


# ── 단순 숫자 11자리 — 구분자 없는 휴대폰 ──────────────────────────────────
# 사용자 입력은 흔히 ``01012345678`` 처럼 하이픈/공백 없이 들어온다.
# ``krphone_plain`` 패턴 (score 0.7) 으로 검출되고, 컨텍스트 없이는 PASS,
# 컨텍스트 (전화/연락/휴대폰) 가 붙으면 BLOCK 으로 올라가야 한다.
def test_plain_11digit_mobile_is_detected_as_phone(analyzer: AnalyzerEngine) -> None:
    """``01012345678`` — 11자리 숫자 그대로도 KR_PHONE 으로 인식되는가."""
    text = "01012345678"
    score = _phone_top_score(analyzer, text)
    assert score is not None, "11자리 모바일 plain 패턴 미검출"


def test_plain_11digit_mobile_with_context_blocks(analyzer: AnalyzerEngine) -> None:
    """``전화 01012345678`` — 컨텍스트 부스트로 medium BLOCK 임계 통과."""
    text = "전화 01012345678 으로 연락주세요."
    score = _phone_top_score(analyzer, text)
    assert score is not None
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099", f"expected BLOCK; got {code} (score={score:.2f})"


@pytest.mark.parametrize(
    "prefix",
    ["010", "011", "016", "017", "018", "019"],
)
def test_plain_11digit_all_mobile_prefixes_detected(analyzer: AnalyzerEngine, prefix: str) -> None:
    """``01X + 8자리`` — 모든 모바일 prefix 가 plain 형태로 검출되는가."""
    text = f"{prefix}12345678"
    score = _phone_top_score(analyzer, text)
    assert score is not None, f"plain 11-digit mobile {prefix} missed"


# ── 단순 숫자 10자리 — 구분자 없는 유선전화 ───────────────────────────────
# 서울 ``02 + 8자리 = 10자리`` 가 가장 흔한 케이스. 그 외 지역번호 (031~064)
# 가 3자리이므로 보통 11자리가 되지만, ``02`` 만 10자리 시나리오가 존재한다.
def test_plain_10digit_seoul_landline_is_detected_as_phone(
    analyzer: AnalyzerEngine,
) -> None:
    """``0212345678`` — 서울 02 + 8자리 = 10자리 가 KR_PHONE 으로 인식되는가."""
    text = "0212345678"
    score = _phone_top_score(analyzer, text)
    assert score is not None, "10자리 서울 유선 plain 패턴 미검출"


def test_plain_10digit_seoul_landline_with_context_blocks(
    analyzer: AnalyzerEngine,
) -> None:
    """``사무실 0212345678`` — 컨텍스트 부스트로 medium BLOCK 통과."""
    text = "사무실 0212345678 로 전화 주세요."
    score = _phone_top_score(analyzer, text)
    assert score is not None
    code = map_detection_to_code(
        entity_type="KR_PHONE",
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2099", f"expected BLOCK; got {code} (score={score:.2f})"
