# SYNTHETIC DATA - NOT REAL PII
"""KR_RRN 인식기의 경계 / 변형 / 외국인 코드 회귀 방지.

기본 검증 (단순 숫자 13자리 / 하이픈 / 체크섬) 은 `test_kr_rrn_recognizer.py`
가 담당. 본 모듈은 다음 영역을 보강한다:

  - gender/century code 1~4 모두 검출 (1900년대 남/여 + 2000년대 남/여)
  - gender code 5~8 (외국인 등록 코드) — 현재 인식기 규칙으로는 미검출,
    즉 외국인등록번호는 별도 entity 로 처리되어야 함을 회귀 가드
  - 잘못된 생년월일 (13월, 02/30, 00/00 등) → 검출 안 됨
  - 분리자 변형 (`.`, ` `, 비표준) → 미검출 (오탐 방지)
  - 좌우 경계 (앞뒤 숫자에 붙어 있는 경우 미검출)
  - 컨텍스트 부스트 (`주민` 등 키워드 부착 시 score 상승)
"""

from __future__ import annotations

import pytest
from presidio_analyzer import AnalyzerEngine

from app.core.analyzer import build_analyzer
from app.core.checksum import rrn_checksum
from app.core.policies import map_detection_to_code


@pytest.fixture(scope="module")
def analyzer() -> AnalyzerEngine:
    return build_analyzer()


def _hits(analyzer: AnalyzerEngine, text: str) -> list:
    return [r for r in analyzer.analyze(text=text, language="ko", entities=["KR_RRN"])]


def _build_rrn(yymmdd: str, gender: int, individual5: str) -> str:
    """헬퍼 — 6자리 날짜 + gender + 5자리 개인 + 체크섬 13자리 RRN 생성."""
    first_twelve = f"{yymmdd}{gender}{individual5}"
    check = rrn_checksum(first_twelve)
    return f"{yymmdd}-{gender}{individual5}{check}"


# ── gender/century code 1~4 매칭 ──────────────────────────────────────────
@pytest.mark.parametrize(
    ("year_yy", "gender"),
    [
        ("85", 1),  # 1985 남성
        ("85", 2),  # 1985 여성
        ("05", 3),  # 2005 남성
        ("05", 4),  # 2005 여성
    ],
)
def test_gender_codes_1_to_4_all_detected(
    analyzer: AnalyzerEngine, year_yy: str, gender: int
) -> None:
    """gender 1~4 (1900/2000년대 내국인 4가지) 모두 BLOCK 으로 매핑."""
    yymmdd = f"{year_yy}0101"
    rrn = _build_rrn(yymmdd, gender, "12345")
    text = f"주민등록번호 {rrn} 입니다."

    hits = _hits(analyzer, text)
    assert hits, f"gender={gender} RRN 미검출: {rrn}"
    top = max(hits, key=lambda r: r.score)
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2001", f"gender={gender} → {code} (score={top.score:.2f})"


# ── gender code 5~8 (외국인) — 현재 인식기로는 미검출 ────────────────────
@pytest.mark.parametrize("gender", [5, 6, 7, 8])
def test_foreigner_gender_codes_not_matched_by_kr_rrn(
    analyzer: AnalyzerEngine, gender: int
) -> None:
    """외국인 등록번호 (gender 5~8) 는 KR_RRN regex 에 매칭되면 안 된다.

    현재 패턴이 `[1-4]` 로 제한되어 있어 외국인 코드는 별도 entity (KR_FOREIGN_REG
    등) 가 담당해야 한다. 이 invariant 가 깨지면 외국인등록번호가 잘못된
    응답 코드로 매핑된다.
    """
    yymmdd = "850101"
    rrn_candidate = f"{yymmdd}-{gender}123456"
    text = f"외국인등록번호 {rrn_candidate}"
    hits = _hits(analyzer, text)
    assert not hits, f"gender={gender} 가 KR_RRN 으로 잘못 매칭됨: {hits}"


# ── 잘못된 생년월일 — 검출 안 됨 ──────────────────────────────────────────
@pytest.mark.parametrize(
    "yymmdd",
    [
        "851301",  # 13월
        "850230",  # 2월 30일
        "850000",  # 0월 0일
        "850100",  # 1월 0일
        "990229",  # 1999 윤년 아님
    ],
)
def test_invalid_dates_dropped_by_validate_result(
    analyzer: AnalyzerEngine, yymmdd: str
) -> None:
    """체크섬은 통과해도 날짜가 비유효하면 validate_result 가 False 반환 → drop.

    Phase 1c — `validate_result` 가 `False` 를 돌려주면 Presidio 가 결과를 제거.
    오탐 방지의 핵심 — 형식만 맞는 13자리 숫자가 RRN 으로 흘러가지 않아야 한다.
    """
    rrn = _build_rrn(yymmdd, 1, "12345")
    text = f"주민등록번호 {rrn}"
    hits = _hits(analyzer, text)
    assert not hits, f"invalid date {yymmdd} 가 검출됨: {hits}"


def test_leap_year_feb_29_valid(analyzer: AnalyzerEngine) -> None:
    """2000년 윤년 2/29 는 유효 날짜로 검출되어야 한다."""
    rrn = _build_rrn("000229", 3, "12345")  # 2000-02-29, 남성
    text = f"주민등록번호 {rrn}"
    hits = _hits(analyzer, text)
    assert hits, f"윤년 2000-02-29 미검출: {rrn}"


# ── 분리자 변형 — 표준 (없음/하이픈) 외에는 미검출 ───────────────────────
@pytest.mark.parametrize(
    "separator",
    [".", " ", "_", "/"],
)
def test_non_hyphen_separators_not_matched(
    analyzer: AnalyzerEngine, separator: str
) -> None:
    """`.`, 공백, `_`, `/` 등 비표준 분리자는 KR_RRN regex 에 매칭되지 않는다.

    표준 형식 (하이픈 / 분리자 없음) 만 인식해 오탐을 차단 — 임의 6+7 숫자가
    공백으로 분리되어 있어도 RRN 으로 인식하면 안 됨.
    """
    yymmdd = "850101"
    rrn_candidate = f"{yymmdd}{separator}1123456"
    text = f"주민등록번호 {rrn_candidate}"
    hits = _hits(analyzer, text)
    assert not hits, f"비표준 분리자 '{separator}' 가 매칭됨: {hits}"


# ── 좌우 경계 — 앞뒤에 숫자 붙어 있으면 미검출 ──────────────────────────
def test_left_boundary_digit_prevents_match(analyzer: AnalyzerEngine) -> None:
    """앞에 숫자가 붙어 있으면 RRN 으로 인식되면 안 된다.

    `9` + RRN 14자리 (총 14 digits) 가 RRN 으로 인식되면 transaction id /
    카드번호 같은 일반 숫자열을 false-positive 로 분류하는 사고가 발생.
    """
    rrn = _build_rrn("850101", 1, "12345")
    text = f"코드 9{rrn} 참조"  # 앞에 9 가 붙어 있음
    hits = _hits(analyzer, text)
    assert not hits, f"앞 숫자 boundary 위반: {hits}"


def test_right_boundary_digit_prevents_match(analyzer: AnalyzerEngine) -> None:
    """뒤에 숫자가 붙어 있어도 RRN 으로 인식되면 안 된다."""
    rrn = _build_rrn("850101", 1, "12345")
    text = f"코드 {rrn}9 참조"
    hits = _hits(analyzer, text)
    assert not hits, f"뒤 숫자 boundary 위반: {hits}"


# ── 컨텍스트 부스트 — `주민` 키워드 근접 시 score 상승 ─────────────────
def test_context_word_boosts_score(analyzer: AnalyzerEngine) -> None:
    """컨텍스트 키워드 (`주민` / `주민번호` / `RRN`) 가 가까이 있으면 score 상승.

    Presidio 의 컨텍스트 부스트가 작동해 동일 RRN 이라도 키워드 없을 때와
    있을 때 점수 차이가 발생해야 한다 (인식기 신뢰도 시그널).
    """
    rrn = _build_rrn("850101", 1, "12345")

    text_no_ctx = f"코드 {rrn} 참조"
    text_with_ctx = f"주민등록번호 {rrn} 확인 부탁드립니다."

    hits_no = _hits(analyzer, text_no_ctx)
    hits_yes = _hits(analyzer, text_with_ctx)

    assert hits_no and hits_yes
    top_no = max(hits_no, key=lambda r: r.score).score
    top_yes = max(hits_yes, key=lambda r: r.score).score
    # 둘 다 BLOCK 임계 (0.78) 통과하지만 컨텍스트 있는 쪽이 같거나 높아야 함
    assert top_yes >= top_no, f"context boost 실패: no={top_no:.2f}, with={top_yes:.2f}"


# ── 1900/2000 boundary — yy=99 vs yy=00 ─────────────────────────────────
def test_century_boundary_yy_99_with_gender_1(analyzer: AnalyzerEngine) -> None:
    """gender=1 + yy=99 → 1999 (1900년대 마지막) 정상 검출."""
    rrn = _build_rrn("990101", 1, "12345")  # 1999-01-01 남성
    hits = _hits(analyzer, f"주민등록번호 {rrn}")
    assert hits, f"1999년 RRN 미검출: {rrn}"


def test_century_boundary_yy_00_with_gender_3(analyzer: AnalyzerEngine) -> None:
    """gender=3 + yy=00 → 2000 (2000년대 시작) 정상 검출."""
    rrn = _build_rrn("000101", 3, "12345")  # 2000-01-01 남성
    hits = _hits(analyzer, f"주민등록번호 {rrn}")
    assert hits, f"2000년 RRN 미검출: {rrn}"
