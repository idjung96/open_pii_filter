"""Phase 1c — Presidio AnalyzerEngine + 커스텀 KR 인식기 통합 회귀 방지 (T1.1~T1.10).

실제 `app.core.analyzer.build_analyzer` 가 만든 AnalyzerEngine 을 그대로
사용한다 — `tests/conftest.py` 의 session-scoped `analyzer` fixture 가
spaCy `ko_core_news_lg` 모델을 단 한 번만 로드해 모든 케이스에 공유한다.

각 테스트는 합성 PII 를 본문에 심고 ① 검출 여부 ② 점수 ③ 정책 매핑 (코드)
세 가지를 함께 검증한다. 분석기 + 정책 어느 한쪽이 망가져도 여기서
잡힌다.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from app.core.policies import map_detection_to_code
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine, RecognizerResult


def _entities(results: list[RecognizerResult]) -> set[str]:
    return {r.entity_type for r in results}


# ── T1.1: 유효한 RRN → KR_RRN 검출 + 체크섬 통과 → BLOCK-2001 ────────────
def test_t1_1_valid_rrn_blocks(analyzer: AnalyzerEngine) -> None:
    """체크섬·생년월일이 모두 유효한 합성 RRN 이 본문에 들어왔을 때:

      1. KR_RRN 으로 검출됨
      2. 점수가 ≥ 0.90 (Presidio 가 `validate_result` 성공 시 1.0 으로 승격)
      3. 정책 매핑이 `BLOCK-2001` (RRN 전용 코드) 로 떨어짐

    세 단계가 모두 살아 있어야 운영에서 RRN 차단이 작동한다.
    """
    g = SyntheticPIIGenerator(seed=11)
    rrn = g.gen_rrn(valid=True)
    text = f"본인의 주민등록번호는 {rrn} 입니다. 확인 부탁드립니다."

    results = analyzer.analyze(text=text, language="ko", entities=["KR_RRN"])
    assert results, f"no KR_RRN detected in: {text}"

    top = max(results, key=lambda r: r.score)
    assert top.entity_type == "KR_RRN"
    assert top.score >= 0.90, f"valid RRN should score ≥0.90, got {top.score}"

    code = map_detection_to_code(
        entity_type=top.entity_type,
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    assert code == "BLOCK-2001"


# ── T1.2: 체크섬 깨진 RRN → 검출되지 않거나 BLOCK 임계 미만 ─────────────
def test_t1_2_invalid_rrn_dropped(analyzer: AnalyzerEngine) -> None:
    """체크섬을 깬 13자리 숫자는 BLOCK 으로 분류되면 안 된다 (오탐 방지).

    `validate_result` 가 `False` 를 반환하면 Presidio 가 결과를 제거하거나
    점수를 임계 아래로 내려야 한다. medium strictness 에서 어떤 KR_RRN
    결과도 `BLOCK-2001` 로 매핑되지 않아야 한다.
    """
    g = SyntheticPIIGenerator(seed=13)
    bad_rrn = g.gen_rrn(valid=False)
    text = f"문의드립니다. 주민번호 {bad_rrn} 확인 부탁드립니다."

    results = analyzer.analyze(text=text, language="ko", entities=["KR_RRN"])
    # Either no result, or a downgraded score that maps to OK-0000 at medium.
    for r in results:
        if r.entity_type != "KR_RRN":
            continue
        code = map_detection_to_code(
            entity_type="KR_RRN", score=r.score, field="post.body", strictness="medium"
        )
        assert code == "OK-0000", (
            f"invalid-checksum RRN should not block; got code={code} score={r.score}"
        )


# ── T1.3 (Phase 9D): 4가지 전화번호 형식 → 임계 이상이면 BLOCK-2099 ─────
def test_t1_3_phone_formats(analyzer: AnalyzerEngine) -> None:
    """모바일 전화번호 4가지 표기 (hyphen/space/plain/+82) 모두 검출되는가.

    Phase 9D 이후 WARN 등급이 폐기되어 phone 도 임계값을 넘으면 BLOCK-2099
    로 흡수된다. 점수가 임계 미만이면 OK-0000 (PASS) — 둘 중 하나여야 하고
    중간 (WARN) 은 더 이상 존재하지 않는다.
    """
    g = SyntheticPIIGenerator(seed=17)
    samples = [
        f"연락처는 {g.gen_phone(format='hyphen')} 입니다.",
        f"연락처는 {g.gen_phone(format='space')} 입니다.",
        f"연락처는 {g.gen_phone(format='plain')} 입니다.",
        f"연락처는 {g.gen_phone(format='international')} 입니다.",
    ]
    for s in samples:
        results = analyzer.analyze(text=s, language="ko", entities=["KR_PHONE"])
        assert any(r.entity_type == "KR_PHONE" for r in results), f"missed: {s}"
        top = max(
            (r for r in results if r.entity_type == "KR_PHONE"),
            key=lambda r: r.score,
        )
        code = map_detection_to_code(
            entity_type="KR_PHONE",
            score=top.score,
            field="post.body",
            strictness="medium",
        )
        # Phase 9D — phone 도 임계값 이상이면 BLOCK 으로 흡수.
        assert code in {"BLOCK-2099", "OK-0000"}


# ── T1.4 (Phase 9D): 이메일 → EMAIL_ADDRESS 검출 → BLOCK 또는 PASS ──────
def test_t1_4_email_warns(analyzer: AnalyzerEngine) -> None:
    """`SYNTH_EMAIL` 형식 이메일이 EMAIL_ADDRESS 로 잡히고 정책 매핑이 정상.

    이메일은 phone 과 마찬가지로 임계 이상이면 BLOCK-2099, 미만이면
    OK-0000. WARN 은 폐기됐으므로 그 외 코드로 가면 회귀.
    """
    g = SyntheticPIIGenerator(seed=19)
    email = g.gen_email()
    text = f"이메일은 {email} 로 회신 부탁드립니다."

    results = analyzer.analyze(text=text, language="ko", entities=["EMAIL_ADDRESS"])
    assert any(r.entity_type == "EMAIL_ADDRESS" for r in results)
    top = next(r for r in results if r.entity_type == "EMAIL_ADDRESS")
    code = map_detection_to_code(
        entity_type="EMAIL_ADDRESS",
        score=top.score,
        field="post.body",
        strictness="medium",
    )
    # Phase 9D — email 도 임계값 이상이면 BLOCK-2099 으로 흡수.
    assert code in {"BLOCK-2099", "OK-0000"}


# ── T1.5: 사업자등록번호 → KR_BUSINESS_NUM 검출 ──────────────────────────
def test_t1_5_business_num(analyzer: AnalyzerEngine) -> None:
    """체크섬이 통과한 합성 사업자번호가 KR_BUSINESS_NUM 으로 검출되는지.

    사업자번호는 10자리 + 마지막 자리 체크섬. 체크섬 알고리즘이 무너지면
    이 단순 케이스부터 미탐이 시작된다.
    """
    g = SyntheticPIIGenerator(seed=23)
    biz = g.gen_business_num(valid=True)
    text = f"사업자등록번호 {biz} 로 세금계산서 발행 부탁드립니다."

    results = analyzer.analyze(text=text, language="ko", entities=["KR_BUSINESS_NUM"])
    assert any(r.entity_type == "KR_BUSINESS_NUM" for r in results), text


# ── T1.6: PII 없는 일반 본문 → 의미 있는 검출 없음 (오탐 방지) ──────────
def test_t1_6_clean_text_passes(analyzer: AnalyzerEngine) -> None:
    """평범한 한국어 문의글에서 임계 (0.5) 이상의 PII 검출이 0 건이어야 한다.

    NER/정규식이 일반 명사·날짜·시간 등을 PII 로 오인하기 쉬워 이 케이스가
    가장 자주 회귀한다. score ≥ 0.50 인 결과만 추리고 빈 리스트인지 확인.
    """
    text = (
        "안녕하세요. 도서관 운영 시간이 어떻게 되는지 문의드립니다. "
        "주말에도 이용할 수 있는지 답변 부탁드립니다. 감사합니다."
    )
    results = analyzer.analyze(text=text, language="ko")
    # Filter out any spurious low-score entities below the medium threshold.
    significant = [r for r in results if r.score >= 0.50]
    assert not significant, f"unexpected detections in clean text: {significant}"


# ── T1.7 (Phase 9E-A): NER 인식기 폐기로 PERSON 검출 케이스 제거 ──────────
# spaCy NER 단독은 일반 게시 컨텐츠에서 오탐 폭증의 원인이 되어 SpacyRecognizer
# 등록을 해제했다. 정규식 + 체크섬 기반 PII 만으로 법적 위험 커버는 충분.


# ── T1.10: 지연시간 예산 — 1 KB 본문 P95 < 500 ms ───────────────────────
def test_t1_10_latency_under_500ms(analyzer: AnalyzerEngine) -> None:
    """1 KB 한국어 본문 분석이 500 ms 이내에 끝나는지.

    LB 뒤에서 동기 호출 (Case A/B) 이 4xx/timeout 으로 떨어지지 않으려면
    분석기 자체가 1 KB 본문을 0.5초 안에 처리해야 한다. 첫 호출은 모델
    워밍업으로 측정에서 제외하고, 이후 5회 중 최대값을 P95 근사치로 사용.
    """
    g = SyntheticPIIGenerator(seed=31)
    sample = g.gen_post_sample(
        entity_types=["KR_RRN", "KR_PHONE", "EMAIL_ADDRESS"],
        density="medium",
    )
    body: str = sample["body"]  # type: ignore[assignment]
    # Pad to ~1KB — Korean text is ~3 bytes/char in UTF-8.
    while len(body.encode("utf-8")) < 1024:
        body += " 추가 문의 사항이 있습니다."

    # Warm the engine, then measure 5 runs and assert max < 500 ms.
    analyzer.analyze(text=body, language="ko")

    durations: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        analyzer.analyze(text=body, language="ko")
        durations.append(time.perf_counter() - t0)

    p95 = sorted(durations)[-1]  # 5 runs → max ≈ P95
    assert p95 < 0.5, f"P95 latency {p95 * 1000:.0f}ms exceeds 500ms budget"
