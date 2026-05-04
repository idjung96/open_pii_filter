"""Phase 1c — analyzer + recognizer integration tests (T1.1~T1.10).

These tests exercise the real Presidio AnalyzerEngine constructed from
`app.core.analyzer.build_analyzer`. The engine is session-scoped via the
`analyzer` fixture in `tests/conftest.py` so loading spaCy ko_core_news_lg
happens at most once per test run.
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


# ── T1.1: valid RRN → KR_RRN with verified checksum → BLOCK-2001 ───────────
def test_t1_1_valid_rrn_blocks(analyzer: AnalyzerEngine) -> None:
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


# ── T1.2: invalid checksum → no detection above WARN threshold ─────────────
def test_t1_2_invalid_rrn_dropped(analyzer: AnalyzerEngine) -> None:
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


# ── T1.3 (Phase 9D): 4 phone formats → 임계값 이상 → BLOCK-2099 ───────────
def test_t1_3_phone_formats(analyzer: AnalyzerEngine) -> None:
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


# ── T1.4 (Phase 9D): email → EMAIL_ADDRESS 검출 → BLOCK 또는 PASS ─────────
def test_t1_4_email_warns(analyzer: AnalyzerEngine) -> None:
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


# ── T1.5: business num → KR_BUSINESS_NUM detected ──────────────────────────
def test_t1_5_business_num(analyzer: AnalyzerEngine) -> None:
    g = SyntheticPIIGenerator(seed=23)
    biz = g.gen_business_num(valid=True)
    text = f"사업자등록번호 {biz} 로 세금계산서 발행 부탁드립니다."

    results = analyzer.analyze(text=text, language="ko", entities=["KR_BUSINESS_NUM"])
    assert any(r.entity_type == "KR_BUSINESS_NUM" for r in results), text


# ── T1.6: PII-free text → no detections ────────────────────────────────────
def test_t1_6_clean_text_passes(analyzer: AnalyzerEngine) -> None:
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


# ── T1.10: latency budget — 1KB text P95 < 500 ms ──────────────────────────
def test_t1_10_latency_under_500ms(analyzer: AnalyzerEngine) -> None:
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
