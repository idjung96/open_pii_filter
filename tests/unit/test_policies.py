"""Phase 1c → 9D — `app.core.policies` 임계값/매핑 회귀 방지.

분석기가 산출한 score 가 어떤 응답 코드로 매핑되는지를 결정하는 정책
모듈을 검증한다. 입력은 `(entity_type, score, field, strictness)` 4종,
출력은 `OK-0000` / `BLOCK-2xxx` 중 하나. 본 모듈은 다음 회귀를 핀(pin):

- 3-tier strictness (low/medium/high) 별 BLOCK 임계값
- BLOCK 카테고리에서 entity 별 전용 코드 (BLOCK-2001 RRN, 2005 카드, …)
- 임계값 미만은 PASS, 이상은 BLOCK 의 2단계 (Phase 9D 이후 WARN 폐기)
- 첨부 필드는 entity 종류 무관 BLOCK-2010 으로 통합
- 미지의 entity_type 도 fallback (BLOCK-2099 / OK-0000) 으로 안전 처리
- `ENTITY_TO_CODE` 테이블의 모든 코드가 실제 카탈로그에 존재
"""

from __future__ import annotations

import pytest

from app.core.policies import (
    ENTITY_TO_CODE,
    map_detection_to_code,
    score_to_band,
)


# ── Threshold sanity per strictness ────────────────────────────────────────
@pytest.mark.parametrize(
    ("strictness", "score", "expected"),
    [
        # low: block ≥ 0.65
        ("low", 0.30, "pass"),
        ("low", 0.50, "pass"),
        ("low", 0.65, "block"),
        # medium: block ≥ 0.78
        ("medium", 0.40, "pass"),
        ("medium", 0.77, "pass"),
        ("medium", 0.78, "block"),
        # high: block ≥ 0.88
        ("high", 0.60, "pass"),
        ("high", 0.87, "pass"),
        ("high", 0.88, "block"),
    ],
)
def test_score_to_band_thresholds(strictness: str, score: float, expected: str) -> None:
    """3-tier strictness 의 BLOCK 임계값을 정확히 핀(pin) 한다.

    임계값 매트릭스:
      - low    → score ≥ 0.65 시 BLOCK
      - medium → score ≥ 0.78 시 BLOCK (기본값)
      - high   → score ≥ 0.88 시 BLOCK

    경계값 (0.65/0.78/0.88) 정확히에서 BLOCK 으로 떨어져야 하고, 그 미만은
    PASS. 임계값이 한 자리 소수점 단위로 바뀌어도 게시판 트래픽의 BLOCK
    률 자체가 크게 흔들리므로 회귀 방지가 중요.
    """
    assert score_to_band(score, strictness) == expected  # type: ignore[arg-type]


# ── Phase 9D: high strictness drops weak bank pattern ──────────────────────
def test_high_strictness_drops_weak_bank_pattern() -> None:
    """`KR_BANK_ACCOUNT_WEAK` (단순 10~14 자리 숫자) 는 점수 ~0.5 라 PASS 유지.

    medium 임계 (0.78) / high 임계 (0.88) 둘 다 그보다 높으므로 BLOCK 으로
    떨어져선 안 된다. Phase 9D 에서 WARN 등급이 폐기됐는데도 약한 패턴이
    BLOCK 으로 흡수되지 않고 PASS 로 안전하게 떨어지는지 확인하는 가드.
    """
    weak_score = 0.5

    medium = map_detection_to_code(
        entity_type="KR_BANK_ACCOUNT_WEAK",
        score=weak_score,
        field="post.body",
        strictness="medium",
    )
    high = map_detection_to_code(
        entity_type="KR_BANK_ACCOUNT_WEAK",
        score=weak_score,
        field="post.body",
        strictness="high",
    )
    assert medium == "OK-0000"
    assert high == "OK-0000"


# ── BLOCK canonical mappings (medium) ─────────────────────────────────────
@pytest.mark.parametrize(
    ("entity_type", "score", "expected"),
    [
        ("KR_RRN", 0.95, "BLOCK-2001"),
        ("KR_DRIVERLICENSE", 0.90, "BLOCK-2002"),
        ("KR_PASSPORT", 0.90, "BLOCK-2003"),
        ("CREDIT_CARD", 0.95, "BLOCK-2005"),
        ("KR_BANK_ACCOUNT", 0.85, "BLOCK-2006"),
        # Phase 9D — phone/email/etc 도 임계값 이상이면 BLOCK 흡수.
        ("KR_PHONE", 0.95, "BLOCK-2099"),
        ("EMAIL_ADDRESS", 0.95, "BLOCK-2099"),
        ("LOCATION", 0.95, "BLOCK-2099"),
        ("PERSON", 0.95, "BLOCK-2099"),
        ("KR_BUSINESS_NUM", 0.90, "BLOCK-2099"),
    ],
)
def test_map_detection_to_code_medium_block(entity_type: str, score: float, expected: str) -> None:
    """medium strictness 에서 BLOCK 카테고리 entity 가 전용 코드로 떨어지는지.

    매핑 표:
      - RRN / 운전면허 / 여권 / 카드 / 계좌 → 각각의 전용 BLOCK-2001~2006
      - 전화/이메일/위치/사람/사업자번호 → 통합 fallback BLOCK-2099
        (Phase 9D 이후 WARN 폐기로 임계값을 넘으면 BLOCK 으로 흡수)

    `BLOCK-2008` (복합 PII) 은 multi-entity 케이스 전용이라 여기 단일 매핑에
    포함되지 않음 — `test_t1_22_multi_block_uses_2008` 가 따로 담당.
    """
    code = map_detection_to_code(
        entity_type=entity_type,
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == expected


# ── PASS band — score below threshold ─────────────────────────────────────
@pytest.mark.parametrize(
    ("entity_type", "score"),
    [
        ("KR_PHONE", 0.70),
        ("EMAIL_ADDRESS", 0.70),
        ("LOCATION", 0.60),
        ("PERSON", 0.60),
        ("KR_BUSINESS_NUM", 0.60),
    ],
)
def test_map_detection_to_code_medium_pass(entity_type: str, score: float) -> None:
    """medium 임계 (0.78) 미만의 점수는 entity 종류 무관 PASS (OK-0000).

    "약한 신호" 인 phone/email/location/person/business 가 점수가 낮을 때
    BLOCK 으로 잘못 분류되면 일반 게시글이 차단되는 사고가 발생 — 이 회귀를
    parametrize 로 5개 entity 모두 확인.
    """
    code = map_detection_to_code(
        entity_type=entity_type,
        score=score,
        field="post.body",
        strictness="medium",
    )
    assert code == "OK-0000"


# ── 첨부 필드는 entity 종류 무관 BLOCK-2010 으로 통합 ─────────────────────
def test_attachment_block_uses_2010() -> None:
    """`field` 가 `attachment.*` 패턴이면 entity 별 코드 대신 BLOCK-2010.

    첨부에서 어떤 종류의 PII 가 잡혔는지가 아니라 "첨부 안에 PII 가 있다"
    라는 사실만 사용자에게 안내. 첨부 단위 BLOCK 사유 통일.
    """
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=0.95,
        field="attachment.att_001",
        strictness="medium",
    )
    assert code == "BLOCK-2010"


def test_attachment_pass_band_drops() -> None:
    """첨부에서도 임계 미만 점수는 PASS — 모든 첨부 검출이 무조건 BLOCK 이
    되지 않도록 점수 임계를 동일하게 적용한다."""
    code = map_detection_to_code(
        entity_type="KR_RRN",
        score=0.30,
        field="attachment.att_001",
        strictness="medium",
    )
    assert code == "OK-0000"


# ── 미지의 entity_type → fallback (BLOCK-2099 / OK-0000) ─────────────────
def test_unknown_entity_falls_back() -> None:
    """등록되지 않은 entity 가 들어와도 안전 fallback 으로 분기해야 한다.

    임계 이상 → 일반 BLOCK 코드 (`BLOCK-2099`)
    임계 미만 → PASS (`OK-0000`)

    실수로 신규 인식기를 추가했는데 `ENTITY_TO_CODE` 매핑을 빠뜨려도
    응답이 무너지지 않도록 보호하는 가드.
    """
    block_fallback = map_detection_to_code(
        entity_type="MYSTERY_ENTITY",
        score=0.95,
        field="post.body",
        strictness="medium",
    )
    pass_fallback = map_detection_to_code(
        entity_type="MYSTERY_ENTITY",
        score=0.30,
        field="post.body",
        strictness="medium",
    )
    assert block_fallback == "BLOCK-2099"
    assert pass_fallback == "OK-0000"  # noqa: S105 — response code, not a password


# ── `ENTITY_TO_CODE` 테이블 — 모든 매핑값이 실제 카탈로그에 존재 ────────
def test_entity_to_code_table_uses_real_codes() -> None:
    """매핑 표의 모든 코드가 `CODES` 카탈로그에 등록되어 있어야 한다.

    `(entity_type, band)` 튜플 → 코드 표가 오타로 인해 미존재 코드를
    가리키면 런타임에 KeyError 가 발생한다. 정책 수정 직후 회귀가 흔하므로
    카탈로그-매핑 정합성을 PR 시점에 강제.
    """
    from app.core.codes import CODES

    for (_etype, _band), code in ENTITY_TO_CODE.items():
        assert code in CODES, f"{code} not in CODES catalog"
