"""Phase 1 — 응답 코드 카탈로그 + `build_response` 회귀 방지 (T1.11~T1.17).

`app/core/codes.py` 의 `CODES` 딕셔너리와 `app/api/responses.build_response`
가 §2.3 (응답 envelope) / §2.4 (코드 카탈로그) / §2.5 (user_message 금지어)
스펙과 한 치도 어긋나지 않도록 카탈로그 무결성·템플릿 치환·금지어
필터·필드 형태를 한 번에 핀(pin) 한다. 코드 추가/삭제/HTTP 매핑 변경은
이 모듈에서 1차로 잡힌다.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.api.responses import (
    audit_all_user_messages,
    build_response,
    user_message_safety_violations,
)
from app.api.schemas import Detection
from app.core.codes import CODES, Verdict, get_code


# ── T1.11: 모든 코드가 필수 필드를 빠짐없이 채웠는지 ─────────────────────
def test_every_code_has_required_fields() -> None:
    """`CODES` 의 모든 엔트리가 자기 키와 일치하고 필수 4종 필드를 채운다.

    검증 포인트:
      - 키 ↔ `rc.code` 일치 (오타로 인한 dict-key 와 객체 불일치 방지)
      - HTTP 상태가 운영 가능한 화이트리스트 집합 안에 있음
      - `verdict` 가 `Verdict` enum 인스턴스 (str 리터럴 누락 방지)
      - `system_message` / `user_message_template` 가 빈 문자열이 아님
    """
    for code, rc in CODES.items():
        assert rc.code == code, f"{code}: code field mismatch"
        assert rc.http_status in {200, 202, 400, 401, 403, 413, 415, 422, 429, 500, 503, 504}
        assert isinstance(rc.verdict, Verdict)
        assert rc.system_message, f"{code}: empty system_message"
        assert rc.user_message_template, f"{code}: empty user_message_template"


def test_category_prefixes_match_verdict() -> None:
    """접두사 (`OK-/WARN-/BLOCK-/ACK-/REQ-/SVR-`) 와 verdict 가 일관되는지.

    예: `BLOCK-2001` 의 `verdict` 가 `Verdict.PASS` 면 안 된다. 카탈로그
    편집 시 사람이 쉽게 저지르는 실수를 자동으로 잡는다.
    """
    prefix_to_verdicts = {
        "OK-": {Verdict.PASS},
        "WARN-": {Verdict.WARN},
        "BLOCK-": {Verdict.BLOCK},
        "ACK-": {Verdict.PROCESSING},
        "REQ-": {Verdict.ERROR},
        "SVR-": {Verdict.ERROR},
    }
    for code, rc in CODES.items():
        prefix = code.split("-")[0] + "-"
        assert prefix in prefix_to_verdicts, f"unknown prefix in {code}"
        assert rc.verdict in prefix_to_verdicts[prefix], (
            f"{code} verdict {rc.verdict} mismatches prefix {prefix}"
        )


# ── T1.13: filename placeholder 치환 ─────────────────────────────────────
def test_block_2010_renders_filename() -> None:
    """`BLOCK-2010` 템플릿의 `{filename}` 가 한글 파일명까지 안전히 치환되는지.

    한글 placeholder 치환 회귀가 발생하면 응답에 ``{filename}`` 이 그대로
    남아 사용자에게 노출되므로 두 가지를 함께 검증:
      - 실제 파일명이 메시지에 등장
      - placeholder literal `{filename}` 은 잔여하지 않음
    """
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2010",
        processing_ms=10,
        template_vars={"filename": "신청서.pdf"},
    )
    assert "신청서.pdf" in resp.user_message
    assert "{filename}" not in resp.user_message


# ── T1.14: 미지의 코드는 KeyError, fallback 코드는 카탈로그에 존재 ─────
def test_unknown_code_raises() -> None:
    """존재하지 않는 코드를 `get_code()` 로 조회하면 `KeyError`.

    실수로 응답 코드를 오타로 적었을 때 런타임에 빈 응답이 나가지 않도록
    엄격히 거절해야 한다 (silent failure 방지).
    """
    with pytest.raises(KeyError):
        get_code("DOES-NOT-EXIST")


def test_fallback_codes_exist() -> None:
    """정책 매핑이 코드를 못 찾을 때 사용되는 fallback 3종이 카탈로그에 존재.

    - `OK-0000` (default PASS)
    - `BLOCK-2099` (default BLOCK)
    - `WARN-1099` (Phase 9D 폐기 등급이지만 호환을 위해 상수 보존)
    """
    assert "BLOCK-2099" in CODES
    assert "WARN-1099" in CODES
    assert "OK-0000" in CODES


# ── T1.15: developer_message 는 ERROR 카테고리만 ─────────────────────────
def test_developer_message_only_for_error() -> None:
    """§2.5 — `developer_message` 는 ERROR (REQ-/SVR-) 응답에만 채워진다.

    PASS / BLOCK 응답에 디버그 정보를 노출하면 ① 내부 구현 디테일 누출
    ② 사용자에게 혼란 야기. ERROR 응답에는 운영자가 호출자에게 안내할
    구체적 사유 (예: 어떤 헤더가 잘못됐는지) 가 들어가야 한다.
    """
    req_id = uuid4()
    # PASS: developer_message 없음
    r_pass = build_response(request_id=req_id, code="OK-0000", processing_ms=1)
    assert r_pass.developer_message is None

    # BLOCK: developer_message 없음 (§2.5 — ERROR 카테고리가 아니므로)
    r_block = build_response(request_id=req_id, code="BLOCK-2001", processing_ms=1)
    assert r_block.developer_message is None

    # ERROR: developer_message 렌더됨
    r_err = build_response(
        request_id=req_id,
        code="REQ-4010",
        processing_ms=1,
    )
    assert r_err.developer_message is not None
    assert "X-Signature" in r_err.developer_message


def test_error_developer_message_rendered_with_vars() -> None:
    """ERROR 응답의 `developer_message` 가 `template_vars` 로 치환되는지.

    `REQ-4015` (IP allowlist 거부) 메시지에 호출자 IP 가 포함되어 운영자가
    바로 발신지를 파악할 수 있어야 한다.
    """
    req_id = uuid4()
    r = build_response(
        request_id=req_id,
        code="REQ-4015",
        processing_ms=1,
        template_vars={"ip": "10.0.0.1"},
    )
    assert r.developer_message is not None
    assert "10.0.0.1" in r.developer_message


# ── T1.16: user_message 정적 검사 ─────────────────────────────────────────
def test_no_user_message_leaks_internal_details() -> None:
    """카탈로그의 모든 `user_message_template` 이 §2.5 금지어 필터를 통과해야 한다.

    내부 구현 노출 (entity 코드 / score / start-end 위치 / 알고리즘명 등)
    이 사용자 메시지에 절대 들어가면 안 된다. 새 코드를 추가할 때마다
    여기서 자동으로 점검된다.
    """
    violations = audit_all_user_messages()
    assert not violations, f"user_message templates leak internal details: {violations}"


def test_safety_check_catches_known_leak() -> None:
    """일부러 잘못 작성한 메시지는 안전 필터가 반드시 잡아야 한다 (counter-test).

    필터 자체가 빈 set 만 돌려주는 회귀를 방지: 명백히 위반인 문자열에서
    `KR_RRN` 와 `score` 두 키워드를 모두 적발해야 한다.
    """
    # 정상 동작 확인: 의도적으로 위반인 문자열은 반드시 감지되어야 한다.
    bad = "해당 KR_RRN (score 0.95)가 위치 12-26에서 검출되었습니다."
    hits = user_message_safety_violations(bad)
    assert "KR_RRN" in hits
    assert "score" in hits


# ── T1.12: 응답 스키마 shape (Phase 9D 이후 `masked` 키 제거) ────────────
def test_response_schema_fields_match_spec() -> None:
    """`DetectPostResponse.model_dump()` 가 §2.3 envelope 필드를 정확히 포함.

    Phase 9D 변경: 마스킹 산출물이 폐기되면서 `masked` 키도 제거됐다.
    이 테스트는 ① 9개 envelope 필드가 모두 존재 ② 폐기된 `masked` 키는
    부활하지 않음 ③ verdict/code/processing_ms/detections 값이 입력 그대로
    직렬화되는지를 한꺼번에 확인한다.
    """
    req_id = uuid4()
    r = build_response(
        request_id=req_id,
        code="BLOCK-2001",
        processing_ms=42,
        detections=[
            Detection(
                field="post.body",
                entity_type="KR_RRN",
                code="BLOCK-2001",
                score=0.98,
                start=12,
                end=26,
                masked_preview="900101-*******",
            )
        ],
    )
    dumped = r.model_dump()

    # §2.3 common envelope (Phase 9D 이후 'masked' 키 제거).
    for k in (
        "request_id",
        "verdict",
        "code",
        "system_message",
        "user_message",
        "developer_message",
        "detections",
        "processed_at",
        "processing_ms",
    ):
        assert k in dumped, f"missing field: {k}"
    assert "masked" not in dumped

    assert dumped["verdict"] == "BLOCK"
    assert dumped["code"] == "BLOCK-2001"
    assert dumped["processing_ms"] == 42
    assert len(dumped["detections"]) == 1


# ── 카탈로그 커버리지 (spec §2.4 의 모든 코드를 갖고 있는가) ──────────────
def test_code_catalog_covers_spec() -> None:
    """§2.4 가 명시한 모든 코드를 `CODES` 가 빠짐없이 포함해야 한다.

    스펙 → 카탈로그 단방향 누락만 잡는다 (카탈로그에 추가된 새 코드는
    여기서 허용). 누락이 발견되면 어떤 코드가 빠졌는지 알기 쉽도록
    `sorted(missing)` 을 메시지에 넣는다.
    """
    required = {
        # PASS
        "OK-0000",
        "OK-0001",
        # WARN
        "WARN-1001",
        "WARN-1002",
        "WARN-1003",
        "WARN-1004",
        "WARN-1005",
        "WARN-1099",
        # BLOCK
        "BLOCK-2001",
        "BLOCK-2002",
        "BLOCK-2003",
        "BLOCK-2004",
        "BLOCK-2005",
        "BLOCK-2006",
        "BLOCK-2007",
        "BLOCK-2008",
        "BLOCK-2010",
        "BLOCK-2011",
        "BLOCK-2012",
        "BLOCK-2099",
        # ACK
        "ACK-3001",
        "ACK-3002",
        # REQ
        "REQ-4001",
        "REQ-4002",
        "REQ-4003",
        "REQ-4004",
        "REQ-4005",
        "REQ-4010",
        "REQ-4011",
        "REQ-4012",
        "REQ-4013",
        "REQ-4014",
        "REQ-4015",
        "REQ-4020",
        "REQ-4030",
        "REQ-4031",
        "REQ-4032",
        "REQ-4033",
        "REQ-4040",
        "REQ-4041",
        "REQ-4042",
        "REQ-4043",
        "REQ-4050",
        "REQ-4051",
        # SVR
        "SVR-5001",
        "SVR-5002",
        "SVR-5003",
        "SVR-5004",
        "SVR-5005",
        "SVR-5006",
        "SVR-5099",
    }
    missing = required - CODES.keys()
    assert not missing, f"missing codes from §2.4: {sorted(missing)}"
