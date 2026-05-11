# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/C — 예외 IP audit-only 모드 회귀 방지 (T4b.11~T4b.13).

`pii.exception_ips` CIDR 에 매칭되는 발신 IP 의 요청은 다음과 같이 처리:

  - 분석기는 **실제로 돌아간다** — 검출 결과 (entity_type / score / span)
    가 모두 산출됨
  - 그러나 사용자에게는 PASS / OK-0000 으로 응답 (BLOCK 강제 무력화)
  - audit_events 행에는 실제 검출 메타데이터가 그대로 남아 사후 모니터링
    / 컴플라이언스 추적이 가능

신뢰된 게시자 (예: 운영팀 게시판 봇) 가 자기 본문에 RRN 을 포함해도
서비스가 멈추지 않게 하면서도, audit 추적은 잃지 않는 안전망.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.core.exception_ip_cache import _reset_for_tests, reload_exception_ips
from app.db.session import get_sessionmaker
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


_EXCEPTION_IP = "203.0.113.42"


@pytest.fixture
async def exception_ip_loaded() -> None:
    """Add a single CIDR row, reload the cache, then clean up."""
    sm = get_sessionmaker()
    label = f"pytest-{uuid.uuid4().hex[:8]}"
    async with sm() as s:
        await s.execute(
            text(
                "INSERT INTO pii.exception_ips (cidr, label, enabled) "
                "VALUES (:cidr, :label, true) "
                "ON CONFLICT (cidr) DO UPDATE SET enabled = true, label = excluded.label"
            ),
            {"cidr": f"{_EXCEPTION_IP}/32", "label": label},
        )
        await s.commit()
        await reload_exception_ips(s)
    try:
        yield
    finally:
        async with sm() as s:
            await s.execute(
                text("DELETE FROM pii.exception_ips WHERE cidr = :cidr"),
                {"cidr": f"{_EXCEPTION_IP}/32"},
            )
            await s.commit()
        _reset_for_tests()


def _payload(*, ip: str, body: str) -> dict[str, object]:
    return {
        "request_id": str(uuid.uuid4()),
        "author": {"name": "pytest", "ip": ip},
        "post": {"board_id": "qna", "title": "synthetic", "body": body},
    }


# ── T4b.11: 예외 IP + 본문 RRN → 사용자 응답은 PASS 강제 ────────────────
async def test_exception_ip_with_rrn_body_returns_pass(
    client: AsyncClient,
    exception_ip_loaded: None,
) -> None:
    """예외 IP 가 RRN 을 포함한 본문을 보내도 사용자에게는 PASS / OK-0000.

    검출이 실제로 일어났음에도 verdict 가 PASS 로 강제되고, 사용자 메시지
    에 "검출된 항목" 접미사가 절대 붙지 않아야 한다 (그러면 사용자에게
    PII 가 있다고 안내하는 셈이라 audit_only 정책과 모순).
    """
    gen = SyntheticPIIGenerator(seed=4011)
    rrn = gen.gen_rrn()
    body = f"본문에 합성 주민등록번호 {rrn} 가 포함되어 있습니다."

    resp = await client.post("/v1/detect/post", json=_payload(ip=_EXCEPTION_IP, body=body))
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["verdict"] == "PASS"
    assert payload["code"] == "OK-0000"
    # The user-facing message must NOT carry the BLOCK summary suffix
    # because we forced verdict→PASS for this trusted author.
    assert "검출된 항목" not in payload["user_message"]


# ── T4b.12: 일반 IP + 본문 RRN → BLOCK + 한글 라벨 안내 ──────────────────
async def test_non_exception_ip_with_rrn_body_returns_block_with_label(
    client: AsyncClient,
) -> None:
    """예외 IP 가 아닌 발신자에게는 정상 BLOCK + 한글 라벨 응답.

    예외 IP 정책이 너무 광범위하게 적용되어 일반 게시자도 PASS 로 처리되는
    회귀를 방지. 또한 사용자 메시지에 한글 라벨 (`주민등록번호`) 이 등장
    하면서도 raw entity 코드 (`KR_RRN`) 는 새지 않는지 함께 확인.
    """
    gen = SyntheticPIIGenerator(seed=4012)
    rrn = gen.gen_rrn()
    body = f"본문에 합성 주민등록번호 {rrn} 가 포함되어 있습니다."

    resp = await client.post(
        "/v1/detect/post",
        json=_payload(ip="198.51.100.7", body=body),
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["verdict"] == "BLOCK"
    # The Korean label must appear in user_message; raw entity codes
    # must not.
    assert "주민등록번호" in payload["user_message"]
    assert "KR_RRN" not in payload["user_message"]
