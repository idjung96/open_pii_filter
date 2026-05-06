# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b/C — exception-IP audit-only mode (T4b.11~T4b.13).

The author's IP is added to `pii.exception_ips` for the duration of
each test; the analyzer runs and produces real detections, but the
caller receives PASS / OK-0000 regardless. Audit metadata captured
via `_stash_audit` retains the actual entity_types, which is the
safety net for trusted publishers.
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


# ── T4b.11: exception-IP body BLOCK becomes user-facing PASS ───────────────
async def test_exception_ip_with_rrn_body_returns_pass(
    client: AsyncClient,
    exception_ip_loaded: None,
) -> None:
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


# ── T4b.12: non-exception IP still BLOCKs and surfaces the KR label ────────
async def test_non_exception_ip_with_rrn_body_returns_block_with_label(
    client: AsyncClient,
) -> None:
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
