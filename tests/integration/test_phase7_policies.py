# SYNTHETIC DATA - NOT REAL PII
"""Phase 7 — DB-driven policy engine.

Covers:
  T7.1 — RRN with score 0.95 → BLOCK + user_message
  T7.2 — weak account-number policy = LOG_ONLY → caller sees PASS,
         audit_events records the entity_type
  T7.3 — adding a policy via add_policy hot-reloads (NOTIFY)

Phase 9E — T7.6 (shadow pattern) 테스트 제거. pii_patterns 인프라가
폐기되어 mode='shadow' 패턴 등록 경로 자체가 사라졌다.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.core.analyzer_cache import reset_analyzer_cache_for_tests
from app.core.policy_engine import reset_policy_cache_for_tests
from app.db.crud import (
    add_policy,
    list_audit_events,
)
from app.db.session import get_sessionmaker

if TYPE_CHECKING:
    from httpx import AsyncClient
    from sqlalchemy.ext.asyncio import AsyncSession


# ── Common helpers ────────────────────────────────────────────────────────
@pytest.fixture
async def reset_caches() -> None:
    """Force the analyzer + policy caches to rebuild before each test."""
    reset_analyzer_cache_for_tests()
    reset_policy_cache_for_tests()
    yield
    reset_analyzer_cache_for_tests()
    reset_policy_cache_for_tests()


@pytest.fixture
async def clean_policies() -> None:
    """Wipe pii_policies before/after each test for isolation."""
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_policies"))
        await s.commit()
    yield
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_policies"))
        await s.commit()


@pytest.fixture
async def clean_audit() -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(text("SET LOCAL app.bypass_audit_lock = 'on'"))
        await s.execute(text("DELETE FROM pii.audit_events"))
        await s.commit()
    yield


async def _wait_for_audit(request_id: str, *, timeout: float = 5.0):
    """Wait for the fire-and-forget audit insert to land."""
    sm = get_sessionmaker()
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with sm() as s:
            rows = await list_audit_events(s, request_id=request_id, limit=10)
        if rows:
            return rows
        await asyncio.sleep(0.05)
    return []


# ── T7.1: KR_RRN with high score → BLOCK ───────────────────────────────────
async def test_t7_1_rrn_blocked_with_user_message(
    client: AsyncClient,
    reset_caches: None,
    clean_audit: None,
) -> None:
    request_id = str(uuid.uuid4())
    payload = {
        "request_id": request_id,
        "post": {
            "board_id": "general",
            "title": "x",
            # Synthetic RRN with valid checksum (900101-1234568) — see
            # tests/fixtures/checksum.rrn_checksum.
            "body": "안녕하세요 주민번호는 900101-1234568 입니다.",
        },
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
        "options": {"strictness": "medium"},
    }
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "BLOCK"
    assert body["code"].startswith("BLOCK-")
    assert body["user_message"]
    assert any(d["entity_type"] == "KR_RRN" for d in body["detections"])


# ── T7.2: LOG_ONLY policy → caller sees PASS, audit records entity ────────
async def test_t7_2_log_only_drops_visible_but_audited(
    client: AsyncClient,
    db_session: AsyncSession,
    reset_caches: None,
    clean_policies: None,
    clean_audit: None,
) -> None:
    sm = get_sessionmaker()
    # Suppress KR_PHONE entirely via LOG_ONLY policy across the WARN band.
    async with sm() as s:
        await add_policy(
            s,
            entity_type="KR_PHONE",
            score_min=0.0,
            score_max=1.0,
            action="LOG_ONLY",
        )

    request_id = str(uuid.uuid4())
    payload = {
        "request_id": request_id,
        "post": {
            "board_id": "general",
            "title": "x",
            "body": "연락처는 010-0000-1234 입니다.",
        },
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
        "options": {"strictness": "medium"},
    }
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Caller should see the entity dropped; verdict can be PASS/OK-0000.
    assert body["verdict"] in ("PASS",)
    assert body["code"] == "OK-0000"
    assert all(d["entity_type"] != "KR_PHONE" for d in body["detections"])

    # But the audit row should still record KR_PHONE in detected_entity_types.
    rows = await _wait_for_audit(request_id)
    assert rows, "audit row missing"
    types_csv = rows[0].detected_entity_types or ""
    assert "KR_PHONE" in types_csv, types_csv


# ── T7.3: hot-reload — adding a policy is reflected without restart ───────
async def test_t7_3_add_policy_hot_reloaded(
    client: AsyncClient,
    reset_caches: None,
    clean_policies: None,
    clean_audit: None,
) -> None:
    sm = get_sessionmaker()

    # Baseline: KR_PHONE is BLOCK at medium strictness (Phase 9D 후 PASS/BLOCK only).
    request_id_1 = str(uuid.uuid4())
    resp = await client.post(
        "/v1/detect/post",
        json={
            "request_id": request_id_1,
            "post": {"board_id": "general", "title": "x", "body": "010-0000-1234 으로 문의주세요."},
            "author": {"name": "홍길동", "ip": "127.0.0.1"},
            "options": {"strictness": "medium"},
        },
    )
    body1 = resp.json()
    assert body1["verdict"] == "BLOCK"

    # Insert a LOG_ONLY policy and force the policy cache to reload (we
    # bypass the LISTEN/NOTIFY path in tests because asyncpg listeners
    # require a real loop-bound session).
    async with sm() as s:
        await add_policy(
            s,
            entity_type="KR_PHONE",
            score_min=0.0,
            score_max=1.0,
            action="LOG_ONLY",
        )
    from app.core.policy_engine import get_policy_cache

    get_policy_cache().request_reload()

    request_id_2 = str(uuid.uuid4())
    resp2 = await client.post(
        "/v1/detect/post",
        json={
            "request_id": request_id_2,
            "post": {"board_id": "general", "title": "x", "body": "010-0000-1234 으로 문의주세요."},
            "author": {"name": "홍길동", "ip": "127.0.0.1"},
            "options": {"strictness": "medium"},
        },
    )
    body2 = resp2.json()
    # Same input now produces PASS because the policy demoted it.
    assert body2["verdict"] == "PASS", body2


# Phase 9E — T7.6 (shadow pattern) 테스트 폐기. pii_patterns 인프라 제거로
# mode='shadow' 패턴 자체가 사라져 검증 대상이 없다.
