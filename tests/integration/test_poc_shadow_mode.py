# SYNTHETIC DATA - NOT REAL PII
"""PoC(shadow) 모드 통합 회귀 테스트.

검증 시나리오:
  - POST /v1/detect/post 에 BLOCK 가는 합성 PII 본문을 보낸다
  - 응답이 PASS(OK-0000) 로 강제된다
  - 동시에 PoC 로그 파일에 실제 판정 (BLOCK + 검출 메타) 이 JSON Lines 로
    1행 기록된다
  - 평문 PII 가 로그 파일에 절대 노출되지 않는다 (§2.5)
  - poc_mode=False 일 때는 기존 동작과 동일하다
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from app.config import Settings, get_settings
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


def _settings_with(tmp_path: Path, **overrides) -> Settings:
    base = Settings().model_dump()
    base.update(overrides)
    if "poc_log_file" not in overrides:
        base["poc_log_file"] = str(tmp_path / "poc.log")
    return Settings(**base)


@pytest.fixture()
def poc_log_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "poc.log"
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(tmp_path, poc_mode=True, poc_log_file=str(log_path)),
    )
    get_settings.cache_clear()
    yield log_path
    get_settings.cache_clear()


@pytest.fixture()
def poc_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "poc.log"
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(tmp_path, poc_mode=False, poc_log_file=str(log_path)),
    )
    get_settings.cache_clear()
    yield log_path
    get_settings.cache_clear()


def _payload(body: str, *, ip: str = "203.0.113.5") -> dict:
    return {
        "request_id": str(uuid.uuid4()),
        "author": {"name": "익명123", "ip": ip},
        "post": {"board_id": "free", "title": "문의", "body": body},
        "options": {"strictness": "medium"},
    }


# ── PoC 모드 ON: 응답은 PASS, 로그는 BLOCK ───────────────────────────────
@pytest.mark.asyncio
async def test_poc_mode_forces_pass_but_logs_actual_block(
    client: AsyncClient,
    poc_log_path: Path,
) -> None:
    """PoC 모드: 합성 RRN 이 들어간 본문 → 응답 PASS, 로그에 실제 BLOCK 기록."""
    g = SyntheticPIIGenerator(seed=42)
    rrn = g.gen_rrn(valid=True)  # 유효한 합성 RRN
    body = f"제 주민번호는 {rrn} 입니다."

    resp = await client.post("/v1/detect/post", json=_payload(body))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # 사용자에게는 PASS
    assert data["code"] == "OK-0000", f"PoC 모드인데 BLOCK 응답이 반환됨: {data}"
    assert data["verdict"] == "PASS"

    # 로그 파일에는 실제 BLOCK 이 기록됐는지
    assert poc_log_path.exists(), "poc 로그 파일이 생성되지 않음"
    lines = poc_log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    rec = json.loads(lines[-1])
    assert rec["kind"] == "body"
    assert rec["actual_verdict"] == "BLOCK", f"실제 BLOCK 이 기록되지 않음: {rec}"
    assert rec["actual_code"].startswith("BLOCK-"), rec
    assert rec["forced_response_code"] == "OK-0000"
    assert any(d["entity_type"] == "KR_RRN" for d in rec["detections"])

    # 평문 PII 비노출 — 로그 파일 전체에 합성 RRN 원문이 들어가면 안 된다.
    file_text = poc_log_path.read_text(encoding="utf-8")
    assert rrn not in file_text, "PoC 로그에 평문 PII 가 기록됨 (§2.5 위반)"
    rrn_digits = rrn.replace("-", "")
    assert rrn_digits not in file_text, "PoC 로그에 hyphen 없는 평문 RRN 이 기록됨 (§2.5 위반)"


# ── PoC 모드 OFF: 기존 동작 (BLOCK 반환) ─────────────────────────────────
@pytest.mark.asyncio
async def test_poc_mode_off_returns_block_no_log_file(
    client: AsyncClient,
    poc_off: Path,
) -> None:
    g = SyntheticPIIGenerator(seed=42)
    body = f"제 주민번호는 {g.gen_rrn(valid=True)} 입니다."

    resp = await client.post("/v1/detect/post", json=_payload(body))
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "BLOCK", "PoC OFF 인데 BLOCK 이 반환되지 않음"
    assert data["code"].startswith("BLOCK-")
    assert not poc_off.exists(), "PoC OFF 인데 로그 파일이 생성됨"


# ── PoC 모드 ON: PASS 입력은 그대로 PASS + 로그도 PASS ──────────────────
@pytest.mark.asyncio
async def test_poc_mode_clean_body_logs_pass(
    client: AsyncClient,
    poc_log_path: Path,
) -> None:
    body = "안녕하세요. 게시판 운영 관련 일반 문의 드립니다."
    resp = await client.post("/v1/detect/post", json=_payload(body))
    assert resp.status_code == 200
    data = resp.json()
    assert data["code"] == "OK-0000"
    assert data["verdict"] == "PASS"

    if poc_log_path.exists() and poc_log_path.stat().st_size > 0:
        rec = json.loads(poc_log_path.read_text(encoding="utf-8").splitlines()[-1])
        assert rec["actual_verdict"] == "PASS"
        assert rec["actual_code"] == "OK-0000"
        assert rec["detections"] == []
