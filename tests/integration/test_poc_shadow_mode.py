# SYNTHETIC DATA - NOT REAL PII
"""PoC(shadow) 모드 통합 회귀 테스트.

검증 시나리오:
  - POST /v1/detect/post 에 BLOCK 가는 합성 PII 본문을 보낸다
  - 응답이 즉시 PASS(OK-0000) 로 반환된다 (분석 대기 없음)
  - 별도 background 태스크가 끝난 뒤 PoC 로그 파일에 실제 판정 (BLOCK +
    검출 메타) 이 JSON Lines 로 1행 기록된다
  - 평문 PII 가 로그 파일에 절대 노출되지 않는다 (§2.5)
  - poc_mode=False 일 때는 기존 동작과 동일하다
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from app.config import Settings, get_settings
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


async def _wait_for_log(path: Path, *, expected_lines: int = 1, timeout_s: float = 5.0) -> None:
    """Background 태스크가 PoC 로그를 append 할 때까지 폴링.

    Fire-and-forget 백그라운드 분석은 응답 반환 후에 실행되므로 테스트에서
    완료를 동기적으로 기다려야 한다.
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) >= expected_lines:
                return
        await asyncio.sleep(0.05)


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


# ── PoC 모드 ON: 응답은 즉시 PASS, 로그는 background 에서 BLOCK 기록 ─────
@pytest.mark.asyncio
async def test_poc_mode_forces_pass_but_logs_actual_block(
    client: AsyncClient,
    poc_log_path: Path,
) -> None:
    """PoC 모드: 합성 RRN 본문 → 즉시 PASS, background 에서 BLOCK 기록."""
    g = SyntheticPIIGenerator(seed=42)
    rrn = g.gen_rrn(valid=True)  # 유효한 합성 RRN
    body = f"제 주민번호는 {rrn} 입니다."

    resp = await client.post("/v1/detect/post", json=_payload(body))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # 사용자에게는 PASS
    assert data["code"] == "OK-0000", f"PoC 모드인데 BLOCK 응답이 반환됨: {data}"
    assert data["verdict"] == "PASS"

    # Background 분석이 완료될 때까지 대기
    await _wait_for_log(poc_log_path, expected_lines=1, timeout_s=10.0)

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


# ── PoC 모드 ON: PASS 입력은 그대로 PASS + background 로그도 PASS ────────
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

    await _wait_for_log(poc_log_path, expected_lines=1, timeout_s=10.0)
    rec = json.loads(poc_log_path.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["actual_verdict"] == "PASS"
    assert rec["actual_code"] == "OK-0000"
    assert rec["detections"] == []


# ── PoC 모드: 응답 즉시 반환 — 분석을 기다리지 않는다 ────────────────────
@pytest.mark.asyncio
async def test_poc_mode_response_is_immediate(
    client: AsyncClient,
    poc_log_path: Path,
) -> None:
    """PoC 모드: 본문 PII 분석을 동기적으로 기다리지 않고 즉시 PASS 반환.

    응답 ``processing_ms`` 가 본문 분석 비용 (≥수백 ms) 보다 훨씬 작아야
    한다 — 백그라운드 태스크가 동작한다는 증거.
    """
    g = SyntheticPIIGenerator(seed=42)
    body = " ".join(f"제 주민번호는 {g.gen_rrn(valid=True)} 입니다." for _ in range(10))

    resp = await client.post("/v1/detect/post", json=_payload(body))
    assert resp.status_code == 200
    data = resp.json()
    assert data["code"] == "OK-0000"
    # 본문 분석은 sync 경로에서 ~수백 ms ~ 수 초 걸린다. 즉시 PASS 라면
    # 200 ms 미만이 합리적인 상한선. 환경 노이즈를 고려해 500 ms 로 잡는다.
    assert data["processing_ms"] < 500, (
        f"PoC 모드인데 응답이 분석을 동기적으로 기다림: {data['processing_ms']}ms"
    )
