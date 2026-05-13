# SYNTHETIC DATA - NOT REAL PII
"""PoC(shadow) 모드 파일 로거 단위 테스트.

검증 포인트:
  - ``poc_mode=False`` 일 때 로그 파일이 생성되지 않는다 (no-op)
  - ``poc_mode=True`` 일 때 body / attachment 결과가 JSON Lines 로 append
  - 평문 PII 가 절대 기록되지 않는다 (Detection 메타만 기록)
  - I/O 실패는 swallow — 호출이 예외를 던지지 않는다
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from app.api.schemas import Detection
from app.config import Settings, get_settings
from app.security import poc_logger


def _settings_with(tmp_path: Path, **overrides) -> Settings:
    base = Settings().model_dump()
    base.update(overrides)
    if "poc_log_file" not in overrides:
        base["poc_log_file"] = str(tmp_path / "poc.log")
    return Settings(**base)


@pytest.fixture()
def _poc_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "poc.log"
    monkeypatch.setattr(
        poc_logger,
        "get_settings",
        lambda: _settings_with(tmp_path, poc_mode=True, poc_log_file=str(log_path)),
        raising=False,
    )
    # detect.py / attachment_processor 가 import 한 get_settings 도 같이 패치 안 하면
    # 우리 logger 내부에서만 패치된다. 하지만 _emit / log_*_decision 은 logger 내부
    # 의 ``get_settings`` 만 참조하므로 충분하다.
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(tmp_path, poc_mode=True, poc_log_file=str(log_path)),
    )
    get_settings.cache_clear()
    return log_path


@pytest.fixture()
def _poc_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "poc.log"
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(tmp_path, poc_mode=False, poc_log_file=str(log_path)),
    )
    get_settings.cache_clear()
    return log_path


def _det(entity: str = "KR_RRN", code: str = "BLOCK-2001", score: float = 0.95) -> Detection:
    return Detection(
        field="post.body",
        entity_type=entity,
        code=code,
        score=score,
        start=0,
        end=14,
    )


# ── poc_mode=False → no-op ───────────────────────────────────────────────
def test_disabled_does_not_create_file(_poc_off: Path) -> None:
    poc_logger.log_body_decision(
        request_id=uuid.uuid4(),
        actual_code="BLOCK-2001",
        actual_verdict="BLOCK",
        detections=[_det()],
        strictness="medium",
        audit_only=False,
        author_ip="203.0.113.5",
        board_id="free",
        processing_ms=42,
    )
    assert not _poc_off.exists(), "poc_mode=False 인데 로그 파일이 생성됨"


# ── poc_mode=True body 기록 ──────────────────────────────────────────────
def test_body_decision_writes_jsonl(_poc_on: Path) -> None:
    rid = uuid.uuid4()
    poc_logger.log_body_decision(
        request_id=rid,
        actual_code="BLOCK-2001",
        actual_verdict="BLOCK",
        detections=[_det()],
        log_only_types={"INTERNAL_NAME"},
        shadow_hit_types={"PERSON"},
        strictness="high",
        audit_only=False,
        author_ip="203.0.113.5",
        board_id="free",
        processing_ms=42,
    )
    assert _poc_on.exists()
    lines = _poc_on.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, f"expected exactly 1 JSON line, got: {lines}"
    rec = json.loads(lines[0])
    assert rec["kind"] == "body"
    assert rec["request_id"] == str(rid)
    assert rec["actual_code"] == "BLOCK-2001"
    assert rec["actual_verdict"] == "BLOCK"
    assert rec["forced_response_code"] == "OK-0000"
    assert rec["forced_response_verdict"] == "PASS"
    assert rec["strictness"] == "high"
    assert rec["log_only_types"] == ["INTERNAL_NAME"]
    assert rec["shadow_hit_types"] == ["PERSON"]
    det = rec["detections"][0]
    assert det["entity_type"] == "KR_RRN"
    assert det["code"] == "BLOCK-2001"
    assert det["score"] == 0.95
    # 평문 비노출 — preview / text 키가 절대 없어야 한다.
    assert "masked_preview" not in det
    assert "text" not in det


# ── poc_mode=True attachment 기록 ────────────────────────────────────────
def test_attachment_decision_writes_jsonl(_poc_on: Path) -> None:
    rid = uuid.uuid4()
    poc_logger.log_attachment_decision(
        request_id=rid,
        job_id="job_abcd1234",
        actual_code="BLOCK-2010",
        actual_verdict="BLOCK",
        attachment_summaries=[
            {
                "attachment_id": "att_1",
                "filename": "resume.pdf",
                "verdict": "BLOCK",
                "code": "BLOCK-2010",
                "detections": [
                    {
                        "field": "attachment.att_1",
                        "entity_type": "KR_RRN",
                        "code": "BLOCK-2001",
                        "score": 0.95,
                        "start": 5,
                        "end": 19,
                    }
                ],
            }
        ],
    )
    rec = json.loads(_poc_on.read_text(encoding="utf-8").splitlines()[0])
    assert rec["kind"] == "attachment"
    assert rec["job_id"] == "job_abcd1234"
    assert rec["actual_code"] == "BLOCK-2010"
    assert rec["attachment_results"][0]["filename"] == "resume.pdf"


# ── 여러 호출이 append 된다 ──────────────────────────────────────────────
def test_multiple_calls_append(_poc_on: Path) -> None:
    for _ in range(3):
        poc_logger.log_body_decision(
            request_id=uuid.uuid4(),
            actual_code="OK-0000",
            actual_verdict="PASS",
            detections=[],
            strictness="medium",
            audit_only=False,
            author_ip="203.0.113.5",
            board_id="free",
            processing_ms=10,
        )
    assert len(_poc_on.read_text(encoding="utf-8").splitlines()) == 3


# ── I/O 실패 swallow ─────────────────────────────────────────────────────
def test_write_failure_does_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "no_such_dir" / "x" / "poc.log"
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(tmp_path, poc_mode=True, poc_log_file=str(bad)),
    )
    # mkdir(parents=True) 가 성공하므로 강제로 OSError 를 일으키려면 open() 가
    # 실패해야 한다 → Path.open 을 패치한다.
    real_open = Path.open

    def _broken_open(self: Path, *args, **kwargs):
        if str(self).endswith("poc.log"):
            raise OSError("simulated I/O failure")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _broken_open)

    # 예외가 새어나오지 않아야 한다.
    poc_logger.log_body_decision(
        request_id=uuid.uuid4(),
        actual_code="OK-0000",
        actual_verdict="PASS",
        detections=[],
        strictness="medium",
        audit_only=False,
        author_ip="",
        board_id="",
        processing_ms=1,
    )
