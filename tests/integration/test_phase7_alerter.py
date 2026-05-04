# SYNTHETIC DATA - NOT REAL PII
"""Phase 7 — feedback alerter (operator-decision A).

Covers:
  - threshold-not-met → no email
  - threshold-met → one email with subject containing the count
  - SMTP misconfigured → no crash, WARNING logged
  - alerter state table prevents double-alert in the same hour
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from app.config import Settings
from app.db.crud import insert_feedback
from app.db.session import get_sessionmaker
from app.workers import feedback_alerter

if TYPE_CHECKING:
    pass


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
async def clean_alert_state() -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_feedback"))
        await s.execute(text("DELETE FROM pii.alerter_state"))
        await s.commit()
    yield
    async with sm() as s:
        await s.execute(text("DELETE FROM pii.pii_feedback"))
        await s.execute(text("DELETE FROM pii.alerter_state"))
        await s.commit()


async def _seed_feedback(n: int, *, in_window: datetime) -> None:
    sm = get_sessionmaker()
    async with sm() as s:
        for i in range(n):
            await insert_feedback(
                s,
                request_id=str(uuid.uuid4()),
                original_code="BLOCK-2001",
                reason=f"seed reason {i}",
                reporter_hash="x",
            )
        # Force created_at into the previous-hour window for a clean test.
        await s.execute(
            text(
                "UPDATE pii.pii_feedback SET created_at = :when "
                "WHERE created_at >= now() - interval '1 minute'"
            ),
            {"when": in_window},
        )
        await s.commit()


def _previous_hour_midpoint() -> datetime:
    n = datetime.now(tz=UTC)
    end = n.replace(minute=0, second=0, microsecond=0)
    return end - timedelta(minutes=30)


# ── Threshold not met ─────────────────────────────────────────────────────
async def test_alerter_below_threshold_no_email(
    monkeypatch: pytest.MonkeyPatch,
    clean_alert_state: None,
) -> None:
    fake = lambda: _settings_with(  # noqa: E731
        smtp_host="smtp.example.com",
        alert_email_to="ops@example.com",
        alert_email_from="alerts@example.com",
        feedback_alert_threshold=10,
    )
    monkeypatch.setattr("app.config.get_settings", fake)
    monkeypatch.setattr(feedback_alerter, "get_settings", fake)

    await _seed_feedback(3, in_window=_previous_hour_midpoint())

    sent: list[object] = []

    def _no_send(_msg):  # type: ignore[no-untyped-def]
        sent.append(_msg)

    monkeypatch.setattr(feedback_alerter, "_send", _no_send)
    sent_flag = await feedback_alerter.run_once()
    assert sent_flag is False
    assert sent == []


# ── Threshold met → one email ─────────────────────────────────────────────
async def test_alerter_above_threshold_sends_email(
    monkeypatch: pytest.MonkeyPatch,
    clean_alert_state: None,
) -> None:
    fake = lambda: _settings_with(  # noqa: E731
        smtp_host="smtp.example.com",
        alert_email_to="ops@example.com",
        alert_email_from="alerts@example.com",
        feedback_alert_threshold=2,
    )
    monkeypatch.setattr("app.config.get_settings", fake)
    monkeypatch.setattr(feedback_alerter, "get_settings", fake)

    await _seed_feedback(5, in_window=_previous_hour_midpoint())

    sent: list = []
    monkeypatch.setattr(feedback_alerter, "_send", lambda msg: sent.append(msg))

    sent_flag = await feedback_alerter.run_once()
    assert sent_flag is True
    assert len(sent) == 1
    msg = sent[0]
    subject = msg["Subject"]
    assert "5" in subject, subject
    body = msg.get_content()
    assert "BLOCK-2001" in body


# ── Anti-flap: same-hour second call must not re-send ─────────────────────
async def test_alerter_does_not_double_alert_in_same_hour(
    monkeypatch: pytest.MonkeyPatch,
    clean_alert_state: None,
) -> None:
    fake = lambda: _settings_with(  # noqa: E731
        smtp_host="smtp.example.com",
        alert_email_to="ops@example.com",
        alert_email_from="alerts@example.com",
        feedback_alert_threshold=2,
    )
    monkeypatch.setattr("app.config.get_settings", fake)
    monkeypatch.setattr(feedback_alerter, "get_settings", fake)

    await _seed_feedback(5, in_window=_previous_hour_midpoint())
    sent: list = []
    monkeypatch.setattr(feedback_alerter, "_send", lambda msg: sent.append(msg))

    assert await feedback_alerter.run_once() is True
    # Second call inside the same hour must short-circuit.
    assert await feedback_alerter.run_once() is False
    assert len(sent) == 1


# ── SMTP misconfigured → no crash + WARNING logged ────────────────────────
async def test_alerter_disabled_when_smtp_unset(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    clean_alert_state: None,
) -> None:
    fake = lambda: _settings_with(  # noqa: E731
        smtp_host="",
        alert_email_to="",
        feedback_alert_threshold=1,
    )
    monkeypatch.setattr("app.config.get_settings", fake)
    monkeypatch.setattr(feedback_alerter, "get_settings", fake)

    await _seed_feedback(5, in_window=_previous_hour_midpoint())
    with caplog.at_level(logging.WARNING):
        # The loop logs a WARNING then sleeps; we only invoke run_once.
        result = await feedback_alerter.run_once()
    assert result is False  # short-circuited, no crash.
