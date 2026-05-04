"""Phase 7 — hourly email alerter for feedback volume.

Operator-decision A: admins do not respond per-feedback; instead, when
the rate exceeds ``Settings.feedback_alert_threshold`` rows in the
previous full hour, send a summary email.

Anti-flap: ``pii.alerter_state`` records ``last_alert_at`` per key
(``'feedback'``) so a process restart inside the same hour does not
re-send the alert.

SMTP: stdlib ``smtplib`` only — no extra dependencies. TLS via
``starttls()`` on port 587, SSL on 465, plaintext otherwise.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import get_settings
from app.db.models import AlerterState, PiiFeedback
from app.db.session import get_sessionmaker

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

ALERTER_KEY = "feedback"
DEFAULT_INTERVAL_SECONDS = 3600


# ── PII-safe text scrubbing ────────────────────────────────────────────────
_PII_PATTERNS = [
    # RRN
    r"\d{6}-?\d{7}",
    # Phone-ish
    r"\d{2,3}-\d{3,4}-\d{4}",
    # Email
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    # Credit-card-ish
    r"\d{4}-\d{4}-\d{4}-\d{4}",
]


def _scrub(text: str, *, max_chars: int = 80) -> str:
    """Mask anything that looks like PII before embedding in an email body."""
    import re
    out = text
    for rx in _PII_PATTERNS:
        out = re.sub(rx, "***", out)
    if len(out) > max_chars:
        out = out[:max_chars] + "…"
    return out


# ── Window math ───────────────────────────────────────────────────────────
def _previous_hour_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    """Return ``[start, end)`` of the previous full hour."""
    n = now or datetime.now(tz=UTC)
    end = n.replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=1)
    return start, end


# ── State helpers ─────────────────────────────────────────────────────────
async def _get_state(session: AsyncSession) -> AlerterState | None:
    return await session.get(AlerterState, ALERTER_KEY)


async def _record_alert(
    session: AsyncSession, *, count: int, alerted_at: datetime
) -> None:
    stmt = (
        pg_insert(AlerterState)
        .values(key=ALERTER_KEY, last_alert_at=alerted_at, last_count=count)
        .on_conflict_do_update(
            index_elements=[AlerterState.key],
            set_={
                "last_alert_at": alerted_at,
                "last_count": count,
                "updated_at": datetime.now(tz=UTC),
            },
        )
    )
    await session.execute(stmt)
    await session.commit()


# ── Email rendering ───────────────────────────────────────────────────────
def _build_email(
    *,
    total: int,
    by_code: list[tuple[str, int]],
    reasons: list[str],
    window_start: datetime,
    window_end: datetime,
    sender: str,
    recipients: list[str],
) -> EmailMessage:
    """Compose the alert email."""
    msg = EmailMessage()
    msg["Subject"] = f"[PII API] feedback volume alert: {total} reports/hour"
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    top_codes_lines = "\n".join(f"  - {code}: {n}" for code, n in by_code[:5])
    top_reasons_lines = "\n".join(f"  - {_scrub(r)}" for r in reasons[:5])

    body = (
        f"Feedback volume exceeded the configured threshold.\n\n"
        f"Window  : {window_start.isoformat()} → {window_end.isoformat()}\n"
        f"Total   : {total}\n\n"
        f"Top codes:\n{top_codes_lines or '  (none)'}\n\n"
        f"Reason snippets:\n{top_reasons_lines or '  (none)'}\n\n"
        f"Review queue: GET /v1/admin/stats/feedback\n"
    )
    msg.set_content(body)
    return msg


# ── SMTP send ─────────────────────────────────────────────────────────────
def _send(msg: EmailMessage) -> None:
    """Send via SMTP. Picks SSL/STARTTLS/plain based on the port."""
    s = get_settings()
    host = s.smtp_host
    port = int(s.smtp_port)
    user = s.smtp_user
    password = s.smtp_password

    if port == 465:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as smtp:
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return

    with smtplib.SMTP(host, port, timeout=20) as smtp:
        if port == 587:
            ctx = ssl.create_default_context()
            smtp.starttls(context=ctx)
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


# ── Main loop ─────────────────────────────────────────────────────────────
async def run_once(*, now: datetime | None = None) -> bool:
    """One alerter pass. Returns True iff an email was sent."""
    s = get_settings()
    if not s.smtp_host or not s.alert_email_to.strip():
        # One-time WARNING per process — caller already logs at startup.
        return False

    sm = get_sessionmaker()
    window_start, window_end = _previous_hour_window(now)

    async with sm() as session:
        # 1. Anti-flap — bail if we already alerted in this hour.
        state = await _get_state(session)
        if (
            state is not None
            and state.last_alert_at is not None
            and state.last_alert_at >= window_end
        ):
            return False

        # 2. Count rows in the previous-hour window.
        count_stmt = (
            select(PiiFeedback)
            .where(PiiFeedback.created_at >= window_start)
            .where(PiiFeedback.created_at < window_end)
        )
        rows = list(await session.scalars(count_stmt))
        total = len(rows)

        if total < s.feedback_alert_threshold:
            return False

        # 3. Aggregate by_code + sample reasons.
        by_code_counts: dict[str, int] = {}
        for r in rows:
            by_code_counts[r.original_code] = by_code_counts.get(r.original_code, 0) + 1
        by_code = sorted(by_code_counts.items(), key=lambda kv: kv[1], reverse=True)
        reasons = [r.reason for r in rows[:5]]

        recipients = [
            r.strip() for r in s.alert_email_to.split(",") if r.strip()
        ]
        sender = s.alert_email_from or recipients[0]

        msg = _build_email(
            total=total,
            by_code=by_code,
            reasons=reasons,
            window_start=window_start,
            window_end=window_end,
            sender=sender,
            recipients=recipients,
        )

        try:
            await asyncio.to_thread(_send, msg)
        except Exception:
            logger.exception("feedback alerter SMTP send failed")
            return False

        await _record_alert(session, count=total, alerted_at=window_end)

    logger.info(
        "feedback alert sent",
        extra={"count": total, "recipients": len(recipients)},
    )
    return True


async def feedback_alerter_loop(
    *, interval_seconds: int | None = None
) -> None:
    """Long-lived alerter loop. Spawned from ``app.main`` lifespan."""
    s = get_settings()
    interval = interval_seconds or s.feedback_alert_interval_seconds

    if not s.smtp_host or not s.alert_email_to.strip():
        logger.warning(
            "feedback alerter disabled (smtp_host or alert_email_to empty)"
        )
        # Still loop so we re-check after a config reload.
        # Keep cadence cheap.
        interval = max(interval, 300)

    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("feedback alerter pass failed")
        await asyncio.sleep(interval)
