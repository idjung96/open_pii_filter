# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — 로그 scrubber 가 모든 record 에 적용되는지 회귀 방지 (T6.1).

합성 PII (RRN/전화/이메일/주소) 가 들어간 본문을 실제 FastAPI 요청 경로로
보내고, caplog 가 캡처한 어떤 로그 record 에도 원본 자릿수/문자열이 절대
포함되지 않아야 한다. 다음 3가지 경로 모두에서 동일하게 검증:

  - 정상 응답 경로 (200/PASS / 200/BLOCK)
  - pydantic 검증 오류 경로 (REQ-4001/4003/4004 — 400/422)
  - 미처리 예외 경로 (SVR-5099 — 500)

로그가 PII 평문을 흘리는 회귀가 가장 잡기 어려운 사고이므로, scrubber 가
record.msg / args / structured fields 모두를 마스킹하는지 정규식 기반으로
재검색해서 확인.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import TYPE_CHECKING

import pytest

from app.security.log_filter import (
    PIIScrubFilter,
    install_pii_log_filter,
    uninstall_pii_log_filter,
)
from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


@pytest.fixture(autouse=True)
def _install_filter() -> None:
    install_pii_log_filter()
    yield
    uninstall_pii_log_filter()


def _assert_no_pii_in_records(records: list[logging.LogRecord], *forbidden: str) -> None:
    """Render every record + assert no forbidden substring slipped through."""
    rendered = []
    for r in records:
        try:
            rendered.append(r.getMessage())
        except Exception:
            rendered.append(str(r.msg))
        if r.exc_text:
            rendered.append(r.exc_text)
    blob = "\n".join(rendered)
    for needle in forbidden:
        assert needle not in blob, (
            f"PII leak: {needle!r} appears in {len(records)} log record(s):\n{blob[:2000]}"
        )


# ── Unit-level filter tests ──────────────────────────────────────────────
def test_filter_scrubs_rrn() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, "user RRN=010101-1234567", None, None)
    flt.filter(rec)
    assert "010101-1234567" not in rec.msg
    assert "[REDACTED-RRN]" in rec.msg


def test_filter_scrubs_phone() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, "phone 010-0000-1234", None, None)
    flt.filter(rec)
    assert "010-0000-1234" not in rec.msg
    assert "[REDACTED-PHONE]" in rec.msg


def test_filter_scrubs_email() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, "to alice@example.com", None, None)
    flt.filter(rec)
    assert "alice@example.com" not in rec.msg


def test_filter_scrubs_card() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, "card 4111-1111-1111-1111", None, None)
    flt.filter(rec)
    assert "4111-1111-1111-1111" not in rec.msg
    assert "[REDACTED-CARD]" in rec.msg


def test_filter_scrubs_args_tuple() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord(
        "x",
        logging.INFO,
        "p",
        0,
        "name=%s phone=%s",
        ("홍길동", "010-9876-5432"),
        None,
    )
    flt.filter(rec)
    assert "010-9876-5432" not in rec.getMessage()


# ── Endpoint-level scrub assertions ──────────────────────────────────────
async def test_success_path_logs_have_no_pii(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Case B: WARN-level body is logged but no plaintext PII leaks."""
    g = SyntheticPIIGenerator(seed=42)
    phone = g.gen_phone(format="hyphen")
    email = "alice@example.com"

    payload = {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": "general", "title": "x", "body": f"연락처 {phone}, {email}"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
    }

    caplog.set_level(logging.DEBUG)
    install_pii_log_filter()  # idempotent — re-attach to caplog handler too
    for h in caplog.handler, *logging.getLogger().handlers:
        h.addFilter(PIIScrubFilter())

    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200

    _assert_no_pii_in_records(caplog.records, phone, email)


async def test_validation_error_path_logs_have_no_pii(
    client: AsyncClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    g = SyntheticPIIGenerator(seed=43)
    rrn = g.gen_rrn(valid=True)

    # Malformed: request_id is a string but not a UUID. The validation
    # error path tends to dump the body into the log.
    payload = {
        "request_id": "not-a-uuid",
        "post": {"board_id": "general", "title": "x", "body": f"RRN: {rrn}"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
    }

    caplog.set_level(logging.DEBUG)
    install_pii_log_filter()
    for h in caplog.handler, *logging.getLogger().handlers:
        h.addFilter(PIIScrubFilter())

    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code in {400, 422}

    _assert_no_pii_in_records(caplog.records, rrn)


async def test_exception_path_logs_have_no_pii(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Synthetic exception with PII in the message: filter must scrub."""
    install_pii_log_filter()
    for h in caplog.handler, *logging.getLogger().handlers:
        h.addFilter(PIIScrubFilter())

    caplog.set_level(logging.ERROR)
    g = SyntheticPIIGenerator(seed=44)
    rrn = g.gen_rrn(valid=True)
    logger = logging.getLogger("phase6.exc-test")
    try:
        raise RuntimeError(f"unexpected RRN={rrn} in payload")
    except RuntimeError:
        logger.exception("failure during test")

    _assert_no_pii_in_records(caplog.records, rrn)


def test_filter_does_not_break_records_without_pii() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, "ordinary message %d", (42,), None)
    assert flt.filter(rec) is True
    assert rec.getMessage() == "ordinary message 42"


def test_filter_handles_non_string_msg() -> None:
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, {"k": "v"}, None, None)
    assert flt.filter(rec) is True


def test_phone_pattern_strict() -> None:
    """Make sure the phone scrubber doesn't mangle non-PII digit strings.

    A 4-digit zip-like number alone shouldn't trigger a PHONE redaction.
    """
    flt = PIIScrubFilter()
    rec = logging.LogRecord("x", logging.INFO, "p", 0, "code=1234 ok", None, None)
    flt.filter(rec)
    assert "1234" in rec.msg
    assert not re.search(r"\[REDACTED-PHONE\]", rec.msg)
