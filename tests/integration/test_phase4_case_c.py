# SYNTHETIC DATA - NOT REAL PII
"""Phase 4 Case-C end-to-end integration tests (T4.13~T4.23).

Each test drives the full request → asyncio worker → DB / webhook
pipeline using the synthetic attachment fixtures. Outbound HTTP for
both fetch_url and callback_url is intercepted with httpx.MockTransport.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import uuid
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from app.api.schemas import (
    Attachment,
    WebhookAttachmentResult,
    WebhookPayload,
)
from app.core.codes import Verdict
from app.db.crud import get_job
from app.db.session import get_sessionmaker
from app.security.idempotency import get_cache
from app.workers.attachment_processor import (
    _decide_attachment_code,
    _overall_verdict,
    process_attachment_job,
)
from app.workers.webhook_sender import RETRY_DELAYS_SECONDS, send_webhook
from tests.fixtures.attachments.create_fixtures import (
    make_text_file,
    make_text_pdf,
)

if TYPE_CHECKING:
    from httpx import AsyncClient


# ── Test helpers ──────────────────────────────────────────────────────────
class _Recorder:
    """Tracks calls into a mocked httpx.MockTransport handler."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []


def _install_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: callable,  # type: ignore[type-arg, valid-type]
) -> None:
    transport = httpx.MockTransport(handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def _make_attachment(
    *, attachment_id: str, filename: str, mime_type: str, payload: bytes,
    fetch_url: str | None = None,
) -> Attachment:
    return Attachment(
        attachment_id=attachment_id,
        filename=filename,
        size_bytes=len(payload),
        mime_type=mime_type,
        sha256=hashlib.sha256(payload).hexdigest(),
        fetch_url=fetch_url or f"https://files.example.com/{filename}",
    )


def _request_payload(
    *,
    attachments: list[dict[str, Any]] | None = None,
    callback_url: str | None = None,
    body: str = "오늘 날씨가 좋네요",
) -> dict[str, Any]:
    return {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": "general", "title": "x", "body": body},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
        "attachments": attachments,
        "callback_url": callback_url,
    }


@pytest.fixture(autouse=True)
def _flush_idempotency_cache() -> None:
    """Each test starts with a clean idempotency cache."""
    get_cache().clear()


# ── T4.13: PDF attachment → 202 + ACK-3001 + job_id ───────────────────────
async def test_t4_13_post_with_pdf_attachment_returns_202(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )

    # Patch transport so the worker's httpx.AsyncClient.GET sees the
    # synthetic PDF and the webhook POST never goes anywhere real.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, content=pdf)
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url="https://callback.example.com/hook",
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 202, resp.text
    payload = resp.json()
    assert payload["code"] == "ACK-3001"
    assert payload["verdict"] == "PROCESSING"
    assert payload["job"]["job_id"].startswith("job_")
    assert payload["job"]["attachment_count"] == 1
    assert payload["body_result"]["code"] in {"OK-0000", "OK-0001"}


# ── T4.14: body BLOCK + attachment → 200 BLOCK (no async work) ────────────
async def test_t4_14_body_block_skips_attachments(
    client: AsyncClient,
) -> None:
    from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

    g = SyntheticPIIGenerator(seed=101)
    rrn = g.gen_rrn(valid=True)

    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )
    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url="https://callback.example.com/hook",
        body=f"주민등록번호 {rrn} 입니다.",
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["verdict"] == "BLOCK"
    assert payload["job"] is None


# ── T4.15: small text attachment still goes async ─────────────────────────
async def test_t4_15_text_attachment_routes_async(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    txt = make_text_file()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="note.txt",
        mime_type="text/plain",
        payload=txt,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=txt)

    _install_transport(monkeypatch, handler)

    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url="https://callback.example.com/hook",
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 202
    assert resp.json()["code"] == "ACK-3001"


# ── T4.16: attachment without callback_url → REQ-4001 ─────────────────────
async def test_t4_16_attachment_without_callback_url(
    client: AsyncClient,
) -> None:
    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )
    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url=None,
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 400
    assert resp.json()["code"] == "REQ-4001"


# ── T4.17: GET /v1/jobs/{job_id} returns status ───────────────────────────
async def test_t4_17_get_job_status(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, content=pdf)
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url="https://callback.example.com/hook",
    )
    resp = await client.post("/v1/detect/post", json=body)
    assert resp.status_code == 202
    job_id = resp.json()["job"]["job_id"]

    # Wait briefly for the worker to make progress.
    for _ in range(40):
        status_resp = await client.get(f"/v1/jobs/{job_id}")
        assert status_resp.status_code == 200
        if status_resp.json()["status"] in {"COMPLETED", "FAILED"}:
            break
        await asyncio.sleep(0.1)

    final = status_resp.json()
    assert final["status"] in {"PROCESSING", "COMPLETED", "FAILED"}
    assert final["job_id"] == job_id


# ── T4.18: webhook arrives with valid HMAC ────────────────────────────────
async def test_t4_18_webhook_hmac_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = bytes(request.read())
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)
    monkeypatch.setattr(
        "app.config.get_settings",
        lambda: _settings_with(webhook_signing_secret="s3cret"),  # noqa: S106
    )

    payload = WebhookPayload(
        request_id=uuid.uuid4(),
        job_id="job_test",
        verdict=Verdict.PASS,
        code="OK-0000",
        user_message="ok",
        attachment_results=[],
        completed_at=__import__(
            "datetime"
        ).datetime.now(tz=__import__("datetime").UTC),
    )
    delivered = await send_webhook(
        "https://callback.example.com/hook",
        payload,
        signing_secret="s3cret",  # noqa: S106 — synthetic test secret
    )
    assert delivered is True
    headers = captured["headers"]
    assert "x-signature" in headers and "x-timestamp" in headers
    canonical = (
        f"{headers['x-timestamp']}\n"
        f"{headers['x-nonce']}\n"
        f"POST\n"
        f"/hook\n"
        f"{hashlib.sha256(captured['body']).hexdigest()}"
    )
    expected = hmac.new(
        b"s3cret", canonical.encode(), hashlib.sha256
    ).hexdigest()
    assert headers["x-signature"] == expected


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    from app.config import Settings
    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


# ── T4.19: webhook payload matches schema ─────────────────────────────────
async def test_t4_19_webhook_payload_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = bytes(request.read())
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    payload = WebhookPayload(
        request_id=uuid.uuid4(),
        job_id="job_zzz",
        verdict=Verdict.WARN,
        code="WARN-1099",
        user_message="ok",
        attachment_results=[
            WebhookAttachmentResult(
                attachment_id="att_001",
                filename="x.pdf",
                verdict=Verdict.PASS,
                code="OK-0000",
            )
        ],
        completed_at=__import__(
            "datetime"
        ).datetime.now(tz=__import__("datetime").UTC),
    )
    ok = await send_webhook(
        "https://callback.example.com/hook", payload, signing_secret=""
    )
    assert ok is True
    parsed = WebhookPayload.model_validate(json.loads(captured["body"]))
    assert parsed.code == "WARN-1099"
    assert parsed.attachment_results[0].attachment_id == "att_001"


# ── T4.20: webhook 5xx triggers retries ───────────────────────────────────
async def test_t4_20_webhook_retries_on_5xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        # Fail twice, then succeed.
        if call_count["n"] <= 2:
            return httpx.Response(503)
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    async def no_sleep(_d: float) -> None:
        return None

    payload = WebhookPayload(
        request_id=uuid.uuid4(),
        job_id="job_retry",
        verdict=Verdict.PASS,
        code="OK-0000",
        user_message="ok",
        attachment_results=[],
        completed_at=__import__(
            "datetime"
        ).datetime.now(tz=__import__("datetime").UTC),
    )
    ok = await send_webhook(
        "https://callback.example.com/hook",
        payload,
        signing_secret="",
        sleep=no_sleep,
    )
    assert ok is True
    assert call_count["n"] == 3


async def test_webhook_gives_up_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(503)

    _install_transport(monkeypatch, handler)

    async def no_sleep(_d: float) -> None:
        return None

    payload = WebhookPayload(
        request_id=uuid.uuid4(),
        job_id="job_fail",
        verdict=Verdict.PASS,
        code="OK-0000",
        user_message="ok",
        attachment_results=[],
        completed_at=__import__(
            "datetime"
        ).datetime.now(tz=__import__("datetime").UTC),
    )
    ok = await send_webhook(
        "https://callback.example.com/hook",
        payload,
        signing_secret="",
        sleep=no_sleep,
    )
    assert ok is False
    assert call_count["n"] == len(RETRY_DELAYS_SECONDS)


# ── T4.21: job retention — DB row is queryable ────────────────────────────
async def test_t4_21_job_row_retained(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, content=pdf)
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url="https://callback.example.com/hook",
    )
    resp = await client.post("/v1/detect/post", json=body)
    job_id = resp.json()["job"]["job_id"]

    # Bypass the API and confirm the row was created in the DB.
    sm = get_sessionmaker()
    async with sm() as session:
        job = await get_job(session, job_id)
    assert job is not None
    assert job.job_id == job_id


# ── T4.22: worker cancellation leaves the job recoverable ─────────────────
async def test_t4_22_worker_cancellation_resilience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancelled worker leaves the job in PROCESSING (not COMPLETED)
    so a future restart could resume it. We verify by cancelling mid-run
    and asserting the row never transitions to COMPLETED."""
    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )

    # Slow handler so we can cancel mid-flight.
    async def slow_handler(_req: httpx.Request) -> httpx.Response:
        await asyncio.sleep(2.0)
        return httpx.Response(200, content=pdf)

    transport = httpx.MockTransport(slow_handler)
    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    sm = get_sessionmaker()
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    from app.db.models import ExtractionJob
    async with sm() as s:
        s.add(ExtractionJob(
            job_id=job_id,
            request_id=str(uuid.uuid4()),
            callback_url=None,
            status="PENDING",
            body_code="OK-0000",
            body_verdict="PASS",
        ))
        await s.commit()

    task = asyncio.create_task(process_attachment_job(
        job_id=job_id,
        request_id=uuid.uuid4(),
        attachments=[attachment],
        callback_url=None,
        body_code="OK-0000",
        body_verdict="PASS",
        strictness="medium",
        sessionmaker=sm,
    ))
    await asyncio.sleep(0.2)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    async with sm() as s:
        job = await get_job(s, job_id)
    assert job is not None
    # Cancelled mid-flight: not COMPLETED. Either still PROCESSING or
    # PENDING is acceptable — the row exists and can be re-driven.
    assert job.status in {"PENDING", "PROCESSING"}
    # Cleanup
    async with sm() as s:
        await s.execute(__import__("sqlalchemy").text(
            "DELETE FROM pii.extraction_jobs WHERE job_id = :j"
        ), {"j": job_id})
        await s.commit()


# ── T4.23: duplicate request_id with attachments → cached 202 ─────────────
async def test_t4_23_idempotent_case_c(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pdf = make_text_pdf()
    attachment = _make_attachment(
        attachment_id="att_001",
        filename="report.pdf",
        mime_type="application/pdf",
        payload=pdf,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, content=pdf)
        return httpx.Response(200)

    _install_transport(monkeypatch, handler)

    body = _request_payload(
        attachments=[attachment.model_dump()],
        callback_url="https://callback.example.com/hook",
    )
    r1 = await client.post("/v1/detect/post", json=body)
    assert r1.status_code == 202
    job_id_1 = r1.json()["job"]["job_id"]

    # Same request_id again — must yield the same envelope.
    r2 = await client.post("/v1/detect/post", json=body)
    assert r2.status_code == 202
    assert r2.json()["job"]["job_id"] == job_id_1


# ── Helper-function unit checks ───────────────────────────────────────────
def test_decide_attachment_code_block_takes_precedence() -> None:
    from app.api.schemas import Detection

    dets = [
        Detection(
            field="attachment.x", entity_type="KR_PHONE",
            code="WARN-1001", score=0.7,
        ),
        Detection(
            field="attachment.x", entity_type="KR_RRN",
            code="BLOCK-2001", score=0.95,
        ),
    ]
    code, verdict = _decide_attachment_code(dets)
    assert verdict is Verdict.BLOCK
    assert code == "BLOCK-2010"


def test_overall_verdict_block_winner() -> None:
    results = [
        WebhookAttachmentResult(
            attachment_id="a", filename="x", verdict=Verdict.BLOCK,
            code="BLOCK-2010",
        ),
    ]
    verdict, code = _overall_verdict("PASS", results)
    assert verdict is Verdict.BLOCK
    assert code == "BLOCK-2010"
