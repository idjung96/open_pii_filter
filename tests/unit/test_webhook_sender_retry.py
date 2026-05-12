# SYNTHETIC DATA - NOT REAL PII
"""Phase 4 — `app.workers.webhook_sender.send_webhook` 회귀 방지.

`send_delete_request` 는 `test_send_delete_request.py` 가 담당. 본 모듈은:

  - `send_webhook` 의 정상 / 실패 / 재시도 시나리오
  - 지수 백오프 정확 수열 (1/4/16/64/256s)
  - `_is_retryable` 의 status code 매핑
  - `_sign` 의 X-Timestamp / X-Nonce / X-Signature 3종 헤더 생성
  - `serialize_payload` 의 JSON 직렬화 안정성
  - HMAC signing 켜짐/꺼짐 분기 (secret None vs 빈문자열 vs 정상)
  - body bytes 길이 0 도 정상 처리 (서명 안정성)
  - retryable status (408/429/5xx) 분기
  - non-retryable 4xx 즉시 종료
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from app.api.schemas import (
    Detection,
    Verdict,
    WebhookAttachmentResult,
    WebhookPayload,
)
from app.workers.webhook_sender import (
    MAX_ATTEMPTS,
    RETRY_DELAYS_SECONDS,
    _canonical_string,
    _is_retryable,
    _sign,
    send_webhook,
    serialize_payload,
)


# ── 모듈 상수 ────────────────────────────────────────────────────────────
def test_max_attempts_equals_five_per_spec() -> None:
    """스펙: 5회 시도. RETRY_DELAYS_SECONDS 길이와 일치."""
    assert MAX_ATTEMPTS == 5
    assert len(RETRY_DELAYS_SECONDS) == 5


def test_retry_delays_exact_sequence() -> None:
    """지수 백오프 수열 1/4/16/64/256 (4^n) — 스펙 §async."""
    assert RETRY_DELAYS_SECONDS == (1.0, 4.0, 16.0, 64.0, 256.0)


def test_retry_delays_total_budget_about_5_minutes() -> None:
    """5회 시도 누적 백오프 ≈ 341초 — 응답 SLA 안 (~5분).

    재시도 정책 변경 시 가장 먼저 깨질 가드 — 5분이 한참 넘어가면 webhook
    소비자 측 timeout 과 충돌."""
    assert sum(RETRY_DELAYS_SECONDS) == 341.0  # 1+4+16+64+256


# ── _is_retryable status 매핑 ────────────────────────────────────────────
@pytest.mark.parametrize(
    "status", [500, 501, 502, 503, 504, 505, 599, 408, 429]
)
def test_is_retryable_5xx_and_408_429(status: int) -> None:
    """5xx + 408 (timeout) + 429 (rate limit) 는 재시도 대상."""
    assert _is_retryable(status) is True


@pytest.mark.parametrize("status", [200, 201, 204, 301, 302, 400, 401, 403, 404, 410, 422])
def test_is_retryable_non_5xx_not_429_or_408_is_false(status: int) -> None:
    """그 외 status 는 재시도하지 않음 (영구 실패 또는 성공)."""
    assert _is_retryable(status) is False


# ── _sign — 3종 헤더 생성 ────────────────────────────────────────────────
def test_sign_returns_three_required_headers() -> None:
    """`_sign` 결과가 정확히 X-Timestamp / X-Nonce / X-Signature 3개."""
    headers = _sign(
        secret="test-secret",  # noqa: S106
        method="POST",
        path="/cb",
        body=b'{"hello":"world"}',
    )
    assert set(headers.keys()) == {"X-Timestamp", "X-Nonce", "X-Signature"}


def test_sign_timestamp_is_unix_seconds_string() -> None:
    """X-Timestamp 는 현재 UNIX 초의 문자열."""
    headers = _sign(
        secret="s", method="POST", path="/x", body=b""  # noqa: S106
    )
    ts = int(headers["X-Timestamp"])
    import time

    now = int(time.time())
    assert abs(now - ts) <= 2  # 2초 이내 최근.


def test_sign_nonce_is_hex_string() -> None:
    """X-Nonce 는 hex 문자열 (token_hex(16) → 32 char)."""
    headers = _sign(secret="s", method="POST", path="/x", body=b"")  # noqa: S106
    nonce = headers["X-Nonce"]
    assert len(nonce) == 32
    assert all(c in "0123456789abcdef" for c in nonce)


def test_sign_signature_matches_canonical_string() -> None:
    """X-Signature 가 우리가 검증 가능한 hmac.new(canonical).hexdigest()."""
    secret = "test-secret"  # noqa: S105
    body = b'{"k":"v"}'
    headers = _sign(secret=secret, method="POST", path="/cb", body=body)

    canonical = _canonical_string(
        timestamp=headers["X-Timestamp"],
        nonce=headers["X-Nonce"],
        method="POST",
        path="/cb",
        body=body,
    )
    expected = hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert headers["X-Signature"] == expected


def test_sign_two_calls_produce_different_nonces() -> None:
    """nonce 가 매번 새로 생성되어야 한다 (재사용 방지)."""
    h1 = _sign(secret="s", method="POST", path="/x", body=b"")  # noqa: S106
    h2 = _sign(secret="s", method="POST", path="/x", body=b"")  # noqa: S106
    assert h1["X-Nonce"] != h2["X-Nonce"]


def test_sign_method_normalized_to_upper_in_canonical() -> None:
    """method 가 소문자로 들어와도 canonical 에 대문자로 정규화."""
    secret = "s"  # noqa: S105
    body = b""
    headers = _sign(secret=secret, method="post", path="/x", body=body)
    canonical_upper = _canonical_string(
        timestamp=headers["X-Timestamp"],
        nonce=headers["X-Nonce"],
        method="POST",
        path="/x",
        body=body,
    )
    expected_upper = hmac.new(
        secret.encode(), canonical_upper.encode(), hashlib.sha256
    ).hexdigest()
    assert headers["X-Signature"] == expected_upper


# ── _canonical_string mirror 가 hmac_auth 와 동일 형식 ───────────────────
def test_webhook_canonical_string_mirrors_hmac_auth() -> None:
    """webhook_sender 의 canonical mirror 가 hmac_auth 와 byte-for-byte 동일."""
    from app.security.hmac_auth import _canonical_string as auth_canonical

    kwargs: dict[str, object] = {
        "timestamp": "1700000000",
        "nonce": "n" * 16,
        "method": "POST",
        "path": "/cb",
        "body": b'{"k":"v"}',
    }
    a = _canonical_string(**kwargs)  # type: ignore[arg-type]
    b = auth_canonical(**kwargs)  # type: ignore[arg-type]
    assert a == b


# ── send_webhook 실제 호출 시나리오 ─────────────────────────────────────
def _make_payload() -> WebhookPayload:
    return WebhookPayload(
        request_id=uuid4(),
        job_id="job_test_xyz",
        verdict=Verdict.BLOCK,
        code="BLOCK-2010",
        user_message="첨부에 개인정보가 포함되어 있습니다.",
        attachment_results=[
            WebhookAttachmentResult(
                attachment_id="att_001",
                filename="report.pdf",
                verdict=Verdict.BLOCK,
                code="BLOCK-2010",
                detections=[
                    Detection(
                        field="attachment.att_001",
                        entity_type="KR_RRN",
                        code="BLOCK-2010",
                        score=0.95,
                        start=100,
                        end=114,
                    )
                ],
            )
        ],
        completed_at=datetime.now(tz=UTC),
    )


async def _no_sleep(_seconds: float) -> None:
    return None


def _patch_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler,  # type: ignore[no-untyped-def]
) -> list[httpx.Request]:
    """test_send_delete_request.py 와 동일한 패턴 — Request 기록 helper."""
    transport = httpx.MockTransport(handler)
    seen: list[httpx.Request] = []

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        kwargs["transport"] = transport
        real_init(self, *args, **kwargs)

    def recording_handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)
    monkeypatch.setattr(transport, "handler", recording_handler)
    return seen


async def test_send_webhook_returns_true_on_first_2xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """200 응답 시 한 번에 True 반환."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 1
    assert seen[0].method == "POST"


async def test_send_webhook_returns_true_on_201_2xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """2xx 영역 전체가 성공 (201 Created 등)."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(201))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 1


async def test_send_webhook_returns_false_on_non_retryable_4xx_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """400/404 같은 영구 실패는 1회 후 즉시 종료."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(404))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == 1


async def test_send_webhook_retries_on_5xx_until_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """5xx 응답을 5회 시도한 뒤 포기 — RETRY_DELAYS_SECONDS 길이."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(503))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == MAX_ATTEMPTS


async def test_send_webhook_retries_on_429(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """429 (rate limit) 도 재시도 영역."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(429))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == MAX_ATTEMPTS


async def test_send_webhook_retries_on_408(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """408 (request timeout) 도 재시도 영역."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(408))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == MAX_ATTEMPTS


async def test_send_webhook_recovers_after_transient_5xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """첫 2회 503 → 3번째 200 — 회복 시나리오. 시도 횟수 = 3, True 반환."""
    counter = {"n": 0}

    def handler(_req: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200)

    seen = _patch_transport(monkeypatch, handler)
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 3


async def test_send_webhook_signs_when_secret_provided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """secret 제공 시 X-Signature 헤더 부착."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="my-secret",  # noqa: S106
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 1
    headers = dict(seen[0].headers)
    assert "x-signature" in headers
    assert "x-timestamp" in headers
    assert "x-nonce" in headers


async def test_send_webhook_omits_signature_when_secret_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """secret 빈 문자열일 때 X-Signature 미부착."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    headers = dict(seen[0].headers)
    assert "x-signature" not in headers
    assert "x-timestamp" not in headers
    assert "x-nonce" not in headers


async def test_send_webhook_includes_query_in_path_for_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """callback_url 의 query string 이 canonical path 에 포함."""
    captured: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["timestamp"] = req.headers["x-timestamp"]
        captured["nonce"] = req.headers["x-nonce"]
        captured["signature"] = req.headers["x-signature"]
        captured["content"] = req.content.decode()
        return httpx.Response(200)

    _patch_transport(monkeypatch, handler)
    ok = await send_webhook(
        "https://board.example.test/cb?token=abc",
        _make_payload(),
        signing_secret="s",  # noqa: S106
        sleep=_no_sleep,
    )
    assert ok is True
    # 서명을 직접 재계산해 query 포함 path 가 맞는지 검증.
    body = captured["content"].encode()
    expected = hmac.new(
        b"s",
        _canonical_string(
            timestamp=captured["timestamp"],
            nonce=captured["nonce"],
            method="POST",
            path="/cb?token=abc",
            body=body,
        ).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert captured["signature"] == expected


async def test_send_webhook_uses_json_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Content-Type: application/json 헤더 항상 부착."""
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert seen[0].headers["content-type"] == "application/json"


async def test_send_webhook_body_is_json_serialized_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """body 가 payload.model_dump_json() 의 byte 표현."""
    payload = _make_payload()
    seen = _patch_transport(monkeypatch, lambda _r: httpx.Response(200))
    await send_webhook(
        "https://board.example.test/cb",
        payload,
        signing_secret="",
        sleep=_no_sleep,
    )
    assert seen[0].content == payload.model_dump_json().encode("utf-8")


async def test_send_webhook_recovers_after_connect_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """첫 호출 ConnectError → 두번째 200. transport 예외도 재시도 대상."""
    counter = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] == 1:
            raise httpx.ConnectError("network down", request=req)
        return httpx.Response(200)

    seen = _patch_transport(monkeypatch, handler)
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 2


async def test_send_webhook_recovers_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """첫 호출 TimeoutException → 두번째 200."""
    counter = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] == 1:
            raise httpx.ReadTimeout("read timeout", request=req)
        return httpx.Response(200)

    seen = _patch_transport(monkeypatch, handler)
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is True
    assert len(seen) == 2


async def test_send_webhook_sleep_called_with_correct_backoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """5xx 5회 → sleep 이 4번 호출되며 인자는 4/16/64/256s (첫 시도 전 sleep 없음).

    `delay = RETRY_DELAYS_SECONDS[attempt]` 의 코드 의도:
      - attempt=0 → sleep 미호출 (즉시 첫 시도)
      - attempt=1~4 → sleep(RETRY[1])=4, sleep(RETRY[2])=16, sleep(RETRY[3])=64, sleep(RETRY[4])=256
    """
    _patch_transport(monkeypatch, lambda _r: httpx.Response(503))
    sleeps: list[float] = []

    async def recording_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=recording_sleep,
    )
    assert sleeps == [4.0, 16.0, 64.0, 256.0]


async def test_send_webhook_returns_false_after_persistent_connect_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """5회 모두 ConnectError → False, 시도 5회."""

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=req)

    seen = _patch_transport(monkeypatch, handler)
    ok = await send_webhook(
        "https://board.example.test/cb",
        _make_payload(),
        signing_secret="",
        sleep=_no_sleep,
    )
    assert ok is False
    assert len(seen) == MAX_ATTEMPTS


# ── serialize_payload 안정성 ─────────────────────────────────────────────
def test_serialize_payload_returns_json_array() -> None:
    """`serialize_payload` 가 attachment_results 만 JSON array 로 직렬화."""
    import json

    payload = _make_payload()
    out = serialize_payload(payload)
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["attachment_id"] == "att_001"
    assert parsed[0]["filename"] == "report.pdf"


def test_serialize_payload_preserves_korean_without_escape() -> None:
    """`ensure_ascii=False` — 한글이 escape 되지 않고 그대로 보존."""
    payload = _make_payload()
    out = serialize_payload(payload)
    # 한글 사용자 메시지는 attachment_results 가 아닌 payload 본문에 있으므로
    # attachment_results 자체에 한글 검증을 위해 filename 한글 케이스 추가.
    payload_kr = payload.model_copy(
        update={
            "attachment_results": [
                payload.attachment_results[0].model_copy(update={"filename": "보고서.pdf"})
            ]
        }
    )
    out_kr = serialize_payload(payload_kr)
    assert "보고서.pdf" in out_kr
    # ASCII escape 가 발생하지 않았는지 — `\\u` 시퀀스 부재.
    assert "\\u" not in out_kr


def test_serialize_payload_empty_attachments_list() -> None:
    """attachment_results 가 빈 리스트여도 `[]` 직렬화."""
    payload = _make_payload().model_copy(update={"attachment_results": []})
    out = serialize_payload(payload)
    assert out == "[]"
