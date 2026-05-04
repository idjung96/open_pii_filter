# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — verify the response envelope never carries plaintext PII (T6.6).

The `Detection` schema only exposes (field, entity_type, code, score,
start, end). The masked field, when present, replaces matched spans
with `*`. We assert these contracts on a real /v1/detect/post round-trip.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


async def test_response_has_no_plaintext_pii(client: AsyncClient) -> None:
    g = SyntheticPIIGenerator(seed=2026)
    rrn = g.gen_rrn(valid=True)
    phone = g.gen_phone(format="hyphen")
    email = "alice@example.com"
    body_text = f"제 RRN은 {rrn}, 전화 {phone}, 이메일 {email} 입니다."

    payload = {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": "general", "title": "x", "body": body_text},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
        "options": {"strictness": "medium"},
    }
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200, resp.text
    payload_out = resp.json()

    # Detections expose start/end only — never the matched substring.
    for det in payload_out.get("detections", []):
        assert "text" not in det
        assert set(det.keys()) <= {
            "field",
            "entity_type",
            "code",
            "score",
            "start",
            "end",
            "masked_preview",
        }
        # masked_preview, when present, is masked — must never repeat
        # the original digits.
        if det.get("masked_preview"):
            mp = det["masked_preview"]
            assert rrn not in mp
            assert phone not in mp
            assert email not in mp

    # Top-level body of the response must not contain the original PII.
    raw_text = resp.text
    assert rrn not in raw_text
    assert phone not in raw_text
    assert email not in raw_text

    # Masked content (if returned) replaces the matched spans with *.
    masked = payload_out.get("masked")
    if masked and masked.get("body"):
        masked_body = masked["body"]
        assert rrn not in masked_body
        assert phone not in masked_body
        assert email not in masked_body
        # And it should still be the same length as the input body.
        assert len(masked_body) == len(body_text)


async def test_developer_message_only_for_error(client: AsyncClient) -> None:
    """developer_message must be None for non-ERROR codes (T6.6)."""
    payload = {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": "general", "title": "x", "body": "오늘 날씨가 좋네요"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
    }
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200
    payload_out = resp.json()
    # OK responses must have no developer_message.
    assert payload_out["code"].startswith("OK-")
    assert payload_out.get("developer_message") in (None, "")


async def test_user_message_safe_substrings(client: AsyncClient) -> None:
    """user_message must never expose internal type names or scores."""
    g = SyntheticPIIGenerator(seed=2026)
    rrn = g.gen_rrn(valid=True)
    payload = {
        "request_id": str(uuid.uuid4()),
        "post": {"board_id": "general", "title": "x", "body": f"RRN: {rrn}"},
        "author": {"name": "홍길동", "ip": "127.0.0.1"},
    }
    resp = await client.post("/v1/detect/post", json=payload)
    assert resp.status_code == 200
    payload_out = resp.json()
    msg = payload_out.get("user_message", "")
    assert rrn not in msg
    forbidden = (
        "score",
        "confidence",
        "presidio",
        "spacy",
        "gliner",
        "regex",
        "KR_RRN",
        "KR_PHONE",
        "EMAIL_ADDRESS",
    )
    lowered = msg.lower()
    for f in forbidden:
        assert f.lower() not in lowered, f"{f!r} leaked into user_message: {msg!r}"
