# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — 응답 envelope 에 평문 PII 가 절대 새지 않는지 회귀 방지 (T6.6).

`Detection` 스키마는 (field / entity_type / code / score / start / end) 만
노출하며, 매칭된 원본 문자열은 절대 포함되지 않는다. 실제
`/v1/detect/post` round-trip 응답을 합성 RRN/전화/이메일로 채워 보낸 뒤
다음을 모두 확인한다:

  - Detection 객체에 `text` 같은 평문 키가 없음
  - masked_preview 가 있어도 원본 PII 문자열과 일치하지 않음 (마스킹 처리)
  - 응답 전체 텍스트 (헤더+본문) 에 합성 PII 가 등장하지 않음
  - `user_message` 가 §2.5 금지어 (entity 코드 / score / 알고리즘명) 미노출
  - ERROR 가 아닌 응답의 `developer_message` 는 None / 빈 문자열
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from tests.fixtures.synthetic_pii_generator import SyntheticPIIGenerator

if TYPE_CHECKING:
    from httpx import AsyncClient


async def test_response_has_no_plaintext_pii(client: AsyncClient) -> None:
    """RRN+전화+이메일이 섞인 본문을 보내고 응답 전체에 평문이 새는지 검사.

    Detection 의 키 집합 화이트리스트 검증 + masked_preview 마스킹 확인 +
    응답 raw text 그루핑 검증의 3중 가드. 한 단계라도 깨지면 응답으로
    PII 가 외부에 나가는 사고 직결.
    """
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
    """non-ERROR 응답 (OK-/BLOCK-) 의 developer_message 는 None/빈 문자열 (T6.6).

    내부 진단 정보가 PASS 응답까지 따라가면 운영 디버깅 단서가 사용자에게
    노출되는 사고 발생.
    """
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
    """user_message 가 entity 타입명·score·알고리즘명 등 내부 디테일을 노출 금지.

    "presidio/spacy/gliner/regex" 등 알고리즘 이름이나 "KR_RRN/KR_PHONE"
    같은 raw entity 코드가 사용자 메시지에 새면 ① 내부 구현 노출 ② 사용자
    혼란. forbidden 목록을 대소문자 무관 검사하여 회귀를 1차로 잡는다.
    """
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
