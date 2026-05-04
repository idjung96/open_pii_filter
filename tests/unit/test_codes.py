"""Phase 1 tests for response-code catalog and response builder (T1.11~T1.17)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.api.responses import (
    audit_all_user_messages,
    build_response,
    user_message_safety_violations,
)
from app.api.schemas import Detection
from app.core.codes import CODES, Verdict, get_code


# ── T1.11: every code has required fields ──────────────────────────────────
def test_every_code_has_required_fields() -> None:
    for code, rc in CODES.items():
        assert rc.code == code, f"{code}: code field mismatch"
        assert rc.http_status in {200, 202, 400, 401, 403, 413, 415, 422, 429, 500, 503, 504}
        assert isinstance(rc.verdict, Verdict)
        assert rc.system_message, f"{code}: empty system_message"
        assert rc.user_message_template, f"{code}: empty user_message_template"


def test_category_prefixes_match_verdict() -> None:
    prefix_to_verdicts = {
        "OK-": {Verdict.PASS},
        "WARN-": {Verdict.WARN},
        "BLOCK-": {Verdict.BLOCK},
        "ACK-": {Verdict.PROCESSING},
        "REQ-": {Verdict.ERROR},
        "SVR-": {Verdict.ERROR},
    }
    for code, rc in CODES.items():
        prefix = code.split("-")[0] + "-"
        assert prefix in prefix_to_verdicts, f"unknown prefix in {code}"
        assert rc.verdict in prefix_to_verdicts[prefix], (
            f"{code} verdict {rc.verdict} mismatches prefix {prefix}"
        )


# ── T1.13: filename placeholder substitution ───────────────────────────────
def test_block_2010_renders_filename() -> None:
    resp = build_response(
        request_id=uuid4(),
        code="BLOCK-2010",
        processing_ms=10,
        template_vars={"filename": "신청서.pdf"},
    )
    assert "신청서.pdf" in resp.user_message
    assert "{filename}" not in resp.user_message


# ── T1.14: unknown entity type → fallback code ─────────────────────────────
def test_unknown_code_raises() -> None:
    with pytest.raises(KeyError):
        get_code("DOES-NOT-EXIST")


def test_fallback_codes_exist() -> None:
    # Fallback codes must be valid entries in the catalog.
    assert "BLOCK-2099" in CODES
    assert "WARN-1099" in CODES
    assert "OK-0000" in CODES


# ── T1.15: developer_message only for ERROR category ───────────────────────
def test_developer_message_only_for_error() -> None:
    req_id = uuid4()
    # PASS: no developer_message
    r_pass = build_response(request_id=req_id, code="OK-0000", processing_ms=1)
    assert r_pass.developer_message is None

    # BLOCK: no developer_message (§2.5 — not ERROR category)
    r_block = build_response(request_id=req_id, code="BLOCK-2001", processing_ms=1)
    assert r_block.developer_message is None

    # ERROR: developer_message rendered
    r_err = build_response(
        request_id=req_id,
        code="REQ-4010",
        processing_ms=1,
    )
    assert r_err.developer_message is not None
    assert "X-Signature" in r_err.developer_message


def test_error_developer_message_rendered_with_vars() -> None:
    req_id = uuid4()
    r = build_response(
        request_id=req_id,
        code="REQ-4015",
        processing_ms=1,
        template_vars={"ip": "10.0.0.1"},
    )
    assert r.developer_message is not None
    assert "10.0.0.1" in r.developer_message


# ── T1.16: user_message static check ───────────────────────────────────────
def test_no_user_message_leaks_internal_details() -> None:
    violations = audit_all_user_messages()
    assert not violations, (
        f"user_message templates leak internal details: {violations}"
    )


def test_safety_check_catches_known_leak() -> None:
    # Sanity: the scanner must detect a deliberately bad string.
    bad = "해당 KR_RRN (score 0.95)가 위치 12-26에서 검출되었습니다."
    hits = user_message_safety_violations(bad)
    assert "KR_RRN" in hits
    assert "score" in hits


# ── T1.12: response schema shape ──────────────────────────────────────────
def test_response_schema_fields_match_spec() -> None:
    """Phase 9D — masked 필드는 응답에서 제거되었다."""
    req_id = uuid4()
    r = build_response(
        request_id=req_id,
        code="BLOCK-2001",
        processing_ms=42,
        detections=[
            Detection(
                field="post.body",
                entity_type="KR_RRN",
                code="BLOCK-2001",
                score=0.98,
                start=12,
                end=26,
                masked_preview="900101-*******",
            )
        ],
    )
    dumped = r.model_dump()

    # §2.3 common envelope (Phase 9D 이후 'masked' 키 제거).
    for k in (
        "request_id", "verdict", "code", "system_message", "user_message",
        "developer_message", "detections", "processed_at", "processing_ms",
    ):
        assert k in dumped, f"missing field: {k}"
    assert "masked" not in dumped

    assert dumped["verdict"] == "BLOCK"
    assert dumped["code"] == "BLOCK-2001"
    assert dumped["processing_ms"] == 42
    assert len(dumped["detections"]) == 1


# ── Code count sanity (spec §2.4) ──────────────────────────────────────────
def test_code_catalog_covers_spec() -> None:
    required = {
        # PASS
        "OK-0000", "OK-0001",
        # WARN
        "WARN-1001", "WARN-1002", "WARN-1003", "WARN-1004", "WARN-1005", "WARN-1099",
        # BLOCK
        "BLOCK-2001", "BLOCK-2002", "BLOCK-2003", "BLOCK-2004", "BLOCK-2005",
        "BLOCK-2006", "BLOCK-2007", "BLOCK-2008", "BLOCK-2010", "BLOCK-2011",
        "BLOCK-2012", "BLOCK-2099",
        # ACK
        "ACK-3001", "ACK-3002",
        # REQ
        "REQ-4001", "REQ-4002", "REQ-4003", "REQ-4004", "REQ-4005",
        "REQ-4010", "REQ-4011", "REQ-4012", "REQ-4013", "REQ-4014", "REQ-4015",
        "REQ-4020", "REQ-4030", "REQ-4031", "REQ-4032", "REQ-4033",
        "REQ-4040", "REQ-4041", "REQ-4042", "REQ-4043", "REQ-4050", "REQ-4051",
        # SVR
        "SVR-5001", "SVR-5002", "SVR-5003", "SVR-5004", "SVR-5005",
        "SVR-5006", "SVR-5099",
    }
    missing = required - CODES.keys()
    assert not missing, f"missing codes from §2.4: {sorted(missing)}"
