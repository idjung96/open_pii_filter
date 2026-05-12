# SYNTHETIC DATA - NOT REAL PII
"""Phase 7 — 공개 개인정보처리방침 (`/v1/legal/privacy-notice`) 회귀 방지.

운영자가 `Settings` 의 회사명·연락처 등을 채우면 마크다운 템플릿의
`{{COMPANY_NAME}}` 같은 placeholder 가 그 값으로 치환되어 응답에 반영
되고, 비어 있는 항목은 placeholder 그대로 남아 운영자가 누락을 알아
챌 수 있도록 한다.

또한 이 엔드포인트는 HMAC 인증 없이 공개 호출 가능해야 한다 (요구사항).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from app.config import Settings

if TYPE_CHECKING:
    from httpx import AsyncClient


def _settings_with(**overrides):  # type: ignore[no-untyped-def]
    base = Settings().model_dump()
    base.update(overrides)
    return Settings(**base)


async def test_privacy_notice_substitutes_company_name(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = lambda: _settings_with(  # noqa: E731
        company_name="기관",
        company_contact_email="contact@example.org",
        data_protection_officer_name="홍길동",
        data_protection_officer_email="dpo@example.org",
    )
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.api.legal as legal_mod

    monkeypatch.setattr(legal_mod, "get_settings", fake)

    resp = await client.get("/v1/legal/privacy-notice")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    body = resp.text
    assert "기관" in body
    # Untouched placeholders mean the operator can spot missing config.
    # When all settings populated, no placeholder should remain for the
    # configured ones.
    assert "{{COMPANY_NAME}}" not in body
    assert "{{COMPANY}}" not in body


async def test_privacy_notice_unset_keeps_placeholder(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty Settings → placeholder remains verbatim."""
    fake = lambda: _settings_with(  # noqa: E731
        company_name="",
        company_contact_email="",
    )
    monkeypatch.setattr("app.config.get_settings", fake)
    import app.api.legal as legal_mod

    monkeypatch.setattr(legal_mod, "get_settings", fake)

    resp = await client.get("/v1/legal/privacy-notice")
    assert resp.status_code == 200
    body = resp.text
    # At least one placeholder still present somewhere.
    assert "{{" in body and "}}" in body


async def test_privacy_notice_is_public(client_anon: AsyncClient) -> None:
    """No HMAC required."""
    resp = await client_anon.get("/v1/legal/privacy-notice")
    assert resp.status_code == 200
