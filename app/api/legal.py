"""GET /v1/legal/privacy-notice — public privacy notice (Phase 7).

Operator-decision D: render ``docs/privacy_notice.md`` with company /
DPO placeholders substituted from ``Settings``. Empty values are left
verbatim so a misconfigured deployment surfaces ``{{COMPANY_NAME}}``
in the body — operator notices, half-renders are not silently shipped.

Public — no auth: privacy notices must always be reachable.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.config import get_settings

router = APIRouter(prefix="/v1/legal", tags=["legal"])


# Repo root → docs/privacy_notice.md
_DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "privacy_notice.md"


_FALLBACK_TEMPLATE = """# 개인정보 처리방침 (PII Detection API)

**회사명**: {{COMPANY_NAME}}
**문의 이메일**: {{COMPANY_CONTACT_EMAIL}}
**문의 전화**: {{COMPANY_CONTACT_PHONE}}

**개인정보 보호책임자**: {{DATA_PROTECTION_OFFICER_NAME}}
**보호책임자 이메일**: {{DATA_PROTECTION_OFFICER_EMAIL}}

본 API는 기관 대표홈페이지 게시판에 게시되는 글의 개인정보 자동 검출
및 마스킹 처리를 위해 사용됩니다.

자세한 내용은 운영자에게 문의하세요.
"""


def _load_template() -> str:
    """Read the template file; fall back to the embedded copy if missing."""
    try:
        return _DOC_PATH.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return _FALLBACK_TEMPLATE


def _render(template: str) -> str:
    s = get_settings()
    # Both the new and the legacy ``docs/privacy_notice.md`` placeholders
    # resolve to the same Settings fields. Empty values keep the
    # placeholder verbatim so the operator notices the gap.
    mapping = {
        "{{COMPANY_NAME}}": s.company_name,
        "{{COMPANY}}": s.company_name,
        "{{COMPANY_CONTACT_EMAIL}}": s.company_contact_email,
        "{{COMPANY_CONTACT_PHONE}}": s.company_contact_phone,
        "{{CONTACT}}": s.company_contact_email,
        "{{DPO_EMAIL}}": s.data_protection_officer_email,
        "{{DPO_NAME}}": s.data_protection_officer_name,
        "{{DATA_PROTECTION_OFFICER_NAME}}": s.data_protection_officer_name,
        "{{DATA_PROTECTION_OFFICER_EMAIL}}": s.data_protection_officer_email,
    }
    out = template
    for placeholder, value in mapping.items():
        if value:
            out = out.replace(placeholder, value)
        # else: leave the placeholder verbatim — operators will notice.
    return out


@router.get("/privacy-notice", response_class=PlainTextResponse)
async def privacy_notice() -> PlainTextResponse:
    """Return the rendered privacy notice as text/markdown."""
    rendered = _render(_load_template())
    return PlainTextResponse(
        content=rendered,
        media_type="text/markdown; charset=utf-8",
    )
