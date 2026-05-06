"""Korean human-readable labels for Presidio entity types (Phase 4b/C).

Detect responses surface the *kind* of PII found so the bulletin-board
operator can act on it ("주민등록번호 가 본문에 포함되어…"). The mapping
returns a Korean noun phrase for each entity_type the analyzer can
emit; unknown types fall back to a generic "개인정보" label.

Importantly the LABELS, not the entity codes themselves (KR_RRN,
EMAIL_ADDRESS, …), are surfaced in `user_message`. The forbidden-string
filter in `app.api.responses` continues to block raw codes so this
module can never accidentally regress §2.5.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

# Mapping is ordered for deterministic test snapshots; Python 3.7+
# preserves insertion order.
ENTITY_LABELS_KR: dict[str, str] = {
    "KR_RRN": "주민등록번호",
    "KR_DRIVERLICENSE": "운전면허번호",
    "KR_PASSPORT": "여권번호",
    "KR_PHONE": "전화번호",
    "KR_BUSINESS_NUM": "사업자등록번호",
    "KR_BANK_ACCOUNT": "계좌번호",
    "KR_BANK_ACCOUNT_WEAK": "계좌번호",
    "EMAIL_ADDRESS": "이메일",
    "CREDIT_CARD": "신용카드번호",
    "PERSON": "이름",
    "LOCATION": "주소",
    "INTERNAL_NAME": "기관 임직원 정보",
}

_FALLBACK_LABEL = "개인정보"


class _HasEntityType(Protocol):
    entity_type: str


def label_for(entity_type: str) -> str:
    """Translate a single entity_type into its Korean label."""
    return ENTITY_LABELS_KR.get(entity_type, _FALLBACK_LABEL)


def detected_summary_kr(
    detections: Iterable[_HasEntityType | dict[str, object]],
) -> str:
    """Compose a comma-joined Korean summary of detected PII kinds.

    Returns an empty string when no detections are passed in. Both
    pydantic models (with ``.entity_type``) and raw dicts are accepted
    so the helper can be used from response builders and audit code
    paths without an extra adapter step.
    """
    seen: set[str] = set()
    labels: list[str] = []
    for d in detections:
        if isinstance(d, dict):
            et = d.get("entity_type")
            if not isinstance(et, str):
                continue
        else:
            et = getattr(d, "entity_type", None)
            if not isinstance(et, str):
                continue
        lbl = label_for(et)
        if lbl in seen:
            continue
        seen.add(lbl)
        labels.append(lbl)
    return ", ".join(labels)
