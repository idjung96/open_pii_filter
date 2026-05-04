"""phase-2c: seed 32 default patterns into pii_patterns

Revision ID: 4a7f8b1c0d92
Revises: 3d16cb2b60e7
Create Date: 2026-04-25 10:10:00.000000

Augments the hardcoded Phase 1 recognizers (KR_RRN/PHONE/BUSINESS_NUM/
BANK_ACCOUNT/DRIVERLICENSE/PASSPORT, EMAIL, CREDIT_CARD) with 32
DB-managed patterns. The seeded patterns cover *new* coverage areas
(landline phones, foreigner reg, vehicle plates, IP/URL, etc.) so that
T2.1 parity holds: every detection produced by Phase 1 is still produced
after seeding, and the seed never overrides an existing entity_type's
core regex.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '4a7f8b1c0d92'
down_revision: Union[str, Sequence[str], None] = '3d16cb2b60e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


SEED_PATTERNS: list[dict[str, object]] = [
    # ── KR_PHONE_LAND (landline) ──────────────────────────────────────────
    {"entity_type": "KR_PHONE_LAND", "pattern_name": "land_seoul_hyphen",
     "regex": r"(?<!\d)02-\d{3,4}-\d{4}(?!\d)", "score": 0.85,
     "context_words": ["전화", "tel", "유선"]},
    {"entity_type": "KR_PHONE_LAND", "pattern_name": "land_regional_hyphen",
     "regex": r"(?<!\d)0(3[1-3]|4[1-4]|5[1-5]|6[1-4])-\d{3,4}-\d{4}(?!\d)",
     "score": 0.85, "context_words": ["전화", "tel"]},
    {"entity_type": "KR_PHONE_LAND", "pattern_name": "land_intl",
     "regex": r"\+82[-\s]?(2|3[1-3]|4[1-4]|5[1-5]|6[1-4])[-\s]?\d{3,4}[-\s]?\d{4}",
     "score": 0.85, "context_words": ["전화", "tel"]},
    {"entity_type": "KR_PHONE_INET", "pattern_name": "phone_070",
     "regex": r"(?<!\d)070-\d{3,4}-\d{4}(?!\d)", "score": 0.8,
     "context_words": ["인터넷", "전화"]},
    {"entity_type": "KR_PHONE_INET", "pattern_name": "phone_050",
     "regex": r"(?<!\d)050\d-\d{3,4}-\d{4}(?!\d)", "score": 0.75,
     "context_words": ["안심번호", "050"]},
    {"entity_type": "KR_FAX", "pattern_name": "fax_hyphen",
     "regex": r"(?<!\d)0\d{1,2}-\d{3,4}-\d{4}(?!\d)", "score": 0.4,
     "context_words": ["팩스", "fax", "fax번호"]},

    # ── KR_BANK_ACCOUNT extra layouts ──────────────────────────────────────
    {"entity_type": "KR_BANK_ACCOUNT", "pattern_name": "krbank_3_6_3",
     "regex": r"(?<!\d)\d{3}-\d{6}-\d{3}(?!\d)", "score": 0.85,
     "context_words": ["계좌", "입금", "송금"]},
    {"entity_type": "KR_BANK_ACCOUNT", "pattern_name": "krbank_4_2_7",
     "regex": r"(?<!\d)\d{4}-\d{2}-\d{7}(?!\d)", "score": 0.85,
     "context_words": ["계좌", "우체국", "post"]},
    {"entity_type": "KR_BANK_ACCOUNT", "pattern_name": "krbank_6_2_2_3",
     "regex": r"(?<!\d)\d{6}-\d{2}-\d{2}-\d{3}(?!\d)", "score": 0.8,
     "context_words": ["계좌", "농협"]},
    {"entity_type": "KR_VIRTUAL_ACCOUNT", "pattern_name": "krvacc_16",
     "regex": r"(?<!\d)\d{16}(?!\d)", "score": 0.5,
     "context_words": ["가상계좌", "virtual"]},

    # ── Korean specialty IDs ───────────────────────────────────────────────
    {"entity_type": "KR_FOREIGN_REG", "pattern_name": "foreign_rrn",
     "regex": r"(?<!\d)\d{6}-[5-8]\d{6}(?!\d)", "score": 0.8,
     "context_words": ["외국인", "alien", "registration"]},
    {"entity_type": "KR_HEALTH_INS", "pattern_name": "health_ins_11",
     "regex": r"(?<!\d)\d-\d{10}(?!\d)", "score": 0.7,
     "context_words": ["건강보험", "보험증", "건강"]},
    {"entity_type": "KR_CORP_REG", "pattern_name": "corp_reg_13",
     "regex": r"(?<!\d)\d{6}-\d{7}(?!\d)", "score": 0.6,
     "context_words": ["법인등록", "법인", "corporate"]},

    # ── Vehicle plates ─────────────────────────────────────────────────────
    {"entity_type": "KR_VEHICLE_PLATE", "pattern_name": "plate_old",
     "regex": r"(?<![가-힣\d])\d{2}[가-힣]\d{4}(?![가-힣\d])", "score": 0.8,
     "context_words": ["차량", "번호판", "자동차"]},
    {"entity_type": "KR_VEHICLE_PLATE", "pattern_name": "plate_new",
     "regex": r"(?<![가-힣\d])\d{3}[가-힣]\d{4}(?![가-힣\d])", "score": 0.8,
     "context_words": ["차량", "번호판", "자동차"]},

    # ── Postal / address ───────────────────────────────────────────────────
    {"entity_type": "KR_ZIPCODE", "pattern_name": "zip_5",
     "regex": r"(?<!\d)\d{5}(?!\d)", "score": 0.3,
     "context_words": ["우편번호", "zip", "주소"]},
    {"entity_type": "KR_ZIPCODE", "pattern_name": "zip_legacy",
     "regex": r"(?<!\d)\d{3}-\d{3}(?!\d)", "score": 0.4,
     "context_words": ["우편번호", "zip"]},

    # ── Card supplemental (NOT card-number itself; that's CREDIT_CARD) ────
    {"entity_type": "KR_CARD_VALIDITY", "pattern_name": "card_validity",
     "regex": r"(?<!\d)(0[1-9]|1[0-2])/(\d{2})(?!\d)", "score": 0.4,
     "context_words": ["유효기간", "valid", "expiry"]},
    {"entity_type": "KR_CARD_CVC", "pattern_name": "card_cvc",
     "regex": r"(?<!\d)\d{3,4}(?!\d)", "score": 0.2,
     "context_words": ["cvc", "cvv", "보안코드"]},

    # ── Date of birth ──────────────────────────────────────────────────────
    {"entity_type": "DATE_OF_BIRTH", "pattern_name": "dob_dash",
     "regex": r"(?<!\d)(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?!\d)",
     "score": 0.5, "context_words": ["생년월일", "생일", "DOB", "출생"]},
    {"entity_type": "DATE_OF_BIRTH", "pattern_name": "dob_dot",
     "regex": r"(?<!\d)(19|20)\d{2}\.(0[1-9]|1[0-2])\.(0[1-9]|[12]\d|3[01])(?!\d)",
     "score": 0.5, "context_words": ["생년월일", "생일", "DOB", "출생"]},
    {"entity_type": "DATE_OF_BIRTH", "pattern_name": "dob_compact",
     "regex": r"(?<!\d)(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?!\d)",
     "score": 0.4, "context_words": ["생년월일", "생일"]},

    # ── Network identifiers ────────────────────────────────────────────────
    {"entity_type": "IP_ADDRESS", "pattern_name": "ipv4",
     "regex": r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
              r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?!\d)", "score": 0.85,
     "context_words": ["ip", "주소"]},
    {"entity_type": "IP_ADDRESS", "pattern_name": "ipv6_simple",
     "regex": r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}(?![A-Fa-f0-9:])",
     "score": 0.85, "context_words": ["ipv6"]},
    {"entity_type": "MAC_ADDRESS", "pattern_name": "mac_colon",
     "regex": r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}(?![A-Fa-f0-9:])",
     "score": 0.85, "context_words": ["mac", "맥주소", "mac주소"]},
    {"entity_type": "URL", "pattern_name": "url_http",
     "regex": r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", "score": 0.7,
     "context_words": ["url", "주소", "링크"]},
    {"entity_type": "EMAIL_ADDRESS", "pattern_name": "email_kr_domain",
     "regex": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.kr\b", "score": 0.9,
     "context_words": ["이메일", "메일", "email"]},

    # ── Older / legacy formats ────────────────────────────────────────────
    {"entity_type": "KR_PASSPORT", "pattern_name": "krpass_legacy_3letter",
     "regex": r"(?<![A-Za-z0-9])[A-Z]{3}\d{6}(?![A-Za-z0-9])", "score": 0.5,
     "context_words": ["여권", "passport"]},
    {"entity_type": "KR_DRIVERLICENSE", "pattern_name": "krdl_plain",
     "regex": r"(?<!\d)\d{12}(?!\d)", "score": 0.4,
     "context_words": ["운전면허", "면허"]},

    # ── PII context-only signals (low score; require context to fire) ─────
    {"entity_type": "KR_NAME_HINT", "pattern_name": "korean_name_3char",
     "regex": r"(?<![가-힣])[가-힣]{2,4}(?![가-힣])", "score": 0.15,
     "context_words": ["이름", "성명", "name", "고객명"]},
    {"entity_type": "KR_EMPLOYEE_ID", "pattern_name": "emp_id_alpha_digits",
     "regex": r"(?<![A-Z0-9])[A-Z]{1,3}\d{4,6}(?![A-Z0-9])", "score": 0.4,
     "context_words": ["사번", "employee", "직원번호"]},
    {"entity_type": "KR_ACCOUNT_TOKEN", "pattern_name": "account_uuidish",
     "regex": r"(?<![A-Fa-f0-9-])[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-"
              r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}(?![A-Fa-f0-9-])",
     "score": 0.5, "context_words": ["토큰", "token", "uuid"]},
]


def upgrade() -> None:
    """Insert the 32 default patterns + history INSERT rows."""
    conn = op.get_bind()

    rows = [
        {
            "entity_type": p["entity_type"],
            "pattern_name": p["pattern_name"],
            "regex": p["regex"],
            "score": p["score"],
            "context_words": list(p.get("context_words", [])),
            "strictness": "medium",
            "enabled": True,
            "version": 1,
            "created_by": "system:seed",
        }
        for p in SEED_PATTERNS
    ]

    insert_sql = sa.text(
        """
        INSERT INTO pii.pii_patterns
          (entity_type, pattern_name, regex, score, context_words,
           strictness, enabled, version, created_by)
        VALUES
          (:entity_type, :pattern_name, :regex, :score, :context_words,
           :strictness, :enabled, :version, :created_by)
        ON CONFLICT (entity_type, pattern_name) DO NOTHING
        RETURNING id
        """
    )
    history_sql = sa.text(
        """
        INSERT INTO pii.pii_pattern_history
          (pattern_id, original_pattern_id, action, snapshot, changed_by)
        VALUES
          (:pid, :pid, 'INSERT', :snapshot, 'system:seed')
        """
    )

    import json
    for row in rows:
        result = conn.execute(insert_sql, row)
        new_id = result.scalar()
        if new_id is None:
            continue  # ON CONFLICT — already seeded
        snapshot = json.dumps(
            {
                "id": new_id,
                "entity_type": row["entity_type"],
                "pattern_name": row["pattern_name"],
                "regex": row["regex"],
                "score": row["score"],
                "context_words": row["context_words"],
                "strictness": row["strictness"],
                "enabled": row["enabled"],
                "version": row["version"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        conn.execute(history_sql, {"pid": new_id, "snapshot": snapshot})


def downgrade() -> None:
    """Remove the seeded patterns (and their history rows) by created_by tag."""
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "DELETE FROM pii.pii_pattern_history WHERE changed_by = 'system:seed'"
        )
    )
    conn.execute(
        sa.text("DELETE FROM pii.pii_patterns WHERE created_by = 'system:seed'")
    )
