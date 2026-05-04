"""phase-2g: disable weak (score < 0.50) seeded patterns by default

Revision ID: 6c1d3f4a5b02
Revises: 5b0c2e3f4a01
Create Date: 2026-04-25 16:30:00.000000

Q4 decision (operator review): seeded patterns with score below the
MIN_REPORTABLE_SCORE floor (0.50) are kept in the catalogue but start
``enabled=false`` so they don't add registry overhead until an operator
opts them in via ``python -m app.cli pattern enable <id>``.
"""
from __future__ import annotations

import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '6c1d3f4a5b02'
down_revision: Union[str, Sequence[str], None] = '5b0c2e3f4a01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # Soft-disable weak seeded patterns. Bumps version + writes UPDATE
    # history rows to satisfy the T2.5 audit invariant.
    rows = conn.execute(
        sa.text(
            "SELECT id, entity_type, pattern_name, regex, score, "
            "       context_words, strictness, version "
            "FROM pii.pii_patterns "
            "WHERE created_by = 'system:seed' "
            "  AND score < 0.50 "
            "  AND enabled = true"
        )
    ).fetchall()

    for row in rows:
        new_version = row.version + 1
        snapshot = json.dumps(
            {
                "id": row.id,
                "entity_type": row.entity_type,
                "pattern_name": row.pattern_name,
                "regex": row.regex,
                "score": row.score,
                "context_words": list(row.context_words or []),
                "strictness": row.strictness,
                "enabled": False,
                "version": new_version,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        conn.execute(
            sa.text(
                "UPDATE pii.pii_patterns "
                "SET enabled = false, version = :v "
                "WHERE id = :id"
            ),
            {"v": new_version, "id": row.id},
        )
        conn.execute(
            sa.text(
                "INSERT INTO pii.pii_pattern_history "
                "  (pattern_id, original_pattern_id, action, snapshot, changed_by) "
                "VALUES (:pid, :pid, 'UPDATE', :snap, 'system:seed-q4')"
            ),
            {"pid": row.id, "snap": snapshot},
        )


def downgrade() -> None:
    """Re-enable previously disabled weak seeds (best-effort)."""
    conn = op.get_bind()
    conn.execute(
        sa.text(
            "UPDATE pii.pii_patterns "
            "SET enabled = true, version = version + 1 "
            "WHERE created_by = 'system:seed' AND score < 0.50 AND enabled = false"
        )
    )
