"""phase-7b: pii.alerter_state — single-row table guarding the feedback alerter

Revision ID: 9f3a7c2e1b41
Revises: 9f3a7c2e1b40
Create Date: 2026-04-25 12:30:00.000000

Stores ``last_alert_at`` per alerter key so a process restart inside the
same hour doesn't re-send the same alert. Single-row upsert pattern
keyed by ``key`` (e.g. 'feedback').
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = "9f3a7c2e1b41"
down_revision: Union[str, Sequence[str], None] = "9f3a7c2e1b40"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerter_state",
        sa.Column("key", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column(
            "last_alert_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "last_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="pii",
    )


def downgrade() -> None:
    op.drop_table("alerter_state", schema="pii")
