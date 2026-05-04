"""phase-9b: audit_events detail columns (request/response body + headers)

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-04-30 11:00:00.000000

Adds three nullable TEXT columns to ``pii.audit_events`` so the
AuditMiddleware can optionally persist full request/response bodies and
sanitised headers for debugging.  Controlled at runtime by the
``audit_detail_enabled`` flag in ``data/system_settings.json``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'audit_events',
        sa.Column('request_body_text', sa.Text(), nullable=True),
        schema='pii',
    )
    op.add_column(
        'audit_events',
        sa.Column('response_body_text', sa.Text(), nullable=True),
        schema='pii',
    )
    op.add_column(
        'audit_events',
        sa.Column('request_headers_text', sa.Text(), nullable=True),
        schema='pii',
    )


def downgrade() -> None:
    op.drop_column('audit_events', 'request_headers_text', schema='pii')
    op.drop_column('audit_events', 'response_body_text', schema='pii')
    op.drop_column('audit_events', 'request_body_text', schema='pii')
