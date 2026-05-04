"""phase-6a: audit_events + append-only triggers

Revision ID: 8e1f5d2a9c30
Revises: 5a885a8844a1
Create Date: 2026-04-25 23:55:00.000000

Creates ``pii.audit_events`` plus a BEFORE UPDATE / BEFORE DELETE trigger
that raises an exception, enforcing the append-only invariant of the
audit log. The retention cleanup worker bypasses the trigger by setting
``SET LOCAL app.bypass_audit_lock = 'on'`` inside its transaction.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = '8e1f5d2a9c30'
down_revision: Union[str, Sequence[str], None] = '5a885a8844a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # api_keys.is_admin — gate for /v1/admin/* endpoints (Phase 6).
    op.add_column(
        'api_keys',
        sa.Column(
            'is_admin',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('false'),
        ),
        schema='pii',
    )

    op.create_table(
        'audit_events',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('request_id', sa.String(length=64), nullable=False),
        sa.Column(
            'occurred_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('api_key_id', sa.String(length=64), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('path', sa.String(length=256), nullable=False),
        sa.Column('http_status', sa.Integer(), nullable=True),
        sa.Column('response_code', sa.String(length=16), nullable=True),
        sa.Column(
            'detected_entity_count',
            sa.Integer(),
            nullable=False,
            server_default=sa.text('0'),
        ),
        sa.Column('detected_entity_types', sa.Text(), nullable=True),
        sa.Column('processing_ms', sa.Integer(), nullable=True),
        sa.Column('body_hash', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        schema='pii',
    )
    op.create_index(
        op.f('ix_pii_audit_events_request_id'),
        'audit_events',
        ['request_id'],
        unique=False,
        schema='pii',
    )
    op.create_index(
        op.f('ix_pii_audit_events_occurred_at'),
        'audit_events',
        ['occurred_at'],
        unique=False,
        schema='pii',
    )
    op.create_index(
        op.f('ix_pii_audit_events_api_key_id'),
        'audit_events',
        ['api_key_id'],
        unique=False,
        schema='pii',
    )
    op.create_index(
        'ix_pii_audit_events_apikey_occurred',
        'audit_events',
        ['api_key_id', sa.text('occurred_at DESC')],
        unique=False,
        schema='pii',
    )

    # Append-only trigger function. The cleanup worker sets
    # `app.bypass_audit_lock = 'on'` to allow retention DELETEs.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION pii.reject_audit_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF coalesce(current_setting('app.bypass_audit_lock', true), '') = 'on' THEN
                RETURN COALESCE(NEW, OLD);
            END IF;
            RAISE EXCEPTION 'audit_events is append-only (use app.bypass_audit_lock for retention cleanup)';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_audit_no_update ON pii.audit_events;
        CREATE TRIGGER trg_audit_no_update
            BEFORE UPDATE ON pii.audit_events
            FOR EACH ROW EXECUTE FUNCTION pii.reject_audit_mutation();
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_audit_no_delete ON pii.audit_events;
        CREATE TRIGGER trg_audit_no_delete
            BEFORE DELETE ON pii.audit_events
            FOR EACH ROW EXECUTE FUNCTION pii.reject_audit_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_no_update ON pii.audit_events;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_no_delete ON pii.audit_events;")
    op.execute("DROP FUNCTION IF EXISTS pii.reject_audit_mutation();")
    op.drop_index(
        'ix_pii_audit_events_apikey_occurred',
        table_name='audit_events',
        schema='pii',
    )
    op.drop_index(
        op.f('ix_pii_audit_events_api_key_id'),
        table_name='audit_events',
        schema='pii',
    )
    op.drop_index(
        op.f('ix_pii_audit_events_occurred_at'),
        table_name='audit_events',
        schema='pii',
    )
    op.drop_index(
        op.f('ix_pii_audit_events_request_id'),
        table_name='audit_events',
        schema='pii',
    )
    op.drop_table('audit_events', schema='pii')
    op.drop_column('api_keys', 'is_admin', schema='pii')
