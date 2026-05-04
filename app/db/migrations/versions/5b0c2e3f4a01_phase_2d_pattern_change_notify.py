"""phase-2d: NOTIFY trigger on pii_patterns + pii_deny_list (T2.2/T2.8)

Revision ID: 5b0c2e3f4a01
Revises: 4a7f8b1c0d92
Create Date: 2026-04-25 10:25:00.000000

Adds a stored function + trigger that emits `NOTIFY pii_pattern_changed`
on every INSERT/UPDATE/DELETE on pii_patterns and pii_deny_list. The
worker subscribes to this channel; on disconnect it falls back to
polling `max(updated_at)`.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = '5b0c2e3f4a01'
down_revision: Union[str, Sequence[str], None] = '4a7f8b1c0d92'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


CHANNEL = "pii_pattern_changed"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION pii.pii_notify_pattern_change()
        RETURNS TRIGGER AS $$
        DECLARE
            payload TEXT;
        BEGIN
            payload := json_build_object(
                'table',  TG_TABLE_NAME,
                'action', TG_OP,
                'id',     COALESCE(NEW.id, OLD.id)
            )::text;
            PERFORM pg_notify('{CHANNEL}', payload);
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        """
        DROP TRIGGER IF EXISTS pii_patterns_notify ON pii.pii_patterns;
        CREATE TRIGGER pii_patterns_notify
            AFTER INSERT OR UPDATE OR DELETE ON pii.pii_patterns
            FOR EACH ROW EXECUTE FUNCTION pii.pii_notify_pattern_change();
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS pii_deny_list_notify ON pii.pii_deny_list;
        CREATE TRIGGER pii_deny_list_notify
            AFTER INSERT OR UPDATE OR DELETE ON pii.pii_deny_list
            FOR EACH ROW EXECUTE FUNCTION pii.pii_notify_pattern_change();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS pii_patterns_notify ON pii.pii_patterns;")
    op.execute("DROP TRIGGER IF EXISTS pii_deny_list_notify ON pii.pii_deny_list;")
    op.execute("DROP FUNCTION IF EXISTS pii.pii_notify_pattern_change();")
