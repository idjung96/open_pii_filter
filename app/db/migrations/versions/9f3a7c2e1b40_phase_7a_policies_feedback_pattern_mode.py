"""phase-7a: pii_policies + pii_feedback + pattern.mode + audit shadow_hit_types

Revision ID: 9f3a7c2e1b40
Revises: 8e1f5d2a9c30
Create Date: 2026-04-25 12:00:00.000000

Phase 7 — policy engine + false-positive feedback + shadow mode.

Adds:
  - ``pii.pii_policies`` — DB-driven (entity_type, score band) → action
    overrides on top of the code-defined policies.py mapping.
  - ``pii.pii_feedback`` — append-only false-positive reports submitted via
    POST /v1/feedback.
  - ``pii_patterns.mode`` (text: 'enabled' | 'shadow' | 'disabled') replacing
    the boolean ``enabled`` column.
  - ``audit_events.shadow_hit_types`` — comma-separated list of entity_types
    that fired only in shadow mode (verdict-neutral).
  - NOTIFY trigger on ``pii_policies`` mirroring Phase 2d so the analyzer
    cache + policy cache hot-reload via the existing pattern_listener.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = "9f3a7c2e1b40"
down_revision: Union[str, Sequence[str], None] = "8e1f5d2a9c30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── pii_policies ────────────────────────────────────────────────────────
    op.create_table(
        "pii_policies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("score_min", sa.Float(), nullable=False),
        sa.Column("score_max", sa.Float(), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column(
            "user_message_template",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "mode",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'enabled'"),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "created_by",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'system'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('BLOCK','WARN','MASK','LOG_ONLY','PASS')",
            name="ck_pii_policies_action",
        ),
        sa.CheckConstraint(
            "mode IN ('enabled','shadow','disabled')",
            name="ck_pii_policies_mode",
        ),
        sa.CheckConstraint(
            "score_min >= 0 AND score_max <= 1 AND score_min <= score_max",
            name="ck_pii_policies_score_band",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "entity_type",
            "score_min",
            "score_max",
            "mode",
            name="uq_pii_policies_entity_band_mode",
        ),
        schema="pii",
    )
    op.create_index(
        op.f("ix_pii_pii_policies_entity_type"),
        "pii_policies",
        ["entity_type"],
        unique=False,
        schema="pii",
    )

    # ── pii_feedback ────────────────────────────────────────────────────────
    op.create_table(
        "pii_feedback",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("original_code", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        # SHA-256 hex of (project salt + email or source IP). Never stores
        # the plaintext email — privacy invariant.
        sa.Column("reporter_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="pii",
    )
    op.create_index(
        op.f("ix_pii_pii_feedback_request_id"),
        "pii_feedback",
        ["request_id"],
        unique=False,
        schema="pii",
    )
    op.create_index(
        "ix_pii_pii_feedback_created_at_desc",
        "pii_feedback",
        [sa.text("created_at DESC")],
        unique=False,
        schema="pii",
    )

    # ── pii_patterns.enabled BOOL → pii_patterns.mode TEXT ─────────────────
    op.add_column(
        "pii_patterns",
        sa.Column(
            "mode",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'enabled'"),
        ),
        schema="pii",
    )
    op.execute(
        "UPDATE pii.pii_patterns SET mode = CASE WHEN enabled THEN 'enabled' ELSE 'disabled' END"
    )
    op.create_check_constraint(
        "ck_pii_patterns_mode",
        "pii_patterns",
        "mode IN ('enabled','shadow','disabled')",
        schema="pii",
    )
    op.drop_column("pii_patterns", "enabled", schema="pii")

    # ── audit_events.shadow_hit_types (verdict-neutral shadow detections) ──
    op.add_column(
        "audit_events",
        sa.Column("shadow_hit_types", sa.Text(), nullable=True),
        schema="pii",
    )

    # ── NOTIFY trigger on pii_policies (mirrors phase-2d) ──────────────────
    op.execute(
        """
        DROP TRIGGER IF EXISTS pii_policies_notify ON pii.pii_policies;
        CREATE TRIGGER pii_policies_notify
            AFTER INSERT OR UPDATE OR DELETE ON pii.pii_policies
            FOR EACH ROW EXECUTE FUNCTION pii.pii_notify_pattern_change();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS pii_policies_notify ON pii.pii_policies;")

    op.drop_column("audit_events", "shadow_hit_types", schema="pii")

    # Restore pii_patterns.enabled BOOL
    op.add_column(
        "pii_patterns",
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        schema="pii",
    )
    op.execute("UPDATE pii.pii_patterns SET enabled = (mode = 'enabled')")
    op.drop_constraint("ck_pii_patterns_mode", "pii_patterns", schema="pii")
    op.drop_column("pii_patterns", "mode", schema="pii")

    op.drop_index(
        "ix_pii_pii_feedback_created_at_desc",
        table_name="pii_feedback",
        schema="pii",
    )
    op.drop_index(
        op.f("ix_pii_pii_feedback_request_id"),
        table_name="pii_feedback",
        schema="pii",
    )
    op.drop_table("pii_feedback", schema="pii")

    op.drop_index(
        op.f("ix_pii_pii_policies_entity_type"),
        table_name="pii_policies",
        schema="pii",
    )
    op.drop_table("pii_policies", schema="pii")
