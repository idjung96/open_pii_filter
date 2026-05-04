"""phase-9e: drop pii.pii_patterns / pii.pii_pattern_history tables

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-04-30 16:00:00.000000

Phase 9E — 사용자 등록 정규식 패턴 인프라 폐기. 검증 로직 없는 단순
정규식 추가 기능은 운영 부담만 늘리고 코드 인식기(체크섬 검증 포함) +
Presidio 내장만으로 법적 위험은 충분히 커버된다.

이 마이그레이션은 Phase 2 에서 도입된 ``pii.pii_patterns`` 와
``pii.pii_pattern_history`` 테이블 + 관련 인덱스 / 트리거 / 시드 데이터를
모두 제거한다. ``downgrade`` 는 참고용으로 동일한 컬럼 구조를 재생성하지만
시드 패턴이나 운영 데이터는 복원하지 않는다.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop history table first (FK dependency), then patterns + triggers."""
    # Phase 2d 에서 도입된 NOTIFY 트리거 / 함수 정리 (있다면).
    op.execute("DROP TRIGGER IF EXISTS trg_pii_patterns_notify ON pii.pii_patterns;")
    op.execute("DROP FUNCTION IF EXISTS pii.notify_pii_pattern_changed() CASCADE;")

    # 자식 테이블(history) 먼저 drop — pii_pattern_history.pattern_id 가
    # pii_patterns.id 를 참조한다.
    op.drop_table("pii_pattern_history", schema="pii")
    op.drop_table("pii_patterns", schema="pii")


def downgrade() -> None:
    """Recreate the tables for reference (no data restoration)."""
    op.create_table(
        "pii_patterns",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("pattern_name", sa.String(length=128), nullable=False),
        sa.Column("regex", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column(
            "context_words",
            sa.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("ARRAY[]::TEXT[]"),
        ),
        sa.Column("strictness", sa.String(length=8), nullable=False),
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
        sa.CheckConstraint("score >= 0 AND score <= 1", name="ck_pii_patterns_score"),
        sa.CheckConstraint(
            "strictness IN ('low','medium','high')",
            name="ck_pii_patterns_strictness",
        ),
        sa.CheckConstraint(
            "mode IN ('enabled','shadow','disabled')",
            name="ck_pii_patterns_mode",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_type", "pattern_name", name="uq_pii_patterns_entity_name"),
        schema="pii",
    )
    op.create_index(
        op.f("ix_pii_pii_patterns_entity_type"),
        "pii_patterns",
        ["entity_type"],
        unique=False,
        schema="pii",
    )

    op.create_table(
        "pii_pattern_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("original_pattern_id", sa.Integer(), nullable=False),
        sa.Column("pattern_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("snapshot", sa.Text(), nullable=False),
        sa.Column(
            "changed_by",
            sa.String(length=64),
            nullable=False,
            server_default=sa.text("'system'"),
        ),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('INSERT','UPDATE','DELETE')",
            name="ck_pii_pattern_history_action",
        ),
        sa.ForeignKeyConstraint(
            ["pattern_id"],
            ["pii.pii_patterns.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="pii",
    )
    op.create_index(
        op.f("ix_pii_pii_pattern_history_original_pattern_id"),
        "pii_pattern_history",
        ["original_pattern_id"],
        unique=False,
        schema="pii",
    )
