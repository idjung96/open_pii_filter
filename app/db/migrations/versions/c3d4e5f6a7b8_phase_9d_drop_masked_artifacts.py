"""phase-9d: drop pii.masked_artifacts table

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-04-30 14:00:00.000000

Phase 9D — 마스킹 파이프라인 폐기. 검출 시 BLOCK 으로 즉시 거절하므로
마스킹 PNG 산출물 / 토큰 URL 의 저장 인프라가 더 이상 필요하지 않다.

이 마이그레이션은 Phase 5 에서 도입된 ``pii.masked_artifacts`` 테이블과
관련 인덱스를 제거한다. ``downgrade`` 는 참고용으로 동일한 컬럼 구조를
재생성한다 — 운영 데이터는 복원하지 않는다.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop ``pii.masked_artifacts`` table + indexes."""
    op.drop_index(
        op.f('ix_pii_masked_artifacts_token'),
        table_name='masked_artifacts',
        schema='pii',
    )
    op.drop_index(
        op.f('ix_pii_masked_artifacts_job_id'),
        table_name='masked_artifacts',
        schema='pii',
    )
    op.drop_index(
        op.f('ix_pii_masked_artifacts_expires_at'),
        table_name='masked_artifacts',
        schema='pii',
    )
    op.drop_table('masked_artifacts', schema='pii')


def downgrade() -> None:
    """Recreate the table for reference (no data restoration)."""
    op.create_table(
        'masked_artifacts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('job_id', sa.String(length=64), nullable=False),
        sa.Column('attachment_id', sa.String(length=64), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('mime_type', sa.String(length=100), nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['job_id'],
            ['pii.extraction_jobs.job_id'],
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        schema='pii',
    )
    op.create_index(
        op.f('ix_pii_masked_artifacts_expires_at'),
        'masked_artifacts',
        ['expires_at'],
        unique=False,
        schema='pii',
    )
    op.create_index(
        op.f('ix_pii_masked_artifacts_job_id'),
        'masked_artifacts',
        ['job_id'],
        unique=False,
        schema='pii',
    )
    op.create_index(
        op.f('ix_pii_masked_artifacts_token'),
        'masked_artifacts',
        ['token'],
        unique=True,
        schema='pii',
    )
