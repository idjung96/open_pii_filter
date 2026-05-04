"""phase-9a: pii.exception_ips + pii.api_ip_callers

Revision ID: a1b2c3d4e5f6
Revises: 9f3a7c2e1b41
Create Date: 2026-04-30 10:40:00.000000

Two new tables:

- ``exception_ips`` — CIDR allowlist for ``post.author.ip``. When the
  post author falls into any cached CIDR the body PII analysis is
  skipped and an OK-0000 PASS verdict is returned immediately.
- ``api_ip_callers`` — CIDR allowlist for HMAC-less authentication.
  When a request arrives without HMAC headers and the source IP matches
  a row, the request is authenticated as ``ip:<cidr>`` and per-row
  rate limits apply.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op


revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "9f3a7c2e1b41"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "exception_ips",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cidr", sa.String(length=50), nullable=False),
        sa.Column(
            "label",
            sa.String(length=200),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cidr", name="uq_exception_ips_cidr"),
        schema="pii",
    )
    op.create_index(
        op.f("ix_pii_exception_ips_cidr"),
        "exception_ips",
        ["cidr"],
        unique=True,
        schema="pii",
    )

    op.create_table(
        "api_ip_callers",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cidr", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column(
            "rate_per_minute",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
        sa.Column(
            "rate_per_hour",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1000"),
        ),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "rate_per_minute > 0 AND rate_per_hour > 0",
            name="ck_api_ip_callers_rate_positive",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cidr", name="uq_api_ip_callers_cidr"),
        schema="pii",
    )
    op.create_index(
        op.f("ix_pii_api_ip_callers_cidr"),
        "api_ip_callers",
        ["cidr"],
        unique=True,
        schema="pii",
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_pii_api_ip_callers_cidr"),
        table_name="api_ip_callers",
        schema="pii",
    )
    op.drop_table("api_ip_callers", schema="pii")
    op.drop_index(
        op.f("ix_pii_exception_ips_cidr"),
        table_name="exception_ips",
        schema="pii",
    )
    op.drop_table("exception_ips", schema="pii")
