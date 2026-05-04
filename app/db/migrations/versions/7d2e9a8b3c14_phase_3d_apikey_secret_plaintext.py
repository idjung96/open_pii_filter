"""phase-3d: rename api_keys.secret_hash → api_keys.secret (Q1)

Revision ID: 7d2e9a8b3c14
Revises: ff6df8c4d0ad
Create Date: 2026-04-25 17:30:00.000000

Q1 decision (operator review): switch to standard HMAC where the
client signs with the plaintext secret and the server stores the same.
The legacy 'secret_hash' column is renamed to 'secret'. Existing rows
hold the old digest value — operators must re-issue keys after this
migration runs.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "7d2e9a8b3c14"
down_revision: Union[str, Sequence[str], None] = "ff6df8c4d0ad"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("api_keys", "secret_hash", new_column_name="secret", schema="pii")


def downgrade() -> None:
    op.alter_column("api_keys", "secret", new_column_name="secret_hash", schema="pii")
