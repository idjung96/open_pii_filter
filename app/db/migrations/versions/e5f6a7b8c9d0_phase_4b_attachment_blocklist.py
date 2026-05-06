"""phase-4b: attachment_blocklist + seed defaults

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-05-06

The new ``pii.attachment_blocklist`` table holds extensions and/or MIME
types that the gateway must reject before fetching the attachment. The
table is mutated at runtime through the admin API; the seed below
matches the project's documented policy (archives + legacy OLE Office +
HWP/HWPX) and gives operators a working baseline immediately after
migration.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: str | Sequence[str] | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# (extension, mime_type, reason) — at least one of (extension, mime_type) must
# be non-NULL per the table CHECK constraint.
_SEED: list[tuple[str | None, str | None, str]] = [
    # Archive containers — analyser cannot inspect packed payload safely.
    ("zip", "application/zip", "archive container"),
    ("rar", "application/vnd.rar", "archive container"),
    ("7z", "application/x-7z-compressed", "archive container"),
    ("tar", "application/x-tar", "archive container"),
    ("gz", "application/gzip", "archive container"),
    ("bz2", "application/x-bzip2", "archive container"),
    ("xz", "application/x-xz", "archive container"),
    ("tgz", None, "archive container"),
    ("tbz", None, "archive container"),
    ("txz", None, "archive container"),
    ("lz", None, "archive container"),
    ("lz4", None, "archive container"),
    ("zst", None, "archive container"),
    ("cab", None, "archive container"),
    ("arj", None, "archive container"),
    ("iso", "application/x-iso9660-image", "archive container"),
    ("lzma", None, "archive container"),
    ("z", None, "archive container"),
    ("ace", None, "archive container"),
    ("sit", None, "archive container"),
    ("dmg", None, "archive container"),
    ("alz", None, "archive container (kr)"),
    ("egg", None, "archive container (kr)"),
    # HWP / HWPX — Linux runtime cannot parse the OLE binary, and the
    # zip-based hwpx is too easy to abuse for archive smuggling.
    ("hwp", "application/x-hwp", "hwp legacy"),
    ("hwp", "application/haansofthwp", "hwp legacy"),
    ("hwpx", "application/hwp+zip", "hwpx"),
    ("hwpx", "application/x-hwpx", "hwpx"),
    ("hwpx", "application/haansofthwpx", "hwpx"),
    # Legacy OLE Office binaries — no MIT/BSD-licensed Linux extractor.
    ("doc", "application/msword", "legacy ole office"),
    ("xls", "application/vnd.ms-excel", "legacy ole office"),
    ("ppt", "application/vnd.ms-powerpoint", "legacy ole office"),
]


def upgrade() -> None:
    op.create_table(
        "attachment_blocklist",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("extension", sa.String(length=32), nullable=True),
        sa.Column("mime_type", sa.String(length=100), nullable=True),
        sa.Column(
            "reason",
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
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "extension IS NOT NULL OR mime_type IS NOT NULL",
            name="ck_attachment_blocklist_match_required",
        ),
        schema="pii",
    )
    op.create_index(
        "ix_pii_attachment_blocklist_extension",
        "attachment_blocklist",
        ["extension"],
        schema="pii",
    )
    op.create_index(
        "ix_pii_attachment_blocklist_mime_type",
        "attachment_blocklist",
        ["mime_type"],
        schema="pii",
    )

    # Seed default rows. We build a fully-schema-qualified Table object
    # so `op.bulk_insert` emits `INSERT INTO pii.attachment_blocklist` —
    # the lightweight `sa.table()` helper drops the schema otherwise.
    seed_table = sa.Table(
        "attachment_blocklist",
        sa.MetaData(),
        sa.Column("extension", sa.String(length=32)),
        sa.Column("mime_type", sa.String(length=100)),
        sa.Column("reason", sa.String(length=200)),
        sa.Column("enabled", sa.Boolean()),
        schema="pii",
    )
    rows = [
        {"extension": ext, "mime_type": mime, "reason": reason, "enabled": True}
        for ext, mime, reason in _SEED
    ]
    if rows:
        op.bulk_insert(seed_table, rows)


def downgrade() -> None:
    op.drop_index(
        "ix_pii_attachment_blocklist_mime_type",
        table_name="attachment_blocklist",
        schema="pii",
    )
    op.drop_index(
        "ix_pii_attachment_blocklist_extension",
        table_name="attachment_blocklist",
        schema="pii",
    )
    op.drop_table("attachment_blocklist", schema="pii")
