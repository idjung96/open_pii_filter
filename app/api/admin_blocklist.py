"""Admin CRUD for `pii.attachment_blocklist` (Phase 4b).

Endpoints (all gated by `require_admin` — same triple-check as
`/v1/admin/audit-events`):

  * GET    /v1/admin/attachment-blocklist          — list all rows
  * POST   /v1/admin/attachment-blocklist          — add a new entry
  * DELETE /v1/admin/attachment-blocklist/{row_id} — disable + delete

Every mutation reloads the in-process cache
(`app.core.blocklist_cache.reload_blocklist`) so the gate is updated
immediately without waiting for a process restart.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import delete, insert, select

from app.api.admin_audit import require_admin
from app.core.blocklist_cache import reload_blocklist
from app.db.models import AttachmentBlocklist
from app.db.session import get_sessionmaker
from app.security.hmac_auth import AuthedCaller

router = APIRouter(prefix="/v1/admin", tags=["admin-blocklist"])


# ── Pydantic IO models ────────────────────────────────────────────────────
class BlocklistRow(BaseModel):
    id: int
    extension: str | None
    mime_type: str | None
    reason: str
    enabled: bool
    created_at: datetime


class BlocklistAddRequest(BaseModel):
    extension: str | None = Field(default=None, max_length=32)
    mime_type: str | None = Field(default=None, max_length=100)
    reason: str = Field(default="", max_length=200)

    @model_validator(mode="after")
    def _at_least_one(self) -> BlocklistAddRequest:
        if not (self.extension or self.mime_type):
            raise ValueError("either extension or mime_type must be provided")
        return self


class BlocklistListResponse(BaseModel):
    rows: list[BlocklistRow]


# ── Routes ────────────────────────────────────────────────────────────────
@router.get(
    "/attachment-blocklist",
    response_model=BlocklistListResponse,
)
async def list_blocklist(
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> BlocklistListResponse:
    """List every blocklist row (enabled and disabled) for the operator."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(
            select(AttachmentBlocklist).order_by(AttachmentBlocklist.id.asc())
        )
        rows = [
            BlocklistRow(
                id=r.id,
                extension=r.extension,
                mime_type=r.mime_type,
                reason=r.reason,
                enabled=r.enabled,
                created_at=r.created_at,
            )
            for r in result.scalars().all()
        ]
    return BlocklistListResponse(rows=rows)


@router.post(
    "/attachment-blocklist",
    response_model=BlocklistRow,
    status_code=201,
)
async def add_blocklist(
    payload: BlocklistAddRequest,
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> BlocklistRow:
    """Insert a new blocklist row and reload the cache."""
    extension = payload.extension.strip().lower().lstrip(".") if payload.extension else None
    mime_type = payload.mime_type.strip().lower() if payload.mime_type else None

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        try:
            stmt = (
                insert(AttachmentBlocklist)
                .values(
                    extension=extension,
                    mime_type=mime_type,
                    reason=payload.reason,
                    enabled=True,
                )
                .returning(AttachmentBlocklist)
            )
            result = await session.execute(stmt)
            row = result.scalar_one()
            await session.commit()
        except Exception as e:
            await session.rollback()
            raise HTTPException(status_code=400, detail=str(e)) from e

        await reload_blocklist(session)
        return BlocklistRow(
            id=row.id,
            extension=row.extension,
            mime_type=row.mime_type,
            reason=row.reason,
            enabled=row.enabled,
            created_at=row.created_at,
        )


@router.delete(
    "/attachment-blocklist/{row_id}",
    status_code=204,
)
async def delete_blocklist(
    row_id: int,
    _caller: AuthedCaller = Depends(require_admin),  # noqa: B008
) -> None:
    """Hard-delete a blocklist row by id and reload the cache."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        existing = await session.execute(
            select(AttachmentBlocklist).where(AttachmentBlocklist.id == row_id)
        )
        if existing.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail=f"blocklist row {row_id} not found")
        await session.execute(delete(AttachmentBlocklist).where(AttachmentBlocklist.id == row_id))
        await session.commit()
        await reload_blocklist(session)
