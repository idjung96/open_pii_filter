"""High-level helper that records an audit_events row from middleware.

Wraps :func:`app.db.crud.insert_audit_event` with the failure-tolerant
semantics middleware needs — a DB outage must never break the request
path. We log the exception and move on.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.db.crud import insert_audit_event

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker

logger = logging.getLogger(__name__)


async def record_request(
    *,
    request_id: str,
    api_key_id: str | None,
    source_ip: str,
    method: str,
    path: str,
    http_status: int,
    response_code: str | None,
    detected_entity_count: int = 0,
    detected_entity_types: str | None = None,
    processing_ms: int | None = None,
    body_hash: str | None = None,
    shadow_hit_types: str | None = None,
    request_body_text: str | None = None,
    response_body_text: str | None = None,
    request_headers_text: str | None = None,
    sessionmaker: async_sessionmaker,  # type: ignore[type-arg]
) -> None:
    """Insert one audit row. Swallows all DB errors (best-effort)."""
    try:
        async with sessionmaker() as session:
            await insert_audit_event(
                session,
                request_id=request_id,
                api_key_id=api_key_id,
                source_ip=source_ip,
                method=method,
                path=path,
                http_status=http_status,
                response_code=response_code,
                detected_entity_count=detected_entity_count,
                detected_entity_types=detected_entity_types,
                processing_ms=processing_ms,
                body_hash=body_hash,
                shadow_hit_types=shadow_hit_types,
                request_body_text=request_body_text,
                response_body_text=response_body_text,
                request_headers_text=request_headers_text,
            )
    except Exception:
        logger.exception("audit insert failed; request continues uninterrupted")
