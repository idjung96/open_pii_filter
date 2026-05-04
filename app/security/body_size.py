"""Starlette middleware: cap the HTTP request body at a fixed size (T3.9).

Defends against payload-bomb DoS in addition to Nginx's
``client_max_body_size``. Returns ``REQ-4030`` (HTTP 413) on violation.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.api.responses import build_response
from app.core.codes import get_code

DEFAULT_MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB (per spec T3.9)


def _too_large_response() -> JSONResponse:
    rc = get_code("REQ-4030")
    from uuid import UUID
    resp = build_response(
        request_id=UUID("00000000-0000-0000-0000-000000000000"),
        code="REQ-4030",
        processing_ms=0,
    )
    return JSONResponse(status_code=rc.http_status, content=resp.model_dump(mode="json"))


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject any request whose body exceeds ``max_bytes``."""

    def __init__(self, app, *, max_bytes: int = DEFAULT_MAX_BODY_BYTES) -> None:  # type: ignore[no-untyped-def]  # noqa: ANN001
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Trust Content-Length when present — almost every well-behaved
        # client sets it, including httpx, requests, curl, and Nginx.
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self._max_bytes:
                    return _too_large_response()
            except ValueError:
                # Fall through to streaming guard for malformed CL.
                pass
            else:
                # CL valid and under cap — let the request through
                # without consuming the stream (so FastAPI can still
                # read req.body() normally downstream).
                return await call_next(request)

        # No Content-Length: stream-and-cap. Re-inject body so the
        # endpoint can consume it.
        body = b""
        more = True
        while more:
            event = await request.receive()
            if event["type"] != "http.request":
                continue
            body += event.get("body", b"") or b""
            more = bool(event.get("more_body", False))
            if len(body) > self._max_bytes:
                return _too_large_response()

        sent = False

        async def _receive() -> dict[str, object]:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = _receive
        return await call_next(request)
