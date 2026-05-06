# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `app.core.blocklist_cache` lookup + reload semantics.

Pure-Python unit tests: the reload helper is exercised against a fake
async session that yields a pre-baked rowset, so we never touch the
real database here.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.core import blocklist_cache as bc


class _FakeResult:
    def __init__(self, rows: list[tuple[str | None, str | None]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str | None, str | None]]:
        return list(self._rows)


class _FakeSession:
    """Minimum surface area for `reload_blocklist`."""

    def __init__(
        self,
        rows: list[tuple[str | None, str | None]] | None = None,
        *,
        raise_exc: BaseException | None = None,
    ) -> None:
        self._rows = rows or []
        self._raise = raise_exc

    async def execute(self, _stmt: Any) -> _FakeResult:
        if self._raise is not None:
            raise self._raise
        return _FakeResult(self._rows)


@pytest.fixture(autouse=True)
def _reset_cache_each_test() -> None:
    bc._reset_for_tests()


def test_norm_ext_strips_dot_and_lowercases() -> None:
    assert bc._norm_ext("file.ZIP") == "zip"
    assert bc._norm_ext(".HWP") == "hwp"
    assert bc._norm_ext("archive.tar.gz") == "gz"
    assert bc._norm_ext("noext") == "noext"
    assert bc._norm_ext("") == ""


async def test_reload_loads_extensions_and_mimes_independently() -> None:
    rows = [
        (
            "zip",
            "application/zip",
        ),
        ("hwp", None),
        (None, "application/x-7z-compressed"),
    ]
    # The fake session yields (extension, mime_type) pairs only.
    session = _FakeSession(rows=[(r[0], r[1]) for r in rows])
    n = await bc.reload_blocklist(session)  # type: ignore[arg-type]
    assert n == 4  # 2 distinct extensions ("zip","hwp") + 2 distinct mimes
    snap = bc.snapshot()
    assert "zip" in snap["extensions"]
    assert "hwp" in snap["extensions"]
    assert "application/zip" in snap["mime_types"]
    assert "application/x-7z-compressed" in snap["mime_types"]


async def test_reload_failure_keeps_previous_state() -> None:
    # First successful load.
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    before = bc.snapshot()
    # Second call raises — cache must not be wiped.
    n = await bc.reload_blocklist(  # type: ignore[arg-type]
        _FakeSession(raise_exc=RuntimeError("db down"))
    )
    assert n == 0
    assert bc.snapshot() == before


async def test_is_blocked_matches_extension_case_insensitive() -> None:
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    blocked, kind = bc.is_blocked(filename="archive.ZIP", mime_type="application/octet-stream")
    assert blocked is True
    assert kind == "extension"


async def test_is_blocked_matches_mime_when_extension_lies() -> None:
    await bc.reload_blocklist(  # type: ignore[arg-type]
        _FakeSession(rows=[(None, "application/x-7z-compressed")])
    )
    blocked, kind = bc.is_blocked(
        filename="payload.bin",  # extension does not match
        mime_type="application/x-7z-compressed",
    )
    assert blocked is True
    assert kind == "mime"


async def test_is_blocked_returns_false_for_allowed_combo() -> None:
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    blocked, kind = bc.is_blocked(filename="report.pdf", mime_type="application/pdf")
    assert blocked is False
    assert kind is None


async def test_is_blocked_handles_empty_inputs() -> None:
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    # Filename without an extension and an empty mime_type must not match.
    blocked, _ = bc.is_blocked(filename="readme", mime_type="")
    assert blocked is False
