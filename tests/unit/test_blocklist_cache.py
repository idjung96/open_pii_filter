# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `app.core.blocklist_cache` lookup + reload 회귀 방지.

첨부 형식 deny-list (`attachment_blocklist` 테이블) 를 인메모리 캐시로
서빙하는 모듈을 검증한다. 실제 DB 를 띄우지 않고 `_FakeSession` 으로
미리 만든 rowset 을 주입해 ① 확장자/MIME 정규화 ② 재로드 실패 시 기존
상태 보존 ③ 대소문자 무관 매칭 등을 빠르게 회귀 검사한다.
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
    """확장자 정규화 — 대문자/선행 점/이중 확장자/확장자 없음 모두 처리.

    `file.ZIP` → `zip`, `.HWP` → `hwp` 처럼 사용자 입력을 소문자·점 제거된
    형태로 통일해야 deny-list 매칭 일관성이 깨지지 않는다. `tar.gz` 같이
    점이 여러 개인 경우는 가장 마지막 확장자만 사용한다.
    """
    assert bc._norm_ext("file.ZIP") == "zip"
    assert bc._norm_ext(".HWP") == "hwp"
    assert bc._norm_ext("archive.tar.gz") == "gz"
    assert bc._norm_ext("noext") == "noext"
    assert bc._norm_ext("") == ""


async def test_reload_loads_extensions_and_mimes_independently() -> None:
    """확장자/MIME 컬럼이 독립적으로 들어와도 각각의 set 으로 인덱싱.

    DB row 는 `(extension, mime_type)` 튜플 형태이고 한쪽만 채워질 수
    있다 (`("hwp", None)` 또는 `(None, "application/x-7z-compressed")`).
    cache 는 양쪽을 별도 set 으로 모아 매칭 시점에 각자 lookup 한다.
    """
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
    """재로드 중 DB 가 죽어도 캐시는 이전 상태를 유지해야 한다.

    DB 일시 장애 때 deny-list 가 통째로 비어버리면 운영자가 차단해 둔
    HWP/ZIP 등이 갑자기 허용되는 보안 사고로 이어진다. 회귀 방지: 두번째
    호출이 예외를 던져도 `snapshot()` 이 첫번째 로드 결과와 동일.
    """
    # 첫번째 호출은 정상 로드.
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    before = bc.snapshot()
    # 두번째 호출은 예외 — 캐시가 비워지면 안 된다.
    n = await bc.reload_blocklist(  # type: ignore[arg-type]
        _FakeSession(raise_exc=RuntimeError("db down"))
    )
    assert n == 0
    assert bc.snapshot() == before


async def test_is_blocked_matches_extension_case_insensitive() -> None:
    """파일명 확장자가 대소문자 구분 없이 매칭되는지.

    사용자는 `archive.ZIP` 처럼 대문자로 올리기도 한다. 캐시에 `zip` 만
    등록돼도 매칭이 성공해야 한다 (lowercased compare).
    """
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    blocked, kind = bc.is_blocked(filename="archive.ZIP", mime_type="application/octet-stream")
    assert blocked is True
    assert kind == "extension"


async def test_is_blocked_matches_mime_when_extension_lies() -> None:
    """확장자가 위장되어 있어도 MIME 으로 잡아낼 수 있어야 한다.

    악의적/실수로 `.bin` 처럼 일반 확장자로 위장한 7z 파일도 MIME 매칭
    경로가 살아 있어야 deny-list 가 우회되지 않는다.
    """
    await bc.reload_blocklist(  # type: ignore[arg-type]
        _FakeSession(rows=[(None, "application/x-7z-compressed")])
    )
    blocked, kind = bc.is_blocked(
        filename="payload.bin",  # 확장자만으로는 매칭 안 됨
        mime_type="application/x-7z-compressed",
    )
    assert blocked is True
    assert kind == "mime"


async def test_is_blocked_returns_false_for_allowed_combo() -> None:
    """허용 형식 (PDF 등) 은 deny-list 와 무관하게 통과해야 한다.

    오탐 방지 — 정상 PDF 가 우연한 매칭으로 거절되면 운영에 큰 불편.
    """
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    blocked, kind = bc.is_blocked(filename="report.pdf", mime_type="application/pdf")
    assert blocked is False
    assert kind is None


async def test_is_blocked_handles_empty_inputs() -> None:
    """확장자 없는 파일명 / 빈 MIME 도 안전하게 처리.

    `readme` 처럼 확장자가 아예 없거나 multipart 헤더 누락으로 MIME 이
    빈 문자열인 케이스에서 예외가 나면 안 되고, 매칭 결과도 False.
    """
    await bc.reload_blocklist(_FakeSession(rows=[("zip", None)]))  # type: ignore[arg-type]
    # 확장자 없는 파일명 + 빈 mime_type → 매칭 안 됨.
    blocked, _ = bc.is_blocked(filename="readme", mime_type="")
    assert blocked is False
