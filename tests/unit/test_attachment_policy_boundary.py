# SYNTHETIC DATA - NOT REAL PII
"""첨부 정책 경계 회귀 방지 (Phase 4 / 4b).

영역:
  - `app.core.blocklist_cache` 의 정규화 edge case (확장자 다중 점, 비-ASCII)
  - `app.extractors.dispatcher` 의 MIME 라우팅 (지원/미지원 분기)
  - `ExtractionError` 의 코드/파일명 propagation
  - text/plain · text/markdown UTF-8 + CP949 fallback 경로
  - HWP 5 → REQ-4033 (Linux 미지원)
  - Attachment schema 검증 (sha256 길이 / max_length)
  - dispatcher MIME 상수 노출 (XLSX_MIMES / HWPX_MIMES 등)

DB / 네트워크 / OCR 엔진 가동이 필요한 케이스는 integration 테스트가 담당.
본 모듈은 결정성 있는 unit 영역만 본다.
"""

from __future__ import annotations

import asyncio
import hashlib

import pytest

from app.api.schemas import Attachment
from app.core import blocklist_cache as bc
from app.extractors.dispatcher import (
    DOCX_MIMES,
    HWPX_MIMES,
    IMAGE_MIME_TYPES,
    PDF_MIMES,
    PPTX_MIMES,
    TEXT_MIMES,
    XLSX_MIMES,
    dispatch_extract,
)
from app.extractors.fetcher import ExtractionError
from app.extractors.hwpx import HWP5_MIMES


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    bc._reset_for_tests()


class _FakeResult:
    def __init__(self, rows: list[tuple[str | None, str | None]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str | None, str | None]]:
        return list(self._rows)


class _FakeSession:
    def __init__(self, rows: list[tuple[str | None, str | None]] | None = None) -> None:
        self._rows = rows or []

    async def execute(self, _stmt) -> _FakeResult:  # type: ignore[no-untyped-def]
        return _FakeResult(self._rows)


def _make_attachment(
    *,
    filename: str = "x.txt",
    mime_type: str = "text/plain",
    sha256: str | None = None,
    size_bytes: int = 0,
) -> Attachment:
    """테스트용 attachment 객체. sha256 은 자동 계산도 옵션."""
    if sha256 is None:
        sha256 = "0" * 64
    return Attachment(
        attachment_id="att_test_001",
        filename=filename,
        size_bytes=size_bytes,
        mime_type=mime_type,
        sha256=sha256,
        fetch_url="https://example.com/x",
    )


# ── blocklist_cache 정규화 edge case ─────────────────────────────────────
def test_norm_ext_multi_dot_keeps_last_only() -> None:
    """`backup.2024.tar.gz` → `gz` (가장 마지막 확장자만)."""
    assert bc._norm_ext("backup.2024.tar.gz") == "gz"


def test_norm_ext_with_only_dot() -> None:
    """단독 점 `.` 은 빈 확장자."""
    assert bc._norm_ext(".") == ""


def test_norm_ext_uppercase_with_spaces() -> None:
    """`FILE.ZIP  ` → 공백 trim + 소문자."""
    assert bc._norm_ext("FILE.ZIP  ") == "zip"


def test_norm_ext_non_ascii_filename() -> None:
    """한글 파일명도 확장자 정규화 정상 작동 — `보고서.PDF` → `pdf`."""
    assert bc._norm_ext("보고서.PDF") == "pdf"


def test_norm_ext_hidden_unix_file() -> None:
    """`.bashrc` 처럼 dot 으로 시작하는 hidden 파일은 확장자가 `bashrc` 로
    잡힌다 (이전 점이 prefix 라서). 정책 결정 — 회귀 가드."""
    assert bc._norm_ext(".bashrc") == "bashrc"


async def test_is_blocked_returns_extension_priority_over_mime() -> None:
    """확장자/MIME 둘 다 차단 대상이면 extension 우선 보고된다."""
    rows: list[tuple[str | None, str | None]] = [("zip", None), (None, "application/zip")]
    await bc.reload_blocklist(_FakeSession(rows))  # type: ignore[arg-type]
    blocked, kind = bc.is_blocked(filename="x.zip", mime_type="application/zip")
    assert blocked is True
    # 코드의 lookup 순서가 extension 먼저 → 회귀 가드.
    assert kind == "extension"


async def test_is_blocked_with_only_mime_match() -> None:
    """확장자는 OK 인데 MIME 만 차단 — kind == 'mime'."""
    rows: list[tuple[str | None, str | None]] = [(None, "application/x-msdownload")]
    await bc.reload_blocklist(_FakeSession(rows))  # type: ignore[arg-type]
    blocked, kind = bc.is_blocked(
        filename="installer.txt",  # 일반 확장자로 위장
        mime_type="application/x-msdownload",
    )
    assert blocked is True
    assert kind == "mime"


async def test_snapshot_returns_sorted_lists() -> None:
    """snapshot 의 list 가 정렬 — admin UI/디버그 일관성."""
    await bc.reload_blocklist(
        _FakeSession(
            [
                ("zip", None),
                ("rar", None),
                ("7z", None),
                (None, "application/x-tar"),
                (None, "application/zip"),
            ]
        )  # type: ignore[arg-type]
    )
    snap = bc.snapshot()
    assert snap["extensions"] == sorted(snap["extensions"])
    assert snap["mime_types"] == sorted(snap["mime_types"])
    assert "7z" in snap["extensions"]


async def test_reset_for_tests_clears_both_sets() -> None:
    """`_reset_for_tests` 가 양쪽 set 모두 비움 — fixture 동작 가드."""
    await bc.reload_blocklist(
        _FakeSession([("zip", "application/zip")]),  # type: ignore[arg-type]
    )
    snap_before = bc.snapshot()
    assert snap_before["extensions"] and snap_before["mime_types"]

    bc._reset_for_tests()
    snap_after = bc.snapshot()
    assert snap_after == {"extensions": [], "mime_types": []}


async def test_is_blocked_empty_filename_with_mime_match() -> None:
    """빈 파일명이어도 MIME 으로 차단 가능 — multipart 누락 케이스."""
    await bc.reload_blocklist(
        _FakeSession([(None, "application/x-7z-compressed")]),  # type: ignore[arg-type]
    )
    blocked, kind = bc.is_blocked(filename="", mime_type="application/x-7z-compressed")
    assert blocked is True
    assert kind == "mime"


# ── ExtractionError 코드 / 파일명 propagation ────────────────────────────
def test_extraction_error_carries_code_and_filename() -> None:
    """ExtractionError 가 code/filename/detail 을 보존."""
    err = ExtractionError("REQ-4042", filename="report.pdf", detail="parser failed")
    assert err.code == "REQ-4042"
    assert err.filename == "report.pdf"
    assert err.detail == "parser failed"
    assert "REQ-4042" in str(err)
    assert "report.pdf" in str(err)


def test_extraction_error_without_detail_is_safe() -> None:
    """detail 미지정 시 None 으로 보존 (str 화는 빈 문자열)."""
    err = ExtractionError("REQ-4033", filename="x.bin")
    assert err.detail is None
    assert "x.bin" in str(err)


def test_extraction_error_is_a_python_exception() -> None:
    """ExtractionError 가 raise 가능한 Exception subclass."""
    with pytest.raises(ExtractionError) as e:
        raise ExtractionError("REQ-4033", filename="x", detail="d")
    assert e.value.code == "REQ-4033"


# ── dispatcher MIME 상수 노출 ────────────────────────────────────────────
def test_pdf_mime_constant() -> None:
    """PDF MIME 가 정확히 `application/pdf` 하나만."""
    assert frozenset({"application/pdf"}) == PDF_MIMES


def test_docx_mime_constant_is_openxml_only() -> None:
    """DOCX 는 OpenXML wordprocessingml 만 지원 (.doc/OLE 는 deny-list)."""
    assert "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in DOCX_MIMES
    assert "application/msword" not in DOCX_MIMES


def test_xlsx_mime_constant_is_openxml_only() -> None:
    """XLSX 는 OpenXML spreadsheetml 만 (.xls 는 deny-list)."""
    assert "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in XLSX_MIMES
    assert "application/vnd.ms-excel" not in XLSX_MIMES


def test_pptx_mime_constant_is_openxml_only() -> None:
    """PPTX 는 OpenXML presentationml 만 (.ppt 는 deny-list)."""
    assert "application/vnd.openxmlformats-officedocument.presentationml.presentation" in PPTX_MIMES
    assert "application/vnd.ms-powerpoint" not in PPTX_MIMES


def test_hwpx_mime_constant_includes_three_variants() -> None:
    """HWPX 3 종 MIME 모두 등록 — 한컴/표준화 다양성."""
    expected = {"application/hwp+zip", "application/x-hwpx", "application/haansofthwpx"}
    assert expected.issubset(HWPX_MIMES)


def test_text_mime_constant_includes_markdown() -> None:
    """Phase 4b 에서 text/markdown 추가."""
    assert "text/plain" in TEXT_MIMES
    assert "text/markdown" in TEXT_MIMES


def test_image_mime_constant_covers_main_formats() -> None:
    """이미지 MIME — PNG/JPEG/TIFF/BMP/WEBP 등."""
    assert "image/png" in IMAGE_MIME_TYPES
    assert "image/jpeg" in IMAGE_MIME_TYPES


def test_hwp5_mimes_separate_from_hwpx() -> None:
    """HWP 5 (`application/x-hwp`) 은 별도 frozenset — Linux 파서 부재로 REQ-4033."""
    overlap = HWP5_MIMES & HWPX_MIMES
    assert overlap == frozenset(), f"HWP5/HWPX 겹침: {overlap}"


# ── dispatch_extract 미지원 MIME → REQ-4033 ──────────────────────────────
def test_dispatch_unsupported_mime_raises_req_4033() -> None:
    """완전히 알 수 없는 MIME 은 REQ-4033 (unsupported)."""
    a = _make_attachment(mime_type="application/x-some-binary-format")
    with pytest.raises(ExtractionError) as e:
        asyncio.run(dispatch_extract(b"\x00", a))
    assert e.value.code == "REQ-4033"
    assert e.value.filename == a.filename


def test_dispatch_hwp5_mime_raises_req_4033_with_hwp5_detail() -> None:
    """HWP 5 binary 는 미지원 — REQ-4033 + detail 에 `HWP 5` 키워드."""
    for mime in HWP5_MIMES:
        a = _make_attachment(mime_type=mime, filename="legacy.hwp")
        with pytest.raises(ExtractionError) as e:
            asyncio.run(dispatch_extract(b"\x00\x00", a))
        assert e.value.code == "REQ-4033"
        assert e.value.detail is not None
        assert "HWP 5" in e.value.detail


def test_dispatch_empty_mime_raises_req_4033() -> None:
    """MIME 이 빈 문자열이어도 REQ-4033 — 안전 fallback."""
    a = _make_attachment(mime_type="text/plain")
    # 직접 mime 을 비워 dispatch 호출하기 위해 Attachment 검증 우회 — pydantic 의
    # max_length=100 은 빈 문자열을 막지 않으므로 가능.
    a_empty_mime = a.model_copy(update={"mime_type": ""})
    with pytest.raises(ExtractionError) as e:
        asyncio.run(dispatch_extract(b"", a_empty_mime))
    assert e.value.code == "REQ-4033"


# ── text/plain UTF-8 decode 정상 동작 ────────────────────────────────────
def test_dispatch_text_plain_utf8_decodes_korean() -> None:
    """UTF-8 한글 텍스트 첨부가 정확히 decode 된다."""
    a = _make_attachment(mime_type="text/plain", filename="memo.txt")
    payload = "안녕하세요. 게시판 시스템입니다.".encode()
    text, needs_ocr = asyncio.run(dispatch_extract(payload, a))
    assert "안녕하세요" in text
    assert needs_ocr is False


def test_dispatch_text_plain_cp949_fallback() -> None:
    """UTF-8 디코딩 실패 시 CP949 fallback."""
    a = _make_attachment(mime_type="text/plain", filename="legacy.txt")
    payload = "주민번호 안내".encode("cp949")
    # UTF-8 로는 decode 실패해야 fallback 발동.
    with pytest.raises(UnicodeDecodeError):
        payload.decode("utf-8")
    text, needs_ocr = asyncio.run(dispatch_extract(payload, a))
    assert "주민번호" in text
    assert needs_ocr is False


def test_dispatch_text_plain_undecodable_raises_req_4042() -> None:
    """UTF-8/CP949 모두 디코딩 불가 → REQ-4042 (corrupt)."""
    a = _make_attachment(mime_type="text/plain", filename="garbage.txt")
    # CP949 도 거절하는 임의 byte sequence — Lone surrogate 0xFE/0xFF 만 가득.
    payload = bytes([0xFE, 0xFE, 0xFE, 0xFE, 0xFE])
    # CP949 가 이 byte 를 거절하는지 먼저 확인 (테스트 가정 검증).
    cp949_fails = False
    try:
        payload.decode("cp949")
    except UnicodeDecodeError:
        cp949_fails = True
    if not cp949_fails:
        pytest.skip("이 byte 가 CP949 에서도 디코딩되어 의미 없음")

    with pytest.raises(ExtractionError) as e:
        asyncio.run(dispatch_extract(payload, a))
    assert e.value.code == "REQ-4042"


def test_dispatch_text_markdown_uses_text_path() -> None:
    """text/markdown 도 text/plain 과 동일하게 decode."""
    a = _make_attachment(mime_type="text/markdown", filename="readme.md")
    payload = b"# Header\n\nbody text"
    text, needs_ocr = asyncio.run(dispatch_extract(payload, a))
    assert "Header" in text
    assert needs_ocr is False


def test_dispatch_text_plain_empty_body_returns_empty_string() -> None:
    """빈 본문도 안전하게 빈 문자열 반환."""
    a = _make_attachment(mime_type="text/plain", filename="empty.txt")
    text, needs_ocr = asyncio.run(dispatch_extract(b"", a))
    assert text == ""
    assert needs_ocr is False


# ── Attachment schema 검증 (Pydantic) ─────────────────────────────────────
def test_attachment_sha256_length_enforced() -> None:
    """sha256 은 64자 정확 — short/long 모두 거절."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x",
            filename="a.pdf",
            size_bytes=1,
            mime_type="application/pdf",
            sha256="0" * 63,  # 1 char too short
            fetch_url="https://example.com/x",
        )
    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x",
            filename="a.pdf",
            size_bytes=1,
            mime_type="application/pdf",
            sha256="0" * 65,  # 1 char too long
            fetch_url="https://example.com/x",
        )


def test_attachment_negative_size_rejected() -> None:
    """size_bytes 는 0 이상."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x",
            filename="a.pdf",
            size_bytes=-1,
            mime_type="application/pdf",
            sha256="0" * 64,
            fetch_url="https://example.com/x",
        )


def test_attachment_zero_size_allowed() -> None:
    """크기 0 인 빈 파일도 schema 차원에서는 허용 (정책 검사가 별도)."""
    a = Attachment(
        attachment_id="x",
        filename="empty.txt",
        size_bytes=0,
        mime_type="text/plain",
        sha256="0" * 64,
        fetch_url="https://example.com/x",
    )
    assert a.size_bytes == 0


def test_attachment_id_max_length_64() -> None:
    """attachment_id 는 최대 64자."""
    from pydantic import ValidationError

    # 64자 정확 — 허용
    Attachment(
        attachment_id="x" * 64,
        filename="a.pdf",
        size_bytes=1,
        mime_type="application/pdf",
        sha256="0" * 64,
        fetch_url="https://example.com/x",
    )
    # 65자 — 거절
    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x" * 65,
            filename="a.pdf",
            size_bytes=1,
            mime_type="application/pdf",
            sha256="0" * 64,
            fetch_url="https://example.com/x",
        )


def test_attachment_filename_max_length_255() -> None:
    """filename 은 최대 255자 (file system 한계 일반)."""
    from pydantic import ValidationError

    # 255자 — 허용
    Attachment(
        attachment_id="x",
        filename="a" * 251 + ".pdf",  # 255 chars
        size_bytes=1,
        mime_type="application/pdf",
        sha256="0" * 64,
        fetch_url="https://example.com/x",
    )
    # 256자 — 거절
    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x",
            filename="a" * 252 + ".pdf",  # 256 chars
            size_bytes=1,
            mime_type="application/pdf",
            sha256="0" * 64,
            fetch_url="https://example.com/x",
        )


def test_attachment_fetch_url_max_length_2048() -> None:
    """fetch_url 은 최대 2048자 (RFC 권장)."""
    from pydantic import ValidationError

    # 2048자 — 허용
    base = "https://example.com/"
    Attachment(
        attachment_id="x",
        filename="a.pdf",
        size_bytes=1,
        mime_type="application/pdf",
        sha256="0" * 64,
        fetch_url=base + "a" * (2048 - len(base)),
    )
    # 2049자 — 거절
    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x",
            filename="a.pdf",
            size_bytes=1,
            mime_type="application/pdf",
            sha256="0" * 64,
            fetch_url=base + "a" * (2049 - len(base)),
        )


def test_attachment_mime_type_max_length_100() -> None:
    """mime_type 은 최대 100자 — 비정상 긴 헤더 방어."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Attachment(
            attachment_id="x",
            filename="a.pdf",
            size_bytes=1,
            mime_type="x" * 101,
            sha256="0" * 64,
            fetch_url="https://example.com/x",
        )


# ── sha256 실제 검증 가능성 (helper) ─────────────────────────────────────
def test_attachment_sha256_can_be_real_hex() -> None:
    """sha256 필드가 실제 SHA-256 hex 값을 받아들임."""
    data = b"hello"
    digest = hashlib.sha256(data).hexdigest()
    a = Attachment(
        attachment_id="x",
        filename="hello.txt",
        size_bytes=len(data),
        mime_type="text/plain",
        sha256=digest,
        fetch_url="https://example.com/x",
    )
    assert a.sha256 == digest
    assert len(a.sha256) == 64
