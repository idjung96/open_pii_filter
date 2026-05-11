# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `app.extractors.xlsx.extract_xlsx` 회귀 방지.

XLSX 추출기의 3가지 핵심 동작을 핀(pin) 한다:

  - 모든 시트의 모든 셀 텍스트가 결과 문자열에 연결됨
  - 숫자/날짜형 셀이 문자열로 변환되어 PII 패턴 (RRN, 사업자번호 등 digit
    런) 이 분석기에 도달할 수 있음
  - 암호화된 MS-CFB 워크북은 REQ-4051 로 거절
  - 손상된 (비-ZIP) 페이로드는 REQ-4042 로 거절

특히 두번째는 흔한 회귀 — `openpyxl` 의 `cell.value` 가 `int` 면 정규식
인식기가 매칭 못 하므로 `str()` 변환을 반드시 거쳐야 한다.
"""

from __future__ import annotations

import pytest

from app.extractors.fetcher import ExtractionError
from app.extractors.xlsx import extract_xlsx
from tests.fixtures.attachments.create_fixtures import (
    SYNTH_PHONE,
    SYNTH_TEXT,
    make_xlsx_with_pii,
)


async def test_extract_xlsx_returns_text_from_every_cell() -> None:
    """문자열·전화번호·숫자형 셀이 모두 결과에 보존되어야 한다.

    합성 fixture 는 셀에 한국어 문자열 (SYNTH_TEXT), 전화번호 (SYNTH_PHONE)
    그리고 정수 `1234567890` 을 넣어둔다. 분석기가 digit run 패턴을
    잡으려면 정수 셀이 문자열로 stringify 된 결과가 추출 텍스트에
    노출되어야 한다.
    """
    text = await extract_xlsx(make_xlsx_with_pii(), "synthetic.xlsx")
    assert SYNTH_TEXT in text
    assert SYNTH_PHONE in text
    # A2 의 숫자 셀 (1234567890) 도 문자열로 노출되어야 PII 패턴이 작동.
    assert "1234567890" in text


async def test_extract_xlsx_rejects_encrypted_blob() -> None:
    """암호화된 MS-CFB 워크북은 REQ-4051 (암호화된 파일) 로 거절해야 한다.

    PPTX 와 동일한 시나리오 — Office password 가 걸린 파일은 OOXML zip 이
    아니라 OLE/CFB 컨테이너가 된다.
    """
    encrypted = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    with pytest.raises(ExtractionError) as excinfo:
        await extract_xlsx(encrypted, "secret.xlsx")
    assert excinfo.value.code == "REQ-4051"


async def test_extract_xlsx_rejects_corrupt_zip() -> None:
    """ZIP 이 아닌 페이로드는 REQ-4042 (첨부 파일 손상) 로 거절.

    Content-Type 만 XLSX 라고 위장한 임의의 바이트가 들어와도 silent 빈
    결과로 흘러가면 안 된다 — 명시적 ExtractionError 발생이 보안.
    """
    with pytest.raises(ExtractionError) as excinfo:
        await extract_xlsx(b"not a zip at all", "broken.xlsx")
    assert excinfo.value.code == "REQ-4042"
