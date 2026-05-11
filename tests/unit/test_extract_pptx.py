# SYNTHETIC DATA - NOT REAL PII
"""Phase 4b — `app.extractors.pptx.extract_pptx` 회귀 방지.

다음 4가지 시나리오를 한 모듈에서 빠르게 핀(pin) 한다:

  - 일반 슬라이드 shape 의 텍스트 본문이 추출됨
  - 발표자 노트 (notes frame) 도 결과에 포함됨 — 공공기관 문서는 PII 가
    노트에 들어가는 사례가 흔하다 (오탐의 정반대 문제 — 미탐 방지)
  - 암호화된 MS-CFB 컨테이너는 REQ-4051 (암호화된 파일) 로 거절
  - 손상된 (비-ZIP) 페이로드는 REQ-4042 (첨부 파일 손상) 로 거절
"""

from __future__ import annotations

import pytest

from app.extractors.fetcher import ExtractionError
from app.extractors.pptx import extract_pptx
from tests.fixtures.attachments.create_fixtures import (
    SYNTH_EMAIL,
    SYNTH_TEXT,
    make_pptx_with_pii,
)


async def test_extract_pptx_returns_text_and_notes() -> None:
    """슬라이드 본문 + 발표자 노트 양쪽 모두에서 PII 토큰이 추출되어야 한다.

    합성 PPTX 는 슬라이드 1에 SYNTH_TEXT 를, 슬라이드 2의 노트에
    SYNTH_EMAIL 을 심어둔다. 둘 다 결과 텍스트에 등장하지 않으면 추출
    경로 중 어느 한 쪽이 누락된 것이다.
    """
    text = await extract_pptx(make_pptx_with_pii(), "synthetic.pptx")
    assert SYNTH_TEXT in text
    # 슬라이드 2의 발표자 노트도 결과에 도달해야 한다.
    assert SYNTH_EMAIL in text


async def test_extract_pptx_rejects_encrypted_blob() -> None:
    """암호화된 (MS-CFB 헤더로 시작하는) PPTX 는 REQ-4051 로 거절.

    Office 의 password-protected 파일은 OOXML zip 컨테이너가 아니라
    `D0 CF 11 E0 ...` 시그니처의 OLE/CFB 가 된다. 이를 추출하려고
    시도하면 zipfile 단계에서 에러가 나야 하고, 그 결과 코드는
    "암호화" 의미를 정확히 갖는 `REQ-4051` 이어야 한다.
    """
    encrypted = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    with pytest.raises(ExtractionError) as excinfo:
        await extract_pptx(encrypted, "secret.pptx")
    assert excinfo.value.code == "REQ-4051"


async def test_extract_pptx_rejects_corrupt_zip() -> None:
    """손상되거나 PPTX 가 아닌 페이로드는 REQ-4042 (첨부 파일 손상) 로 거절.

    Content-Type 만 PPTX 라고 위장한 임의의 바이트 (예: 텍스트) 가 들어와도
    추출기가 안전하게 ExtractionError 로 종료되어야 한다. silent 빈 결과는
    오탐의 정반대 사고 (전부 통과) 로 이어지므로 명시적 거절이 중요.
    """
    with pytest.raises(ExtractionError) as excinfo:
        await extract_pptx(b"definitely not a zip", "broken.pptx")
    assert excinfo.value.code == "REQ-4042"
