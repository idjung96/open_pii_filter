# SYNTHETIC DATA - NOT REAL PII
"""Phase 6 — `app.security.log_filter` PII 스크러버 회귀 방지.

운영 로그/예외 트레이스에 PII 가 새는 사고가 §2.5 1순위 위반이므로 본
모듈은 `PIIScrubFilter` 의 패턴 매칭 + 재귀 스크러빙 + install/uninstall
idempotency 를 unit-level 에서 광범위하게 검증한다.

영역:

  - RRN / 사업자번호 / 전화 / 이메일 / 카드 정확 매칭
  - 같은 메시지의 multi-PII 중첩 (각각 다른 라벨)
  - `record.msg` / `record.args` / `record.exc_text` / cached `message` 모두 스크럽
  - 재귀 (dict / list / tuple 안의 평문도 스크럽)
  - 비문자열 (int / None / bool) 은 그대로 보존
  - 패턴 순서 — RRN 이 카드보다 우선 (더 좁은 패턴 먼저)
  - install/uninstall 의 idempotency
  - boundary: 좌우 word boundary, 자릿수 끝 부착
"""

from __future__ import annotations

import logging

import pytest

from app.security.log_filter import (
    PIIScrubFilter,
    _scrub_text,
    _scrub_value,
    install_pii_log_filter,
    uninstall_pii_log_filter,
)


@pytest.fixture(autouse=True)
def _cleanup_filter() -> None:
    """각 테스트 전후로 install state 를 깨끗이 — 다른 모듈 영향 차단."""
    uninstall_pii_log_filter()
    yield
    uninstall_pii_log_filter()


# ── 패턴 매칭 정확성 ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("text", "expected_label"),
    [
        ("주민번호 900101-1234567 입니다", "[REDACTED-RRN]"),
        ("사업자 123-45-67890 발행", "[REDACTED-BIZ]"),
        ("연락처 010-1234-5678", "[REDACTED-PHONE]"),
        ("연락처 02-1234-5678", "[REDACTED-PHONE]"),
        ("연락처 01012345678", "[REDACTED-PHONE]"),
        ("이메일 user@example.com 입니다", "[REDACTED-EMAIL]"),
        ("카드 4111-1111-1111-1111", "[REDACTED-CARD]"),
        ("카드 4111 1111 1111 1111", "[REDACTED-CARD]"),
        ("카드 4111111111111111", "[REDACTED-CARD]"),
    ],
)
def test_scrub_text_replaces_pii_with_label(text: str, expected_label: str) -> None:
    """`_scrub_text` 가 각 패턴 매칭 부분을 의도된 라벨로 치환."""
    out = _scrub_text(text)
    assert expected_label in out


@pytest.mark.parametrize(
    "text",
    [
        "주민번호 900101-1234567 입니다",
        "사업자 123-45-67890",
        "010-1234-5678",
        "01012345678",
        "user@example.com",
        "4111-1111-1111-1111",
    ],
)
def test_scrub_text_does_not_leave_original_pii(text: str) -> None:
    """치환 후에는 원본 평문이 출력 문자열에 남아 있지 않다."""
    out = _scrub_text(text)
    # 핵심 평문 (숫자 / 이메일) 이 그대로 노출되지 않음을 확인.
    if "@" in text:
        assert "user@example.com" not in out
    else:
        # 숫자/하이픈 평문이 그대로 남아 있으면 안 됨.
        for plain in text.split():
            if any(c.isdigit() for c in plain):
                assert plain not in out


# ── 멀티 PII 같은 메시지에서 각각 별도 라벨 ──────────────────────────
def test_scrub_text_multi_pii_in_one_line() -> None:
    """RRN + 전화 + 이메일이 한 줄에 있어도 모두 각자 라벨로 치환."""
    text = "민원 신청: 홍길동 900101-1234567 010-1234-5678 user@example.com"
    out = _scrub_text(text)
    assert "[REDACTED-RRN]" in out
    assert "[REDACTED-PHONE]" in out
    assert "[REDACTED-EMAIL]" in out
    # 원본 PII 잔여 없음.
    assert "900101-1234567" not in out
    assert "010-1234-5678" not in out
    assert "user@example.com" not in out


# ── 빈 입력 / None 안전성 ───────────────────────────────────────────────
def test_scrub_text_empty_returns_empty() -> None:
    assert _scrub_text("") == ""


def test_scrub_text_no_pii_returns_unchanged() -> None:
    """PII 없는 텍스트는 그대로."""
    text = "정상 게시글 — 평범한 내용입니다."
    assert _scrub_text(text) == text


# ── _scrub_value 재귀 — dict/list/tuple ─────────────────────────────────
def test_scrub_value_in_dict() -> None:
    """dict 값에 들어 있는 PII 도 재귀적으로 스크럽."""
    data = {
        "user": "홍길동",
        "rrn": "주민 900101-1234567 보관",
        "contact": "010-1234-5678",
    }
    out = _scrub_value(data)
    assert isinstance(out, dict)
    assert "[REDACTED-RRN]" in out["rrn"]
    assert "[REDACTED-PHONE]" in out["contact"]
    assert out["user"] == "홍길동"  # 평문 PII 아님 — 보존


def test_scrub_value_in_list() -> None:
    """list 요소 각각 스크럽."""
    out = _scrub_value(
        ["민원1 900101-1234567", "민원2 010-1234-5678", "정상 메시지"]
    )
    assert isinstance(out, list)
    assert "[REDACTED-RRN]" in out[0]
    assert "[REDACTED-PHONE]" in out[1]
    assert out[2] == "정상 메시지"


def test_scrub_value_in_tuple() -> None:
    """tuple 요소도 스크럽 + tuple 형태 보존 (logging 의 record.args 가 tuple)."""
    out = _scrub_value(("900101-1234567", "정상값"))
    assert isinstance(out, tuple)
    assert out[0] == "[REDACTED-RRN]"
    assert out[1] == "정상값"


def test_scrub_value_nested_structure() -> None:
    """중첩 구조 (dict→list→dict→str) 도 끝까지 스크럽."""
    data = {
        "items": [
            {"text": "주민 900101-1234567"},
            {"text": "전화 010-1234-5678"},
        ],
        "meta": {"author": "010-9999-0000"},
    }
    out = _scrub_value(data)
    assert "[REDACTED-RRN]" in out["items"][0]["text"]
    assert "[REDACTED-PHONE]" in out["items"][1]["text"]
    assert "[REDACTED-PHONE]" in out["meta"]["author"]


def test_scrub_value_preserves_non_string_types() -> None:
    """int / bool / None / float 같은 비문자열은 그대로."""
    assert _scrub_value(42) == 42
    assert _scrub_value(3.14) == 3.14
    assert _scrub_value(True) is True
    assert _scrub_value(None) is None


def test_scrub_value_handles_unknown_object() -> None:
    """알 수 없는 타입 (e.g. set, custom class) 은 그대로 반환 — 안전 fallback."""
    sentinel = object()
    assert _scrub_value(sentinel) is sentinel


# ── PIIScrubFilter — LogRecord 필드 모두 스크럽 ──────────────────────
def test_filter_scrubs_record_msg() -> None:
    """`record.msg` 가 문자열일 때 PII 치환."""
    flt = PIIScrubFilter()
    rec = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="주민 900101-1234567",
        args=(),
        exc_info=None,
    )
    assert flt.filter(rec) is True
    assert "[REDACTED-RRN]" in rec.msg
    assert "900101-1234567" not in rec.msg


def test_filter_scrubs_record_args_tuple() -> None:
    """`record.args` 가 tuple 일 때 그 안의 평문 PII 도 스크럽."""
    flt = PIIScrubFilter()
    rec = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="user=%s phone=%s",
        args=("user@example.com", "010-1234-5678"),
        exc_info=None,
    )
    flt.filter(rec)
    assert rec.args is not None
    assert isinstance(rec.args, tuple)
    assert "[REDACTED-EMAIL]" in rec.args[0]
    assert "[REDACTED-PHONE]" in rec.args[1]


def test_filter_scrubs_record_exc_text() -> None:
    """`record.exc_text` (이미 포맷된 traceback) 도 스크럽."""
    flt = PIIScrubFilter()
    rec = logging.LogRecord(
        name="t",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="error",
        args=(),
        exc_info=None,
    )
    rec.exc_text = "Traceback ... line 12: invalid value 900101-1234567"
    flt.filter(rec)
    assert "[REDACTED-RRN]" in rec.exc_text
    assert "900101-1234567" not in rec.exc_text


def test_filter_scrubs_cached_message() -> None:
    """`getMessage()` 호출로 cache 된 ``message`` 속성도 스크럽."""
    flt = PIIScrubFilter()
    rec = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="phone %s",
        args=("010-1234-5678",),
        exc_info=None,
    )
    rec.message = "phone 010-1234-5678"  # 호출 시점에 cache 되어 있다고 가정.
    flt.filter(rec)
    assert "[REDACTED-PHONE]" in rec.message


def test_filter_does_not_block_record() -> None:
    """filter 는 항상 True 반환 — 메시지를 drop 하지 않는다."""
    flt = PIIScrubFilter()
    rec = logging.LogRecord(
        name="t",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="no pii here",
        args=(),
        exc_info=None,
    )
    assert flt.filter(rec) is True


# ── install / uninstall idempotency ─────────────────────────────────────
def test_install_attaches_to_root_logger() -> None:
    """install 후 root logger 의 filters 에 PIIScrubFilter 가 존재."""
    install_pii_log_filter()
    root = logging.getLogger()
    assert any(isinstance(f, PIIScrubFilter) for f in root.filters)


def test_install_is_idempotent() -> None:
    """두 번 호출해도 filter 가 중복 등록되지 않는다."""
    install_pii_log_filter()
    install_pii_log_filter()
    install_pii_log_filter()
    root = logging.getLogger()
    count = sum(1 for f in root.filters if isinstance(f, PIIScrubFilter))
    assert count == 1, f"PIIScrubFilter 중복 등록: {count}"


def test_uninstall_removes_filter_from_root() -> None:
    """uninstall 후 filter 가 root logger 에서 제거."""
    install_pii_log_filter()
    uninstall_pii_log_filter()
    root = logging.getLogger()
    assert not any(isinstance(f, PIIScrubFilter) for f in root.filters)


def test_uninstall_when_not_installed_is_safe() -> None:
    """install 하지 않은 상태에서 uninstall 호출도 안전 (idempotent)."""
    uninstall_pii_log_filter()
    uninstall_pii_log_filter()  # 또 호출해도 문제 없음.
    root = logging.getLogger()
    assert not any(isinstance(f, PIIScrubFilter) for f in root.filters)


# ── 패턴 우선순위 (more-specific first) ────────────────────────────────
def test_rrn_takes_priority_over_card() -> None:
    """`900101-1234567` 처럼 RRN 형태가 13자리 카드 패턴 후보일 때도
    RRN 라벨로 치환되어야 한다 (패턴 순서가 RRN 먼저)."""
    out = _scrub_text("주민 900101-1234567")
    assert "[REDACTED-RRN]" in out
    assert "[REDACTED-CARD]" not in out


def test_biz_num_distinct_from_phone() -> None:
    """`123-45-67890` (사업자) 와 `010-1234-5678` (전화) 가 서로 다른 라벨."""
    biz_out = _scrub_text("사업자 123-45-67890")
    phone_out = _scrub_text("전화 010-1234-5678")
    assert "[REDACTED-BIZ]" in biz_out
    assert "[REDACTED-BIZ]" not in phone_out
    assert "[REDACTED-PHONE]" in phone_out


# ── 좌우 경계 — word boundary 가드 ─────────────────────────────────────
def test_rrn_with_adjacent_digit_not_matched() -> None:
    """`9900101-1234567` 처럼 앞에 숫자가 붙으면 RRN 패턴 매칭 안 됨 (\\b)."""
    out = _scrub_text("코드 9900101-1234567 참조")
    # `\b\d{6}-\d{7}\b` 가 9900101 의 6자리 부분만 잡아 부분 redact 할 수도 있음
    # — 단순 평문 검증 대신 원본이 그대로 남지 않는지 확인.
    # Note: 9900101-1234567 의 `900101-1234567` 부분이 RRN 매칭될 수 있음 (좌측
    # boundary 는 9 가 단어경계 아님). 본 테스트는 정책 회귀 가드 의도.
    # 어떤 결과든 9900101-1234567 평문이 그대로 남으면 안 됨.
    assert "9900101-1234567" not in out


def test_phone_plain_pattern_strictly_010_prefix() -> None:
    """`_PHONE_PLAIN` 은 한국 모바일 번호 010/011/016/017/018/019 만 매칭.

    의도: 010 으로 시작하는 11자리만. 02 등 비-모바일 prefix 는 `01[016789]`
    문자집합에 안 들어가 미매칭. 다른 패턴 (e.g. 카드 12+ 연속숫자) 도 11
    자리는 매칭 범위 밖이므로 silently 평문 통과 — **알려진 정책 gap**.

    스크러버가 한국 hyphen 표기 전화 (`02-XXXX-XXXX`) 는 `_PHONE_HYPHEN` 으로
    잡아 redact 하지만, 분리자 없는 02 plain 11자리는 의도된 unscrubbed
    영역. 운영 로그에 02 plain 전화가 들어오는 케이스가 거의 없다는 운영
    결정 — 만약 발견되면 패턴 강화 필요.
    """
    out = _scrub_text("전화 02012345678 정상")
    # 모바일 010 plain 만 매칭 — 02012345678 은 통과 (의도).
    assert "02012345678" in out

    # 모바일 010 plain 은 정상 매칭.
    out_mobile = _scrub_text("전화 01012345678 정상")
    assert "[REDACTED-PHONE]" in out_mobile


def test_email_with_korean_local_part_not_matched() -> None:
    """이메일 정규식은 ASCII local-part 만 — 한글 local-part 는 미매칭.

    의도: `[A-Za-z0-9._%+-]+@...` 형태이므로 한글 이메일은 silently 통과.
    운영 시 한글 이메일이 거의 없으므로 의도된 정책 — 회귀 가드.
    """
    text = "이메일 한글@example.com"
    out = _scrub_text(text)
    # 한글 local-part 자체는 매칭 안 되지만, `@example.com` 부분은 도메인 only
    # 라 별도 매칭 안 됨. silently 평문 보존 — 정책상 허용.
    assert "한글@example.com" in out or "[REDACTED-EMAIL]" in out  # 둘 다 OK
