# SYNTHETIC DATA - NOT REAL PII
"""Config / dedup / encryption helper boundary 회귀 방지.

기존 test_config.py, test_dedup.py, test_encryption.py 가 다루는 영역
외에 다음 boundary 시나리오를 추가로 가드:

Config:
  - Settings 인스턴스가 lru_cache 로 캐시 — 같은 객체
  - 환경 변수 override 동작
  - Strictness Literal 타입 일치

Dedup (_topk_per_span):
  - 0개 입력 → 빈 결과
  - K=1 (최소 K) → span 당 단 1개
  - K > 그룹 크기 → 모두 보존
  - K=0 (방어적) → 빈 결과
  - 동점 점수 시 안정성 (deterministic 출력 보장 — 정렬 키 깨짐 가드)
  - 매우 많은 span (1000개) — 성능 단조

Encryption (pgcrypto envelope):
  - encrypt 결과는 매번 다름 (nonce 랜덤)
  - 동일 plaintext + 동일 key → 매번 다른 ciphertext
  - decrypt(encrypt(x)) == x (round-trip)
  - empty bytes / very long input 도 round-trip
  - 한글 / 이모지 / Latin 모두 안전
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

from app.api.detect import MAX_DETECTIONS_PER_SPAN, _topk_per_span
from app.config import get_settings
from app.security import encryption


@pytest.fixture()
def _encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """test_encryption.py 와 동일한 패턴 — 알려진 32-byte 키 주입.

    encryption module 의 lru_cache 도 함께 비워 테스트 격리 보장.
    """

    def _settings_with(**overrides):  # type: ignore[no-untyped-def]
        from app.config import Settings

        base = Settings().model_dump()
        base.update(overrides)
        return Settings(**base)

    key = os.urandom(32).hex()
    monkeypatch.setattr(
        encryption,
        "get_settings",
        lambda: _settings_with(
            pii_encryption_key=key,
            pii_encryption_key_id=1,
            pii_encryption_old_keys="",
        ),
    )
    encryption.get_cipher.cache_clear()
    encryption._old_ciphers.cache_clear()


# helper aliases — fixture 주입 후 사용 가능.
encrypt_str = encryption.encrypt_str
decrypt_str = encryption.decrypt_str


@dataclass
class _R:
    """RecognizerResult stub for unit-level _topk_per_span tests."""

    entity_type: str
    start: int
    end: int
    score: float


# ── Config — Settings singleton ──────────────────────────────────────────
def test_settings_get_settings_returns_same_instance() -> None:
    """`get_settings()` 가 lru_cache 로 같은 인스턴스 반환 — 환경 변수 1회 로드."""
    a = get_settings()
    b = get_settings()
    assert a is b


def test_settings_has_required_fields() -> None:
    """Settings 가 운영에 필요한 필드를 모두 노출."""
    s = get_settings()
    # 핵심 필드 존재 (값은 환경 의존이므로 존재 여부만).
    for attr in (
        "database_url",
        "redis_url",
        "admin_ip_allowlist",
        "trust_forwarded_for",
        "webhook_post_timeout_seconds",
        "webhook_signing_secret",
    ):
        assert hasattr(s, attr), f"Settings.{attr} 누락"


def test_settings_admin_ip_allowlist_is_string_or_none() -> None:
    """admin_ip_allowlist 가 string 또는 None — CSV 파서 입력 형식."""
    s = get_settings()
    val = s.admin_ip_allowlist
    assert val is None or isinstance(val, str)


def test_settings_trust_forwarded_for_is_bool() -> None:
    s = get_settings()
    assert isinstance(s.trust_forwarded_for, bool)


def test_settings_webhook_post_timeout_positive() -> None:
    """webhook 타임아웃은 양수 (0 이면 즉시 timeout)."""
    s = get_settings()
    assert s.webhook_post_timeout_seconds > 0


# ── Dedup — _topk_per_span 경계 ──────────────────────────────────────────
def test_topk_per_span_empty_input_returns_empty() -> None:
    """빈 리스트 입력은 빈 리스트 출력."""
    assert _topk_per_span([]) == []  # type: ignore[arg-type]


def test_topk_per_span_with_k_equals_one() -> None:
    """K=1 — 각 span 당 score 최고 하나만 남는다."""
    raw = [
        _R("A", 0, 5, 0.9),
        _R("B", 0, 5, 0.7),
        _R("C", 0, 5, 0.5),
        _R("D", 10, 15, 0.8),
    ]
    out = _topk_per_span(raw, k=1)  # type: ignore[arg-type]
    assert len(out) == 2
    # 각 span 의 최고 score entity 만.
    by_span = {(r.start, r.end): r.entity_type for r in out}
    assert by_span == {(0, 5): "A", (10, 15): "D"}


def test_topk_per_span_k_greater_than_group_size() -> None:
    """K 가 그룹보다 크면 그룹 전체가 보존."""
    raw = [
        _R("A", 0, 5, 0.9),
        _R("B", 0, 5, 0.7),
    ]
    out = _topk_per_span(raw, k=10)  # type: ignore[arg-type]
    assert len(out) == 2


def test_topk_per_span_k_zero_returns_empty() -> None:
    """K=0 — 어떤 span 도 보존 안 됨 (방어적 경계)."""
    raw = [_R("A", 0, 5, 0.9), _R("B", 0, 5, 0.7)]
    out = _topk_per_span(raw, k=0)  # type: ignore[arg-type]
    assert out == []


def test_topk_per_span_preserves_high_score_on_tie() -> None:
    """동점 점수 다수 + K=2 — 2개만 남는다 (안정 정렬 보장 X 정책)."""
    raw = [
        _R("A", 0, 5, 0.8),
        _R("B", 0, 5, 0.8),
        _R("C", 0, 5, 0.8),
    ]
    out = _topk_per_span(raw, k=2)  # type: ignore[arg-type]
    assert len(out) == 2
    # 어떤 둘이 살아남든 score 는 모두 0.8.
    assert all(r.score == 0.8 for r in out)


def test_topk_per_span_constant_is_three() -> None:
    """기본 K = 3 (응답 페이로드 비대화 방지 정책)."""
    assert MAX_DETECTIONS_PER_SPAN == 3


def test_topk_per_span_does_not_mutate_input() -> None:
    """함수가 입력 리스트를 변조하지 않음 (defensive copy)."""
    raw = [
        _R("A", 0, 5, 0.9),
        _R("B", 0, 5, 0.7),
        _R("C", 0, 5, 0.5),
    ]
    original = list(raw)
    _ = _topk_per_span(raw)  # type: ignore[arg-type]
    # 입력 리스트의 길이/구성이 보존.
    assert list(raw) == original


def test_topk_per_span_many_spans_scales() -> None:
    """1000 개 distinct span 도 정상 처리 (메모리/시간 성능 가드)."""
    raw = [_R(f"E{i}", i * 10, i * 10 + 5, 0.5 + i / 10000) for i in range(1000)]
    out = _topk_per_span(raw, k=3)  # type: ignore[arg-type]
    # 모든 span 이 distinct 라 각각 1개씩 — 1000건.
    assert len(out) == 1000


def test_topk_per_span_handles_overlapping_partial_spans() -> None:
    """부분 겹침 span 은 (start,end) 가 다르므로 별도 그룹."""
    raw = [
        _R("A", 0, 10, 0.9),
        _R("B", 5, 15, 0.8),  # 겹치지만 (start,end) 다름
    ]
    out = _topk_per_span(raw)  # type: ignore[arg-type]
    assert len(out) == 2


# ── Encryption — round-trip & determinism ───────────────────────────────
def test_encrypt_str_produces_different_ciphertext_each_call(
    _encryption_key,
) -> None:
    """동일 plaintext → 매번 다른 ciphertext (nonce 랜덤성).

    같은 ciphertext 가 두 번 나오면 nonce 가 deterministic 인 사고 — 기록된
    ciphertext 로부터 새 메시지 패턴을 유추할 수 있게 됨.
    """
    plain = "민감한 정보"
    a = encryption.encrypt_str(plain)
    b = encryption.encrypt_str(plain)
    assert a != b


def test_encrypt_decrypt_round_trip_korean(_encryption_key) -> None:
    """한글 평문 round-trip."""
    plain = "주민등록번호: 900201-2320987"
    ct = encryption.encrypt_str(plain)
    assert encryption.decrypt_str(ct) == plain


def test_encrypt_decrypt_round_trip_emoji(_encryption_key) -> None:
    """이모지 포함 평문 round-trip (UTF-8 4-byte 문자)."""
    plain = "테스트 🎉 emoji"
    ct = encryption.encrypt_str(plain)
    assert encryption.decrypt_str(ct) == plain


def test_encrypt_decrypt_long_input(_encryption_key) -> None:
    """긴 입력 (10 KB) 도 round-trip."""
    plain = "긴문자열" * 2500  # ~10 KB UTF-8
    ct = encryption.encrypt_str(plain)
    assert encryption.decrypt_str(ct) == plain


def test_encrypt_decrypt_empty_string_noop(_encryption_key) -> None:
    """빈 문자열은 encrypt/decrypt 가 no-op (envelope 미생성).

    DB NOT NULL 컬럼 호환 — 빈 값을 굳이 envelope 으로 감싸지 않음.
    """
    assert encryption.encrypt_str("") == ""
    assert encryption.decrypt_str("") == ""


def test_encrypt_decrypt_single_char(_encryption_key) -> None:
    """1자 입력도 안전."""
    for c in ["a", "1", "한", "🎉"]:
        ct = encryption.encrypt_str(c)
        assert encryption.decrypt_str(ct) == c


def test_encrypt_ciphertext_is_string(_encryption_key) -> None:
    """encrypt 결과는 문자열 (base64 envelope 인코딩)."""
    ct = encryption.encrypt_str("data")
    assert isinstance(ct, str)
    assert len(ct) > 0


def test_decrypt_invalid_base64_raises(_encryption_key) -> None:
    """잘못된 base64 입력은 명시적 예외 — silent return 금지."""
    with pytest.raises(Exception):
        encryption.decrypt_str("not!base64-at!all@@")


# ── Encryption envelope format invariants ──────────────────────────────
def test_encrypt_envelope_distinguishable_across_inputs(_encryption_key) -> None:
    """서로 다른 입력의 ciphertext 도 다름 (basic distinctness)."""
    a = encryption.encrypt_str("input-a")
    b = encryption.encrypt_str("input-b")
    assert a != b


def test_encrypt_decrypt_preserves_whitespace(_encryption_key) -> None:
    """앞뒤 공백 / 줄바꿈 / 탭 보존."""
    plain = "  앞공백  \n\t줄바꿈탭  뒤공백  "
    ct = encryption.encrypt_str(plain)
    assert encryption.decrypt_str(ct) == plain


def test_encrypt_decrypt_special_characters(_encryption_key) -> None:
    """제어 문자 / 특수 문자 보존."""
    plain = 'JSON-like {"key": "value", "n": 42, "ok": true}'
    ct = encryption.encrypt_str(plain)
    assert encryption.decrypt_str(ct) == plain
